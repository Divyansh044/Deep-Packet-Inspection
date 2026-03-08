/*
 * policy_engine.cpp — Policy Implementation
 * ==========================================
 *
 * This file implements the "brain" of our DPI system.
 * It reads configuration files when the program starts, saving
 * the bad IPs and Domains into our `unordered_set` (hash map) memory.
 *
 * During live traffic analysis, it takes the output from our parsers
 * (like the `http_parser` or `tls_parser`) and checks if they hit
 * the blocklist.
 *
 * NOTE ON WILDCARDS:
 * ──────────────────
 * A big feature of enterprise DPI is "wildcard" blocking.
 * If I block "*.ads.com", it should block:
 *   - "banner.ads.com"
 *   - "api.ads.com"
 *   - "ads.com" itself.
 *
 * We implement a fast suffix-matching algorithm in `isDomainBlocked()`.
 */

#include "../include/policy_engine.h"
#include <fstream>
#include <iostream>

using namespace std;

PolicyEngine::PolicyEngine() {
  // Basic constructor
}

// ─────────────────────────────────────────────────────────────────────────────
// loadBlockedDomains()
// ─────────────────────────────────────────────────────────────────────────────
// We open the text file and insert every line into our hash set.
// This gives us instant lookups later.
bool PolicyEngine::loadBlockedDomains(const std::string &filepath) {
  ifstream file(filepath);
  if (!file.is_open()) {
    cerr << "[ERROR] Could not open " << filepath << endl;
    return false;
  }

  string line;
  while (getline(file, line)) {
    // Strip trailing newline characters like \r or empty spaces
    line.erase(line.find_last_not_of(" \n\r\t") + 1);

    // Ignore empty lines and comments
    if (line.empty() || line[0] == '#')
      continue;

    // Insert into our lightning-fast hash set
    blocked_domains_.insert(line);
  }
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// loadBlockedIPs()
// ─────────────────────────────────────────────────────────────────────────────
// Exact same logic as domains, but into the IP hash set.
bool PolicyEngine::loadBlockedIPs(const std::string &filepath) {
  ifstream file(filepath);
  if (!file.is_open()) {
    cerr << "[ERROR] Could not open " << filepath << endl;
    return false;
  }

  string line;
  while (getline(file, line)) {
    line.erase(line.find_last_not_of(" \n\r\t") + 1);
    if (line.empty() || line[0] == '#')
      continue;

    blocked_ips_.insert(line);
  }
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// checkPacket() — The Core Brain Logic
// ─────────────────────────────────────────────────────────────────────────────
/*
 * Every single packet captured from the network comes here after parsing.
 * The order of checks matters:
 *
 * 1. IP Blocklist  (Is the destination IP bad?)
 * 2. DNS Blocklist (Did they ask for a bad website?)
 * 3. Web Blocklist (Is the HTTP Host or TLS SNI bad?)
 */
bool PolicyEngine::checkPacket(const ParsedPacket &packet,
                               Alert &alert_out) const {

  // ── 1. Check IP ──
  // Is the source or destination IP in our blocklist?
  // Hash Set `find()` is O(1) time complexity - it takes nanoseconds.
  if (!packet.src_ip.empty() &&
      blocked_ips_.find(packet.src_ip) != blocked_ips_.end()) {
    alert_out.rule_type = "Blocked Source IP";
    alert_out.matched_value = packet.src_ip;
    alert_out.description = "Connection originating from a blocked IP address.";
    return true; // ALERT fired!
  }
  if (!packet.dest_ip.empty() &&
      blocked_ips_.find(packet.dest_ip) != blocked_ips_.end()) {
    alert_out.rule_type = "Blocked Destination IP";
    alert_out.matched_value = packet.dest_ip;
    alert_out.description = "Connection attempted to a blocked IP address.";
    return true; // ALERT fired!
  }

  // ── 2. Check DNS Query ──
  if (!packet.dns_query.empty() && isDomainBlocked(packet.dns_query)) {
    alert_out.rule_type = "Blocked DNS Lookup";
    alert_out.matched_value = packet.dns_query;
    alert_out.description =
        "Computer asked the network for a forbidden website's IP.";
    return true; // ALERT!
  }

  // ── 3. Check HTTP Host ──
  if (!packet.http_host.empty() && isDomainBlocked(packet.http_host)) {
    alert_out.rule_type = "Blocked HTTP Request";
    alert_out.matched_value = packet.http_host;
    alert_out.description = "Unencrypted web request to blocked domain.";
    return true; // ALERT!
  }

  // ── 4. Check TLS SNI (HTTPS) ──
  if (!packet.tls_sni.empty() && isDomainBlocked(packet.tls_sni)) {
    alert_out.rule_type = "Blocked HTTPS Handshake";
    alert_out.matched_value = packet.tls_sni;
    alert_out.description =
        "TLS ClientHello exposed a blocked Server Name Indication (SNI).";
    return true; // ALERT!
  }

  // If we get here, the packet matches no rules. It's clean.
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// PRIVATE: isDomainBlocked() — Handles wildcards!
// ─────────────────────────────────────────────────────────────────────────────
/*
 * How do we test if "api.ads.malware.com" matches "*.malware.com"?
 *
 * We check the full name first. If it's not blocked, we chop off the FIRST
 * word (up to the period), add a "*." to the front, and check again!
 *
 * Example input: "api.ads.com"
 *   Check 1: "api.ads.com" -> not found
 *   Check 2: "*.ads.com"   -> found! (Alert triggers)
 *   Check 3: "*.com"       -> (would run if check 2 failed)
 */
bool PolicyEngine::isDomainBlocked(const std::string &domain) const {

  // First, try an exact match (e.g., "malware.com")
  if (blocked_domains_.find(domain) != blocked_domains_.end()) {
    return true;
  }

  // If no exact match, try stripping subdomains to see if a wildcard fits.
  size_t pos_dot = 0;
  std::string temp_domain = domain;

  // Keep finding the next dot
  while ((pos_dot = temp_domain.find('.')) != std::string::npos) {

    // Chop off the first part, e.g., "api.ads.com" -> "ads.com"
    temp_domain = temp_domain.substr(pos_dot + 1);

    // We don't want to block just ".com", so make sure there's another dot
    // (This prevents blocking top level domains unless explicitly told to)
    if (temp_domain.find('.') != std::string::npos ||
        temp_domain.length() > 2) {

      // Reconstruct the wildcard String: "*.ads.com"
      std::string wildcard_test = "*." + temp_domain;

      // Check if our blocklist contains this specific wildcard string
      if (blocked_domains_.find(wildcard_test) != blocked_domains_.end()) {
        return true;
      }
    } else {
      // we hit the TLD (like .com or .org), stop checking
      break;
    }
  }

  return false; // Domain is safe
}
