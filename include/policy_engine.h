/*
 * policy_engine.h — Rule Matching & Detection Engine
 * ===================================================
 *
 * WHY THIS FILE EXISTS:
 * ---------------------
 * Now that our parsers (Phase 1) can extract IP addresses and domain names,
 * and our Packet Capture (Phase 2) is feeding them to us, we need a "Brain".
 *
 * The Policy Engine checks every single packet against a list of rules
 * (e.g., "Is this domain in our blocked list?").
 *
 * PERFORMANCE IS CRITICAL:
 * ────────────────────────
 * We might be processing 100,000+ packets per second. If our blocklist
 * has 10,000 bad domains, we absolutely CANNOT use a slow list search.
 *
 * INTERVIEW Q: "What data structure do you use for the blocklist, and why?"
 * A: An unordered_set (Hash Set). Searching an array/vector is O(N) time.
 *    Searching a Hash Set is O(1) time. No matter if we have 10 rules or
 *    10 million rules, checking a packet takes the exact same microscopic
 *    amount of time.
 */

#ifndef POLICY_ENGINE_H
#define POLICY_ENGINE_H

#include "protocols.h" // Gives us ParsedPacket
#include <string>
#include <unordered_set>

// ─────────────────────────────────────────────────────────────────────────────
// Alert Struct
// ─────────────────────────────────────────────────────────────────────────────
// When a packet breaks a rule, we generate an Alert.
struct Alert {
  std::string rule_type;     // e.g., "Blocked Domain" or "Blocked IP"
  std::string matched_value; // e.g., "malware.com" or "1.2.3.4"
  std::string description;   // Human-readable reason
};

// ─────────────────────────────────────────────────────────────────────────────
// Policy Engine Class
// ─────────────────────────────────────────────────────────────────────────────
class PolicyEngine {
public:
  PolicyEngine();

  /*
   * loadBlockedDomains()
   * Reads a text file of bad domains (one per line) and loads them
   * into our super-fast Hash Set memory.
   */
  bool loadBlockedDomains(const std::string &filepath);

  /*
   * loadBlockedIPs()
   * Reads a text file of bad IPs (one per line) into a Hash Set.
   */
  bool loadBlockedIPs(const std::string &filepath);

  /*
   * checkPacket()
   * The core logic. Takes a fully parsed packet, checks its IPs and
   * Domains against our Hash Sets.
   *
   * Returns true if an ALERT was generated (meaning it's bad traffic).
   * The alert details are placed into the 'alert_out' variable.
   */
  bool checkPacket(const ParsedPacket &packet, Alert &alert_out) const;

  // Getters for statistics
  size_t getBlockedDomainCount() const { return blocked_domains_.size(); }
  size_t getBlockedIPCount() const { return blocked_ips_.size(); }

private:
  // O(1) Hash Sets for lightning-fast matching
  std::unordered_set<std::string> blocked_domains_;
  std::unordered_set<std::string> blocked_ips_;

  // Helper function to handle wildcard domains (e.g., checking
  // if "api.ads.com" matches "*.ads.com")
  bool isDomainBlocked(const std::string &domain) const;
};

#endif // POLICY_ENGINE_H
