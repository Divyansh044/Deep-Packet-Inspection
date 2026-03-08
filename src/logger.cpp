/*
 * logger.cpp — Output & Statistics Implementation
 * =================================================
 */

#include "../include/logger.h"
#include <algorithm>
#include <iostream>

using namespace std;

// ─────────────────────────────────────────────────────────────────────────────
// Domain → Application Name Classifier
// ─────────────────────────────────────────────────────────────────────────────
// When we see an SNI/DNS domain like "www.youtube.com", we classify it as
// "YouTube". This makes the stats report human-readable.
//
// INTERVIEW Q: "How do commercial DPIs classify applications?"
// A: Exactly like this — a curated table of known domains/IPs mapped to
//    application names. At scale, this uses a Aho-Corasick trie for
//    microsecond multi-pattern matching across millions of rules.
static const struct {
  const char *keyword;
  const char *app;
} DOMAIN_MAP[] = {
    {"youtube.com", "YouTube"},
    {"googlevideo.com", "YouTube"},
    {"ytimg.com", "YouTube"},
    {"facebook.com", "Facebook"},
    {"fbcdn.net", "Facebook"},
    {"instagram.com", "Instagram"},
    {"cdninstagram.com", "Instagram"},
    {"twitter.com", "Twitter / X"},
    {"twimg.com", "Twitter / X"},
    {"x.com", "Twitter / X"},
    {"netflix.com", "Netflix"},
    {"nflxvideo.net", "Netflix"},
    {"google.com", "Google"},
    {"googleapis.com", "Google"},
    {"gstatic.com", "Google"},
    {"googletagmanager.com", "Google"},
    {"github.com", "GitHub"},
    {"githubassets.com", "GitHub"},
    {"githubusercontent.com", "GitHub"},
    {"microsoft.com", "Microsoft"},
    {"windows.com", "Microsoft"},
    {"live.com", "Microsoft"},
    {"amazon.com", "Amazon"},
    {"amazonaws.com", "Amazon AWS"},
    {"cloudfront.net", "Amazon AWS"},
    {"whatsapp.com", "WhatsApp"},
    {"whatsapp.net", "WhatsApp"},
    {"telegram.org", "Telegram"},
    {"spotify.com", "Spotify"},
    {"scdn.co", "Spotify"},
    {"tiktok.com", "TikTok"},
    {"discord.com", "Discord"},
    {"discordapp.com", "Discord"},
    {"reddit.com", "Reddit"},
    {"redd.it", "Reddit"},
    {"twitch.tv", "Twitch"},
    {"cloudflare.com", "Cloudflare"},
    {"1dot1dot1dot1.cloudflare", "Cloudflare"},
};
static const int DOMAIN_MAP_SIZE = sizeof(DOMAIN_MAP) / sizeof(DOMAIN_MAP[0]);

// ─────────────────────────────────────────────────────────────────────────────
// Constructor
// ─────────────────────────────────────────────────────────────────────────────
Logger::Logger()
    : debug_mode_(false), total_packets_scanned_(0), total_alerts_triggered_(0),
      total_forwarded_(0), total_dropped_(0), total_bytes_(0), tcp_packets_(0),
      udp_packets_(0) {}

void Logger::setDebugBuild(bool enable) { debug_mode_ = enable; }

// ─────────────────────────────────────────────────────────────────────────────
// Standard Output Methods
// ─────────────────────────────────────────────────────────────────────────────
void Logger::info(const string &message) {
  cout << COLOR_BLUE << "[INFO] " << COLOR_RESET << message << "\n";
}
void Logger::success(const string &message) {
  cout << COLOR_GREEN << "[OK] " << COLOR_RESET << message << "\n";
}
void Logger::warning(const string &message) {
  cout << COLOR_YELLOW << "[WARN] " << COLOR_RESET << message << "\n";
}
void Logger::error(const string &message) {
  cerr << COLOR_RED << "[ERROR] " << COLOR_RESET << message << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// File Logging Setup
// ─────────────────────────────────────────────────────────────────────────────
void Logger::setLogFile(const string &filepath) {
  log_file_.open(filepath, ios::out | ios::app);
  if (!log_file_.is_open()) {
    error("Could not open log file: " + filepath);
  } else {
    success("Logging traffic to: " + filepath);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Counter Methods
// ─────────────────────────────────────────────────────────────────────────────
void Logger::incrementPacketsScanned() { total_packets_scanned_++; }
void Logger::incrementForwarded() { total_forwarded_++; }
void Logger::incrementDropped() { total_dropped_++; }

// ─────────────────────────────────────────────────────────────────────────────
// recordPacketStats — Called for every parsed packet
// ─────────────────────────────────────────────────────────────────────────────
// This is where we update all our breakdown counters.
void Logger::recordPacketStats(const ParsedPacket &packet) {
  // Transport layer counters
  total_bytes_ += packet.packet_length;
  if (packet.transport_proto == "TCP")
    tcp_packets_++;
  else if (packet.transport_proto == "UDP")
    udp_packets_++;

  // Determine the domain name from whatever was parsed
  string domain;
  if (!packet.tls_sni.empty())
    domain = packet.tls_sni;
  else if (!packet.dns_query.empty())
    domain = packet.dns_query;
  else if (!packet.http_host.empty())
    domain = packet.http_host;

  // App-level classification
  string app_name;
  if (!domain.empty()) {
    app_name = classifyDomain(domain);
    // Record this domain in our detected list
    detected_domains_[domain] = app_name;
  } else if (packet.app_protocol == "DNS") {
    app_name = "DNS";
  } else if (packet.dest_port == 443 || packet.src_port == 443) {
    // Port 443 but no SNI parsed yet (encrypted data packets)
    app_name = "HTTPS";
  } else if (packet.dest_port == 80 || packet.src_port == 80) {
    app_name = "HTTP";
  } else {
    app_name = "Unknown";
  }

  app_counts_[app_name]++;
}

// ─────────────────────────────────────────────────────────────────────────────
// Alert Logging
// ─────────────────────────────────────────────────────────────────────────────
void Logger::logAlert(const Alert &alert, const ParsedPacket &packet) {
  total_alerts_triggered_++;

  // Console output with colors
  cout << "\n";
  cout << COLOR_RED << "██████████████████ SECURITY ALERT ██████████████████\n"
       << COLOR_RESET;
  cout << COLOR_YELLOW << "Type   : " << COLOR_RESET << alert.rule_type << "\n";
  cout << COLOR_YELLOW << "Match  : " << COLOR_RESET << COLOR_RED
       << alert.matched_value << COLOR_RESET << "\n";
  cout << COLOR_YELLOW << "Reason : " << COLOR_RESET << alert.description
       << "\n";
  cout << COLOR_YELLOW << "Packet : " << COLOR_RESET
       << formatPacketSummary(packet) << "\n";
  cout << COLOR_RED
       << "████████████████████████████████████████████████████\n\n"
       << COLOR_RESET;

  // File output
  if (log_file_.is_open()) {
    log_file_ << "[ALERT] " << alert.rule_type << " | " << alert.matched_value
              << " | " << alert.description << " | "
              << formatPacketSummary(packet) << "\n";
    log_file_.flush();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// debugPacket — Record every packet to the log file
// ─────────────────────────────────────────────────────────────────────────────
void Logger::debugPacket(const ParsedPacket &packet) {
  if (debug_mode_) {
    cout << COLOR_GRAY << "[-] " << formatPacketSummary(packet) << COLOR_RESET
         << "\n";
  }

  if (log_file_.is_open() && !packet.src_ip.empty()) {
    log_file_ << "[TRAFFIC] " << formatPacketSummary(packet) << "\n";
    log_file_.flush();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// classifyDomain — Map a hostname to its app name
// ─────────────────────────────────────────────────────────────────────────────
string Logger::classifyDomain(const string &domain) const {
  for (int i = 0; i < DOMAIN_MAP_SIZE; i++) {
    // Check if the known keyword appears anywhere in the domain
    if (domain.find(DOMAIN_MAP[i].keyword) != string::npos) {
      return DOMAIN_MAP[i].app;
    }
  }
  // No match — it's just generic HTTPS
  return "HTTPS";
}

// ─────────────────────────────────────────────────────────────────────────────
// Box-drawing helpers
// ─────────────────────────────────────────────────────────────────────────────
void Logger::printBox(const string &title, int width) const {
  int pad = (width - 2 - (int)title.size()) / 2;
  cout << COLOR_BLUE << "+" << string(width - 2, '=') << "+\n";
  cout << "|" << string(pad, ' ') << COLOR_BOLD << title << COLOR_RESET
       << COLOR_BLUE << string(width - 2 - pad - (int)title.size(), ' ')
       << "|\n";
  cout << "+" << string(width - 2, '=') << "+\n" << COLOR_RESET;
}

void Logger::printRow(const string &label, const string &value,
                      int width) const {
  string line = " " + label + ": " + value;
  int pad = width - 2 - (int)line.size();
  if (pad < 0)
    pad = 0;
  cout << COLOR_BLUE << "|" << COLOR_RESET << line << string(pad, ' ')
       << COLOR_BLUE << "|\n"
       << COLOR_RESET;
}

void Logger::printDivider(int width) const {
  cout << COLOR_BLUE << "+" << string(width - 2, '=') << "+\n" << COLOR_RESET;
}

void Logger::printBottom(int width) const {
  cout << COLOR_BLUE << "+" << string(width - 2, '=') << "+\n" << COLOR_RESET;
}

void Logger::printAppBar(const string &name, uint64_t count, uint64_t total,
                         bool blocked, int width) const {
  double pct = total > 0 ? (100.0 * count / total) : 0.0;
  int bar_len = (int)(pct / 5.0); // 1 char per 5%
  if (bar_len > 20)
    bar_len = 20;
  string bar(bar_len, '#');

  // Format: "║ YouTube          4   5.2% # (BLOCKED)"
  char buf[64];
  snprintf(buf, sizeof(buf), "%-18s %4llu %5.1f%% %-20s", name.c_str(),
           (unsigned long long)count, pct, bar.c_str());
  string line = " ";
  line += buf;
  if (blocked)
    line += " (BLOCKED)";

  int pad = width - 2 - (int)line.size();
  if (pad < 0)
    pad = 0;

  cout << COLOR_BLUE << "|" << COLOR_RESET;
  if (blocked)
    cout << COLOR_RED;
  cout << line;
  if (blocked)
    cout << COLOR_RESET;
  cout << string(pad, ' ') << COLOR_BLUE << "|\n" << COLOR_RESET;
}

// ─────────────────────────────────────────────────────────────────────────────
// printSummary — The rich statistics dashboard
// ─────────────────────────────────────────────────────────────────────────────
void Logger::printSummary() const {
  const int W = 64; // box width

  cout << "\n";
  printBox("DPI ENGINE SESSION REPORT", W);

  // ── Traffic Overview ──
  printRow("Total Packets", to_string(total_packets_scanned_), W);
  printRow("Total Bytes", to_string(total_bytes_) + " bytes", W);
  printRow("TCP Packets", to_string(tcp_packets_), W);
  printRow("UDP Packets", to_string(udp_packets_), W);
  printDivider(W);

  // ── Forwarded / Dropped ──
  printRow("Forwarded", to_string(total_forwarded_), W);
  if (total_alerts_triggered_ > 0) {
    string blocked_str = to_string(total_alerts_triggered_) + " ⚠";
    printRow("Alerts Triggered", blocked_str, W);
  } else {
    printRow("Alerts Triggered", "0 (clean traffic)", W);
  }
  printDivider(W);

  // ── Application Breakdown ──
  // Print a sub-header
  {
    string hdr = " APPLICATION BREAKDOWN";
    int pad = W - 2 - (int)hdr.size();
    cout << COLOR_BLUE << "|" << COLOR_BOLD << hdr << COLOR_RESET << COLOR_BLUE
         << string(pad, ' ') << "|\n"
         << COLOR_RESET;
  }
  printDivider(W);

  // Sort app counts by count (descending)
  vector<pair<string, uint64_t>> sorted_apps(app_counts_.begin(),
                                             app_counts_.end());
  sort(sorted_apps.begin(), sorted_apps.end(),
       [](const pair<string, uint64_t> &a, const pair<string, uint64_t> &b) {
         return a.second > b.second;
       });

  for (const auto &kv : sorted_apps) {
    printAppBar(kv.first, kv.second, total_packets_scanned_, false, W);
  }
  printDivider(W);

  // ── Detected Domains / SNIs ──
  if (!detected_domains_.empty()) {
    string hdr = " DETECTED DOMAINS / SNIs";
    int pad = W - 2 - (int)hdr.size();
    cout << COLOR_BLUE << "|" << COLOR_BOLD << hdr << COLOR_RESET << COLOR_BLUE
         << string(pad, ' ') << "|\n"
         << COLOR_RESET;
    printDivider(W);

    int shown = 0;
    for (const auto &kv : detected_domains_) {
      if (shown >= 20)
        break; // cap to avoid giant tables
      string line = "  " + kv.first + " -> " + kv.second;
      int pad2 = W - 2 - (int)line.size();
      if (pad2 < 0) {
        line = line.substr(0, W - 5) + "...";
        pad2 = 0;
      }
      cout << COLOR_BLUE << "|" << COLOR_RESET << line << string(pad2, ' ')
           << COLOR_BLUE << "|\n"
           << COLOR_RESET;
      shown++;
    }
    if ((int)detected_domains_.size() > 20) {
      string more =
          "  ... and " + to_string(detected_domains_.size() - 20) + " more";
      int pad2 = W - 2 - (int)more.size();
      cout << COLOR_BLUE << "|" << COLOR_GRAY << more << COLOR_RESET
           << string(pad2, ' ') << COLOR_BLUE << "|\n"
           << COLOR_RESET;
    }
  }

  printBottom(W);
}

// ─────────────────────────────────────────────────────────────────────────────
// formatPacketSummary — One-line human-readable packet description
// ─────────────────────────────────────────────────────────────────────────────
string Logger::formatPacketSummary(const ParsedPacket &packet) const {
  string summary = packet.src_ip + ":" + to_string(packet.src_port) + " -> " +
                   packet.dest_ip + ":" + to_string(packet.dest_port);

  summary += " [" + packet.transport_proto;
  if (packet.app_protocol != "Unknown" && !packet.app_protocol.empty()) {
    summary += "/" + packet.app_protocol;
  }
  summary += "] ";

  if (packet.app_protocol == "DNS" && !packet.dns_query.empty())
    summary += "- Query: " + packet.dns_query;
  else if (packet.app_protocol == "HTTP" && !packet.http_host.empty())
    summary += "- Host: " + packet.http_host;
  else if (packet.app_protocol == "TLS" && !packet.tls_sni.empty())
    summary += "- SNI: " + packet.tls_sni;

  return summary;
}
