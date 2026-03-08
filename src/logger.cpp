/*
 * logger.cpp — Output & Statistics Implementation
 * =================================================
 */

#include "../include/logger.h"
#include <iomanip>
#include <iostream>

using namespace std;

Logger::Logger()
    : debug_mode_(false), total_packets_scanned_(0),
      total_alerts_triggered_(0) {}

void Logger::setDebugBuild(bool enable) { debug_mode_ = enable; }

// ─────────────────────────────────────────────────────────────────────────────
// Standard Output Methods
// ─────────────────────────────────────────────────────────────────────────────

void Logger::info(const std::string &message) {
  cout << COLOR_BLUE << "[INFO] " << COLOR_RESET << message << "\n";
}

void Logger::success(const std::string &message) {
  cout << COLOR_GREEN << "[OK] " << COLOR_RESET << message << "\n";
}

void Logger::warning(const std::string &message) {
  cout << COLOR_YELLOW << "[WARN] " << COLOR_RESET << message << "\n";
}

void Logger::error(const std::string &message) {
  cerr << COLOR_RED << "[ERROR] " << COLOR_RESET << message << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// DPI Specific Methods
// ─────────────────────────────────────────────────────────────────────────────

void Logger::incrementPacketsScanned() { total_packets_scanned_++; }

// This triggers when the Policy Engine returns 'true'
void Logger::logAlert(const Alert &alert, const ParsedPacket &packet) {
  total_alerts_triggered_++;

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
}

// If we are developing, we might want to see every packet that passes through.
void Logger::debugPacket(const ParsedPacket &packet) {
  if (!debug_mode_)
    return;

  cout << COLOR_GRAY << "[-] " << formatPacketSummary(packet) << COLOR_RESET
       << "\n";
}

// Helper: Turns our complex struct into a neat one-liner string
// e.g., "192.168.1.5:54321 -> 1.1.1.1:53 [DNS] Query: google.com"
std::string Logger::formatPacketSummary(const ParsedPacket &packet) const {
  std::string summary = packet.src_ip + ":" + to_string(packet.src_port) +
                        " -> " + packet.dest_ip + ":" +
                        to_string(packet.dest_port);

  summary += " [" + packet.transport_proto;
  if (packet.app_protocol != "Unknown") {
    summary += "/" + packet.app_protocol;
  }
  summary += "] ";

  // Add specific application details if we successfully parsed them
  if (packet.app_protocol == "DNS" && !packet.dns_query.empty()) {
    summary += "- Query: " + packet.dns_query;
  } else if (packet.app_protocol == "HTTP" && !packet.http_host.empty()) {
    summary += "- Host: " + packet.http_host;
  } else if (packet.app_protocol == "TLS" && !packet.tls_sni.empty()) {
    summary += "- SNI: " + packet.tls_sni;
  }

  return summary;
}

// ─────────────────────────────────────────────────────────────────────────────
// Final Report
// ─────────────────────────────────────────────────────────────────────────────
// Called right before the program crashes or gracefully exits.
void Logger::printSummary() const {
  cout << "\n";
  cout << COLOR_BLUE << "================ DPI ENGINE SUMMARY ================\n"
       << COLOR_RESET;

  cout << "Packets Scanned  : " << total_packets_scanned_ << "\n";

  if (total_alerts_triggered_ > 0) {
    cout << "Threats Blocked  : " << COLOR_RED << total_alerts_triggered_
         << COLOR_RESET << "\n";
  } else {
    cout << "Threats Blocked  : " << COLOR_GREEN << "0" << COLOR_RESET << "\n";
  }

  cout << COLOR_BLUE
       << "====================================================\n\n"
       << COLOR_RESET;
}
