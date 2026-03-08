/*
 * logger.h — Output & Statistics Handling
 * ========================================
 *
 * Central logger for all output: colored console, file logging, and
 * the rich end-of-session statistics dashboard.
 */

#ifndef LOGGER_H
#define LOGGER_H

#include "../include/policy_engine.h"
#include <cstdint>
#include <fstream>
#include <map>
#include <string>

// ─────────────────────────────────────────────────────────────────────────────
// ANSI Color Codes
// ─────────────────────────────────────────────────────────────────────────────
const std::string COLOR_RED = "\033[31m";
const std::string COLOR_GREEN = "\033[32m";
const std::string COLOR_YELLOW = "\033[33m";
const std::string COLOR_BLUE = "\033[34m";
const std::string COLOR_CYAN = "\033[36m";
const std::string COLOR_GRAY = "\033[90m";
const std::string COLOR_BOLD = "\033[1m";
const std::string COLOR_RESET = "\033[0m";

class Logger {
public:
  Logger();

  // Basic logging
  void info(const std::string &message);
  void success(const std::string &message);
  void warning(const std::string &message);
  void error(const std::string &message);

  // Debug logging
  void setDebugBuild(bool enable);
  void debugPacket(const ParsedPacket &packet);

  // Output log file setup
  void setLogFile(const std::string &filepath);

  // The main event: logging a security alert from the Policy Engine
  void logAlert(const Alert &alert, const ParsedPacket &packet);

  // Keeping track of performance
  void incrementPacketsScanned();
  void incrementForwarded();
  void incrementDropped();

  // Called when a packet passes through the app-layer parsers
  void recordPacketStats(const ParsedPacket &packet);

  // Print the final rich dashboard
  void printSummary() const;

private:
  bool debug_mode_;
  std::ofstream log_file_;

  // ── Basic counters ──
  uint64_t total_packets_scanned_;
  uint64_t total_alerts_triggered_;
  uint64_t total_forwarded_;
  uint64_t total_dropped_;
  uint64_t total_bytes_;

  // ── Per-protocol counters ──
  uint64_t tcp_packets_;
  uint64_t udp_packets_;

  // ── Application-level breakdown ──
  // Key = app name (e.g. "YouTube", "GitHub", "HTTPS", "DNS", "Unknown")
  // Value = count of packets
  std::map<std::string, uint64_t> app_counts_;

  // ── Detected domains / SNIs ──
  // maps hostname -> app category (e.g. "github.com" -> "GitHub")
  std::map<std::string, std::string> detected_domains_;

  // ── Helper: classify a domain into an app name ──
  std::string classifyDomain(const std::string &domain) const;

  // ── Helper: box-drawing summary output ──
  std::string formatPacketSummary(const ParsedPacket &packet) const;
  void printBox(const std::string &title, int width) const;
  void printRow(const std::string &label, const std::string &value,
                int width) const;
  void printDivider(int width) const;
  void printBottom(int width) const;
  void printAppBar(const std::string &name, uint64_t count, uint64_t total,
                   bool blocked, int width) const;
};

#endif // LOGGER_H
