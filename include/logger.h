/*
 * logger.h — Output & Statistics Handling
 * ========================================
 *
 * WHY THIS FILE EXISTS:
 * ---------------------
 * A DPI engine isn't useful if it blocks packets silently. It needs to tell the
 * user what is happening.
 *
 * We don't want `std::cout` statements scattered randomly across 10 different
 * files. That makes it impossible to format logs consistently, turn off debug
 * messages, or safely log from multiple threads.
 *
 * Instead, we route all output through this central Logger class.
 *
 * FEATURES:
 * ---------
 * 1. Colored terminal output (Red for danger, Green for success, Gray for
 * debug)
 * 2. Statistics tracking (How many packets scanned? How many blocked?)
 * 3. Graceful summary printing when the program exits.
 */

#ifndef LOGGER_H
#define LOGGER_H

#include "../include/policy_engine.h"
#include <cstdint>
#include <string>

// ─────────────────────────────────────────────────────────────────────────────
// ANSI Color Codes
// ─────────────────────────────────────────────────────────────────────────────
// These are special text strings that terminal emulators (like bash,
// powershell) understand. When the terminal sees "\033[31m", it switches the
// text color to red.
// "\033[0m" resets the color back to normal.
const std::string COLOR_RED = "\033[31m";
const std::string COLOR_GREEN = "\033[32m";
const std::string COLOR_YELLOW = "\033[33m";
const std::string COLOR_BLUE = "\033[34m";
const std::string COLOR_GRAY = "\033[90m";
const std::string COLOR_RESET = "\033[0m";

class Logger {
public:
  Logger();

  // Basic logging
  void info(const std::string &message);
  void success(const std::string &message);
  void warning(const std::string &message);
  void error(const std::string &message);

  // Debug logging (used for printing every single packet when developing)
  // Can be toggled on/off to increase speed during real-world usage.
  void setDebugBuild(bool enable);
  void debugPacket(const ParsedPacket &packet);

  // The main event: logging a security alert from the Policy Engine
  void logAlert(const Alert &alert, const ParsedPacket &packet);

  // Keeping track of performance
  void incrementPacketsScanned();
  void printSummary() const;

private:
  bool debug_mode_;

  // Counters for our final summary report
  uint64_t total_packets_scanned_;
  uint64_t total_alerts_triggered_;

  // Helper function to extract a neat summary from a packet
  std::string formatPacketSummary(const ParsedPacket &packet) const;
};

#endif // LOGGER_H
