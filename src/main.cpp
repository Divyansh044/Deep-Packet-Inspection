/*
 * main.cpp — The Deep Packet Inspection Engine
 * ============================================
 *
 * This is where everything comes together!
 *
 * We initialize our 4 core components:
 * 1. Logger (The Mouth)
 * 2. Policy Engine (The Brain)
 * 3. Packet Parser (The Eyes)
 * 4. Packet Capture (The Hands)
 *
 * When the Packet Capture grabs a packet, it calls `processPacketHandler`.
 * This acts as an assembly line, passing the packet from the Eyes -> Brain ->
 * Mouth.
 */

#include "../include/dns_parser.h"
#include "../include/http_parser.h"
#include "../include/logger.h"
#include "../include/packet_capture.h"
#include "../include/packet_parser.h"
#include "../include/policy_engine.h"
#include "../include/tls_parser.h"
#include <csignal>
#include <iostream>

using namespace std;

// ─────────────────────────────────────────────────────────────────────────────
// GLOBAL STATE (Required for C-style callbacks and graceful shutdown)
// ─────────────────────────────────────────────────────────────────────────────
// The `libpcap` library uses a C-style callback function for packets.
// Because it's not object-oriented, our callback needs access to global
// pointers so it can talk to the rest of our C++ application.
Logger *g_logger = nullptr;
PolicyEngine *g_policy = nullptr;
PacketParser *g_parser = nullptr;
PacketCapture *g_capture = nullptr;
DnsParser *g_dns_parser = nullptr;
HttpParser *g_http_parser = nullptr;
TlsParser *g_tls_parser = nullptr;

// ─────────────────────────────────────────────────────────────────────────────
// GRACEFUL SHUTDOWN (Ctrl+C Handler)
// ─────────────────────────────────────────────────────────────────────────────
// When the user presses Ctrl+C, instead of just killing the program violently,
// we want to catch the signal, stop capturing packets, and print our summary
// strings.
void handleSignal(int signum) {
  if (g_logger) {
    g_logger->info("\nCaught signal " + to_string(signum) +
                   ". Shutting down gracefully...");
    g_logger->printSummary(); // Print "100 packets scanned, 2 threats blocked"
  }

  if (g_capture) {
    g_capture
        ->stopCapture(); // Tell the library to exit its infinite listening loop
  }

  // Exit cleanly
  exit(0);
}

// ─────────────────────────────────────────────────────────────────────────────
// THE ASSEMBLY LINE (Packet Callback)
// ─────────────────────────────────────────────────────────────────────────────
// This function gets called by the PacketCapture class thousands of times a
// second every time a new packet arrives off the wire.
void processPacketHandler(const uint8_t *packet_data, uint32_t packet_length,
                          const struct timeval &ts) {

  // 1. Tell Logger we saw a packet
  g_logger->incrementPacketsScanned();

  // 2. PARSE IT (The Eyes)
  // We feed the raw binary bytes into our parsers to extract IPs/Domains
  ParsedPacket parsed;
  if (!g_parser->parse(packet_data, packet_length, parsed)) {
    // If it's a damaged packet or a protocol we don't care about, ignore it.
    return;
  }

  // 2.5 DEEP INSPECTION
  // If we have an application payload, try to parse it
  if (parsed.payload != nullptr && parsed.payload_length > 0) {
    if (parsed.dest_port == 53 || parsed.src_port == 53) {
      g_dns_parser->parse(parsed.payload, parsed.payload_length, parsed);
    } else if (parsed.dest_port == 80 || parsed.src_port == 80) {
      g_http_parser->parse(parsed.payload, parsed.payload_length, parsed);
    } else if (parsed.dest_port == 443 || parsed.src_port == 443) {
      g_tls_parser->parse(parsed.payload, parsed.payload_length, parsed);
    }
  }

  // Update all statistics counters (per-app, per-protocol, detected domains)
  g_logger->recordPacketStats(parsed);

  // Debug mode: Print every single parsed packet details to screen
  g_logger->debugPacket(parsed);

  // 3. CHECK RULES (The Brain)
  // Now that we have readable IPs and Domains, check if they are blocked
  Alert alert;
  if (g_policy->checkPacket(parsed, alert)) {

    // 4. TRIGGER ALERT (The Mouth) — Policy Engine said "BAD!"
    g_logger->logAlert(alert, parsed);
    g_logger->incrementDropped();
  } else {
    // Packet is clean — count it as forwarded
    g_logger->incrementForwarded();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// STARTUP AND INITIALIZATION
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char *argv[]) {
  // 1. Create our core components
  Logger logger;
  PolicyEngine policy;
  PacketParser parser;
  PacketCapture capture;
  DnsParser dns_parser;
  HttpParser http_parser;
  TlsParser tls_parser;

  // Link our global pointers for the callback and signal handler
  g_logger = &logger;
  g_policy = &policy;
  g_parser = &parser;
  g_capture = &capture;
  g_dns_parser = &dns_parser;
  g_http_parser = &http_parser;
  g_tls_parser = &tls_parser;

  // Register Ctrl+C so we can print statistics when exiting
  signal(SIGINT, handleSignal);

  logger.info("Initializing Deep Packet Inspection Engine...");

  // Optional: Turn on debugging if you want to see all traffic
  // logger.setDebugBuild(true);

  // 2. Load the Rule Databases into Memory
  logger.info("Loading blocklists into fast memory...");

  // Note: Paths are relative to the executable location (build directory
  // usually) It's robust to load using relative path from `src/` to `config/`
  string domain_file = "../config/blocked_domains.txt";
  string ip_file = "../config/blocked_ips.txt";

  if (policy.loadBlockedDomains(domain_file)) {
    logger.success("Loaded " + to_string(policy.getBlockedDomainCount()) +
                   " forbidden domains.");
  } else {
    logger.warning("Could not load forbidden domains (File missing?)");
  }

  if (policy.loadBlockedIPs(ip_file)) {
    logger.success("Loaded " + to_string(policy.getBlockedIPCount()) +
                   " forbidden IP addresses.");
  } else {
    logger.warning("Could not load forbidden IPs (File missing?)");
  }

  // 3. Start Capturing Packets!

  // Parse command line arguments
  string capture_mode = "";
  string target = "";

  for (int i = 1; i < argc; ++i) {
    string arg = argv[i];
    if (arg == "--list") {
      logger.info("Available network interfaces:");
      auto interfaces = capture.listInterfaces();
      for (size_t j = 0; j < interfaces.size(); ++j) {
        cout << "  [" << j << "] " << interfaces[j] << "\n";
      }
      return 0;
    } else if (arg == "-i" && i + 1 < argc) {
      capture_mode = "live";
      target = argv[++i];
    } else if (arg == "-f" && i + 1 < argc) {
      capture_mode = "offline";
      target = argv[++i];
    } else if (arg == "--debug") {
      logger.setDebugBuild(true);
    } else {
      logger.error("Unknown argument: " + arg);
      cout << "Usage:\n";
      cout << "  dpi_engine.exe -i <interface_name>   (Live Capture)\n";
      cout << "  dpi_engine.exe -f <pcap_file>        (Offline PCAP Replay)\n";
      cout << "  dpi_engine.exe --list                (List all interfaces)\n";
      cout << "  dpi_engine.exe --debug               (Print every parsed "
              "packet)\n";
      return 1;
    }
  }

  if (capture_mode == "") {
    logger.error("No capture mode specified.");
    cout << "Please specify either -i for live capture or -f for offline pcap "
            "replay.\n";
    cout << "Example: dpi_engine.exe -f ../pcap_files/test_traffic.pcap\n";
    cout << "Run with --list to see available live interfaces.\n";
    return 1;
  }

  // Set up the log file
  string log_path = "../security_alerts.log";
  logger.setLogFile(log_path);

  logger.info("Setting up Packet Capture layer (libpcap/Npcap)...");

  bool success = false;

  if (capture_mode == "live") {
    logger.info("Attempting to listen to live interface: " + target);
    success = capture.openLive(target);
    if (!success) {
      logger.error("Failed to open interface. Try running as "
                   "Administrator/Root or check name with --list.");
      return 1;
    }
  } else if (capture_mode == "offline") {
    logger.info("Attempting to open offline capture file: " + target);
    success = capture.openFile(target);
    if (!success) {
      logger.error("Failed to open packet capture file. Does the file exist?");
      return 1;
    }
  }

  logger.info("Capture source opened successfully. Starting capture loop...");
  success = capture.startCapture(processPacketHandler);

  if (success) {
    logger.success("Capture completed successfully.");
  } else {
    logger.error("Capture loop terminated with an error.");
  }

  // Print final stats
  logger.printSummary();

  return 0;
}
