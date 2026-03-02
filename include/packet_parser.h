/*
 * packet_parser.h — Packet Parser Interface
 * ==========================================
 *
 * WHY THIS FILE EXISTS:
 * ---------------------
 * A raw packet arrives as a flat array of bytes (uint8_t*).
 * The PacketParser's job is to "peel the onion" — walk through each layer
 * (Ethernet → IP → TCP/UDP) and fill in a friendly ParsedPacket struct.
 *
 * HOW IT WORKS (the "onion peeling" analogy):
 * ───────────────────────────────────────────
 * Imagine you receive a box (Ethernet). You open it and find another box
 * inside (IP). You open that and find yet another box (TCP or UDP).
 * Finally, inside that last box, you find the actual letter (payload).
 *
 * In code, we do this by advancing a pointer through the raw data:
 *
 *   raw_data ─────┐
 *                  ▼
 *   [Ethernet 14B][IP 20+B][TCP 20+B][Payload ...]
 *       │              │         │         │
 *       ▼              ▼         ▼         ▼
 *   parse layer 2  parse L3  parse L4  hand off to
 *                                      app parsers
 *
 * INTERVIEW CONCEPT — "Pointer Arithmetic":
 * We start with a pointer to byte 0. After reading the Ethernet header
 * (14 bytes), we move the pointer forward by 14 to reach the IP header.
 * After reading IP (whose size we learn from IHL), we advance again.
 * This is how we navigate through the packet WITHOUT copying any data.
 *
 * INTERVIEW Q: "Why is this called zero-copy parsing?"
 * A: Because we never copy the packet data into new buffers. We just
 *    cast pointers to overlay our structs directly onto the raw memory.
 *    This is extremely fast and memory efficient.
 */

#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include "protocols.h"
#include <cstdint>

class PacketParser {
public:
  /*
   * parse() — The main entry point.
   *
   * Parameters:
   *   data   - Pointer to the start of raw packet bytes (from pcap).
   *   length - Total number of bytes in the packet.
   *   result - Reference to a ParsedPacket that we fill in.
   *
   * Returns:
   *   true  if we successfully parsed at least through Layer 3 (IP).
   *   false if the packet is malformed or too short.
   *
   * INTERVIEW Q: "Why return bool instead of throwing an exception?"
   * A: Packets arrive at very high rates (thousands per second).
   *    Exception handling is slow. Returning false and moving on is
   *    the standard approach in performance-critical packet processing.
   */
  bool parse(const uint8_t *data, uint32_t length, ParsedPacket &result);

private:
  /*
   * Each layer has its own private parser method.
   * They each take:
   *   - data   : pointer to where THIS layer starts in the raw buffer
   *   - length : remaining bytes from this point onward
   *   - result : the ParsedPacket to fill in
   *
   * They each return true/false for success/failure.
   */

  // Layer 2: Read Ethernet header, extract MACs and ether_type
  bool parseEthernet(const uint8_t *data, uint32_t length,
                     ParsedPacket &result);

  // Layer 3: Read IPv4 header, extract IPs and protocol number
  bool parseIPv4(const uint8_t *data, uint32_t length, ParsedPacket &result);

  // Layer 4: Read TCP header, extract ports and locate payload
  bool parseTCP(const uint8_t *data, uint32_t length, ParsedPacket &result);

  // Layer 4: Read UDP header, extract ports and locate payload
  bool parseUDP(const uint8_t *data, uint32_t length, ParsedPacket &result);
};

#endif // PACKET_PARSER_H
