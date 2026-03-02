/*
 * dns_parser.cpp — DNS Query/Response Parser Implementation
 * =========================================================
 *
 * HOW A DNS MESSAGE IS STRUCTURED:
 * ────────────────────────────────
 * A DNS message has two main parts:
 *
 *   ┌──────────────────────────────────────────┐
 *   │           HEADER (12 bytes, fixed)        │
 *   ├──────────────────────────────────────────┤
 *   │ Transaction ID (2B) — matches Q to A     │
 *   │ Flags (2B)          — is this query or    │
 *   │                       response? etc.      │
 *   │ Question Count (2B) — how many questions  │
 *   │ Answer Count (2B)   — how many answers    │
 *   │ Authority Count (2B)                      │
 *   │ Additional Count (2B)                     │
 *   ├──────────────────────────────────────────┤
 *   │           QUESTION SECTION               │
 *   ├──────────────────────────────────────────┤
 *   │ Domain Name  (variable length)           │
 *   │ Query Type   (2B) — A, AAAA, MX, etc.   │
 *   │ Query Class  (2B) — usually IN (Internet)│
 *   └──────────────────────────────────────────┘
 *
 * HOW DNS ENCODES DOMAIN NAMES:
 * ─────────────────────────────
 * "google.com" is NOT stored as a simple string. Instead:
 *
 *   [6] g o o g l e [3] c o m [0]
 *    ↑                ↑         ↑
 *   length=6        length=3   end (zero = stop)
 *
 * Each "label" (part between dots) is preceded by its byte-length.
 * The name terminates when we read a length byte of 0.
 *
 * So: "www.google.com" → [3]www[6]google[3]com[0]
 *
 * DNS COMPRESSION (tricky part):
 * ──────────────────────────────
 * To save space, DNS can replace a label with a POINTER to a name
 * that appeared earlier in the message.
 *
 * A pointer is identified when the top 2 bits are set (value >= 0xC0):
 *   Byte 1: 1 1 x x x x x x  }  Together these form a 14-bit offset
 *   Byte 2: x x x x x x x x  }  into the DNS message where the name is
 *
 * INTERVIEW Q: "Why does DNS use this compression?"
 * A: A single DNS response might contain the same domain name many times
 *    (in question, answer, authority sections). Compression avoids
 *    repeating "google.com" over and over, saving bandwidth.
 */

#include "../include/dns_parser.h"
#include <cstring>

// DNS header is always exactly 12 bytes
constexpr uint32_t DNS_HEADER_SIZE = 12;

// DNS flags — the QR bit (bit 15) tells us if this is a query or response
// In the flags field (2 bytes), after ntohs():
//   Bit 15 = QR: 0 = query, 1 = response
constexpr uint16_t DNS_FLAG_QR = 0x8000;

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC: parse() — Main DNS parsing entry point
// ─────────────────────────────────────────────────────────────────────────────
/*
 * Called when our packet parser detects a UDP packet on port 53.
 *
 * What we do:
 *   1. Read the 12-byte DNS header
 *   2. Check if it's a query or response (QR flag)
 *   3. Read the question section to extract the domain name
 *   4. Store the domain in result.dns_query
 */
bool DnsParser::parse(const uint8_t *payload, uint32_t payload_length,
                      ParsedPacket &result) {

  // ── Safety check: need at least 12 bytes for DNS header ──
  if (payload_length < DNS_HEADER_SIZE) {
    return false;
  }

  // ── Step 1: Read the DNS header fields ──
  // We read each 2-byte field manually using pointer offsets.
  //
  // Why not use a struct like we did for Ethernet/IP/TCP?
  // We could! But the DNS header is simple enough (6 fields × 2 bytes)
  // that reading them directly is clearer for learning purposes.

  // Bytes 0-1: Transaction ID (we don't need this for DPI)
  // uint16_t transaction_id = ntohs(*(uint16_t*)(payload + 0));

  // Bytes 2-3: Flags
  uint16_t flags = ntohs(*(const uint16_t *)(payload + 2));

  // Bytes 4-5: Question count (how many questions in this message)
  uint16_t question_count = ntohs(*(const uint16_t *)(payload + 4));

  // Bytes 6-7: Answer count (we note this but don't parse answers yet)
  // uint16_t answer_count = ntohs(*(uint16_t*)(payload + 6));

  // ── Step 2: Determine if this is a query or response ──
  // The QR bit (bit 15 of flags) tells us:
  //   0 = this is a QUESTION  ("what's the IP for google.com?")
  //   1 = this is an ANSWER   ("google.com is at 142.250.x.x")
  result.is_dns_response = (flags & DNS_FLAG_QR) != 0;

  // ── Step 3: We need at least one question to extract a domain ──
  if (question_count == 0) {
    result.app_protocol = "DNS";
    return true; // Valid DNS but no questions — unusual but possible
  }

  // ── Step 4: Extract the domain name from the question section ──
  // The question section starts right after the 12-byte header.
  //
  // Question format:
  //   [domain name (variable)] [query type (2B)] [query class (2B)]
  //
  // We only care about the domain name.

  std::string domain_name;
  uint32_t bytes_consumed =
      extractDomainName(payload, payload_length, DNS_HEADER_SIZE, domain_name);

  if (bytes_consumed == 0) {
    return false; // Failed to decode the domain name
  }

  // ── Step 5: Store results ──
  result.app_protocol = "DNS";
  result.dns_query = domain_name;

  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// PRIVATE: extractDomainName() — Decode DNS label encoding
// ─────────────────────────────────────────────────────────────────────────────
/*
 * This is the trickiest part of DNS parsing.
 *
 * We need to handle two cases:
 *   Case 1 — Normal label:  [length] [characters...]
 *   Case 2 — Pointer:       [0xC0 | offset_high] [offset_low]
 *
 * EXAMPLE walkthrough for "www.google.com":
 *
 *   Offset: 0    1    2    3    4    5    6    7    8    9   10   11   12  13
 *   Bytes:  03   77   77   77   06   67   6F   6F   67   6C  65   03  63  6F
 *           ↑    w    w    w    ↑    g    o    o    g    l   e    ↑   c   o
 *         len=3              len=6                            len=3
 *
 *   Offset: 14   15
 *   Bytes:  6D   00
 *           m    ↑
 *               END (length=0)
 *
 *   Result: "www" + "." + "google" + "." + "com" = "www.google.com"
 *
 * INTERVIEW Q: "How do you prevent infinite loops with DNS pointers?"
 * A: We track a maximum number of pointer jumps. If we exceed it,
 *    we treat the packet as malformed and bail out. This prevents
 *    a crafted packet from making us loop forever.
 */
uint32_t DnsParser::extractDomainName(const uint8_t *payload,
                                      uint32_t payload_length, uint32_t offset,
                                      std::string &name) {

  name.clear();

  // Track the original position so we know how many bytes WE consumed
  // (vs. how many bytes we READ, which can differ due to pointer jumps)
  uint32_t original_offset = offset;
  bool jumped = false;         // Have we followed a pointer?
  uint32_t bytes_consumed = 0; // Bytes consumed from OUR position
  int max_jumps = 50;          // Safety limit to prevent infinite loops
  int jump_count = 0;

  while (offset < payload_length) {
    // Read the length/pointer byte
    uint8_t label_length = payload[offset];

    // ── Case 0: End of name (length byte = 0) ──
    if (label_length == 0) {
      // If we never jumped, the bytes consumed = everything from
      // original_offset to here + 1 (for the zero terminator).
      if (!jumped) {
        bytes_consumed = offset - original_offset + 1;
      }
      break;
    }

    // ── Case 2: Pointer (top 2 bits are 11, i.e., value >= 0xC0) ──
    //
    // Example: byte = 0xC0 0x0C means "go to offset 12 in the message"
    //   0xC0 = 1100 0000
    //          ^^─────── top 2 bits = 11 → this is a pointer
    //   0xC0 0x0C → offset = (0xC0 & 0x3F) << 8 | 0x0C = 0 << 8 | 12 = 12
    //
    if ((label_length & 0xC0) == 0xC0) {
      // Need one more byte for the full pointer
      if (offset + 1 >= payload_length) {
        return 0; // Malformed: pointer extends past the data
      }

      // If this is the FIRST pointer we encounter, record how many
      // bytes we actually consumed (pointer = 2 bytes)
      if (!jumped) {
        bytes_consumed = offset - original_offset + 2;
      }

      // Calculate the offset the pointer points to
      // Mask off the top 2 bits (0x3F = 0011 1111) and combine with next byte
      uint16_t pointer_offset =
          ((label_length & 0x3F) << 8) | payload[offset + 1];

      // Jump to that position
      offset = pointer_offset;
      jumped = true;

      // Safety: prevent infinite pointer loops
      jump_count++;
      if (jump_count > max_jumps) {
        return 0; // Too many jumps — probably a malicious packet
      }

      continue; // Start reading from the new offset
    }

    // ── Case 1: Normal label ──
    // label_length tells us how many characters follow
    offset++; // Move past the length byte

    // Safety: make sure the label doesn't extend past our data
    if (offset + label_length > payload_length) {
      return 0; // Malformed: label goes past end of packet
    }

    // Add a dot separator (except before the first label)
    if (!name.empty()) {
      name += '.';
    }

    // Copy the label characters (e.g., "google")
    // We append character by character — simple and safe.
    for (uint32_t i = 0; i < label_length; i++) {
      name += static_cast<char>(payload[offset + i]);
    }

    // Move past all the characters we just read
    offset += label_length;
  }

  // If we never encountered a pointer, calculate bytes consumed the normal way
  if (!jumped && bytes_consumed == 0) {
    bytes_consumed = offset - original_offset;
  }

  return bytes_consumed;
}
