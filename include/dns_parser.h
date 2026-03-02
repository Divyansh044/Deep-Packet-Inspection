/*
 * dns_parser.h — DNS Query/Response Parser Interface
 * ===================================================
 *
 * WHY THIS FILE EXISTS:
 * ---------------------
 * DNS (Domain Name System) is the "phone book" of the internet.
 * Before your browser can load google.com, it sends a DNS query asking:
 *   "What IP address does google.com have?"
 *
 * For a DPI engine, DNS is EXTREMELY valuable because:
 *   1. It tells us which websites a user is trying to visit
 *   2. It works for BOTH HTTP and HTTPS traffic
 *   3. DNS queries are almost always unencrypted (even for HTTPS sites!)
 *
 * HOW DNS FITS IN THE PACKET STACK:
 * ─────────────────────────────────
 * [Ethernet] → [IP] → [UDP port 53] → [DNS Query/Response]
 *
 * DNS almost always uses UDP on port 53. When our packet parser sees
 * a UDP packet with port 53, we know the payload is a DNS message.
 *
 * INTERVIEW CONCEPT — "Why parse DNS in a DPI engine?"
 * A: DNS reveals user intent (which sites they visit), it's usually
 *    unencrypted, and it's the first step before any web connection.
 *    Blocking/alerting at the DNS level can stop malicious traffic
 *    before it even connects to the bad server.
 */

#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include "../include/protocols.h"
#include <cstdint>
#include <string>

class DnsParser {
public:
  /*
   * parse() — Extract DNS information from a UDP payload.
   *
   * Parameters:
   *   payload       - Pointer to the start of DNS data (right after UDP header)
   *   payload_length - How many bytes of DNS data we have
   *   result        - The ParsedPacket to fill in (dns_query, is_dns_response)
   *
   * Returns:
   *   true if we successfully extracted a domain name.
   *   false if the data is too short or malformed.
   */
  bool parse(const uint8_t *payload, uint32_t payload_length,
             ParsedPacket &result);

private:
  /*
   * extractDomainName() — Decode a DNS-encoded domain name.
   *
   * DNS encodes "google.com" as: [6]g o o g l e[3]c o m[0]
   *   - Each label is preceded by its LENGTH as a single byte
   *   - The name ends with a zero-length label (0x00)
   *
   * This function reads that encoding and returns "google.com".
   *
   * Parameters:
   *   payload       - Pointer to the START of the entire DNS message
   *   payload_length - Total DNS message size (for bounds checking)
   *   offset        - Where in the payload this name starts
   *   name          - Output string to write the decoded name into
   *
   * Returns:
   *   The number of bytes consumed from the payload (so we know where
   *   the next field starts). Returns 0 on error.
   *
   * INTERVIEW CONCEPT — "DNS Name Compression":
   * To save space, DNS can use "pointers" instead of repeating full names.
   * If the top 2 bits of a length byte are 11 (i.e., value >= 0xC0),
   * the next byte forms a pointer (offset) to where the name actually is.
   * This is called "message compression" (RFC 1035, Section 4.1.4).
   */
  uint32_t extractDomainName(const uint8_t *payload, uint32_t payload_length,
                             uint32_t offset, std::string &name);
};

#endif // DNS_PARSER_H
