/*
 * tls_parser.h — TLS ClientHello / SNI Parser Interface
 * ======================================================
 *
 * WHY THIS FILE EXISTS:
 * ---------------------
 * Today, over 95% of web traffic uses HTTPS (HTTP wrapped in TLS encryption).
 * We CAN'T read the encrypted content, but there's a loophole:
 *
 * During the TLS "handshake" (before encryption starts), the client sends
 * a "ClientHello" message that contains the SERVER NAME in plain text.
 * This is called SNI — Server Name Indication.
 *
 * WHY SNI EXISTS:
 * ───────────────
 * Just like HTTP's Host header, SNI solves the "one IP, many websites" problem.
 * When a server hosts multiple HTTPS sites, it needs to know WHICH site's
 * certificate to present BEFORE encryption begins. The client puts the
 * domain name in the ClientHello so the server can pick the right certificate.
 *
 * THE HANDSHAKE FLOW:
 * ───────────────────
 *   Client → Server: ClientHello (contains SNI: "netflix.com")  ← WE READ THIS
 *   Server → Client: ServerHello + Certificate
 *   Client → Server: Key Exchange
 *   [... encrypted communication begins ...]
 *
 * INTERVIEW CONCEPT — "Why can DPI see the SNI?"
 * A: The ClientHello is sent BEFORE encryption is negotiated.
 *    It HAS to be unencrypted because the client and server haven't
 *    agreed on encryption keys yet. This is why SNI is visible to
 *    network monitors, firewalls, and DPI engines.
 *
 * INTERVIEW CONCEPT — "Encrypted SNI (ESNI / ECH)"
 * A: Newer protocols like ECH (Encrypted Client Hello) encrypt the SNI
 *    field too, which blocks this technique. However, ECH adoption is
 *    still limited (mainly Cloudflare), so SNI parsing remains effective
 *    for most traffic as of 2024-2025.
 */

#ifndef TLS_PARSER_H
#define TLS_PARSER_H

#include "../include/protocols.h"
#include <cstdint>
#include <string>

class TlsParser {
public:
  /*
   * parse() — Look for a TLS ClientHello and extract the SNI.
   *
   * Parameters:
   *   payload        - TCP payload data (after TCP header)
   *   payload_length - Size of the payload
   *   result         - ParsedPacket to fill in (tls_sni, app_protocol)
   *
   * Returns:
   *   true  if this is a TLS ClientHello (even if SNI is not found)
   *   false if this is not a TLS record
   */
  bool parse(const uint8_t *payload, uint32_t payload_length,
             ParsedPacket &result);

private:
  /*
   * parseClientHello() — Navigate through the ClientHello message
   *                      to find the SNI extension.
   *
   * The ClientHello has many fields we need to skip over to reach
   * the extensions list where SNI lives. Think of it as navigating
   * through a nested Russian doll of variable-length fields.
   */
  bool parseClientHello(const uint8_t *data, uint32_t length,
                        ParsedPacket &result);

  /*
   * extractSNI() — Parse the extensions list to find SNI (type 0x0000).
   *
   * TLS extensions are a list of type-length-value (TLV) entries.
   * We scan through them until we find the one with type = 0 (SNI).
   */
  bool extractSNI(const uint8_t *data, uint32_t length, ParsedPacket &result);
};

#endif // TLS_PARSER_H
