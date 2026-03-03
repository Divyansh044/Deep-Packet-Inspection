/*
 * tls_parser.cpp — TLS ClientHello / SNI Parser Implementation
 * =============================================================
 *
 * TLS RECORD STRUCTURE (the outermost layer):
 * ────────────────────────────────────────────
 * Every TLS message is wrapped in a "record":
 *
 *   ┌─────────────┬───────────┬──────────┬────────────────────┐
 *   │ Content Type │ Version   │ Length   │ Payload ...         │
 *   │  (1 byte)   │ (2 bytes) │ (2 bytes)│ (variable)         │
 *   └─────────────┴───────────┴──────────┴────────────────────┘
 *
 *   Content Type: 0x16 = Handshake (what we want)
 *                 0x17 = Application Data (encrypted, can't read)
 *                 0x15 = Alert
 *                 0x14 = Change Cipher Spec
 *
 *   Version: 0x0301 = TLS 1.0, 0x0303 = TLS 1.2
 *            (TLS 1.3 uses 0x0303 here for compatibility)
 *
 * INSIDE THE HANDSHAKE RECORD — ClientHello:
 * ──────────────────────────────────────────
 * The handshake payload starts with:
 *
 *   ┌─────────────────┬────────────────────┐
 *   │ Handshake Type  │ Length (3 bytes)    │
 *   │  (1 byte)       │                    │
 *   └─────────────────┴────────────────────┘
 *
 *   Handshake Type: 0x01 = ClientHello ← what we want
 *
 * INSIDE THE ClientHello:
 * ───────────────────────
 * This is where it gets nested. We have to skip through several
 * variable-length fields to reach the Extensions:
 *
 *   ┌──────────────────────────────────────┐
 *   │ Client Version (2B)                  │
 *   │ Client Random  (32B)                 │
 *   │ Session ID Length (1B) + Session ID   │
 *   │ Cipher Suites Length (2B) + Suites    │
 *   │ Compression Methods Length (1B) + ...  │
 *   │ Extensions Length (2B) + Extensions    │  ← SNI IS HERE
 *   └──────────────────────────────────────┘
 *
 * INSIDE THE EXTENSIONS:
 * ──────────────────────
 * Extensions are a list of Type-Length-Value (TLV) entries:
 *
 *   ┌────────────┬──────────┬───────────────┐
 *   │ Type (2B)  │ Len (2B) │ Data (Len B)  │
 *   └────────────┴──────────┴───────────────┘
 *
 *   SNI extension type = 0x0000
 *
 * INSIDE THE SNI EXTENSION:
 * ─────────────────────────
 *   ┌────────────────────┬────────────┬──────────┬──────────────────┐
 *   │ SNI List Len (2B)  │ Type (1B)  │ Len (2B) │ Hostname (Len B) │
 *   └────────────────────┴────────────┴──────────┴──────────────────┘
 *
 *   Type: 0x00 = hostname
 *
 * So the full path to get to the domain name is:
 *   TLS Record → Handshake → ClientHello → skip fields → Extensions → SNI →
 * hostname
 *
 * INTERVIEW Q: "This seems like a lot of nesting. Why so complex?"
 * A: TLS was designed to be extensible. Each layer has variable-length
 *    fields and optional sections. The deep nesting allows flexibility
 *    (new cipher suites, new extensions) without breaking compatibility.
 */

#include "../include/tls_parser.h"

// ─────────────────────────────────────────────────────────────────────────────
// TLS Constants
// ─────────────────────────────────────────────────────────────────────────────
constexpr uint8_t TLS_CONTENT_HANDSHAKE =
    0x16; // We only care about handshake records
constexpr uint8_t TLS_HANDSHAKE_CLIENT_HELLO = 0x01; // ClientHello message type
constexpr uint16_t TLS_EXTENSION_SNI = 0x0000;       // SNI extension type

// TLS record header = 1 (type) + 2 (version) + 2 (length) = 5 bytes
constexpr uint32_t TLS_RECORD_HEADER_SIZE = 5;

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC: parse() — Check if this is a TLS ClientHello
// ─────────────────────────────────────────────────────────────────────────────
/*
 * The first thing we check in a TCP payload:
 *   Byte 0: Is it 0x16 (Handshake)?
 *   Byte 1-2: Does the version look like TLS? (0x0301 to 0x0303)
 *   Byte 3-4: Record length
 *   Byte 5: Is the handshake type 0x01 (ClientHello)?
 *
 * If all checks pass, we dive into parseClientHello().
 *
 * INTERVIEW Q: "How do you distinguish TLS from other TCP protocols?"
 * A: The very first byte of a TLS record is the content type.
 *    0x16 = Handshake. Combined with a valid TLS version (0x0301-0x0303),
 *    this is a strong fingerprint. We also verify the handshake type
 *    is 0x01 (ClientHello) since that's the one containing SNI.
 */
bool TlsParser::parse(const uint8_t *payload, uint32_t payload_length,
                      ParsedPacket &result) {

  // Need at least 5 bytes (TLS record header) + 1 byte (handshake type)
  if (payload_length < TLS_RECORD_HEADER_SIZE + 1) {
    return false;
  }

  // ── Check 1: Content type must be Handshake (0x16) ──
  if (payload[0] != TLS_CONTENT_HANDSHAKE) {
    return false; // Not a TLS handshake
  }

  // ── Check 2: TLS version sanity check ──
  // Byte 1 should be 0x03 (SSL 3.0 / TLS family)
  // Byte 2 should be 0x00 to 0x04 (SSLv3=0x00, TLS1.0=0x01, ... TLS1.3=0x03)
  //
  // Note: Even TLS 1.3 uses 0x0303 in the record layer for backward
  // compatibility. The actual version is negotiated inside the handshake.
  if (payload[1] != 0x03 || payload[2] > 0x04) {
    return false;
  }

  // ── Read the record length (bytes 3-4, big-endian) ──
  // This tells us how many bytes of handshake data follow.
  uint16_t record_length = (payload[3] << 8) | payload[4];

  // Sanity: record length shouldn't exceed what we have
  // (We use the smaller of record_length vs remaining data)
  uint32_t available = payload_length - TLS_RECORD_HEADER_SIZE;
  if (record_length > available) {
    record_length = (uint16_t)available; // Parse what we have
  }

  // ── Check 3: Handshake type must be ClientHello (0x01) ──
  // The handshake message starts at byte 5 (after the 5-byte record header)
  const uint8_t *handshake_data = payload + TLS_RECORD_HEADER_SIZE;
  if (handshake_data[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
    return false; // It's a handshake, but not ClientHello (maybe ServerHello)
  }

  // Mark as TLS
  result.app_protocol = "TLS";

  // ── Skip the 4-byte handshake header (1B type + 3B length) ──
  // and dive into the ClientHello body
  if (record_length < 4) {
    return true; // Too short for a real ClientHello, but it IS TLS
  }

  return parseClientHello(handshake_data + 4, record_length - 4, result);
}

// ─────────────────────────────────────────────────────────────────────────────
// PRIVATE: parseClientHello() — Navigate through ClientHello to Extensions
// ─────────────────────────────────────────────────────────────────────────────
/*
 * This function skips through the fixed and variable-length fields inside
 * a ClientHello to reach the Extensions list.
 *
 * Think of it like opening a series of nested boxes:
 *   Box 1: Client Version (2B)     — skip
 *   Box 2: Client Random (32B)     — skip
 *   Box 3: Session ID (1B len + variable) — skip
 *   Box 4: Cipher Suites (2B len + variable) — skip
 *   Box 5: Compression Methods (1B len + variable) — skip
 *   Box 6: Extensions (2B len + variable) — PARSE THIS!
 *
 * We use an 'offset' variable that we advance through each field.
 * After skipping boxes 1-5, whatever remains is the extensions.
 *
 * INTERVIEW Q: "Why do you need to skip so many fields?"
 * A: TLS ClientHello packs many negotiation parameters before extensions.
 *    There's no shortcut — we must parse each length field to know
 *    where the next section starts, because everything is variable-length.
 */
bool TlsParser::parseClientHello(const uint8_t *data, uint32_t length,
                                 ParsedPacket &result) {

  uint32_t offset = 0;

  // ═══════════════════════════════════════════════════════════════
  // FIELD 1: Client Version (2 bytes) — skip
  // ═══════════════════════════════════════════════════════════════
  // e.g., 0x0303 for TLS 1.2. We don't need this.
  offset += 2;
  if (offset > length)
    return false;

  // ═══════════════════════════════════════════════════════════════
  // FIELD 2: Client Random (32 bytes) — skip
  // ═══════════════════════════════════════════════════════════════
  // 32 bytes of random data used for key generation. Skip it.
  offset += 32;
  if (offset > length)
    return false;

  // ═══════════════════════════════════════════════════════════════
  // FIELD 3: Session ID (1 byte length + variable data) — skip
  // ═══════════════════════════════════════════════════════════════
  // Used for session resumption. The first byte tells us the length.
  if (offset >= length)
    return false;
  uint8_t session_id_length = data[offset];
  offset += 1 + session_id_length; // Skip length byte + session ID data
  if (offset > length)
    return false;

  // ═══════════════════════════════════════════════════════════════
  // FIELD 4: Cipher Suites (2 byte length + variable data) — skip
  // ═══════════════════════════════════════════════════════════════
  // List of encryption algorithms the client supports.
  // Length is 2 bytes (big-endian) because there can be MANY suites.
  if (offset + 2 > length)
    return false;
  uint16_t cipher_suites_length = (data[offset] << 8) | data[offset + 1];
  offset += 2 + cipher_suites_length;
  if (offset > length)
    return false;

  // ═══════════════════════════════════════════════════════════════
  // FIELD 5: Compression Methods (1 byte length + variable) — skip
  // ═══════════════════════════════════════════════════════════════
  // Almost always just [0x01, 0x00] (1 method: no compression).
  // TLS 1.3 mandates no compression for security.
  if (offset >= length)
    return false;
  uint8_t compression_length = data[offset];
  offset += 1 + compression_length;
  if (offset > length)
    return false;

  // ═══════════════════════════════════════════════════════════════
  // FIELD 6: Extensions (2 byte length + variable) — PARSE!
  // ═══════════════════════════════════════════════════════════════
  // We made it! Everything from here is extensions data.
  if (offset + 2 > length)
    return false;
  uint16_t extensions_length = (data[offset] << 8) | data[offset + 1];
  offset += 2;

  // Make sure extensions don't extend past our data
  if (offset + extensions_length > length) {
    extensions_length = (uint16_t)(length - offset);
  }

  // Dive into the extensions to find SNI
  return extractSNI(data + offset, extensions_length, result);
}

// ─────────────────────────────────────────────────────────────────────────────
// PRIVATE: extractSNI() — Find and read the SNI extension
// ─────────────────────────────────────────────────────────────────────────────
/*
 * Extensions are a sequence of TLV (Type-Length-Value) entries:
 *
 *   ┌────────────┬──────────┬───────────────────────────────────┐
 *   │ Type (2B)  │ Len (2B) │ Extension Data (Len bytes)        │
 *   ├────────────┼──────────┼───────────────────────────────────┤
 *   │ Type (2B)  │ Len (2B) │ Extension Data (Len bytes)        │
 *   └────────────┴──────────┴───────────────────────────────────┘
 *
 * We loop through them looking for type = 0x0000 (SNI).
 *
 * When we find SNI, its data contains:
 *
 *   ┌──────────────────────┬────────────┬────────────────┬────────────────┐
 *   │ SNI List Length (2B) │ Type (1B)  │ Name Len (2B)  │ Hostname       │
 *   └──────────────────────┴────────────┴────────────────┴────────────────┘
 *
 *   Type 0x00 = hostname (the only type defined)
 *
 * INTERVIEW Q: "What is TLV encoding?"
 * A: Type-Length-Value is a very common pattern in binary protocols.
 *    You read the Type to know WHAT it is, the Length to know HOW BIG
 *    it is, and then read that many bytes of Value. It's self-describing
 *    and extensible — you can skip unknown types by reading their length.
 */
bool TlsParser::extractSNI(const uint8_t *data, uint32_t length,
                           ParsedPacket &result) {

  uint32_t offset = 0;

  // Loop through extensions
  while (offset + 4 <= length) { // Need at least 4 bytes: 2 (type) + 2 (len)

    // Read extension type (2 bytes, big-endian)
    uint16_t ext_type = (data[offset] << 8) | data[offset + 1];

    // Read extension length (2 bytes, big-endian)
    uint16_t ext_length = (data[offset + 2] << 8) | data[offset + 3];

    offset += 4; // Move past type + length

    // Make sure the extension data doesn't overflow
    if (offset + ext_length > length) {
      break;
    }

    // ── Is this the SNI extension? (type = 0x0000) ──
    if (ext_type == TLS_EXTENSION_SNI) {

      // Inside SNI extension:
      //   Bytes 0-1: SNI list length (2B)
      //   Byte 2:    Server name type (1B) — 0x00 = hostname
      //   Bytes 3-4: Server name length (2B)
      //   Bytes 5+:  The actual hostname

      const uint8_t *sni_data = data + offset;
      uint32_t sni_length = ext_length;

      // We need at least 5 bytes (2 + 1 + 2)
      if (sni_length < 5) {
        offset += ext_length;
        continue;
      }

      // Skip SNI list length (2B) — we already know from ext_length
      // Read server name type
      uint8_t name_type = sni_data[2];

      // Read server name length
      uint16_t name_length = (sni_data[3] << 8) | sni_data[4];

      // Type 0x00 = hostname
      if (name_type == 0x00 && name_length > 0 &&
          5 + name_length <= sni_length) {
        // Extract the hostname as a string
        result.tls_sni = std::string(
            reinterpret_cast<const char *>(sni_data + 5), name_length);
        return true; // Found it!
      }
    }

    // Move to the next extension
    offset += ext_length;
  }

  // No SNI found (possible — some clients don't send it)
  return true; // Still valid TLS, just no SNI
}
