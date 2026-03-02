/*
 * http_parser.h — HTTP Request Parser Interface
 * ===============================================
 *
 * WHY THIS FILE EXISTS:
 * ---------------------
 * HTTP (HyperText Transfer Protocol) is the language your browser uses
 * to fetch web pages. When you type a URL and press Enter, your browser
 * sends an HTTP request like:
 *
 *   GET /index.html HTTP/1.1\r\n
 *   Host: www.example.com\r\n
 *   User-Agent: Mozilla/5.0 ...\r\n
 *   \r\n
 *
 * Unlike DNS (binary) or TLS (encrypted), HTTP is PLAIN TEXT.
 * This makes it the easiest application protocol to parse — we just
 * search for text patterns in the TCP payload.
 *
 * FOR DPI, WE CARE ABOUT:
 * ──────────────────────────
 *   1. Method — GET, POST, PUT, DELETE, etc. (what action?)
 *   2. URI    — /index.html, /api/users  (what resource?)
 *   3. Host   — www.example.com           (which website?)
 *
 * The Host header is the most important for blocklist matching —
 * it tells us which domain the browser is talking to.
 *
 * INTERVIEW CONCEPT — "Why can we only see HTTP, not HTTPS?"
 * A: HTTP sends everything in plain text → we can read it all.
 *    HTTPS wraps HTTP inside TLS encryption → we can't read the content.
 *    For HTTPS, we use the TLS SNI field instead (Step 5).
 *
 * INTERVIEW CONCEPT — "HTTP/1.1 vs HTTP/2 vs HTTP/3"
 * A: HTTP/1.1 = plain-text, one request at a time, easy to parse (what we
 * handle) HTTP/2   = binary framing, multiplexed, compressed headers (harder to
 * parse) HTTP/3   = uses QUIC (UDP-based), encrypted by default Most DPI
 * engines focus on HTTP/1.1 since 2 and 3 are typically encrypted.
 */

#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include "../include/protocols.h"
#include <cstdint>
#include <string>

class HttpParser {
public:
  /*
   * parse() — Check if a TCP payload contains an HTTP request and extract
   * fields.
   *
   * Parameters:
   *   payload        - Pointer to TCP payload data (after TCP header)
   *   payload_length - Size of the payload in bytes
   *   result         - ParsedPacket to fill in (http_method, http_uri,
   * http_host)
   *
   * Returns:
   *   true  if this looks like an HTTP request (starts with a known method)
   *   false if it's not HTTP (could be TLS, raw data, etc.)
   *
   * INTERVIEW Q: "How do you identify if a TCP payload is HTTP?"
   * A: HTTP requests ALWAYS start with a method verb (GET, POST, etc.)
   *    followed by a space. We check the first few bytes for known methods.
   *    This is called "protocol detection" or "protocol fingerprinting."
   */
  bool parse(const uint8_t *payload, uint32_t payload_length,
             ParsedPacket &result);

private:
  /*
   * extractRequestLine() — Parse "GET /path HTTP/1.1\r\n"
   *
   * Extracts the method (GET) and URI (/path) from the first line.
   * The first line of an HTTP request always follows this format:
   *   METHOD SP URI SP VERSION CRLF
   *
   * SP = space (0x20), CRLF = carriage return + line feed (\r\n)
   */
  bool extractRequestLine(const std::string &data, ParsedPacket &result);

  /*
   * extractHostHeader() — Find and extract "Host: www.example.com"
   *
   * The Host header tells us which website the request is for.
   * We search for "Host: " (case-insensitive) and read until end of line.
   *
   * INTERVIEW Q: "Why is the Host header important?"
   * A: A single IP address can host hundreds of websites (virtual hosting).
   *    The Host header tells the server WHICH site is being requested.
   *    For DPI, it's how we identify the domain without relying on DNS.
   */
  std::string extractHostHeader(const std::string &data);
};

#endif // HTTP_PARSER_H
