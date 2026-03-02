/*
 * http_parser.cpp — HTTP Request Parser Implementation
 * =====================================================
 *
 * HOW AN HTTP REQUEST LOOKS IN RAW BYTES:
 * ───────────────────────────────────────
 * When your browser requests a web page, the TCP payload contains
 * plain ASCII text like this:
 *
 *   G E T   / i n d e x . h t m l   H T T P / 1 . 1 \r \n
 *   H o s t :   w w w . e x a m p l e . c o m \r \n
 *   U s e r - A g e n t :   M o z i l l a / 5 . 0 \r \n
 *   \r \n
 *
 * Each line ends with \r\n (CRLF — Carriage Return + Line Feed).
 * An empty line (\r\n\r\n) marks the end of headers.
 *
 * OUR PARSING STRATEGY:
 * ─────────────────────
 *   1. Convert the raw bytes to a std::string for easy text searching
 *   2. Check if it starts with a known HTTP method (GET, POST, etc.)
 *   3. Parse the request line: METHOD URI VERSION
 *   4. Search for the "Host:" header
 *
 * INTERVIEW Q: "Why convert to string instead of parsing byte-by-byte?"
 * A: HTTP is a text protocol — using std::string gives us find(), substr(),
 *    and other convenient functions. For binary protocols (DNS, TLS) we
 *    parse bytes directly, but for text protocols, strings are cleaner.
 */

#include "../include/http_parser.h"
#include <algorithm> // For std::transform (case conversion)
#include <cctype>    // For std::tolower

// ─────────────────────────────────────────────────────────────────────────────
// Known HTTP methods — we check if the payload starts with one of these
// ─────────────────────────────────────────────────────────────────────────────
/*
 * HTTP defines these request methods:
 *   GET     — retrieve a resource (most common, just fetching a page)
 *   POST    — submit data (form submissions, API calls)
 *   PUT     — replace a resource entirely
 *   DELETE  — remove a resource
 *   HEAD    — like GET but only returns headers (no body)
 *   OPTIONS — ask what methods the server supports
 *   PATCH   — partially update a resource
 *   CONNECT — establish a tunnel (used by proxies for HTTPS)
 *
 * INTERVIEW Q: "What's the difference between GET and POST?"
 * A: GET retrieves data (parameters in URL, cacheable, bookmarkable).
 *    POST sends data (parameters in body, not cached, not bookmarkable).
 *    GET is idempotent (same request = same result), POST is not.
 */
static const char *HTTP_METHODS[] = {"GET ",  "POST ",    "PUT ",   "DELETE ",
                                     "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "};
static const int NUM_HTTP_METHODS = 8;

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC: parse() — Main entry point
// ─────────────────────────────────────────────────────────────────────────────
/*
 * Called when we have a TCP payload that MIGHT be HTTP.
 * We check if it starts with a known method verb to confirm.
 *
 * INTERVIEW Q: "How do you distinguish HTTP from other TCP protocols?"
 * A: We look at the first few bytes. HTTP requests always start with
 *    a method name (GET, POST, etc.) followed by a space. If we see that
 *    pattern, it's HTTP. This is called "protocol fingerprinting" —
 *    identifying a protocol by its characteristic byte patterns.
 */
bool HttpParser::parse(const uint8_t *payload, uint32_t payload_length,
                       ParsedPacket &result) {

  // Need at least a few bytes to identify the method
  if (payload_length < 4) {
    return false;
  }

  // ── Step 1: Convert raw bytes to a string ──
  // We cap at 2048 bytes because:
  //   - HTTP headers are typically a few hundred bytes
  //   - We don't need the body (images, HTML, etc.)
  //   - Limiting size prevents wasting memory on large payloads
  uint32_t parse_length = std::min(payload_length, (uint32_t)2048);
  std::string data(reinterpret_cast<const char *>(payload), parse_length);

  // ── Step 2: Check if it starts with a known HTTP method ──
  // We compare the first few characters against our method list.
  //
  // Why "starts with"? Because HTTP requests ALWAYS begin with
  // the method name — there's nothing before it.
  bool is_http = false;
  for (int i = 0; i < NUM_HTTP_METHODS; i++) {
    // Compare the beginning of our data with each method string
    if (data.compare(0, strlen(HTTP_METHODS[i]), HTTP_METHODS[i]) == 0) {
      is_http = true;
      break;
    }
  }

  if (!is_http) {
    return false; // Not an HTTP request — probably TLS, SSH, or other protocol
  }

  // ── Step 3: It's HTTP! Mark it and parse the details ──
  result.app_protocol = "HTTP";

  // Extract method and URI from the request line
  extractRequestLine(data, result);

  // Extract the Host header
  result.http_host = extractHostHeader(data);

  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// PRIVATE: extractRequestLine() — Parse "GET /path HTTP/1.1\r\n"
// ─────────────────────────────────────────────────────────────────────────────
/*
 * The first line of an HTTP request is called the "Request Line."
 * Its format is always:
 *
 *   METHOD  SP  URI  SP  VERSION  CRLF
 *
 *   Example: "GET /index.html HTTP/1.1\r\n"
 *             ^^^              ^^^
 *           method=GET       uri=/index.html
 *
 * We find the two spaces to split it into three parts.
 *
 * INTERVIEW Q: "What information does the request line contain?"
 * A: Three things separated by spaces:
 *    1. Method (GET/POST/...) — what action to perform
 *    2. URI (/path/to/resource) — what resource to act on
 *    3. Version (HTTP/1.1) — which HTTP version
 */
bool HttpParser::extractRequestLine(const std::string &data,
                                    ParsedPacket &result) {

  // Find the end of the first line (\r\n)
  size_t line_end = data.find("\r\n");
  if (line_end == std::string::npos) {
    return false; // No complete line found
  }

  // Extract just the first line: "GET /index.html HTTP/1.1"
  std::string request_line = data.substr(0, line_end);

  // Find the FIRST space — separates METHOD from URI
  size_t first_space = request_line.find(' ');
  if (first_space == std::string::npos) {
    return false;
  }

  // Find the SECOND space — separates URI from VERSION
  size_t second_space = request_line.find(' ', first_space + 1);
  if (second_space == std::string::npos) {
    return false;
  }

  // ── Extract method: everything before the first space ──
  // "GET /index.html HTTP/1.1"
  //  ^^^
  result.http_method = request_line.substr(0, first_space);

  // ── Extract URI: everything between the two spaces ──
  // "GET /index.html HTTP/1.1"
  //      ^^^^^^^^^^^
  result.http_uri =
      request_line.substr(first_space + 1, second_space - first_space - 1);

  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// PRIVATE: extractHostHeader() — Find "Host: www.example.com"
// ─────────────────────────────────────────────────────────────────────────────
/*
 * HTTP headers follow the request line, each on its own line:
 *
 *   GET /index.html HTTP/1.1\r\n
 *   Host: www.example.com\r\n        ← THIS is what we want
 *   User-Agent: Mozilla/5.0\r\n
 *   Accept: text/html\r\n
 *   \r\n                              ← empty line = end of headers
 *
 * We search for "host:" (case-insensitive, because per RFC 7230,
 * header field names are case-insensitive).
 *
 * INTERVIEW Q: "Why is the Host header mandatory in HTTP/1.1?"
 * A: One server can host multiple websites on the same IP address.
 *    The Host header tells the server which site is being requested.
 *    This is called "virtual hosting." Without it, the server wouldn't
 *    know which website to serve.
 */
std::string HttpParser::extractHostHeader(const std::string &data) {

  // Convert the data to lowercase for case-insensitive searching.
  // HTTP spec says header names are case-insensitive, so
  // "Host:", "host:", "HOST:" are all valid.
  std::string lower_data = data;
  std::transform(lower_data.begin(), lower_data.end(), lower_data.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  // Search for "\r\nhost:" — we include \r\n to make sure we're
  // matching a header line, not text inside a value.
  //
  // Why "\r\nhost:" instead of just "host:"?
  //   - "host:" at position 0 would mean it's the request line (wrong)
  //   - "\r\nhost:" ensures it's on its own header line
  std::string search_key = "\r\nhost:";
  size_t pos = lower_data.find(search_key);

  if (pos == std::string::npos) {
    return ""; // No Host header found
  }

  // Move past "\r\nhost:" to get to the value
  pos += search_key.length();

  // Skip any whitespace after the colon
  // "Host:  www.example.com" — there might be spaces after ":"
  while (pos < data.size() && data[pos] == ' ') {
    pos++;
  }

  // Find the end of this header line (\r\n)
  size_t end_pos = data.find("\r\n", pos);
  if (end_pos == std::string::npos) {
    // No \r\n found — take everything remaining
    end_pos = data.size();
  }

  // Extract the host value from the ORIGINAL data (not lowercased)
  // so we preserve the original casing of the domain name.
  return data.substr(pos, end_pos - pos);
}
