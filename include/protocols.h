/*
 * protocols.h — Network Protocol Header Definitions
 * ==================================================
 *
 * WHY THIS FILE EXISTS:
 * ---------------------
 * When a packet travels over the network, it's just a big blob of raw bytes.
 * But those bytes follow a strict structure — like filling out a form where
 * field 1 is always 6 bytes, field 2 is always 2 bytes, etc.
 *
 * This file defines C++ structs that mirror exactly how those bytes are
 * laid out in memory. By casting the raw byte pointer to our struct pointer,
 * we can instantly read any field — no manual byte counting needed.
 *
 * INTERVIEW CONCEPT — "Struct Casting / Zero-Copy Parsing":
 * Instead of copying bytes into variables one by one, we overlay a struct
 * on top of the raw buffer. This is extremely fast (zero-copy) and is how
 * real tools like Wireshark work internally.
 *
 * INTERVIEW CONCEPT — "Byte Order / Endianness":
 * Your CPU stores numbers in "little-endian" (least significant byte first),
 * but networks send numbers in "big-endian" (most significant byte first).
 * This is called "Network Byte Order." We must convert multi-byte fields
 * using ntohs() (network-to-host-short, 2 bytes) and ntohl() (4 bytes).
 */

#ifndef PROTOCOLS_H
#define PROTOCOLS_H

// ─────────────────────────────────────────────────────────────────────────────
// Platform-specific includes
// ─────────────────────────────────────────────────────────────────────────────
#ifdef _WIN32
// On Windows, Winsock2 gives us ntohs(), ntohl(), inet_ntoa(), etc.
// ws2tcpip.h gives us inet_ntop() for converting IPs to readable strings.
#include <winsock2.h>
#include <ws2tcpip.h>
#else
// On Linux/Mac, these come from different headers.
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include <cstdint> // For fixed-width types: uint8_t, uint16_t, uint32_t
#include <string>  // For std::string

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 2: ETHERNET HEADER (14 bytes)
// ─────────────────────────────────────────────────────────────────────────────
/*
 * Ethernet is the FIRST layer we encounter in a packet.
 * Think of it as the outer envelope.
 *
 * Layout in memory (14 bytes total):
 * ┌───────────────────┬───────────────────┬──────────────┐
 * │  Dest MAC (6 B)   │  Src MAC  (6 B)   │  Type (2 B)  │
 * └───────────────────┴───────────────────┘──────────────┘
 *
 * - Dest MAC: The hardware address of the receiving network card
 * - Src MAC : The hardware address of the sending network card
 * - Type    : Tells us what's INSIDE (0x0800 = IPv4, 0x86DD = IPv6)
 *
 * INTERVIEW Q: "What is a MAC address?"
 * A: A 6-byte unique identifier burned into every network card (NIC).
 *    Example: AA:BB:CC:DD:EE:FF. It works at Layer 2 (Data Link).
 */

// We pack the struct so the compiler doesn't add padding bytes between fields.
// Without packing, the compiler might insert gaps to align fields to 4-byte
// boundaries, which would break our overlay onto raw packet data.
#pragma pack(push, 1)

struct EthernetHeader {
  uint8_t dest_mac[6]; // Destination MAC address (6 bytes)
  uint8_t src_mac[6];  // Source MAC address (6 bytes)
  uint16_t ether_type; // Protocol inside: 0x0800 = IPv4 (in network byte order)
};

#pragma pack(pop)

// Ethernet type constants (in host byte order — we compare AFTER converting)
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;
constexpr uint16_t ETHERTYPE_ARP = 0x0806;

// Size of Ethernet header is always 14 bytes
constexpr int ETHERNET_HEADER_SIZE = 14;

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 3: IPv4 HEADER (20–60 bytes)
// ─────────────────────────────────────────────────────────────────────────────
/*
 * Once we peel off the Ethernet envelope and see type = 0x0800,
 * the next bytes form an IPv4 header.
 *
 * Key fields for DPI:
 *   - src_ip / dest_ip : WHO is talking to WHOM (the IP addresses)
 *   - protocol         : WHAT transport layer is inside (6=TCP, 17=UDP)
 *   - ihl              : Header length (because IPv4 headers can vary in size)
 *
 * Layout (minimum 20 bytes):
 * ┌─────────┬─────────┬──────────────────┬──────────────────┐
 * │ Ver+IHL │  ToS    │   Total Length    │  Identification  │
 * ├─────────┴─────────┼──────────────────┼──────────────────┤
 * │  Flags + Offset   │      TTL         │    Protocol      │
 * ├───────────────────┼──────────────────┴──────────────────┤
 * │  Header Checksum  │         Source IP (4 bytes)          │
 * ├───────────────────┼─────────────────────────────────────┤
 * │                   Destination IP (4 bytes)               │
 * └─────────────────────────────────────────────────────────┘
 *
 * INTERVIEW Q: "What does IHL mean?"
 * A: Internet Header Length. It's the header size in 4-byte units.
 *    Minimum value is 5 → 5×4 = 20 bytes. Max is 15 → 15×4 = 60 bytes.
 *    If IHL > 5, there are "options" appended to the header.
 *
 * INTERVIEW Q: "What does TTL mean?"
 * A: Time To Live. Each router decrements it by 1. When it hits 0, the packet
 *    is dropped. This prevents packets from looping forever. Typical starting
 *    values: Windows=128, Linux=64.
 */

#pragma pack(push, 1)

struct IPv4Header {
  // First byte contains TWO fields packed together (4 bits each):
  //   High nibble = Version (always 4 for IPv4)
  //   Low nibble  = IHL (header length in 4-byte words)
  // NOTE: On little-endian machines (x86), bit-fields are stored LSB first,
  //       so we declare ihl before version.
  uint8_t ihl : 4;     // Header length (in 4-byte words, min 5)
  uint8_t version : 4; // IP version (always 4)

  uint8_t tos; // Type of Service / DSCP (QoS priority)
  uint16_t
      total_length; // Total packet size (header + payload), network byte order
  uint16_t identification; // Used for reassembling fragmented packets
  uint16_t flags_offset;   // Flags (3 bits) + Fragment Offset (13 bits)
  uint8_t ttl;             // Time to Live (hop counter)
  uint8_t protocol;        // What's inside: 6=TCP, 17=UDP, 1=ICMP
  uint16_t checksum;       // Header integrity check
  uint32_t src_ip;         // Source IP address (4 bytes, network byte order)
  uint32_t dest_ip; // Destination IP address (4 bytes, network byte order)
  // Options may follow if ihl > 5, but we handle that dynamically
};

#pragma pack(pop)

// IP protocol number constants
constexpr uint8_t IP_PROTO_ICMP = 1;
constexpr uint8_t IP_PROTO_TCP = 6;
constexpr uint8_t IP_PROTO_UDP = 17;

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 4: TCP HEADER (20–60 bytes)
// ─────────────────────────────────────────────────────────────────────────────
/*
 * TCP = Transmission Control Protocol (reliable, ordered delivery).
 * Used by HTTP, HTTPS, SSH, FTP, etc.
 *
 * Key fields for DPI:
 *   - src_port / dest_port : Which APPLICATION on each machine
 *   - data_offset          : Where the actual payload starts
 *   - flags                : SYN/ACK/FIN etc. (connection state)
 *
 * Common ports: 80=HTTP, 443=HTTPS, 22=SSH, 53=DNS(sometimes)
 *
 * INTERVIEW Q: "What is the TCP 3-way handshake?"
 * A: To establish a connection:
 *    1. Client → Server: SYN        ("I want to connect")
 *    2. Server → Client: SYN+ACK    ("OK, I acknowledge")
 *    3. Client → Server: ACK        ("Great, we're connected")
 */

#pragma pack(push, 1)

struct TCPHeader {
  uint16_t src_port;       // Source port number (network byte order)
  uint16_t dest_port;      // Destination port number (network byte order)
  uint32_t seq_number;     // Sequence number (for ordering data)
  uint32_t ack_number;     // Acknowledgment number
  uint8_t data_offset : 4; // Header length in 4-byte words (like IHL)
  uint8_t reserved : 3;    // Reserved bits (always 0)
  uint8_t ns : 1;          // ECN-nonce flag
  uint8_t flags;           // TCP flags: FIN, SYN, RST, PSH, ACK, URG
  uint16_t window_size;    // Flow control: how much data the sender can receive
  uint16_t checksum;       // Integrity check
  uint16_t urgent_pointer; // Points to urgent data (rarely used)
};

#pragma pack(pop)

// TCP flag bitmasks — use these to check individual flags
// Example: if (tcp->flags & TCP_FLAG_SYN) { /* it's a SYN packet */ }
constexpr uint8_t TCP_FLAG_FIN = 0x01; // Connection teardown
constexpr uint8_t TCP_FLAG_SYN = 0x02; // Connection setup
constexpr uint8_t TCP_FLAG_RST = 0x04; // Connection reset (abort)
constexpr uint8_t TCP_FLAG_PSH = 0x08; // Push data immediately
constexpr uint8_t TCP_FLAG_ACK = 0x10; // Acknowledgment
constexpr uint8_t TCP_FLAG_URG = 0x20; // Urgent data present

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 4: UDP HEADER (always exactly 8 bytes)
// ─────────────────────────────────────────────────────────────────────────────
/*
 * UDP = User Datagram Protocol (fast, no guarantees).
 * Used by DNS, video streaming, gaming, VoIP.
 *
 * Much simpler than TCP — just 4 fields, 8 bytes total:
 * ┌──────────────┬──────────────┐
 * │  Src Port    │  Dest Port   │
 * ├──────────────┼──────────────┤
 * │  Length      │  Checksum    │
 * └──────────────┴──────────────┘
 *
 * INTERVIEW Q: "TCP vs UDP — when would you use each?"
 * A: TCP when you need reliability (web pages, file transfer).
 *    UDP when speed matters more (DNS lookups, live video, gaming).
 */

#pragma pack(push, 1)

struct UDPHeader {
  uint16_t src_port;  // Source port (network byte order)
  uint16_t dest_port; // Destination port (network byte order)
  uint16_t length;    // Total UDP packet size (header + payload)
  uint16_t checksum;  // Integrity check (optional in IPv4)
};

#pragma pack(pop)

constexpr int UDP_HEADER_SIZE = 8;

// ─────────────────────────────────────────────────────────────────────────────
// PARSED PACKET — Our friendly result structure
// ─────────────────────────────────────────────────────────────────────────────
/*
 * After we parse all the layers, we fill in this struct with the "interesting"
 * information in a human-readable format. This is what the rest of our engine
 * (policy engine, logger) will work with — they never touch raw bytes.
 *
 * Think of this as: "Here's a summary of what we found in this packet."
 */

struct ParsedPacket {
  // === Layer 2 (Ethernet) ===
  std::string src_mac;  // e.g. "AA:BB:CC:DD:EE:FF"
  std::string dest_mac; // e.g. "11:22:33:44:55:66"

  // === Layer 3 (IP) ===
  std::string src_ip;      // e.g. "192.168.1.5"
  std::string dest_ip;     // e.g. "142.250.190.46"
  uint8_t ip_protocol = 0; // 6=TCP, 17=UDP, 1=ICMP

  // === Layer 4 (TCP/UDP) ===
  uint16_t src_port = 0;       // e.g. 54321 (random high port)
  uint16_t dest_port = 0;      // e.g. 443 (HTTPS)
  std::string transport_proto; // "TCP" or "UDP"

  // === Layer 7 (Application) ===
  std::string app_protocol; // "DNS", "HTTP", "TLS", or "Unknown"

  // DNS-specific fields
  std::string dns_query; // e.g. "google.com"
  bool is_dns_response = false;

  // HTTP-specific fields
  std::string http_method; // "GET", "POST", etc.
  std::string http_host;   // e.g. "example.com"
  std::string http_uri;    // e.g. "/index.html"

  // TLS-specific fields
  std::string tls_sni; // Server Name Indication, e.g. "netflix.com"

  // Metadata
  uint32_t packet_length = 0;       // Total packet size in bytes
  const uint8_t *payload = nullptr; // Pointer to application-layer payload
  uint32_t payload_length = 0;      // Size of payload in bytes
};

// ─────────────────────────────────────────────────────────────────────────────
// UTILITY FUNCTIONS
// ─────────────────────────────────────────────────────────────────────────────

/*
 * Convert a 6-byte MAC address to a human-readable string.
 * Input:  raw bytes like {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
 * Output: string like "AA:BB:CC:DD:EE:FF"
 */
inline std::string mac_to_string(const uint8_t mac[6]) {
  char buf[18]; // 17 characters + null terminator
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1],
           mac[2], mac[3], mac[4], mac[5]);
  return std::string(buf);
}

/*
 * Convert a 4-byte IPv4 address (in network byte order) to a readable string.
 * Input:  uint32_t like 0xC0A80105 (which is 192.168.1.5)
 * Output: string like "192.168.1.5"
 *
 * We use inet_ntop() which is the modern, safe version of inet_ntoa().
 *
 * INTERVIEW Q: "Why inet_ntop over inet_ntoa?"
 * A: inet_ntoa() uses a static internal buffer (not thread-safe).
 *    inet_ntop() writes to YOUR buffer, so it's safe for multithreading.
 */
inline std::string ip_to_string(uint32_t ip) {
  char buf[INET_ADDRSTRLEN]; // 16 bytes (max "255.255.255.255\0")
  struct in_addr addr;
  addr.s_addr = ip; // Already in network byte order
  inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN);
  return std::string(buf);
}

/*
 * Get a human-readable name for an IP protocol number.
 * Used in logging to print "TCP" instead of "6".
 */
inline std::string protocol_to_string(uint8_t protocol) {
  switch (protocol) {
  case IP_PROTO_TCP:
    return "TCP";
  case IP_PROTO_UDP:
    return "UDP";
  case IP_PROTO_ICMP:
    return "ICMP";
  default:
    return "Unknown(" + std::to_string(protocol) + ")";
  }
}

#endif // PROTOCOLS_H
