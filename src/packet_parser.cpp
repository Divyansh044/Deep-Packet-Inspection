/*
 * packet_parser.cpp — Packet Parser Implementation
 * =================================================
 *
 * This file contains the actual parsing logic. We walk through the raw
 * packet bytes layer by layer:
 *
 *   1. parseEthernet() — reads outer envelope, checks if it's IPv4
 *   2. parseIPv4()     — reads IP addresses, checks if it's TCP or UDP
 *   3. parseTCP()      — reads port numbers, locates the payload
 *      or parseUDP()   — reads port numbers, locates the payload
 *
 * After all layers are parsed, the ParsedPacket struct is fully populated
 * and ready for the policy engine (Step 7) to inspect.
 */

#include "../include/packet_parser.h"
#include "../include/protocols.h"

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC: parse() — Main entry point
// ─────────────────────────────────────────────────────────────────────────────
/*
 * This is what gets called for EVERY packet captured.
 * It kicks off the layered parsing, starting from Ethernet.
 *
 * INTERVIEW Q: "Walk me through what happens when a packet arrives."
 * A: 1. pcap hands us a raw byte array and its length
 *    2. We call parse(), which calls parseEthernet()
 *    3. parseEthernet() reads the MACs and ether_type
 *    4. If ether_type is IPv4, it calls parseIPv4()
 *    5. parseIPv4() reads IPs and protocol, then calls parseTCP() or parseUDP()
 *    6. TCP/UDP parsers read ports and locate the payload
 *    7. The filled ParsedPacket is returned to the caller
 */
bool PacketParser::parse(const uint8_t *data, uint32_t length,
                         ParsedPacket &result) {
  // Store total packet length in the result
  result.packet_length = length;

  // Start peeling from Layer 2 (Ethernet)
  return parseEthernet(data, length, result);
}

// ─────────────────────────────────────────────────────────────────────────────
// PRIVATE: parseEthernet() — Layer 2
// ─────────────────────────────────────────────────────────────────────────────
/*
 * The Ethernet header is ALWAYS the first 14 bytes of the packet.
 *
 * What we do here:
 *   1. Check if we have at least 14 bytes (if not, packet is garbage)
 *   2. Cast the raw pointer to our EthernetHeader struct
 *   3. Extract source & destination MAC addresses
 *   4. Read ether_type to know what's inside
 *   5. If it's IPv4 (0x0800), advance the pointer by 14 and call parseIPv4()
 *
 * INTERVIEW CONCEPT — "Type Casting Raw Pointers":
 * The line:
 *     const EthernetHeader* eth = reinterpret_cast<const
 * EthernetHeader*>(data);
 *
 * tells the compiler: "treat the bytes at 'data' as if they were an
 * EthernetHeader struct." This works ONLY because our struct is #pragma packed
 * to match the exact byte layout on the wire.
 */
bool PacketParser::parseEthernet(const uint8_t *data, uint32_t length,
                                 ParsedPacket &result) {

  // Safety check: do we have enough bytes for an Ethernet header?
  if (length < ETHERNET_HEADER_SIZE) {
    return false; // Packet too short — skip it
  }

  // ── Step 1: Overlay our struct onto the raw bytes ──
  // This is the "struct casting" / "zero-copy" technique.
  // After this line, eth->dest_mac, eth->src_mac, eth->ether_type all work.
  const EthernetHeader *eth = reinterpret_cast<const EthernetHeader *>(data);

  // ── Step 2: Extract MAC addresses into readable strings ──
  result.src_mac = mac_to_string(eth->src_mac);
  result.dest_mac = mac_to_string(eth->dest_mac);

  // ── Step 3: Check what protocol is inside ──
  // ntohs() = Network TO Host Short
  // ether_type is stored in big-endian (network byte order) on the wire,
  // but our CPU is little-endian, so we must convert before comparing.
  uint16_t type = ntohs(eth->ether_type);

  if (type == ETHERTYPE_IPV4) {
    // Move the pointer past the Ethernet header (14 bytes forward)
    // and hand off to the IPv4 parser.
    //
    // Think of it as: "I've read the outer envelope, now let me open
    // the next one that's inside."
    return parseIPv4(data + ETHERNET_HEADER_SIZE, length - ETHERNET_HEADER_SIZE,
                     result);
  }

  // If it's not IPv4 (could be IPv6, ARP, etc.), we don't parse further.
  // We still return true because the Ethernet layer itself was valid.
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// PRIVATE: parseIPv4() — Layer 3
// ─────────────────────────────────────────────────────────────────────────────
/*
 * At this point, 'data' points to where the IP header starts
 * (right after the 14-byte Ethernet header).
 *
 * What we do:
 *   1. Check minimum size (20 bytes for IPv4)
 *   2. Read the IHL field to get the ACTUAL header size (could be > 20 if
 * options present)
 *   3. Extract source and destination IP addresses
 *   4. Read the 'protocol' field to know what's inside (TCP=6, UDP=17)
 *   5. Advance pointer by IP header size, call parseTCP() or parseUDP()
 *
 * INTERVIEW CONCEPT — "Why is IP header length variable?"
 * The IPv4 header CAN contain optional fields (like Record Route, Timestamp).
 * The IHL field tells us the actual size: IHL × 4 bytes.
 *   - IHL = 5 → 20 bytes (no options, most common)
 *   - IHL = 6 → 24 bytes (one 4-byte option)
 *   - IHL = 15 → 60 bytes (maximum)
 * We MUST read IHL to know where the next layer starts!
 */
bool PacketParser::parseIPv4(const uint8_t *data, uint32_t length,
                             ParsedPacket &result) {

  // Minimum IPv4 header = 20 bytes
  if (length < 20) {
    return false;
  }

  // ── Step 1: Overlay our struct ──
  const IPv4Header *ip = reinterpret_cast<const IPv4Header *>(data);

  // ── Step 2: Calculate actual header size from IHL ──
  // IHL is in 4-byte units, so multiply by 4 to get bytes.
  //
  //   Example: IHL = 5  →  5 × 4 = 20 bytes (standard, no options)
  //            IHL = 7  →  7 × 4 = 28 bytes (has 8 bytes of options)
  //
  uint32_t ip_header_size = ip->ihl * 4;

  // Sanity checks:
  //   - IHL must be at least 5 (20 bytes minimum for valid IPv4)
  //   - The calculated size must not exceed the remaining data
  if (ip_header_size < 20 || ip_header_size > length) {
    return false;
  }

  // ── Step 3: Extract IP addresses ──
  // ip->src_ip and ip->dest_ip are already in network byte order.
  // ip_to_string() handles the conversion to "dotted decimal" format.
  result.src_ip = ip_to_string(ip->src_ip);
  result.dest_ip = ip_to_string(ip->dest_ip);

  // ── Step 4: Store the protocol number ──
  result.ip_protocol = ip->protocol;
  result.transport_proto = protocol_to_string(ip->protocol);

  // ── Step 5: Calculate where the transport layer (TCP/UDP) starts ──
  // The transport header begins right after the IP header.
  const uint8_t *transport_data = data + ip_header_size;
  uint32_t transport_length = length - ip_header_size;

  // ── Step 6: Hand off to the correct transport parser ──
  switch (ip->protocol) {
  case IP_PROTO_TCP:
    return parseTCP(transport_data, transport_length, result);

  case IP_PROTO_UDP:
    return parseUDP(transport_data, transport_length, result);

  default:
    // Protocol we don't handle (e.g., ICMP, IGMP).
    // Still a valid packet, we just stop parsing here.
    return true;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PRIVATE: parseTCP() — Layer 4 (TCP)
// ─────────────────────────────────────────────────────────────────────────────
/*
 * 'data' now points to the start of the TCP header.
 *
 * What we do:
 *   1. Check minimum size (20 bytes for TCP)
 *   2. Extract source and destination port numbers
 *   3. Read data_offset to find where the payload starts
 *   4. Set the payload pointer and length in ParsedPacket
 *
 * INTERVIEW CONCEPT — "data_offset (TCP header length)":
 * Just like IP's IHL, TCP's data_offset tells us the header size in 4-byte
 * units.
 *   - Minimum: 5 → 20 bytes
 *   - Maximum: 15 → 60 bytes (if TCP options like MSS, Window Scale are
 * present)
 *
 * The PAYLOAD (actual application data — HTTP, TLS, etc.) starts AFTER the
 * TCP header. This is what our application-layer parsers (Steps 3-5) will read.
 *
 * INTERVIEW Q: "How do you find the HTTP data inside a TCP packet?"
 * A: Skip Ethernet header (14B) + IP header (IHL×4) + TCP header
 * (data_offset×4). Whatever remains is the payload — that's where HTTP/TLS data
 * lives.
 */
bool PacketParser::parseTCP(const uint8_t *data, uint32_t length,
                            ParsedPacket &result) {

  // Minimum TCP header = 20 bytes
  if (length < 20) {
    return false;
  }

  // ── Step 1: Overlay our struct ──
  const TCPHeader *tcp = reinterpret_cast<const TCPHeader *>(data);

  // ── Step 2: Extract port numbers ──
  // Ports are 2 bytes each, stored in network byte order.
  // ntohs() converts them to host byte order so we can read them normally.
  //
  //   Example: Port 443 on the wire = bytes [01, BB]
  //            ntohs(0x01BB) = 443
  result.src_port = ntohs(tcp->src_port);
  result.dest_port = ntohs(tcp->dest_port);

  // ── Step 3: Calculate TCP header size ──
  // data_offset is in 4-byte units (just like IP's IHL).
  uint32_t tcp_header_size = tcp->data_offset * 4;

  if (tcp_header_size < 20 || tcp_header_size > length) {
    return false;
  }

  // ── Step 4: Locate the payload ──
  // Everything after the TCP header is application-layer data.
  // This is what HTTP, TLS, DNS-over-TCP, etc. parsers will read.
  result.payload = data + tcp_header_size;
  result.payload_length = length - tcp_header_size;

  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// PRIVATE: parseUDP() — Layer 4 (UDP)
// ─────────────────────────────────────────────────────────────────────────────
/*
 * UDP is much simpler than TCP — fixed 8-byte header, no connection state.
 *
 * What we do:
 *   1. Check minimum size (8 bytes)
 *   2. Extract source and destination ports
 *   3. Set payload pointer (right after the 8-byte header)
 *
 * INTERVIEW Q: "Why is UDP simpler than TCP?"
 * A: UDP has no connection setup (no handshake), no ordering guarantees,
 *    no retransmission. The header is fixed at 8 bytes (vs TCP's 20-60).
 *    This makes it faster but unreliable — perfect for DNS, streaming, gaming.
 */
bool PacketParser::parseUDP(const uint8_t *data, uint32_t length,
                            ParsedPacket &result) {

  // UDP header is always exactly 8 bytes
  if (length < UDP_HEADER_SIZE) {
    return false;
  }

  // ── Step 1: Overlay our struct ──
  const UDPHeader *udp = reinterpret_cast<const UDPHeader *>(data);

  // ── Step 2: Extract port numbers ──
  result.src_port = ntohs(udp->src_port);
  result.dest_port = ntohs(udp->dest_port);

  // ── Step 3: Locate the payload ──
  // UDP payload starts right after the 8-byte header.
  // For DNS packets (port 53), this payload will contain the DNS query.
  result.payload = data + UDP_HEADER_SIZE;
  result.payload_length = length - UDP_HEADER_SIZE;

  return true;
}
