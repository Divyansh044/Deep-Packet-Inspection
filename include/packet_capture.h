/*
 * packet_capture.h — Packet Capture Interface (Live & File)
 * ==========================================================
 *
 * WHY THIS FILE EXISTS:
 * ---------------------
 * We have built parsers that know how to process raw bytes. But how do
 * we GET those raw bytes in the first place?
 *
 * The industry-standard way to capture network traffic in C/C++ is a library
 * called "libpcap" (or "Npcap" / "WinPcap" on Windows). Wireshark uses it.
 *
 * This class wraps libpcap to provide two core features:
 *   1. LIVE CAPTURE: Hooking into a network card to sniff traffic right now.
 *   2. FILE REPLAY: Opening a saved .pcap file and feeding the packets
 *      to our engine as if they were live.
 *
 * WHY FILE REPLAY IS AWESOME:
 * ───────────────────────────
 * As the developer, you pointed out a great truth: testing with files is
 * much better than live capture! Live capture is unpredictable. File replay
 * gives us reproducible, perfect tests every time. If a packet crashes our
 * engine, we can replay that exact file 100 times until we fix the bug.
 */

#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <functional>
#include <string>
#include <vector>

// Include the pcap library
// On Windows, you need the Npcap SDK installed and linked.
#include <pcap.h>

// ─────────────────────────────────────────────────────────────────────────────
// Type alias for our callback function
// ─────────────────────────────────────────────────────────────────────────────
// When we start capturing, pcap runs in a loop. For every packet it finds,
// it will "call back" to our code.
//
// Our callback needs three things:
//   1. The raw packet bytes (const uint8_t*)
//   2. The total length of the packet (uint32_t)
//   3. The time it was captured (const struct timeval&) - useful for PCAPs
using PacketHandlerCallback = std::function<void(
    const uint8_t *data, uint32_t length, const struct timeval &ts)>;

class PacketCapture {
public:
  PacketCapture();
  ~PacketCapture();

  /*
   * listInterfaces() — Find all network cards on this computer.
   * Returns a list of friendly names (e.g., "Wi-Fi", "Ethernet 2").
   */
  static std::vector<std::string> listInterfaces();

  /*
   * openLive() — Connect to a physical network card.
   *   interfaceName: The name from listInterfaces()
   *   bpfFilter:     Optional filter like "tcp port 80" or "udp port 53"
   *                  (BPF = Berkeley Packet Filter. It lets the OS drop
   *                  packets we don't care about before they reach our app,
   *                  which is incredibly fast).
   */
  bool openLive(const std::string &interfaceName,
                const std::string &bpfFilter = "");

  /*
   * openFile() — Open a saved .pcap file for replay testing.
   *   pcapFilePath: Path to the .pcap file
   *   bpfFilter:    Optional BPF filter (same as live)
   */
  bool openFile(const std::string &pcapFilePath,
                const std::string &bpfFilter = "");

  /*
   * startCapture() — Begin pulling packets and feeding them to the callback.
   * This function blocks (runs in a loop) until we stop it or the file ends.
   */
  bool startCapture(PacketHandlerCallback callback);

  /*
   * stopCapture() — Break out of the capture loop safely.
   */
  void stopCapture();

private:
  pcap_t *pcap_handle_; // The underlying pcap completely hides whether
                        // it's a live card or a file from us.

  std::string error_buffer_; // Holds error messages from pcap functions
};

#endif // PACKET_CAPTURE_H
