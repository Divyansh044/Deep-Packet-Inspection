/*
 * packet_capture.cpp — Packet Capture Implementation using libpcap
 * =================================================================
 *
 * This file contains the C++ wrapper around the C library "libpcap".
 *
 * INTERVIEW Q: "What is a pcap wrapper?"
 * A: It's an object-oriented class that takes messy C-style functions
 *    (like pcap_open_live, pcap_compile, pcap_loop) and makes them safe
 *    and easy to use in C++. It handles opening handles, applying filters,
 *    running the capture loop, and cleaning up memory when done.
 *
 * HOW PCAP WORKS IN 4 STEPS:
 * ──────────────────────────
 *   1. OPEN: We call pcap_open_live (for NICs) or pcap_open_offline (for
 * files). Both return the exact same object: a `pcap_t*`. This means the rest
 * of our code doesn't care if we are reading a file or watching live traffic!
 *
 *   2. FILTER: We can optionally pass a string like "tcp port 80 or udp port
 * 53". pcap_compile() turns this string into a BPF (Berkeley Packet Filter).
 *              pcap_setfilter() tells the OS kernel to drop anything that
 * doesn't match before our app even sees it. This is incredibly fast.
 *
 *   3. LOOP: We call pcap_loop(). It sits there waiting for packets forever
 *            (until the file ends or we stop it). Every time a packet arrives,
 *            it calls our static bridge function (`globalPacketHandler`), which
 *            routes it back to our C++ lambda callback.
 *
 *   4. CLOSE: When the loop breaks, we call pcap_close() to free memory and
 *             release the network card.
 */

#include "../include/packet_capture.h"

#include <iostream>

// ─────────────────────────────────────────────────────────────────────────────
// C-Style Callback Bridge
// ─────────────────────────────────────────────────────────────────────────────
// libpcap is a C library. It doesn't understand C++ objects or lambdas.
// It requires a raw C function pointer for its callback.
//
// To fix this, we create a static C function (`globalPacketHandler`).
// When we call `pcap_loop`, we pass two things:
//   1. This static function
//   2. A void pointer (`user`) that secretly holds our C++ std::function
//   callback.
//
// When pcap gets a packet, it calls `globalPacketHandler`. We cast `user` back
// to our C++ lambda and invoke it!

static void globalPacketHandler(u_char *user, const struct pcap_pkthdr *pkthdr,
                                const u_char *packet) {

  // Cast the void* 'user' parameter back into our C++ std::function pointer
  PacketHandlerCallback *callback =
      reinterpret_cast<PacketHandlerCallback *>(user);

  // Call our C++ lambda with the packet data, length, and timestamp
  if (callback && *callback) {
    (*callback)(packet, pkthdr->caplen, pkthdr->ts);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Class Implementation
// ─────────────────────────────────────────────────────────────────────────────

PacketCapture::PacketCapture() : pcap_handle_(nullptr) {
  // We intentionally leave the constructor empty.
  // Memory is allocated when the user calls openLive() or openFile().
}

PacketCapture::~PacketCapture() {
  // If the object is destroyed (e.g., program exits), clean up cleanly.
  if (pcap_handle_) {
    pcap_close(pcap_handle_);
    pcap_handle_ = nullptr;
  }
}

// ── List available network cards on this computer ──
std::vector<std::string> PacketCapture::listInterfaces() {
  std::vector<std::string> interfaces;
  pcap_if_t *alldevs;
  char errbuf[PCAP_ERRBUF_SIZE];

  // pcap_findalldevs queries the OS for a list of NICs
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    std::cerr << "Error finding devices: " << errbuf << std::endl;
    return interfaces;
  }

  // Loop through the linked list pcap gave us
  for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
    // 'name' is the system UUID on Windows (e.g., \Device\NPF_{...})
    // 'description' is the human-readable name ("Wi-Fi", "Ethernet")
    std::string name = (d->description) ? d->description : d->name;
    interfaces.push_back(name);
  }

  // We must free the list memory, or we'll have a memory leak
  pcap_freealldevs(alldevs);

  return interfaces;
}

// ── Capture live traffic from a network card ──
bool PacketCapture::openLive(const std::string &interfaceName,
                             const std::string &bpfFilter) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs;
  pcap_if_t *dev = nullptr;

  // 1. We have to map the human-readable name ("Wi-Fi") back to the system UUID
  // (\Device\NPF_...)
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    error_buffer_ = std::string("Error finding devices: ") + errbuf;
    return false;
  }

  for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
    std::string name = (d->description) ? d->description : d->name;
    if (name == interfaceName) {
      dev = d;
      break;
    }
  }

  if (!dev) {
    error_buffer_ = "Could not find interface: " + interfaceName;
    pcap_freealldevs(alldevs);
    return false;
  }

  // 2. Open the physical network card
  //   - dev->name: the UUID
  //   - 65535: snaplen (capture the whole packet, not just headers)
  //   - 1: promiscuous mode (capture ALL traffic on the network, not just
  //   traffic meant for us)
  //   - 1000: read timeout in milliseconds
  pcap_handle_ = pcap_open_live(dev->name, 65535, 1, 1000, errbuf);

  pcap_freealldevs(alldevs); // Done with the list

  if (!pcap_handle_) {
    error_buffer_ = std::string("Could not open device: ") + errbuf;
    return false;
  }

  // 3. Apply the BPF Filter (Optional)
  if (!bpfFilter.empty()) {
    struct bpf_program fp;
    // Compile the string ("tcp port 80") into a binary filter
    if (pcap_compile(pcap_handle_, &fp, bpfFilter.c_str(), 0,
                     PCAP_NETMASK_UNKNOWN) == -1) {
      error_buffer_ =
          std::string("Could not parse filter: ") + pcap_geterr(pcap_handle_);
      return false;
    }
    // Tell the OS kernel to apply the filter
    if (pcap_setfilter(pcap_handle_, &fp) == -1) {
      error_buffer_ =
          std::string("Could not install filter: ") + pcap_geterr(pcap_handle_);
      return false;
    }
    pcap_freecode(&fp);
  }

  return true;
}

// ── Open a saved .pcap file for replay ──
bool PacketCapture::openFile(const std::string &pcapFilePath,
                             const std::string &bpfFilter) {
  char errbuf[PCAP_ERRBUF_SIZE];

  // 1. Open the file. Returns the exact same `pcap_t*` as openLive!
  pcap_handle_ = pcap_open_offline(pcapFilePath.c_str(), errbuf);

  if (!pcap_handle_) {
    error_buffer_ = std::string("Could not open PCAP file '") + pcapFilePath +
                    "': " + errbuf;
    return false;
  }

  // 2. Apply the BPF Filter (Optional) — same as live!
  if (!bpfFilter.empty()) {
    struct bpf_program fp;
    if (pcap_compile(pcap_handle_, &fp, bpfFilter.c_str(), 0,
                     PCAP_NETMASK_UNKNOWN) == -1) {
      error_buffer_ =
          std::string("Could not parse filter: ") + pcap_geterr(pcap_handle_);
      return false;
    }
    if (pcap_setfilter(pcap_handle_, &fp) == -1) {
      error_buffer_ =
          std::string("Could not install filter: ") + pcap_geterr(pcap_handle_);
      return false;
    }
    pcap_freecode(&fp);
  }

  return true;
}

// ── Run the capture loop ──
bool PacketCapture::startCapture(PacketHandlerCallback callback) {
  if (!pcap_handle_) {
    error_buffer_ = "Cannot start capture: Handle is null (Did you call "
                    "openLive/openFile?)";
    return false;
  }

  // pcap_loop waits for packets forever.
  //   -1    : run infinitely (until error, stopCapture() is called, or EOF for
  //   files) user  : we pass a pointer to our C++ lambda so the bridge function
  //   can use it
  pcap_loop(pcap_handle_, -1, globalPacketHandler,
            reinterpret_cast<u_char *>(&callback));

  return true;
}

// ── Stop the capture loop gracefully ──
void PacketCapture::stopCapture() {
  if (pcap_handle_) {
    // Tells pcap_loop to return after the current packet finishes
    pcap_breakloop(pcap_handle_);
  }
}
