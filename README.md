# Deep Packet Inspection (DPI) Engine
A high-performance, Layer 2 through Layer 7 Deep Packet Inspection Engine built from scratch in C++. 

This project operates completely in user-space, leveraging the `libpcap`/`Npcap` library to intercept network traffic. It unpacks the raw binaries of Ethernet, IP, TCP, and UDP headers using zero-copy memory mapping, and dives into the application payloads to extract unencrypted DNS queries, HTTP host headers, and TLS Server Name Indications (SNI) from HTTPS handshakes. 

These extracted indicators are checked in real-time against a dynamic hash-set-based blocklist with wildcard subdomain matching algorithms, allowing the engine to instantly alert on malicious traffic.

---

## Features
- **Zero-Copy Parsing**: Overlays C++ structs directly onto raw packet buffers for ultra-fast Layer 2-4 analysis.
- **Deep Application Inspection**: 
  - Extracts HTTP Host Headers.
  - Extracts DNS UDP queries (handling pointer-based label compression).
  - Skips varied-length cryptographic cipher suites to extract TLS SNI plain-text fields from HTTPS ClientHello handshakes.
- **Dual Capture Modes**: 
  - **Live Mode**: Intercepts traffic directly from physical network interfaces (Wi-Fi, Ethernet).
  - **Offline Mode**: Replays and analyzes saved `.pcap` files for testing.
- **O(1) Policy Enforcement**: Compares domains/IPs against thousands of blocklist rules instantly using hashed unordered sets.
- **Wildcard Matching**: Dynamically resolves subdomains (e.g. blocking `*.badnets.com` blocks `api.badnets.com`).

---

## 🛠️ Build Instructions

### Prerequisites
1. **C++17 Compiler** (GCC, Clang, or MSVC)
2. **CMake** (v3.10 or higher)
3. **Capture Library**:
   - **Windows:** Install the [Npcap SDK](https://npcap.com/guide/npcap-devguide.html). (Update the path strings in `CMakeLists.txt` appropriately if installed outside of `D:/npcap-sdk-1.16`).
   - **Linux/macOS:** Install `libpcap-dev` via your package manager (`sudo apt install libpcap-dev`).

### Compiling
Navigate to the root directory of the project and execute the following commands in your terminal:
```bash
# Create a build directory
mkdir build
cd build

# Generate build files
cmake ..

# Compile the executable
cmake --build .
```
*(Note for Windows: This will generate `dpi_engine.exe` inside the `build/Debug/` folder).*

---

## 🚀 How to Run the Engine

First, populate your blocklists inside the `config/` directory. (e.g., `config/blocked_domains.txt`).

### 1. Find Your Network Interfaces
To run in live mode, you must first ask the engine what network cards it has access to.
```bash
./build/Debug/dpi_engine.exe --list
```
*Output Example:*
```text
Available network interfaces:
  [0] \Device\NPF_{A1B2...} (Wi-Fi)
  [1] \Device\NPF_{C3D4...} (Ethernet)
```

### 2. Live Capture Mode
Pass the `-i` argument followed by the exact name of the interface you wish to sniff. **You may need Administrator/Root privileges to open a live capture device.**
```bash
# Example
./build/Debug/dpi_engine.exe -i "\Device\NPF_{A1B2...}"
```

### 3. Offline PCAP Testing Mode
Pass the `-f` argument followed by a path to a `.pcap` or `.pcapng` file. The engine will ingest the file at maximum speed and print any alerts.
```bash
./build/Debug/dpi_engine.exe -f "../pcap_files/test_traffic.pcap"
```

### Advanced: Debug Output
To see *every single packet* that is successfully parsed by the application layers (not just the alerts), append `--debug` to your command.
```bash
./build/Debug/dpi_engine.exe -f "../pcap_files/test_traffic.pcap" --debug
```

---

## 📁 Project Architecture
*   `include/protocols.h` - Zero-copy memory structs matching standard OSI layer byte structures.
*   `src/packet_parser.cpp` - Steps through packet headers, applying structs and extracting addresses/ports.
*   `src/dns_parser.cpp`, `http_parser.cpp`, `tls_parser.cpp` - Application layer deep inspectors.
*   `src/packet_capture.cpp` - Object-oriented wrapper around C-style `libpcap`.
*   `src/policy_engine.cpp` - Fast hash sets and wildcard verification algorithms for blocklists.
*   `src/logger.cpp` - Formats stdout/stderr in ANSI color codes and tracks program statistics.
*   `src/main.cpp` - Handles initialization, binds the pcap callback to the global parsing state, and coordinates graceful shutdown.
