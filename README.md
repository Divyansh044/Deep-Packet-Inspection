# Deep Packet Inspection (DPI) Engine

> A Layer 2 → Layer 7 network traffic analyzer built from scratch in C++. It intercepts raw packets off the wire, dissects every header by hand, and surfaces human-readable intelligence: which sites you visited, which app generated the traffic, and whether any connection matches a blocklist.

---

## What Is This Project?

Most firewalls operate at Layer 3/4 — they block IP addresses and ports. A **Deep Packet Inspection (DPI) engine** goes further: it reads inside the packet all the way to the application layer to understand *what* is being communicated, even for encrypted traffic.

This engine does exactly that. Even though HTTPS traffic is fully encrypted, the very first packet of every HTTPS connection (the **TLS ClientHello**) contains the destination domain in plain text as the **Server Name Indication (SNI)**. Our engine reads this, classifies the traffic (YouTube, GitHub, Microsoft, etc.), logs it, and checks it against a blocklist — all in real time.

---

## How It Works — The Pipeline

Every single packet your computer sends or receives travels through this pipeline:

```
  NIC (Network Card)
       |
       v
  [Npcap / libpcap]          <-- Raw bytes captured from the wire
       |
       v
  PacketParser               <-- Strips Ethernet (14B) → IP (20B+) → TCP/UDP (20B+)
       |                         using zero-copy struct overlays
       v
  Application Parsers        <-- Reads the payload:
  ├── DnsParser              |     Port 53 → extracts domain query label encoding
  ├── HttpParser             |     Port 80 → reads "Host:" HTTP header
  └── TlsParser              |     Port 443 → skips cipher suites to find SNI field
       |
       v
  PolicyEngine               <-- Checks destination domain/IP against blocked lists
       |                         using O(1) hash set lookups + wildcard matching
       v
  Logger                     <-- Writes [TRAFFIC] lines to security_alerts.log,
                                 fires [ALERT] on blocklist match,
                                 accumulates statistics for final dashboard
```

---

## Sample Output

### Live Console (during capture)

```
[INFO] Initializing Deep Packet Inspection Engine...
[INFO] Loading blocklists into fast memory...
[OK] Loaded 4 forbidden domains.
[OK] Loaded 3 forbidden IP addresses.
[OK] Logging traffic to: ../security_alerts.log
[INFO] Setting up Packet Capture layer (libpcap/Npcap)...
[INFO] Attempting to listen to live interface: Qualcomm Atheros QCA9377 Wireless Network Adapter
[INFO] Capture source opened successfully. Starting capture loop...
```

When a blocked domain is hit, a real-time alert fires in red:

```
██████████████████ SECURITY ALERT ██████████████████
Type   : Blocked Domain
Match  : youtube.com
Reason : Connection attempt to a known malicious domain.
Packet : 192.168.0.15:62022 -> 142.250.x.x:443 [TCP/TLS] - SNI: www.youtube.com
████████████████████████████████████████████████████
```

### End-of-Session Dashboard (on Ctrl+C)

```
+==============================================================+
|                  DPI ENGINE SESSION REPORT                   |
+==============================================================+
| Total Packets: 2897                                          |
| Total Bytes: 1049136 bytes                                   |
| TCP Packets: 767                                             |
| UDP Packets: 0                                               |
+==============================================================+
| Forwarded: 2897                                              |
| Alerts Triggered: 0 (clean traffic)                          |
+==============================================================+
| APPLICATION BREAKDOWN                                        |
+==============================================================+
| Unknown            2545  87.8% #################             |
| HTTPS               277   9.6% #                             |
| DNS                  44   1.5%                               |
| Google               17   0.6%                               |
| YouTube              10   0.3%                               |
| GitHub                3   0.1%                               |
| Microsoft             1   0.0%                               |
+==============================================================+
| DETECTED DOMAINS / SNIs                                      |
+==============================================================+
|  antigravity-unleash.goog -> HTTPS                           |
|  collector.github.com -> GitHub                              |
|  fonts.gstatic.com -> Google                                 |
|  github.com -> GitHub                                        |
|  googleads.g.doubleclick.net -> HTTPS                        |
|  i.ytimg.com -> YouTube                                      |
|  v20.events.data.microsoft.com -> Microsoft                  |
|  www.coursera.org -> HTTPS                                   |
|  www.google.co.in -> HTTPS                                   |
|  www.google.com -> Google                                    |
|  www.youtube.com -> YouTube                                  |
+==============================================================+
```

### Traffic Log File (`security_alerts.log`)

Every packet is recorded with source IP, destination IP, protocol, and application-level details:

```
[TRAFFIC] 192.168.0.15:62022 -> 192.168.0.1:53 [TCP/DNS] - Query: www.youtube.com
[TRAFFIC] 192.168.0.15:61912 -> 20.207.73.82:443 [TCP/TLS] - SNI: github.com
[TRAFFIC] 192.168.0.15:57695 -> 52.140.118.28:443 [TCP/TLS] - SNI: settings-win.data.microsoft.com
[TRAFFIC] 192.168.0.15:57863 -> 52.84.205.30:443 [TCP/TLS] - SNI: www.coursera.org
[TRAFFIC] 192.168.0.15:57970 -> 192.168.0.1:53 [TCP/DNS] - Query: fonts.gstatic.com
[ALERT]   Blocked Domain | youtube.com | Blocked by policy | 192.168.0.15:62022 -> 142.250.x.x:443 [TCP/TLS]
```

---

## Understanding the Log Output

| Line Type | Meaning |
|---|---|
| `[TRAFFIC] ... [TCP]` | An encrypted data packet within an established TLS session. |
| `[TRAFFIC] ... [TCP/TLS] - SNI: github.com` | The very first packet of an HTTPS connection. The domain is visible in plain text in the TLS handshake. |
| `[TRAFFIC] ... [TCP/DNS] - Query: www.youtube.com` | Your PC asked "what is the IP for youtube.com?" — captured before the connection even begins. |
| `[TRAFFIC] ... [TCP/HTTP] - Host: example.com` | Unencrypted HTTP request. The full destination domain is visible. |
| `[ALERT] ...` | A packet matched the blocklist. The connection attempt was flagged. |

### Why are most lines just `[TCP]`?

Each HTTPS session consists of one TLS handshake (where SNI is visible) followed by hundreds of encrypted data packets. Those data packets look identical — just raw encrypted bytes. We correctly capture the SNI from the handshake and log all subsequent packets in that session as plain `[TCP]`.

---

## 🛠️ Build Instructions

### Prerequisites
1. **C++17 Compiler** (GCC, Clang, or MSVC)
2. **CMake** (v3.10 or higher)
3. **Capture Library**:
   - **Windows:** Install the [Npcap SDK](https://npcap.com/guide/npcap-devguide.html) and update the path in `CMakeLists.txt`.
   - **Linux/macOS:** `sudo apt install libpcap-dev`

### Compiling

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

> On Windows, the binary is at `build/Debug/dpi_engine.exe`. Run PowerShell **as Administrator** for live capture.

---

## 🚀 Running the Engine

### Step 1 — Configure your blocklists

Edit the files in `config/`:

**`config/blocked_domains.txt`** — one domain per line:
```
youtube.com
malware.example.com
ads.doubleclick.net
```

**`config/blocked_ips.txt`** — one IP per line:
```
192.168.1.50
10.0.0.99
```

Wildcard subdomain matching is automatic — blocking `youtube.com` also blocks `www.youtube.com`, `music.youtube.com`, etc.

### Step 2 — Find your network interface

```bash
./build/Debug/dpi_engine.exe --list
```

### Step 3 — Run in live mode

```bash
# Windows (run as Administrator)
./build/Debug/dpi_engine.exe -i "Qualcomm Atheros QCA9377 Wireless Network Adapter"

# Linux/macOS (run as root)
sudo ./build/dpi_engine -i eth0
```

### Step 4 — Run in offline mode (PCAP file)

```bash
./build/Debug/dpi_engine.exe -f "../pcap_files/test.pcap"
```

### Optional flags

| Flag | Effect |
|---|---|
| `--list` | List all available network interfaces |
| `-i <name>` | Live capture from named interface |
| `-f <file>` | Analyze a saved `.pcap` file |
| `--debug` | Print every parsed packet to the console |

### Step 5 — Check the output

| Output | Location |
|---|---|
| Real-time alerts | Console (colored) |
| All traffic history | `security_alerts.log` in the project root |
| Session statistics | Printed when you press `Ctrl+C` |

---

## 📁 Project Architecture

```
Deep Packet Inspection/
├── include/
│   ├── protocols.h         # Zero-copy memory structs for Ethernet/IP/TCP/UDP headers
│   ├── packet_parser.h     # Layer 2-4 parser declarations
│   ├── dns_parser.h        # DNS query extractor
│   ├── http_parser.h       # HTTP Host header extractor
│   ├── tls_parser.h        # TLS ClientHello SNI extractor
│   ├── packet_capture.h    # libpcap/Npcap wrapper
│   ├── policy_engine.h     # Blocklist engine declarations
│   └── logger.h            # Logger and statistics dashboard
├── src/
│   ├── main.cpp            # Startup, shutdown, packet callback loop
│   ├── packet_parser.cpp   # Header-by-header packet dissection
│   ├── dns_parser.cpp      # DNS label encoding + pointer compression
│   ├── http_parser.cpp     # HTTP request line + Host header parsing
│   ├── tls_parser.cpp      # TLS record → ClientHello → extensions → SNI
│   ├── packet_capture.cpp  # libpcap open/loop/close wrapper
│   ├── policy_engine.cpp   # Hash set blocklist + wildcard matching
│   └── logger.cpp          # Colored output, file logging, session stats
├── config/
│   ├── blocked_domains.txt # One domain per line
│   └── blocked_ips.txt     # One IP per line
├── security_alerts.log     # Generated at runtime — full traffic record
└── CMakeLists.txt
```

### Component Deep Dive

#### `protocols.h` — Zero-Copy Structs
Instead of copying bytes out of a packet buffer into separate variables, we overlay C++ structs directly onto the raw memory. A `reinterpret_cast<const IPv4Header*>(data)` costs zero CPU cycles — we're just giving the compiler a lens to read the same bytes.

#### `packet_parser.cpp` — Layer 2-4 Dissection
Walks through each header in sequence:
- Reads the Ethernet type field to confirm it's IPv4
- Uses the IP header's `IHL` (Internet Header Length) field to skip variable-length options
- Uses the TCP header's `data_offset` field to find where the application payload begins

#### `tls_parser.cpp` — SNI Extraction
The TLS ClientHello contains extensions after a variable-length area of cipher suites. Our parser:
1. Identifies the TLS Record (type `0x16`) and Handshake type (`0x01` = ClientHello)
2. Skips past the protocol version, random bytes, session ID, cipher suites, and compression methods
3. Iterates through extensions until it finds extension type `0x0000` (SNI)
4. Reads the SNI hostname — the only unencrypted field revealing the HTTPS destination

#### `policy_engine.cpp` — O(1) Blocklist Matching
Uses `std::unordered_set<std::string>` for exact domain and IP matches. For wildcard matching, walks up the domain hierarchy: for `mail.evil.com`, checks `mail.evil.com` → `evil.com` → `com`.

#### `logger.cpp` — Application Classifier + Statistics
Maintains a `std::map<string, uint64_t>` counting packets per app. A domain table maps 35+ known service keywords to app names (e.g., `ytimg.com` → `YouTube`). `printSummary()` renders the final dashboard from these counters.

---

## 🔒 Security Notes

- **Detection only, not prevention**: This engine logs and alerts but does not drop packets. Real packet blocking requires kernel-level hooks (`netfilter`/`iptables` on Linux, `WFP` on Windows).
- **Requires elevated privileges**: Raw packet capture requires Administrator/root access.
- **Encrypted traffic**: Only the SNI field of TLS is visible. The actual content of HTTPS sessions is not readable.
- **DNS-over-HTTPS (DoH)**: If your OS uses DoH (e.g., through `1.1.1.1` or `8.8.8.8` over HTTPS), DNS queries will appear as plain HTTPS traffic and the domain name will only be visible via SNI.
