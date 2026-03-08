# Deep Packet Inspection (DPI) Engine - Comprehensive Step-by-Step Guide

This document is a complete, beginner-friendly guide to everything we have built in our Deep Packet Inspection (DPI) engine up to Phase 2 (Packet Capture). It breaks down complex networking and C++ concepts into simple analogies, terminology, and real-world workflows.

---

## 1. The Big Picture: What is DPI?

**The Real-World Analogy: The Post Office vs. The Secret Agent**
*   **A Standard Firewall (The Post Office):** It looks at the outside of an envelope. It reads the Return Address (Source IP) and the Mailing Address (Destination IP). If a rule says "No mail to BadTown," the firewall throws the letter away without ever opening it.
*   **Deep Packet Inspection (The Secret Agent):** DPI doesn't just look at the envelope; it carefully cuts the envelope open, pulls out the letter, and reads it. It checks if the letter contains malicious instructions, requests for stolen data, or attempts to reach a blocked website. If it finds something bad, it intercepts the letter.

**What Our Engine Does:**
Our C++ engine intercepts raw data packets flowing over a network, peels them open layer by layer, translates the raw binary numbers into readable text (like website names), checks those names against a blocklist, and triggers an alert if the traffic is forbidden.

---

## 2. Core Concepts: The OSI Envelopes

To understand this project, you must understand how data travels on the internet. Data is wrapped in multiple "envelopes" (called headers) before being sent. 

### The Layers of a Packet
When we receive a packet, it looks like a russian nesting doll of envelopes.

1.  **Layer 2: Ethernet (The Hardware Envelope)**
    *   **What it does:** Moves data physically from one machine to the immediate next machine on the same local network (e.g., from your laptop to your home Wi-Fi router).
    *   **Key Term - MAC Address:** Every network card (Wi-Fi or Ethernet port) in the world has a 100% unique, physical ID called a MAC address (e.g., `AA:BB:CC:DD:EE:FF`). Ethernet uses this to deliver the packet locally.

2.  **Layer 3: IP (Internet Protocol) (The Global Mailing Address)**
    *   **What it does:** Moves data across the world, from your home router all the way to Google's servers.
    *   **Key Term - IP Address:** The logical internet address (e.g., `192.168.1.5` for your laptop, `142.250.190.46` for Google). It tells routers exactly where to send the packet.

3.  **Layer 4: TCP / UDP (The Delivery Method)**
    *   **What it does:** Once the packet gets to the correct computer (IP address), how does it know *which application* gets the data? It uses **Ports**.
    *   **Key Term - Port:** Like an apartment number inside a building. Web browsers use Port 80 or 443; gaming and video calls use other ports.
    *   **TCP (Transmission Control Protocol):** The reliable, tracked delivery. Like registered mail. It guarantees all data arrives strictly in order. Used for loading web pages where missing a single image breaks the site.
    *   **UDP (User Datagram Protocol):** The fast, reckless delivery. Like throwing a tennis ball. It's incredibly fast, but there are no guarantees it gets caught. Used for live video or quick lookups (like asking "What is Google's IP address?").

4.  **Layer 7: Application Data (The Actual Letter)**
    *   **What it is:** The actual content is stored inside the final envelope. Is it an HTTP web request? Is it an encrypted HTTPS connection? Is it a DNS lookup? Our engine cares most about this layer.

---

## 3. The Architecture: What We Built So Far

We have built Phase 1 (The Translators/Parsers) and start of Phase 2 (The Catcher/Packet Capture). 

### 

### Step 2: `packet_parser.cpp` (The Envelope Opener)
*   **What we did:** We wrote the function that takes a raw packet and unboxes it layer by layer.
*   **Workflow:**
    1. Look at the first 14 bytes (Ethernet). Record the MAC addresses.
    2. Move the reading pointer exactly 14 bytes forward. 
    3. Look at the next 20+ bytes (IP). Record the IP addresses. Read the `Header Length` to know how big the IP envelope is.
    4. Move the reading pointer forward. Look at the next bytes (TCP or UDP). Record the Ports. Read the TCP `Data Offset` to find where the header ends.
    5. Everything that remains is handed off to Application layer parsers (Steps 3, 4, 5).

### Step 3: `dns_parser.cpp` (The Phonebook Reader)
*   **What it is:** DNS changes names like "youtube.com" into computer IP addresses. It runs on UDP Port 53.
*   **Why it's important:** It is usually Unencrypted. Even if a user tries to visit a secured `https://` site, their computer must first ask DNS for the IP address in plain text. By intercepting DNS, we know exactly what website they want to visit.
*   **The Tricky Part - DNS Label Compression & Pointers:**
    *   DNS tries to save space on the network. Instead of sending `"www.example.com"`, it sends `[3]www[7]example[3]com[0]`. 
    *   If it wants to say `"api.example.com"` later in the same packet, it sends `[3]api` followed by a **Pointer** that says "Jump back up to byte #25 and read the rest from there." Our code has to follow these jumps without getting trapped in an infinite loop!

### Step 4: `http_parser.cpp` (The Web Request Scanner)
*   **What it is:** Parses plain text, unencrypted website traffic (HTTP, Port 80).
*   **Workflow:** We take the raw payload, turn it into a regular string, and search for the `Host:` label (e.g., `Host: www.malware.com`). 
*   **Key Concept - Virtual Hosting:** A single computer server might host 1,000 different websites on the *same IP Address*. The `Host:` header is the only way a server knows which specific website the user requested. We extract this to see if the domain is blocked.

### Step 5: `tls_parser.cpp` (The HTTPS Encryption Loophole)
*   **What it is:** Over 95% of traffic today uses HTTPS (TLS Encryption). Traditional firewalls are blinded by it. 
*   **The Loophole - SNI (Server Name Indication):** Before encryption starts, the client (your browser) and the server must do a handshake to set up the secret keys. During this unencrypted handshake, the browser sends a **ClientHello** message saying, "Hi, I want to talk to netflix.com, please give me your certificate."
*   **What we do:** Our parser dives extremely deep into this binary ClientHello message, skips past random numbers, cipher lists, and session names (each is a variable size, forcing us to carefully measure and skip them), until it finds the **SNI Extension** and extracts the domain name in plain text!

### Step 6: `packet_capture.cpp` (The Packet Snatcher)
*   **What it is:** Up until now, we taught our engine *how* to read packets, but it couldn't actually *get* them. Step 6 uses an industry-standard library called `libpcap` (or `Npcap` on Windows—the same engine Wireshark uses) to grab packets out of thin air.
*   **The Power - Unified Data Flow:** Our wrapper hides the ugly C-level code and provides two simple options: `openLive()` and `openFile()`. From the rest of our C++ engine's perspective, reading a saved `.pcap` testing file is entirely identical to intercepting live Wi-Fi traffic.
*   **Key Concept - Promiscuous Mode:** Normally, your Wi-Fi card ignores all invisible internet traffic that is floating through the air unless it is explicitly addressed to your computer. When we turn on "Promiscuous Mode," we tell the Wi-Fi card: "Listen to everyone's conversation in the entire room, even if they aren't talking to you." 
*   **Key Concept - BPF Filters:** If we captured every single packet on a busy network, our app might freeze from the overload. We compile rules called BPFs (Berkeley Packet Filters) like `"tcp port 80 or udp port 53"`. These rules are handed directly to the computer's Operating System Kernel (the deepest level of the computer). The Kernel acts like a bouncer at a club—it drops packets that don't match the rule instantly, meaning our C++ application only ever sees the traffic it actually cares about.
*   **Key Concept - C-to-C++ Callback Bridge:** `libpcap` is written in pure C, and C doesn't understand modern C++ classes. The packet capture runs in an infinite loop, and whenever it catches a packet, it has to safely hand it back to our modern C++ engine using a clever pointer casting trick (our `globalPacketHandler` bridge).

---

## 4. Phase 2 Completion: The Brain and the Mouth

With our system possessing **Eyes** (Parsers) and **Hands** (Packet Capture), we finally gave it a **Brain** (The Policy Engine) and a **Mouth** (The Logger).

### Step 7: `policy_engine.cpp` (The Brain)
*   **What it is:** The logic center that decides if a packet is safe or dangerous.
*   **Workflow:** At startup, it reads `blocked_domains.txt` and `blocked_ips.txt`. Every time the parser finishes dissecting a packet, it hands the results (IPs, HTTP Hosts, TLS SNIs, DNS Queries) to the Policy Engine.
*   **Key Concept - O(1) Hash Sets:** If we have 10,000 blocked domains, checking a standard list takes too long (O(N) time). We load our rules into C++ `unordered_set` structures. Because they use mathematical hashing, checking if a domain is blocked takes the exact same microscopic amount of time whether we have 10 rules or 10 million rules (O(1) time).
*   **Key Concept - Wildcard Matching:** We implemented an algorithm to catch subdomains. If `*.ads.com` is on the blocklist, the engine dynamically chops up incoming requests (e.g., `api.europe.ads.com` -> `europe.ads.com` -> `ads.com`) and tests for wildcard matches at every level.

### Step 8: `logger.cpp` & `main.cpp` (The Mouth and The Assembly Line)
*   **`logger.cpp`**: Instead of messy `cout` statements everywhere, all output routes through the Logger. It uses ANSI escape codes to paint the terminal Red for security alerts or Green for successes. It also keeps counting metrics (total packets scanned vs. alerts triggered) in the background.
*   **`main.cpp` (The Assembly Line)**: The central Nervous System. 
    1. It boots up, parses user command-line arguments (`-i` for live, `-f` for offline).
    2. Initializes the Parsers, Policy Engine, and Logger.
    3. Starts the Packet Capture loop.
    4. Provides the **Callback Function**: A C-to-C++ bridge. Every time a packet arrives, `main.cpp` orchestrates the workflow: Send to Parser -> Send to Policy Engine -> If bad, Send to Logger.
    5. **Graceful Shutdown**: It catches OS-level interruption signals (`Ctrl+C`). Instead of crashing instantly, it tells the capture loop to stop, calculates the final statistics from the Logger, prints a neat summary to the screen, and exits safely.
