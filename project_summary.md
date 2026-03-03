# Deep Packet Inspection (DPI) Engine - Beginner's Guide & Project Summary

This document explains everything we have built in Phase 1 of the DPI Engine project. It is written for someone with zero prior knowledge of networking or C++.

---

## 1. What is Deep Packet Inspection (DPI)?

**The Real-World Analogy: The Post Office**
Imagine a regular post office (a normal firewall). It looks at the outside of an envelope: it sees who sent the letter (Return Address) and who is receiving it (Mailing Address). If the post office has a rule saying "No mail to BadTown," it throws the letter away. That's traditional packet filtering.

Deep Packet Inspection (DPI) is like a **security guard who opens the envelope and reads the letter inside**. Instead of just looking at the addresses, the guard checks if the letter contains a secret code, illegal instructions, or requests to a forbidden website. If it does, the guard stops the letter.

**What our project does:**
Our C++ engine captures raw data packets flowing through the network, opens them up layer by layer, reads the contents (like which website the user is trying to visit), and will eventually block or alert on bad traffic.

---

## 2. The Concepts You Need to Study

To understand this project fully, you need to understand how data travels on the internet. It uses the **OSI Model / TCP/IP Layered Model**.

Data is wrapped in multiple "envelopes" (layers) before it is sent over the wire. When we receive data, we have to "peel" these layers off one by one.

### The Envelopes (The Layers)

1.  **Layer 2: Ethernet (The Outer Envelope)**
    *   **What it does:** Gets data from your computer to your home router (the next physical hop).
    *   **Key Term - MAC Address:** Every network card (Wi-Fi or Ethernet port) in the world has a 100% unique ID called a MAC address (e.g., `AA:BB:CC:DD:EE:FF`). Ethernet uses this to physically deliver the packet over the local cable or airwaves.

2.  **Layer 3: IP (Internet Protocol) (The Mailing Address)**
    *   **What it does:** Gets data across the global internet, from your router to Google's servers.
    *   **Key Term - IP Address:** The logical address on the internet (e.g., `192.168.1.5` or `142.250.190.46`). It tells routers *where* in the world the packet needs to go.

3.  **Layer 4: TCP / UDP (The Delivery Method)**
    *   **What it does:** Once the packet reaches the correct computer (IP address), how does it know *which app* (Chrome, Spotify, Skype) gets the data? It uses **Ports**.
    *   **Key Term - Port:** Like an apartment number in a building. (e.g., Port 80 = Web browsing, Port 443 = Secure web, Port 53 = DNS).
    *   **TCP (Transmission Control Protocol):** The reliable delivery method. Like sending a package with tracked, guaranteed delivery. Used for web pages (HTTP/HTTPS) because missing a piece of the code breaks the site.
    *   **UDP (User Datagram Protocol):** The fast delivery method. Like throwing a tennis ball. It's fast, but if it drops, no one cares. Used for live video calls or quick lookups (DNS).

4.  **Layer 7: Application (The Actual Letter inside)**
    *   **What it does:** The actual meaning of the data. Is it asking for a webpage (HTTP)? Is it asking for an IP address (DNS)? Is it a secure connection (TLS/HTTPS)?

**The Parsing Workflow (Peeling the Onion):**
Raw Bytes -> [Ethernet] -> [IP] -> [TCP or UDP] -> [HTTP, DNS, or TLS Payload/Data]

---

## 3. What We Have Built So Far (Phase 1: Parsers)

We built the tools to take raw, meaningless 1s and 0s and turn them into readable information.

### Step 1: `protocols.h` (The Blueprints)
*   **What it is:** Defines the exact layout of the envelopes (Ethernet, IP, TCP, UDP). We told C++ exactly how many bytes each piece of information takes. (e.g., "The first 6 bytes are the Destination MAC, the next 6 are the Source MAC," etc.).
*   **Key C++ Concept - Struct Casting:** We don't copy the raw data. We "overlay" our blueprint (struct) directly onto the raw memory. It's like putting a transparent stencil over a page of random letters to read the hidden message instantly. This makes the code extremely fast.
*   **Key Concept - Endianness (Byte Order):** Computers read memory backwards compared to networks. We use tools like `ntohs()` (Network to Host Short) to flip the numbers the right way around so our computer understands them.

### Step 2: `packet_parser.cpp` (The Onion Peeler)
*   **What it is:** The main engine that uses the blueprints from Step 1.
*   **Workflow:**
    1.  It takes raw data.
    2.  Reads the first 14 bytes as the **Ethernet** envelope.
    3.  Throws that envelope away, moves the "pointer" (our reading cursor) forward, and reads the **IP** envelope.
    4.  Throws that away, moves forward, and reads the **TCP** or **UDP** envelope.
    5.  Whatever is left over is the **Payload** (The Layer 7 actual data).

### Step 3: `dns_parser.cpp` (The Phonebook Reader)
*   **What it is:** DNA (Domain Name System) translates names like "google.com" into IP numbers. Our parser reads DNS packets to see *what websites the user is asking for*. This works on UDP Port 53.
*   **Why it's important:** It's usually sent in plain text (unencrypted). Even if the user is visiting a secure website, their initial DNS request tells us where they are going.
*   **The Tricky Part - Compression:** DNS tries to save space. If "google.com" appears twice, the second time it just says "Look at byte #12". Our code has to follow these pointers without getting stuck in an infinite loop.

### Step 4: `http_parser.cpp` (The Web Request Reader)
*   **What it is:** Reads plain-text web browsing traffic. It looks for commands like `GET /index.html`.
*   **Why it's important:** We search for the `Host:` label. This explicitly tells us which website domain the user is visiting (e.g., `Host: www.badwebsite.com`).
*   **The Tricky Part:** Because it's plain text, we have to treat the raw bytes as a String of characters and use text-search tools (like searching for the word "Host:") instead of fixed byte positions.

### Step 5: `tls_parser.cpp` (The HTTPS Loophole Exploiter)
*   **What it is:** TLS is the encryption that makes HTTPS secure (putting the padlock icon in your browser). We *cannot* read the data inside a TLS packet. It's scrambled.
*   **The Loophole - SNI (Server Name Indication):** Before the client (browser) and server agree on a secret password to scramble the data, they must have an initial "Handshake." During this Handshake, the client sends a message called the **ClientHello** in *plain text*. Inside the ClientHello is the **SNI**—the name of the website it wants to talk to (e.g., "netflix.com").
*   **The Tricky Part:** The ClientHello is a nightmare to read. It's composed of many variable-length boxes nested inside each other. Our parser has to meticulously read the length of Box A, skip over Box A, find Box B, skip it, until it finally digs down to the Extensions box where the SNI (Domain Name) lives.

---

## 4. Summary of Where We Are

We have completely built the "Eyes" of the system.
If you feed our code raw network bytes, it can accurately report:
*   "This packet is going from IP A to IP B."
*   "It is using the TCP protocol to port 443."
*   "Inside, it contains an HTTPS connection request to 'youtube.com'."

**What is Next (Phase 2 & 3):**
Now that our system has eyes, we need to give it a **Brain**.
We will build the **Packet Capture** logic (to grab live traffic off your Wi-Fi card) and the **Policy Engine** (the brain that takes the output of our parsers, checks it against a blocklist, and yells "ALERT!" if a forbidden website is seen).
