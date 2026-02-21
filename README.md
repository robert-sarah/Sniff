# 📡 SNIFF — Advanced Network Audit & WiFi Tactics Pro

**SNIFF** is a high-performance, professional-grade network security auditing tool. It combines passive traffic analysis, active network mapping, and advanced WiFi tactical operations into a single, streamlined interface.

Developed for security researchers and authorized auditors, SNIFF provides deep visibility into network activity without capturing private content, while offering powerful tools to test network resilience.

---

## 🚀 Key Features

### 1. 📡 Passive Traffic Audit
*   **Real-time Dashboard:** Monitor device activity, OS fingerprinting (via TTL), and throughput (kbps).
*   **App Detection:** Heuristic detection of VoIP calls (WhatsApp, Telegram, Teams), Streaming (Netflix, YouTube), and Messaging.
*   **Credential Sniffing:** Factual detection of cleartext credentials in HTTP POST packets during MITM tests.
*   **PCAP Logging:** Save full or filtered (VoIP only) traffic for Wireshark analysis.

### 2. ☢️ Active Network Mapping (MITM)
*   **ARP Scanner:** High-speed discovery of active hosts and gateway identification.
*   **ARP Spoofing:** Conduct security audits by redirecting flow through your machine (Man-in-the-Middle).
*   **Port Scanner:** Multi-threaded service discovery to identify open ports (SSH, FTP, Web, Database).

### 3. 💥 WiFi Tactical Operations
*   **Karma Attack:** Automagically impersonate any network nearby devices are searching for.
*   **Evil Twin:** Deploy a rogue Access Point with an integrated **Captive Portal**, **Fake DNS**, and **DHCP Server**.
*   **Deauthentication:** Targeted or broadcast disconnection of clients from their original AP.
*   **Beacon Flooding:** Generate dozens of fake SSIDs to test scanner resilience and area confusion.
*   **WPS Audit:** Identify nearby networks with vulnerable WPS configurations.

### 4. 🗝️ Cryptographic Audit
*   **WPA/WPA2 Cracker:** Factual, non-simulated handshake auditing. Implements real PMK derivation and MIC (Message Integrity Check) verification against wordlists.

---

## 🛠️ Usage Guide

### Installation
```bash
pip install -r requirements.txt
# Ensure airmon-ng suite is installed (kali-linux-default or aircrack-ng)
```

### Command Arsenal
| Command | Description |
| :--- | :--- |
| `interfaces` | List available wireless interfaces. |
| `monitor start <iface>` | Enable monitor mode (kills interfering processes). |
| `scan <iface>` | Discover nearby Access Points and client associations. |
| `wps <iface>` | Scan specifically for WPS-enabled networks. |
| `sniff <iface>` | Start the live Traffic Audit dashboard. |
| `arp scan` | Discover all IP/MAC pairs on the local network. |
| `arp spoof <tgt> <gw>` | Start a MITM flow redirection between target and gateway. |
| `portscan <ip>` | Enumerate open services on a specific IP. |
| `karma` | Start the Karma attack (Probe Request responder). |
| `eviltwin <ssid> <mac>`| Deploy a full Rogue AP with Portal and DNS Redirection. |
| `crack <pcap> <words>` | Audit the password strength of a captured WPA handshake. |
| `deauth <mac> <ap>` | Send deauthentication frames to kick a client. |

---

## 🏗️ Architecture
SNIFF uses a **Hybrid Infrastructure**:
*   **Modular:** Individual files in `modules/` allow for clean development and customization.
*   **Standalone:** All logic is inlined into `sniff.py`, allowing you to use a single portable file for field audits.

## ⚖️ Legal Disclaimer
**FOR AUTHORIZED AUDITING ONLY.** This tool is designed for network security professionals to test their own infrastructure. Accessing networks or intercepting data without explicit permission is illegal. The developers assume no liability for misuse.

---
*Created with focus on Visual Excellence and Technical Depth.*
