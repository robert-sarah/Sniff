# 📡 SNIFF — Network Activity Monitor

A beautiful CLI network traffic analyzer built with **Python + Rich + Scapy**.  
Detect device activity on your network: VoIP calls, streaming, browsing, and more.

> ⚠️ **For authorized network monitoring only.** Only use on networks you own or have explicit permission to monitor.  
> This tool does **NOT** capture or display any conversation content — only metadata and activity classification.

---

## ✨ Features

- 🔍 **Interface Management** — List wireless interfaces, enable/disable monitor mode (`airmon-ng`)
- 📡 **Network Scanner** — Discover nearby WiFi networks and connected devices (`airodump-ng`)
- 📊 **Live Traffic Monitor** — Real-time dashboard showing per-device network activity
- 📞 **VoIP Detection** — Detect if devices are on phone calls (WhatsApp, Telegram, Discord, Zoom, Teams, etc.)
- 🎬 **Traffic Classification** — Identify streaming, web browsing, DNS, email, SSH traffic
- 🎨 **Beautiful UI** — Rich terminal interface with live-updating tables

---

## 📦 Requirements

- **Python 3.10+**
- **aircrack-ng** suite installed (`airmon-ng`, `airodump-ng`)
- **Root/sudo** privileges (required for packet capture)
- **Linux** with a WiFi adapter that supports monitor mode

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

```bash
sudo python sniff.py
```

### Commands

| Command | Description |
|---|---|
| `interfaces` | List available wireless interfaces |
| `monitor start <iface>` | Enable monitor mode |
| `monitor stop <iface>` | Disable monitor mode |
| `scan <iface> [duration]` | Scan for nearby networks & devices |
| `scan <iface> -b <bssid> -c <ch>` | Targeted scan on a specific AP |
| `sniff <iface> [duration]` | Start live traffic monitoring |
| `sniff <iface> -m <mac>` | Monitor a specific device |
| `status` | Show current monitor mode status |
| `help` | Show help menu |
| `clear` | Clear screen |
| `exit` | Quit |

### Examples

```bash
# List interfaces
sniff ❯ interfaces

# Start monitor mode
sniff ❯ monitor start wlan0

# Scan networks for 20 seconds
sniff [wlan0mon] ❯ scan wlan0mon 20

# Start live monitoring (Ctrl+C to stop)
sniff [wlan0mon] ❯ sniff wlan0mon

# Monitor a specific device
sniff [wlan0mon] ❯ sniff wlan0mon -m AA:BB:CC:DD:EE:FF

# Monitor for 60 seconds
sniff [wlan0mon] ❯ sniff wlan0mon -m AA:BB:CC:DD:EE:FF 60

# Stop monitor mode and exit
sniff [wlan0mon] ❯ monitor stop wlan0mon
sniff ❯ exit
```

---

## 📊 What It Detects

| Icon | Activity | How It's Detected |
|---|---|---|
| 📞 | VoIP / Phone Call | SIP/RTP ports, UDP packet patterns, app-specific ports |
| 🎬 | Streaming | RTMP, RTSP ports |
| 🌐 | Web / HTTPS | HTTP/HTTPS ports (80, 443) |
| 🔍 | DNS | DNS queries (port 53) |
| 📧 | Email | SMTP, IMAP, POP3 ports |
| 🔒 | SSH | Port 22 |
| 📶 | Other | Unclassified traffic |

### VoIP App Detection

| App | Detection Method |
|---|---|
| WhatsApp | STUN/TURN ports 3478-3497 |
| Telegram | Ports 1000-1099 |
| Discord | Ports 50000-50099 |
| Zoom | Ports 8801, 8802, 8443 |
| Teams | STUN ports 3478-3481 |
| FaceTime | RTP range 16384-16483 |
| Signal | Ports 3478, 10000 |
| Viber | Ports 5242-5243, 7985-7987 |
| Skype | STUN ports 3478-3481 |

---

## ⚖️ Legal

This tool is intended for **legitimate network administration** and **security research** on networks you own or have authorization to monitor. Unauthorized network monitoring may violate local laws.
