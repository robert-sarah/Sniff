"""
sniffer.py - Network Traffic Sniffer & Activity Detector
Uses scapy to sniff packets and detect traffic patterns.
Detects: VoIP calls, streaming, web browsing, DNS, etc.
Does NOT capture or display packet content — only metadata & activity type.
Can save captured packets to .pcap files for Wireshark analysis.
"""

import os
import time
import threading
from collections import defaultdict
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich.progress import SpinnerColumn, Progress

try:
    from scapy.all import sniff as scapy_sniff, IP, TCP, UDP, DNS, Dot11, conf, wrpcap, EAPOL, RadioTap
    from scapy.utils import PcapWriter
    import collections
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

console = Console()

# ─── Traffic Classification ─────────────────────────────────────────────────

# VoIP ports (SIP, RTP, etc.)
VOIP_PORTS = {
    5060, 5061,          # SIP
    3478, 3479,          # STUN/TURN
    *range(16384, 32768) # RTP range (common)
}

# Common VoIP RTP port ranges by app
VOIP_APP_PORTS = {
    "WhatsApp":  range(3478, 3498),
    "Telegram":  range(1000, 1100),
    "Discord":   range(50000, 50100),
    "Zoom":      {8801, 8802, 8443},
    "Teams":     {3478, 3479, 3480, 3481},
    "FaceTime":  range(16384, 16484),
    "Signal":    {3478, 10000},
    "Viber":     {5242, 5243, 7985, 7987},
    "Skype":     range(3478, 3482),
}

STREAMING_PORTS = {
    1935,   # RTMP
    554,    # RTSP
    8554,   # RTSP alt
}

WEB_PORTS = {80, 443, 8080, 8443}

MAIL_PORTS = {25, 465, 587, 993, 995, 143, 110}

DNS_PORTS = {53, 5353}

SSH_PORTS = {22}

# Messaging Detection (Heuristic)
# Small TCP bursts to common SSL ports are often messages
MESSAGING_THRESHOLD = 3   # Packets in a burst
MESSAGING_WINDOW = 2      # Seconds


class DeviceTracker:
    """Track per-device network activity."""

    def __init__(self):
        self.devices: dict[str, dict] = {}
        self.lock = threading.Lock()

    def update(self, mac: str, ip: str, activity: str, bytes_count: int = 0, rssi: int = -100, is_handshake: bool = False, dst_ip: str | None = None):
        with self.lock:
            now = datetime.now()
            if mac not in self.devices:
                self.devices[mac] = {
                    "ip": ip,
                    "first_seen": now,
                    "last_seen": now,
                    "activities": defaultdict(int),
                    "total_packets": 0,
                    "total_bytes": 0,
                    "is_calling": False,
                    "is_messaging": False,
                    "voip_packets": 0,
                    "msg_packets": 0,
                    "voip_app": None,
                    "last_msg_time": 0,
                    "rssi": rssi,
                    "handshakes": 0,
                    "destinations": set(),
                    "activity_history": collections.deque([0] * 20, maxlen=20),
                    "current_period_pkts": 0,
                    "last_tick": time.time(),
                }
            dev = self.devices[mac]
            dev["ip"] = ip
            dev["last_seen"] = now
            dev["activities"][activity] += 1
            dev["total_packets"] += 1
            dev["total_bytes"] += bytes_count

            # Update RSSI (keep strongest signal for accuracy)
            if rssi != -100:
                dev["rssi"] = max(dev["rssi"], rssi) if dev["rssi"] != -100 else rssi
                
            # Update Handshakes
            if is_handshake:
                dev["handshakes"] += 1
                
            # Update Destinations
            if dst_ip and dst_ip != "255.255.255.255" and not dst_ip.startswith("224."):
                dev["destinations"].add(dst_ip)

            # Update Timeline Logic (1 second bins)
            curr_time = time.time()
            dev["current_period_pkts"] += 1
            if curr_time - dev["last_tick"] >= 1.0:
                dev["activity_history"].append(dev["current_period_pkts"])
                dev["current_period_pkts"] = 0
                dev["last_tick"] = curr_time

            # Update counts
            if activity == "📞 VoIP/Call":
                dev["voip_packets"] += 1
            elif activity == "💬 Message":
                dev["msg_packets"] += 1

    def get_snapshot(self) -> dict:
        with self.lock:
            return dict(self.devices)


def classify_traffic(pkt) -> tuple[str, str | None]:
    """
    Classify a packet into an activity type.
    Returns (activity_label, voip_app_or_None).
    """
    if not pkt.haslayer(IP):
        return "📶 Other", None

    sport = dport = 0
    proto = "?"

    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        proto = "TCP"
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        proto = "UDP"

    ports = {sport, dport}

    # DNS
    if ports & DNS_PORTS or pkt.haslayer(DNS):
        return "🔍 DNS", None

    # VoIP Detection (priority check)
    for app, app_ports in VOIP_APP_PORTS.items():
        app_ports_set = set(app_ports) if not isinstance(app_ports, set) else app_ports
        if ports & app_ports_set:
            return "📞 VoIP/Call", app

    if ports & VOIP_PORTS:
        return "📞 VoIP/Call", None

    # High frequency small UDP packets = likely RTP (voice)
    if proto == "UDP" and pkt.haslayer(UDP):
        payload_len = len(pkt[UDP].payload) if pkt[UDP].payload else 0
        if 50 < payload_len < 300:
            # Typical RTP voice packet size
            if sport > 10000 and dport > 10000:
                return "📞 VoIP/Call", None

    # Streaming
    if ports & STREAMING_PORTS:
        return "🎬 Streaming", None

    # Web / HTTPS / Messaging detection
    if ports & WEB_PORTS:
        # Heuristic: Small packets on TCP 443 might be signaling/messaging
        if pkt.haslayer(TCP):
            payload_len = len(pkt[TCP].payload) if pkt[TCP].payload else 0
            if 0 < payload_len < 500:
                return "💬 Message", None
        return "🌐 Web/HTTPS", None

    # Email
    if ports & MAIL_PORTS:
        return "📧 Email", None

    # SSH
    if ports & SSH_PORTS:
        return "🔒 SSH", None

    return "📶 Other", None


def _get_mac(pkt) -> str | None:
    """Try to extract source MAC address from packet."""
    if hasattr(pkt, "src") and ":" in str(pkt.src):
        return str(pkt.src).upper()
    if pkt.haslayer("Ether"):
        return str(pkt["Ether"].src).upper()
    return None


def _build_dashboard(
    tracker: DeviceTracker,
    interface: str,
    start_time: float,
    pcap_info: dict | None = None,
) -> Table:
    """Build the live dashboard table."""
    elapsed = int(time.time() - start_time)
    mins, secs = divmod(elapsed, 60)

    snapshot = tracker.get_snapshot()

    # Recording indicator
    rec_str = ""
    if pcap_info:
        rec_str = f"  │  [bold red]● REC[/] [dim]{pcap_info['filename']}[/]  ({pcap_info['count']} pkts)"

    # Main device table
    table = Table(
        title=f"📡 SNIFF — Live Network Monitor  │  [cyan]{interface}[/]  │  ⏱ {mins:02d}:{secs:02d}{rec_str}",
        title_style="bold white",
        border_style="bright_blue",
        header_style="bold white on #1a1a2e",
        row_styles=["on #16213e", "on #0f3460"],
        padding=(0, 1),
        expand=True,
    )
    table.add_column("  MAC Address", style="cyan", width=18)
    table.add_column("PWR", justify="center", width=5)
    table.add_column("Handshake", justify="center", style="bold yellow", width=10)
    table.add_column("Appels", justify="right", style="bold green", width=8)
    table.add_column("Messages", justify="right", style="bold blue", width=9)
    table.add_column("Timeline", justify="center", width=12)
    table.add_column("Destinations", style="dim", width=15)
    table.add_column("Packets", style="blue", justify="right", width=8)
    table.add_column("Last Seen", style="dim", width=10)

    for mac, dev in sorted(snapshot.items(), key=lambda x: x[1]["total_packets"], reverse=True):
        # Determine the main activity
        activities = dev["activities"]
        main_activity = max(activities, key=activities.get) if activities else "?"

        # Get counters
        voip_count = dev.get("voip_packets", 0)
        msg_count = dev.get("msg_packets", 0)
        
        # Color coding for non-zero values
        voip_str = str(voip_count) if voip_count > 0 else "[dim]0[/]"
        msg_str = str(msg_count) if msg_count > 0 else "[dim]0[/]"

        # RSSI Color
        rssi = dev.get("rssi", -100)
        rssi_style = "green" if rssi > -60 else "yellow" if rssi > -80 else "red"
        rssi_str = f"[{rssi_style}]{rssi}[/]" if rssi != -100 else "[dim]?[/]"

        # Handshake indicator
        hs_count = dev.get("handshakes", 0)
        hs_str = f"[bold yellow]YES ({hs_count})[/]" if hs_count > 0 else "[dim]—[/]"

        # Timeline Sparkline-like bar
        history = list(dev["activity_history"])
        max_val = max(history) if any(history) else 1
        timeline = ""
        chars = " ▂▃▄▅▆▇█"
        for val in history:
            idx = int((val / max_val) * (len(chars) - 1))
            timeline += chars[idx]
        
        # Destinations summary
        dests = list(dev.get("destinations", []))
        dest_str = dests[0] if dests else "—"
        if len(dests) > 1:
            dest_str += f" (+{len(dests)-1})"

        # Format data size
        total_bytes = dev["total_bytes"]
        if total_bytes > 1_000_000:
            data_str = f"{total_bytes / 1_000_000:.1f} M"
        elif total_bytes > 1_000:
            data_str = f"{total_bytes / 1_000:.1f} K"
        else:
            data_str = f"{total_bytes} B"

        # Last seen
        last = dev["last_seen"].strftime("%H:%M:%S")

        table.add_row(
            f"  {mac}",
            rssi_str,
            hs_str,
            voip_str,
            msg_str,
            f"[cyan]{timeline}[/]",
            dest_str,
            str(dev["total_packets"]),
            last,
        )

    if not snapshot:
        table.add_row(
            "[dim]waiting...[/]", "[dim]—[/]", "[dim]—[/]",
            "[dim]—[/]", "[dim]scanning...[/]", "[dim]0[/]",
            "[dim]0 B[/]", "[dim]—[/]",
        )

    return table


def start_sniffing(
    interface: str,
    duration: int = 0,
    filter_mac: str | None = None,
    output_file: str | None = None,
    voip_only: bool = False,
):
    """
    Start live packet sniffing and display real-time device activity dashboard.
    
    Args:
        interface: Network interface to sniff on (must be in monitor mode or promiscuous)
        duration: Duration in seconds (0 = unlimited, Ctrl+C to stop)
        filter_mac: Optional MAC address to filter/focus on
        output_file: Optional .pcap file path to save captured packets (Wireshark-compatible)
        voip_only: If True and output_file is set, only save VoIP-related packets to pcap
    """
    if not SCAPY_AVAILABLE:
        console.print(
            Panel(
                "[bold red]Scapy is not installed![/]\n\n"
                "Install it with: [cyan]pip install scapy[/]",
                title="⚠ Missing Dependency",
                border_style="red",
            )
        )
        return

    tracker = DeviceTracker()
    stop_event = threading.Event()
    start_time = time.time()

    # ── PCAP recording setup ────────────────────────────────────────────
    pcap_writer = None
    pcap_info = None

    if output_file:
        # Ensure .pcap extension
        if not output_file.endswith(".pcap"):
            output_file += ".pcap"

        # Create output directory if needed
        out_dir = os.path.dirname(output_file)
        if out_dir and not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)

        try:
            pcap_writer = PcapWriter(output_file, append=False, sync=True)
            pcap_info = {
                "filename": os.path.basename(output_file),
                "filepath": os.path.abspath(output_file),
                "count": 0,
                "voip_only": voip_only,
            }
            console.print(
                f"  [bold red]● REC[/] Saving packets to: [cyan]{os.path.abspath(output_file)}[/]"
            )
            if voip_only:
                console.print("  [yellow]🎯 VoIP-only mode: only saving VoIP/call packets[/]")
        except Exception as e:
            console.print(f"[bold red]Failed to create pcap file: {e}[/]")
            pcap_writer = None
            pcap_info = None

    # ── Packet handler ──────────────────────────────────────────────────
    def packet_handler(pkt):
        nonlocal pcap_info
        if stop_event.is_set():
            return

        # Extract Physical Layer info (RSSI)
        rssi = -100
        if pkt.haslayer(RadioTap):
            try:
                rssi = pkt[RadioTap].dBm_AntSignal
            except (AttributeError, TypeError):
                pass

        # Extract Handshake (EAPOL)
        is_handshake = pkt.haslayer(EAPOL)

        mac = _get_mac(pkt)
        if not mac or mac == "FF:FF:FF:FF:FF:FF":
            return

        if filter_mac and mac.upper() != filter_mac.upper():
            return

        ip = "?"
        dst_ip = None
        if pkt.haslayer(IP):
            ip = pkt[IP].src
            dst_ip = pkt[IP].dst

        pkt_len = len(pkt) if pkt else 0
        activity, voip_app = classify_traffic(pkt)

        tracker.update(mac, ip, activity, pkt_len, rssi, is_handshake, dst_ip)

        if voip_app:
            with tracker.lock:
                if mac in tracker.devices:
                    tracker.devices[mac]["voip_app"] = voip_app

        # ── Save to pcap ────────────────────────────────────────────
        if pcap_writer and pcap_info is not None:
            should_save = True
            if pcap_info["voip_only"] and activity != "📞 VoIP/Call":
                should_save = False

            if should_save:
                try:
                    pcap_writer.write(pkt)
                    pcap_info["count"] += 1
                except Exception:
                    pass  # Don't crash the sniffer on write errors

    def sniff_thread():
        try:
            scapy_sniff(
                iface=interface,
                prn=packet_handler,
                store=False,
                stop_filter=lambda _: stop_event.is_set(),
                timeout=duration if duration > 0 else None,
            )
        except Exception as e:
            console.print(f"\n[bold red]Sniff error: {e}[/]")
        finally:
            stop_event.set()

    # Start sniffing in background thread
    thread = threading.Thread(target=sniff_thread, daemon=True)
    thread.start()

    rec_msg = ""
    if pcap_info:
        mode = "VoIP packets only" if voip_only else "all packets"
        rec_msg = f"\n  Recording: [bold red]● REC[/] → [cyan]{pcap_info['filepath']}[/] ({mode})"

    console.print(
        Panel(
            f"[bold green]🔊 Sniffing started on [cyan]{interface}[/cyan][/]\n"
            f"  Filter MAC: [yellow]{filter_mac or 'None (all devices)'}[/]\n"
            f"  Duration: [yellow]{f'{duration}s' if duration > 0 else 'Unlimited (Ctrl+C to stop)'}[/]"
            f"{rec_msg}\n\n"
            f"  [dim]Detecting: VoIP calls, streaming, web, DNS, email, SSH...[/]",
            title="📡 SNIFF",
            border_style="bright_cyan",
        )
    )

    try:
        with Live(
            _build_dashboard(tracker, interface, start_time, pcap_info),
            console=console,
            refresh_per_second=2,
            transient=False,
        ) as live:
            while not stop_event.is_set():
                live.update(_build_dashboard(tracker, interface, start_time, pcap_info))
                time.sleep(0.5)

    except KeyboardInterrupt:
        stop_event.set()
        console.print("\n[bold yellow]⏹ Sniffing stopped by user.[/]")

    thread.join(timeout=3)

    # ── Close pcap file ─────────────────────────────────────────────────
    if pcap_writer:
        try:
            pcap_writer.close()
        except Exception:
            pass

        if pcap_info:
            file_size = os.path.getsize(pcap_info["filepath"]) if os.path.exists(pcap_info["filepath"]) else 0
            if file_size > 1_000_000:
                size_str = f"{file_size / 1_000_000:.1f} MB"
            elif file_size > 1_000:
                size_str = f"{file_size / 1_000:.1f} KB"
            else:
                size_str = f"{file_size} B"

            console.print(
                Panel(
                    f"[bold green]✔ Capture saved![/]\n\n"
                    f"  📁 File: [bold cyan]{pcap_info['filepath']}[/]\n"
                    f"  📦 Packets: [yellow]{pcap_info['count']}[/]\n"
                    f"  💾 Size: [yellow]{size_str}[/]\n\n"
                    f"  [dim]Open in Wireshark:[/]\n"
                    f"  [green]wireshark {pcap_info['filepath']}[/]",
                    title="💾 PCAP Saved",
                    border_style="bright_green",
                )
            )

    # Final summary
    _print_summary(tracker)


def _print_summary(tracker: DeviceTracker):
    """Print a summary after sniffing session ends."""
    snapshot = tracker.get_snapshot()
    if not snapshot:
        console.print("[dim]No devices detected.[/]")
        return

    console.print("\n")

    table = Table(
        title="📊 Session Summary",
        title_style="bold cyan",
        border_style="bright_green",
        header_style="bold white on #1a1a2e",
        padding=(0, 1),
    )
    table.add_column("MAC", style="cyan", width=20)
    table.add_column("RSSI", justify="center", width=8)
    table.add_column("Handshake", justify="center", width=12)
    table.add_column("Appels", justify="center", width=8)
    table.add_column("Messages", justify="center", width=8)
    table.add_column("Destinations", style="dim", width=15)
    table.add_column("Total Packets", style="blue", justify="right", width=13)

    callers = 0
    for mac, dev in sorted(snapshot.items(), key=lambda x: x[1]["total_packets"], reverse=True):
        activities = dev["activities"]
        main_activity = max(activities, key=activities.get) if activities else "?"
        
        voip_pkts = dev.get("voip_packets", 0)
        msg_pkts = dev.get("msg_packets", 0)
        rssi = dev.get("rssi", -100)
        hs = dev.get("handshakes", 0)
        dests = len(dev.get("destinations", []))

        table.add_row(
            mac,
            f"{rssi} dBm" if rssi != -100 else "Unknown",
            f"YES ({hs})" if hs > 0 else "No",
            f"[bold green]{voip_pkts}[/]" if voip_pkts > 0 else "0",
            f"[bold blue]{msg_pkts}[/]" if msg_pkts > 0 else "0",
            f"{dests} unique IPs",
            str(dev["total_packets"]),
        )

    console.print(table)
    console.print(
        f"\n  [bold]Devices:[/] {len(snapshot)}  │  "
        f"[bold green]Active callers:[/] {callers}  │  "
        f"[bold blue]Total unique MACs:[/] {len(snapshot)}\n"
    )
