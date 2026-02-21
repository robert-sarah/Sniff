#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║   SNIFF — Network Activity Monitor                   ║
║   Passive WiFi traffic analyzer & VoIP detector      ║
║                                                      ║
║   Uses: airmon-ng, airodump-ng, scapy               ║
║   Detects: VoIP calls, streaming, web, DNS, etc.    ║
║   Does NOT capture conversation content.             ║
╚══════════════════════════════════════════════════════╝

Usage:
    sudo python sniff.py

Requires:
    - aircrack-ng suite installed (airmon-ng, airodump-ng)
    - Python 3.10+
    - pip install rich scapy prompt_toolkit
    - Root/sudo privileges
"""

import sys
import os
import shlex
from rich.console import Console
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter

from ui import show_banner, show_help, show_status
from modules.interfaces import list_interfaces, start_monitor, stop_monitor
from modules.scanner import scan_networks, scan_target, scan_wps
from modules.sniffer import start_sniffing
from modules.network_audit import ARPAuditor
from modules.wifi_ops import WiFiOperator
from modules.portal import CaptivePortal

console = Console()

# ─── Command completer ──────────────────────────────────────────────────────

COMMANDS = [
    "interfaces", "monitor", "start", "stop",
    "scan", "wps", "sniff", "arp", "deauth", "beacon", "eviltwin", "stop_wifi", 
    "help", "status", "clear", "exit", "quit",
]

completer = WordCompleter(COMMANDS, ignore_case=True)

# ─── State ───────────────────────────────────────────────────────────────────

state = {
    "monitor_iface": None,
    "base_iface": None,
    "arp_auditor": None,
    "wifi_ops": None,
    "portal": None,
}


# ─── Command Handlers ───────────────────────────────────────────────────────

def cmd_interfaces():
    """List wireless interfaces."""
    ifaces = list_interfaces()
    return ifaces


def cmd_monitor(args: list[str]):
    """Handle monitor start/stop."""
    if len(args) < 2:
        console.print("[yellow]Usage: monitor start|stop <interface>[/]")
        return

    action = args[0].lower()
    iface = args[1]

    if action == "start":
        mon_iface = start_monitor(iface)
        if mon_iface:
            state["monitor_iface"] = mon_iface
            state["base_iface"] = iface
    elif action == "stop":
        iface_to_stop = state.get("monitor_iface", iface)
        success = stop_monitor(iface_to_stop)
        if success:
            state["monitor_iface"] = None
            state["base_iface"] = None
    else:
        console.print(f"[yellow]Unknown monitor action: {action}[/]")
        console.print("[dim]Usage: monitor start|stop <interface>[/]")


def cmd_scan(args: list[str]):
    """Handle scan command."""
    if not args:
        console.print("[yellow]Usage: scan <interface> [duration][/]")
        console.print("[yellow]       scan <interface> -b <bssid> -c <channel> [duration][/]")
        return

    iface = args[0]
    duration = 15
    bssid = None
    channel = None

    i = 1
    while i < len(args):
        if args[i] == "-b" and i + 1 < len(args):
            bssid = args[i + 1]
            i += 2
        elif args[i] == "-c" and i + 1 < len(args):
            try:
                channel = int(args[i + 1])
            except ValueError:
                console.print(f"[red]Invalid channel: {args[i + 1]}[/]")
                return
            i += 2
        else:
            try:
                duration = int(args[i])
            except ValueError:
                console.print(f"[red]Unknown argument: {args[i]}[/]")
                return
            i += 1

    if bssid and channel:
        scan_target(iface, bssid, channel, duration)
    else:
        scan_networks(iface, duration)


def cmd_sniff(args: list[str]):
    """Handle sniff command."""
    if not args:
        console.print("[yellow]Usage: sniff <interface> [duration][/]")
        console.print("[yellow]       sniff <interface> -m <mac> [duration][/]")
        console.print("[yellow]       sniff <interface> -o <file.pcap>         (record all packets)[/]")
        console.print("[yellow]       sniff <interface> -o <file.pcap> -vo     (record VoIP only)[/]")
        return

    iface = args[0]
    duration = 0
    filter_mac = None
    output_file = None
    voip_only = False

    i = 1
    while i < len(args):
        if args[i] == "-m" and i + 1 < len(args):
            filter_mac = args[i + 1]
            i += 2
        elif args[i] == "-o" and i + 1 < len(args):
            output_file = args[i + 1]
            i += 2
        elif args[i] == "-vo":
            voip_only = True
            i += 1
        else:
            try:
                duration = int(args[i])
            except ValueError:
                console.print(f"[red]Unknown argument: {args[i]}[/]")
                return
            i += 1

    start_sniffing(iface, duration, filter_mac, output_file, voip_only)


# ─── Main Loop ──────────────────────────────────────────────────────────────

def cmd_arp(args: list[str]):
    """Handle ARP audit commands."""
    if not args:
        console.print("[yellow]Usage: arp scan [interface] [range][/]")
        console.print("[yellow]       arp spoof <interface> <target_ip> <gateway_ip>[/]")
        console.print("[yellow]       arp stop <target_ip> <gateway_ip>[/]")
        return

    subcmd = args[0].lower()
    
    if subcmd == "scan":
        iface = args[1] if len(args) > 1 else (state["monitor_iface"] or state["base_iface"])
        if not iface:
            console.print("[red]Error: No interface specified or detected.[/]")
            return
        
        if not state["arp_auditor"]:
            state["arp_auditor"] = ARPAuditor(iface)
        
        ip_range = args[2] if len(args) > 2 else None
        state["arp_auditor"].scan_network(ip_range)

    elif subcmd == "spoof":
        if len(args) < 4:
            console.print("[yellow]Usage: arp spoof <interface> <target_ip> <gateway_ip>[/]")
            return
        
        iface = args[1]
        target_ip = args[2]
        gateway_ip = args[3]

        if not state["arp_auditor"] or state["arp_auditor"].interface != iface:
            state["arp_auditor"] = ARPAuditor(iface)
        
        state["arp_auditor"].enable_ip_forwarding()
        state["arp_auditor"].spoof_test(target_ip, gateway_ip)

    elif subcmd == "stop":
        if len(args) < 3:
            console.print("[yellow]Usage: arp stop <target_ip> <gateway_ip>[/]")
            return
        
        target_ip = args[1]
        gateway_ip = args[2]

        if state["arp_auditor"]:
            state["arp_auditor"].stop_spoof_test(target_ip, gateway_ip)
        else:
            console.print("[red]Error: No active ARP auditor found.[/]")


def cmd_wps(args: list[str]):
    """Handle WPS scan command."""
    if not args:
        console.print("[yellow]Usage: wps <interface> [duration][/]")
        return
    iface = args[0]
    duration = int(args[1]) if len(args) > 1 else 15
    scan_wps(iface, duration)


def cmd_wifi_ops(command: str, args: list[str]):
    """Handle deauth and beacon commands."""
    # Use monitor interface from state, otherwise error
    iface = state["monitor_iface"]
    if not iface:
        console.print("[red]Error: You must start monitor mode first! ([bold]monitor start <iface>[/])[/]")
        return

    if not state["wifi_ops"] or state["wifi_ops"].interface != iface:
        state["wifi_ops"] = WiFiOperator(iface)

    if command == "deauth":
        if len(args) < 2:
            console.print("[yellow]Usage: deauth <target_mac> <gateway_mac> [count][/]")
            return
        target = args[0]
        gateway = args[1]
        count = int(args[2]) if len(args) > 2 else 0
        state["wifi_ops"].deauth(target, gateway, count)

    elif command == "beacon":
        names = args if args else None
        state["wifi_ops"].beacon_flood(names)

    elif command == "eviltwin":
        if len(args) < 2:
            console.print("[yellow]Usage: eviltwin <ssid> <ap_mac> [target_client_mac][/]")
            return
        ssid = args[0]
        ap_mac = args[1]
        target_mac = args[2] if len(args) > 2 else None
        
        # 1. Start Cloner (and targeted Deauth if target_mac is set)
        state["wifi_ops"].evil_twin(ssid, ap_mac, target_mac)
        
        # 2. Start Portal
        if not state["portal"]:
            state["portal"] = CaptivePortal()
            state["portal"].start()
        
        if target_mac:
            console.print(f"\n[bold green]⚡ AUTO-MODE:[/] Cloned [cyan]{ssid}[/] and kicking client [red]{target_mac}[/] automatically.")
        else:
            console.print("\n[bold cyan]💡 Next Step:[/] You should now run [bold red]deauth[/] on the real AP to force devices to switch to your clone.")
            console.print(f"[dim]Example: deauth FF:FF:FF:FF:FF:FF {ap_mac}[/]")

    elif command == "stop_wifi":
        if state["wifi_ops"]:
            state["wifi_ops"].stop()
        if state["portal"]:
            state["portal"].stop()
            state["portal"] = None


def main():
    # Check root on Linux
    if os.name != "nt" and os.geteuid() != 0:
        console.print(
            "[bold red]⚠ Sniff requires root privileges![/]\n"
            "[dim]Run with: sudo python sniff.py[/]"
        )
        sys.exit(1)

    show_banner()
    show_help()

    session = PromptSession(
        history=InMemoryHistory(),
        auto_suggest=AutoSuggestFromHistory(),
        completer=completer,
    )

    while True:
        try:
            # Build prompt
            mon_indicator = ""
            if state["monitor_iface"]:
                mon_indicator = f" <ansiyellow>[{state['monitor_iface']}]</ansiyellow>"

            user_input = session.prompt(
                HTML(f"<ansibrightcyan><b>sniff</b></ansibrightcyan>{mon_indicator}<ansigray> ❯ </ansigray>"),
            )

            user_input = user_input.strip()
            if not user_input:
                continue

            try:
                parts = shlex.split(user_input)
            except ValueError:
                parts = user_input.split()

            command = parts[0].lower()
            args = parts[1:]

            # ── Route commands ───────────────────────────────
            if command in ("exit", "quit", "q"):
                # Clean up monitor mode if still active
                if state["monitor_iface"]:
                    console.print("[dim]Stopping monitor mode before exit...[/]")
                    stop_monitor(state["monitor_iface"])
                console.print("[bold cyan]👋 Bye![/]")
                break

            elif command == "help":
                show_help()

            elif command == "clear":
                console.clear()
                show_banner()

            elif command in ("interfaces", "ifaces", "if"):
                cmd_interfaces()

            elif command == "monitor":
                cmd_monitor(args)

            elif command == "scan":
                cmd_scan(args)

            elif command == "wps":
                cmd_wps(args)

            elif command == "sniff":
                cmd_sniff(args)

            elif command == "arp":
                cmd_arp(args)

            elif command == "deauth":
                cmd_wifi_ops("deauth", args)

            elif command == "beacon":
                cmd_wifi_ops("beacon", args)

            elif command == "stop_wifi":
                cmd_wifi_ops("stop_wifi", args)

            elif command == "status":
                show_status(state["monitor_iface"], state["base_iface"])

            else:
                console.print(
                    f"[bold red]Unknown command:[/] [yellow]{command}[/]\n"
                    "[dim]Type 'help' for available commands.[/]"
                )

        except KeyboardInterrupt:
            console.print("\n[dim]Type 'exit' to quit.[/]")
            continue
        except EOFError:
            console.print("[bold cyan]👋 Bye![/]")
            break


if __name__ == "__main__":
    main()
