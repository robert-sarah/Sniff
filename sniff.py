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
from modules.scanner import scan_networks, scan_target
from modules.sniffer import start_sniffing

console = Console()

# ─── Command completer ──────────────────────────────────────────────────────

COMMANDS = [
    "interfaces", "monitor", "start", "stop",
    "scan", "sniff", "help", "status",
    "clear", "exit", "quit",
]

completer = WordCompleter(COMMANDS, ignore_case=True)

# ─── State ───────────────────────────────────────────────────────────────────

state = {
    "monitor_iface": None,
    "base_iface": None,
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

            elif command == "sniff":
                cmd_sniff(args)

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
