"""
scanner.py - WiFi Network & Device Scanner
Wraps airodump-ng to discover nearby access points and connected clients.
"""

import subprocess
import csv
import os
import time
import signal
import tempfile
import re
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.text import Text

console = Console()


def scan_networks(interface: str, duration: int = 15):
    """
    Scan for nearby WiFi networks and clients using airodump-ng.
    Returns (access_points, clients).
    """
    console.print(
        f"\n[bold cyan]📡 Scanning networks on [green]{interface}[/green] "
        f"for [yellow]{duration}s[/yellow]...[/]\n"
    )

    tmpdir = tempfile.mkdtemp(prefix="sniff_")
    prefix = os.path.join(tmpdir, "scan")

    try:
        proc = subprocess.Popen(
            [
                "airodump-ng",
                interface,
                "--write", prefix,
                "--output-format", "csv",
                "--write-interval", "1",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        time.sleep(duration)
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)

    except Exception as e:
        console.print(f"[bold red]Error during scan: {e}[/]")
        return [], []

    # Parse the CSV output
    csv_file = f"{prefix}-01.csv"
    if not os.path.exists(csv_file):
        console.print("[bold red]No scan data captured.[/]")
        return [], []

    access_points = []
    clients = []
    section = None

    try:
        with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("BSSID") and "channel" in line.lower():
                    section = "ap"
                    continue
                elif line.startswith("Station MAC"):
                    section = "client"
                    continue

                parts = [p.strip() for p in line.split(",")]

                if section == "ap" and len(parts) >= 14:
                    ap = {
                        "bssid": parts[0],
                        "power": parts[8] if parts[8] else "?",
                        "beacons": parts[9] if parts[9] else "0",
                        "data": parts[10] if parts[10] else "0",
                        "channel": parts[3] if parts[3] else "?",
                        "encryption": parts[5] if parts[5] else "?",
                        "cipher": parts[6] if parts[6] else "?",
                        "auth": parts[7] if parts[7] else "?",
                        "essid": parts[13] if parts[13] else "<hidden>",
                    }
                    if re.match(r"[0-9A-Fa-f]{2}:", ap["bssid"]):
                        access_points.append(ap)

                elif section == "client" and len(parts) >= 6:
                    client = {
                        "station": parts[0],
                        "power": parts[3] if len(parts) > 3 and parts[3] else "?",
                        "packets": parts[4] if len(parts) > 4 and parts[4] else "0",
                        "bssid": parts[5] if len(parts) > 5 and parts[5] else "(not associated)",
                        "probes": parts[6] if len(parts) > 6 else "",
                    }
                    if re.match(r"[0-9A-Fa-f]{2}:", client["station"]):
                        clients.append(client)

    except Exception as e:
        console.print(f"[bold red]Error parsing scan data: {e}[/]")

    # Clean up temp files
    for f in os.listdir(tmpdir):
        os.remove(os.path.join(tmpdir, f))
    os.rmdir(tmpdir)

    # Display Access Points
    display_access_points(access_points)
    display_clients(clients)

    return access_points, clients


def display_access_points(access_points: list):
    """Display discovered access points in a rich table."""
    table = Table(
        title="🏠 Access Points Discovered",
        title_style="bold cyan",
        border_style="bright_blue",
        header_style="bold white on dark_blue",
        row_styles=["", "dim"],
        padding=(0, 1),
    )
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("ESSID", style="bold green", min_width=15)
    table.add_column("BSSID", style="cyan", width=18)
    table.add_column("CH", style="yellow", justify="center", width=4)
    table.add_column("PWR", style="magenta", justify="center", width=5)
    table.add_column("ENC", style="red", justify="center", width=8)
    table.add_column("Beacons", style="blue", justify="right", width=8)
    table.add_column("Data", style="green", justify="right", width=6)

    for i, ap in enumerate(access_points, 1):
        enc_style = "green" if "OPN" in ap["encryption"] else "red"
        table.add_row(
            str(i),
            ap["essid"],
            ap["bssid"],
            ap["channel"],
            ap["power"],
            f"[{enc_style}]{ap['encryption']}[/]",
            ap["beacons"],
            ap["data"],
        )

    if access_points:
        console.print(table)
        console.print(f"  [dim]Total: {len(access_points)} access points[/]\n")
    else:
        console.print("[dim yellow]  No access points found.[/]\n")


def display_clients(clients: list):
    """Display discovered clients in a rich table."""
    table = Table(
        title="📱 Clients / Devices Detected",
        title_style="bold cyan",
        border_style="bright_magenta",
        header_style="bold white on purple4",
        row_styles=["", "dim"],
        padding=(0, 1),
    )
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Station MAC", style="bold yellow", width=18)
    table.add_column("Associated AP", style="cyan", width=18)
    table.add_column("PWR", style="magenta", justify="center", width=5)
    table.add_column("Packets", style="green", justify="right", width=8)
    table.add_column("Probes", style="blue", min_width=10)

    for i, cl in enumerate(clients, 1):
        table.add_row(
            str(i),
            cl["station"],
            cl["bssid"],
            cl["power"],
            cl["packets"],
            cl.get("probes", ""),
        )

    if clients:
        console.print(table)
        console.print(f"  [dim]Total: {len(clients)} clients[/]\n")
    else:
        console.print("[dim yellow]  No clients found.[/]\n")


def scan_target(interface: str, bssid: str, channel: int, duration: int = 30):
    """
    Focus scan on a specific access point to see its connected clients.
    """
    console.print(
        f"\n[bold cyan]🎯 Targeting [green]{bssid}[/green] on CH [yellow]{channel}[/yellow] "
        f"for [yellow]{duration}s[/yellow]...[/]\n"
    )

    tmpdir = tempfile.mkdtemp(prefix="sniff_")
    prefix = os.path.join(tmpdir, "target")

    try:
        proc = subprocess.Popen(
            [
                "airodump-ng",
                interface,
                "--bssid", bssid,
                "--channel", str(channel),
                "--write", prefix,
                "--output-format", "csv",
                "--write-interval", "1",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        time.sleep(duration)
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)

    except Exception as e:
        console.print(f"[bold red]Error during targeted scan: {e}[/]")
        return [], []

    csv_file = f"{prefix}-01.csv"
    if not os.path.exists(csv_file):
        console.print("[bold red]No scan data captured.[/]")
        return [], []

    access_points = []
    clients = []
    section = None

    try:
        with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("BSSID") and "channel" in line.lower():
                    section = "ap"
                    continue
                elif line.startswith("Station MAC"):
                    section = "client"
                    continue

                parts = [p.strip() for p in line.split(",")]

                if section == "ap" and len(parts) >= 14:
                    ap = {
                        "bssid": parts[0],
                        "power": parts[8] if parts[8] else "?",
                        "data": parts[10] if parts[10] else "0",
                        "channel": parts[3] if parts[3] else "?",
                        "essid": parts[13] if parts[13] else "<hidden>",
                    }
                    if re.match(r"[0-9A-Fa-f]{2}:", ap["bssid"]):
                        access_points.append(ap)

                elif section == "client" and len(parts) >= 6:
                    client = {
                        "station": parts[0],
                        "power": parts[3] if len(parts) > 3 and parts[3] else "?",
                        "packets": parts[4] if len(parts) > 4 and parts[4] else "0",
                        "bssid": parts[5] if len(parts) > 5 else "",
                    }
                    if re.match(r"[0-9A-Fa-f]{2}:", client["station"]):
                        clients.append(client)

    except Exception as e:
        console.print(f"[bold red]Error parsing data: {e}[/]")

    for f in os.listdir(tmpdir):
        os.remove(os.path.join(tmpdir, f))
    os.rmdir(tmpdir)

    display_access_points(access_points)
    display_clients(clients)

    return access_points, clients
