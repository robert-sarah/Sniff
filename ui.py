"""
ui.py - Rich UI Components for Sniff
Banner, help menus, and styling.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns

console = Console()

BANNER = r"""
[bold cyan]
   ██████  ███    ██ ██ ███████ ███████ 
  ██       ████   ██ ██ ██      ██      
  ███████  ██ ██  ██ ██ █████   █████ 
       ██  ██  ██ ██ ██ ██      ██    
  ██████   ██   ████ ██ ██      ██    
[/]
[dim bright_blue]  ─────────────────────────────────────[/]
[bold white]  📡 Network Activity Monitor v1.0[/]
[dim]  Passive traffic analysis & VoIP detection[/]
[dim bright_blue]  ─────────────────────────────────────[/]
"""


def show_banner():
    """Display the welcome banner."""
    console.print(
        Panel(
            BANNER,
            border_style="bright_blue",
            padding=(1, 4),
        )
    )


def show_help():
    """Display the help menu with all available commands."""
    table = Table(
        title="🛠 Available Commands",
        title_style="bold cyan",
        border_style="bright_blue",
        header_style="bold white on #1a1a2e",
        row_styles=["", "dim"],
        padding=(0, 2),
        expand=True,
    )
    table.add_column("Command", style="bold green", min_width=30)
    table.add_column("Description", style="white", min_width=40)

    commands = [
        ("interfaces", "List available wireless interfaces"),
        ("monitor start <iface>", "Enable monitor mode on interface"),
        ("monitor stop <iface>", "Disable monitor mode"),
        ("", ""),
        ("scan <iface> [duration]", "Scan for networks & devices"),
        ("wps <iface> [duration]", "🔓 Scan for WPS-enabled networks"),
        ("", ""),
        ("arp scan [iface] [range]", "🌐 Map network (IP/MAC discovery)"),
        ("arp spoof <iface> <target> <gw>", "☢ MITM: Redirect traffic to you"),
        ("arp stop <target> <gw>", "🧹 Restore network ARP tables"),
        ("", ""),
        ("deauth <target> <ap> [count]", "💥 Kick device(s) from WiFi"),
        ("beacon <ssid1> <ssid2>...", "🌀 Flood area with fake SSIDs"),
        ("eviltwin <ssid> <mac> [target]", "🎭 Coordinate Evil Twin attack"),
        ("stop_wifi", "🛑 Stop all active WiFi attacks"),
        ("", ""),
        ("sniff <iface> [duration]", "📡 Start live traffic monitoring"),
        ("sniff <iface> -m <mac>", "Monitor specific device and OS/Apps"),
        ("crack <pcap> <wordlist>", "🗝 Audit Handshake strength"),
        ("", ""),
        ("help", "Show this help menu"),
        ("clear", "Clear the screen"),
        ("exit / quit", "Exit Sniff"),
    ]

    for cmd, desc in commands:
        if cmd == "":
            table.add_row("[dim]─[/]", "[dim]─[/]")
        else:
            table.add_row(cmd, desc)

    console.print(table)

    console.print(
        Panel(
            "[bold yellow]⚠ Legal Notice[/]\n\n"
            "This tool is for [bold]authorized network monitoring only[/].\n"
            "Only use on networks you own or have explicit permission to monitor.\n"
            "Traffic [bold green]content is never captured[/] — only metadata & activity type.",
            border_style="yellow",
            padding=(1, 2),
        )
    )


def show_status(monitor_iface: str | None, current_iface: str | None):
    """Show current status."""
    status_items = []

    if monitor_iface:
        status_items.append(f"[bold green]● Monitor Mode:[/] [cyan]{monitor_iface}[/]")
    else:
        status_items.append("[dim]● Monitor Mode: OFF[/]")

    if current_iface:
        status_items.append(f"[bold green]● Interface:[/] [cyan]{current_iface}[/]")
    else:
        status_items.append("[dim]● Interface: None[/]")

    console.print(
        Panel(
            "\n".join(status_items),
            title="📊 Status",
            border_style="bright_blue",
            padding=(0, 2),
        )
    )
