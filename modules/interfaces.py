"""
interfaces.py - Network Interface Management
Wraps airmon-ng to manage monitor mode on wireless interfaces.
"""

import subprocess
import re
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()


def run_cmd(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    """Run a system command and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return -1, "", f"[!] Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -2, "", f"[!] Command timed out: {' '.join(cmd)}"


def list_interfaces():
    """List all wireless interfaces using airmon-ng."""
    code, stdout, stderr = run_cmd(["airmon-ng"])

    if code != 0:
        console.print(
            Panel(
                f"[bold red]Error running airmon-ng[/]\n{stderr}",
                title="⚠ Error",
                border_style="red",
            )
        )
        return []

    table = Table(
        title="📡 Wireless Interfaces",
        title_style="bold cyan",
        border_style="bright_blue",
        header_style="bold white on dark_blue",
        row_styles=["", "dim"],
        padding=(0, 2),
    )
    table.add_column("PHY", style="cyan", justify="center")
    table.add_column("Interface", style="bold green", justify="center")
    table.add_column("Driver", style="yellow", justify="center")
    table.add_column("Chipset", style="magenta")

    interfaces = []
    lines = stdout.strip().split("\n")
    for line in lines:
        line = line.strip()
        if not line or line.startswith("PHY") or line.startswith("-"):
            continue
        parts = re.split(r"\t+", line)
        if len(parts) >= 3:
            phy = parts[0] if len(parts) > 0 else "?"
            iface = parts[1] if len(parts) > 1 else "?"
            driver = parts[2] if len(parts) > 2 else "?"
            chipset = parts[3] if len(parts) > 3 else "Unknown"
            table.add_row(phy, iface, driver, chipset)
            interfaces.append(iface)

    if interfaces:
        console.print(table)
    else:
        console.print("[dim yellow]  No wireless interfaces found.[/]")

    return interfaces


def start_monitor(interface: str) -> str | None:
    """Enable monitor mode on an interface using airmon-ng."""
    console.print(
        f"\n[bold cyan]⏳ Enabling monitor mode on [green]{interface}[/green]...[/]"
    )

    # Kill interfering processes first
    run_cmd(["airmon-ng", "check", "kill"])

    code, stdout, stderr = run_cmd(["airmon-ng", "start", interface])
    output = stdout + stderr

    if code != 0:
        console.print(
            Panel(
                f"[bold red]Failed to enable monitor mode[/]\n{output}",
                title="⚠ Error",
                border_style="red",
            )
        )
        return None

    # Detect the new monitor interface name
    mon_match = re.search(r"(\w+mon\d*)", output)
    if mon_match:
        mon_iface = mon_match.group(1)
    elif "mon" in interface:
        mon_iface = interface
    else:
        mon_iface = f"{interface}mon"

    console.print(
        Panel(
            f"[bold green]✔ Monitor mode enabled[/]\n"
            f"  Interface: [cyan]{mon_iface}[/]",
            title="📡 Monitor Mode",
            border_style="green",
        )
    )
    return mon_iface


def stop_monitor(interface: str) -> bool:
    """Disable monitor mode on an interface."""
    console.print(
        f"\n[bold cyan]⏳ Disabling monitor mode on [green]{interface}[/green]...[/]"
    )

    code, stdout, stderr = run_cmd(["airmon-ng", "stop", interface])

    if code != 0:
        console.print(
            Panel(
                f"[bold red]Failed to disable monitor mode[/]\n{stderr}",
                title="⚠ Error",
                border_style="red",
            )
        )
        return False

    console.print(
        Panel(
            f"[bold green]✔ Monitor mode disabled[/]\n"
            f"  Interface [cyan]{interface}[/] is back to managed mode.",
            title="📡 Managed Mode",
            border_style="green",
        )
    )

    # Restart NetworkManager
    run_cmd(["systemctl", "start", "NetworkManager"])

    return True
