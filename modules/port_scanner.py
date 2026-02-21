"""
port_scanner.py - Fast Port & Service Scanner
Identifies open ports and potential services on target devices.
"""

import socket
import threading
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}

def scan_single_port(ip, port, results):
    """Attempts to connect to a specific port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                results.append((port, service))
    except:
        pass

def scan_device_ports(ip, port_range=None):
    """Scans a device for open ports."""
    if not port_range:
        ports = list(COMMON_PORTS.keys())
    else:
        ports = range(port_range[0], port_range[1] + 1)

    console.print(f"[bold cyan]🔍 Scanning Services on:[/] [white]{ip}[/]")
    
    results = []
    threads = []

    with Progress() as progress:
        task = progress.add_task("[yellow]Scanning ports...", total=len(ports))
        
        for port in ports:
            t = threading.Thread(target=scan_single_port, args=(ip, port, results))
            t.start()
            threads.append(t)
            progress.update(task, advance=1)

        for t in threads:
            t.join()

    # Display Results
    table = Table(title=f"📜 Services found on {ip}", title_style="bold green")
    table.add_column("Port", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Service", style="yellow")

    if not results:
        console.print("[dim red]No common ports open found.[/]")
    else:
        for port, service in sorted(results):
            table.add_row(str(port), "OPEN", service)
        console.print(table)
    
    return results
