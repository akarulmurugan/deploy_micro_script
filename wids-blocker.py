#!/usr/bin/env python3
import json
import subprocess
import time
from datetime import datetime

# List of authorized MACs (your devices)
AUTHORIZED_MACS = {
    "AA:BB:CC:DD:EE:FF",  # Your phone
    "11:22:33:44:55:66",  # Your laptop
}

# Your router's SSID
YOUR_ROUTER_SSID = "YourHomeWiFi"

def block_mac(mac_address, reason):
    """Block MAC address using iptables"""
    # Check if already blocked
    check = subprocess.run(
        f"sudo iptables -L INPUT -n | grep {mac_address}",
        shell=True,
        capture_output=True
    )
    
    if check.returncode != 0:  # Not blocked yet
        print(f"[{datetime.now()}] BLOCKING {mac_address} - {reason}")
        
        # Block with iptables
        commands = [
            f"sudo iptables -A INPUT -m mac --mac-source {mac_address} -j DROP",
            f"sudo iptables -A FORWARD -m mac --mac-source {mac_address} -j DROP"
        ]
        
        for cmd in commands:
            subprocess.run(cmd, shell=True)
        
        # Log to file
        with open("/var/log/wids_block.log", "a") as f:
            f.write(f"{datetime.now()} | BLOCKED | {mac_address} | {reason}\n")

def process_packet(packet_data):
    """Process incoming WIDS packet"""
    try:
        data = json.loads(packet_data)
        
        mac = data.get("mac", "").upper()
        ssid = data.get("ssid", "")
        attack_type = data.get("attack_type", "")
        
        # Check if unauthorized device
        if mac not in AUTHORIZED_MACS:
            # Block if probing for YOUR network
            if ssid == YOUR_ROUTER_SSID:
                block_mac(mac, f"Probing for {YOUR_ROUTER_SSID}")
            
            # Block if trying to authenticate
            elif attack_type == "auth_attempt":
                block_mac(mac, "Authentication attempt")
            
            # Block if associated
            elif attack_type == "association":
                block_mac(mac, "Network association")
    
    except json.JSONDecodeError:
        pass

# Main loop (read from server log/API)
if __name__ == "__main__":
    # This would connect to your WIDS server
    # For now, simulate reading packets
    print("WIDS Auto-Blocker started...")
    print(f"Monitoring for intrusions on SSID: {YOUR_ROUTER_SSID}")
