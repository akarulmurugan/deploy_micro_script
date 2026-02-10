#!/usr/bin/env python3
"""
WIDS SERVER WITH AUTO-BLOCKING & EMAIL NOTIFICATIONS
"""
from flask import Flask, request, jsonify, render_template_string
from datetime import datetime, timedelta
import json
import subprocess
import threading
import time
import os
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sqlite3
from collections import defaultdict

app = Flask(__name__)

# ========== CONFIGURATION ==========
YOUR_SSID = "Airtel_sath_0300"  # Your router SSID

# Email Configuration (REQUIRED for notifications)
EMAIL_CONFIG = {
    'enabled': True,  # Set to False to disable email
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'your_email@gmail.com',  # CHANGE THIS
    'sender_password': 'your_app_password',  # CHANGE THIS (Google App Password)
    'recipient_email': 'your_alerts_email@gmail.com'  # CHANGE THIS
}

# Files and paths
AUTHORIZED_MACS_FILE = "authorized_macs.json"
DB_FILE = "wids_database.db"
BLOCK_LOG_FILE = "blocked_devices.log"

# ========== DATA STORAGE ==========
devices = {}
packets = []
authorized_macs = set()
sensors = {}
threat_log = []
packet_rates = defaultdict(list)

# ========== LOAD CONFIG ==========
def load_authorized_macs():
    global authorized_macs
    try:
        if os.path.exists(AUTHORIZED_MACS_FILE):
            with open(AUTHORIZED_MACS_FILE, 'r') as f:
                data = json.load(f)
                authorized_macs = set(data.get('authorized_macs', []))
            print(f"✅ Loaded {len(authorized_macs)} authorized MACs")
        else:
            authorized_macs = set()
    except Exception as e:
        print(f"❌ Error loading authorized MACs: {e}")
        authorized_macs = set()

def save_authorized_macs():
    try:
        with open(AUTHORIZED_MACS_FILE, 'w') as f:
            json.dump({
                'authorized_macs': list(authorized_macs),
                'updated': datetime.now().isoformat()
            }, f, indent=2)
    except Exception as e:
        print(f"❌ Error saving authorized MACs: {e}")

# ========== DATABASE FUNCTIONS ==========
def init_database():
    """Initialize SQLite database"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Blocked devices table
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_devices
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  mac TEXT UNIQUE,
                  reason TEXT,
                  blocked_at TIMESTAMP,
                  unblocked_at TIMESTAMP,
                  status TEXT DEFAULT 'blocked')''')
    
    # Alerts table
    c.execute('''CREATE TABLE IF NOT EXISTS alerts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  alert_type TEXT,
                  mac TEXT,
                  message TEXT,
                  severity TEXT,
                  created_at TIMESTAMP,
                  email_sent BOOLEAN DEFAULT 0)''')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized")

def log_blocked_device(mac, reason):
    """Log blocked device to database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''INSERT OR REPLACE INTO blocked_devices 
                     (mac, reason, blocked_at, status) 
                     VALUES (?, ?, ?, ?)''',
                 (mac.upper(), reason, datetime.now(), 'blocked'))
        conn.commit()
        conn.close()
        
        # Also log to file
        with open(BLOCK_LOG_FILE, 'a') as f:
            f.write(f"{datetime.now()} | BLOCKED | {mac} | {reason}\n")
            
        print(f"📝 Logged blocked device: {mac}")
        return True
    except Exception as e:
        print(f"❌ Error logging blocked device: {e}")
        return False

def get_blocked_devices():
    """Get all blocked devices"""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT mac, reason, blocked_at FROM blocked_devices WHERE status='blocked'")
        devices = c.fetchall()
        conn.close()
        
        blocked_list = []
        for mac, reason, blocked_at in devices:
            blocked_list.append({
                'mac': mac,
                'reason': reason,
                'blocked_at': blocked_at
            })
        return blocked_list
    except:
        return []

# ========== EMAIL FUNCTIONS ==========
def send_email_alert(subject, body, is_html=False):
    """Send email alert"""
    if not EMAIL_CONFIG['enabled']:
        print("📧 Email notifications disabled")
        return False
    
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = EMAIL_CONFIG['sender_email']
        msg['To'] = EMAIL_CONFIG['recipient_email']
        msg['Subject'] = subject
        
        if is_html:
            msg.attach(MIMEText(body, 'html'))
        else:
            msg.attach(MIMEText(body, 'plain'))
        
        # Connect to SMTP server
        server = smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port'])
        server.starttls()
        server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
        
        # Send email
        server.send_message(msg)
        server.quit()
        
        print(f"📧 Email sent: {subject}")
        return True
        
    except Exception as e:
        print(f"❌ Email error: {e}")
        return False

def send_intrusion_alert(mac, attack_type, ssid, rssi):
    """Send intrusion alert email"""
    subject = f"🚨 WIDS ALERT: {attack_type} detected"
    
    body_html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; border-left: 5px solid #ff4444;">
            <h1 style="color: #ff4444;">🚨 WIRELESS INTRUSION DETECTED</h1>
            
            <div style="background: #fff8f8; padding: 20px; border-radius: 5px; margin: 20px 0;">
                <h2 style="color: #333;">Intrusion Details</h2>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Attack Type:</strong></td>
                        <td style="padding: 8px; border-bottom: 1px solid #eee;"><span style="color: #ff4444; font-weight: bold;">{attack_type}</span></td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>MAC Address:</strong></td>
                        <td style="padding: 8px; border-bottom: 1px solid #eee;"><code>{mac}</code></td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Target SSID:</strong></td>
                        <td style="padding: 8px; border-bottom: 1px solid #eee;">{ssid}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Signal Strength:</strong></td>
                        <td style="padding: 8px; border-bottom: 1px solid #eee;">{rssi} dBm</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Time:</strong></td>
                        <td style="padding: 8px; border-bottom: 1px solid #eee;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td>
                    </tr>
                </table>
            </div>
            
            <div style="background: #f0f8ff; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <h3 style="color: #0066cc;">✅ Action Taken:</h3>
                <p>Device has been <strong>automatically blocked</strong> from accessing your network using iptables.</p>
            </div>
            
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; color: #666; font-size: 12px;">
                <p>This is an automated alert from your WIDS (Wireless Intrusion Detection System).</p>
                <p>Check dashboard for more details: http://YOUR_SERVER_IP:8000</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return send_email_alert(subject, body_html, is_html=True)

# ========== IPTABLES BLOCKING FUNCTIONS ==========
def block_with_iptables(mac, reason):
    """Block MAC address using iptables"""
    try:
        mac = mac.upper()
        
        # Check if already blocked
        check = subprocess.run(
            f"sudo iptables -L INPUT -n 2>/dev/null | grep -i {mac}",
            shell=True, capture_output=True, text=True
        )
        
        if check.returncode != 0:  # Not blocked yet
            print(f"[{datetime.now()}] 🚨 BLOCKING {mac} - {reason}")
            
            # Block incoming traffic
            subprocess.run(
                f"sudo iptables -A INPUT -m mac --mac-source {mac} -j DROP",
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            # Block forwarded traffic
            subprocess.run(
                f"sudo iptables -A FORWARD -m mac --mac-source {mac} -j DROP",
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            
            # Save iptables rules
            subprocess.run(
                "sudo iptables-save > /etc/iptables/rules.v4",
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            
            # Log to database
            log_blocked_device(mac, reason)
            
            print(f"✅ Successfully blocked {mac}")
            return True
        else:
            print(f"⚠️ {mac} already blocked")
            return False
            
    except Exception as e:
        print(f"❌ Error blocking {mac}: {e}")
        return False

def unblock_mac(mac):
    """Unblock MAC address"""
    try:
        mac = mac.upper()
        print(f"[{datetime.now()}] 🔓 UNBLOCKING {mac}")
        
        # Remove iptables rules
        subprocess.run(
            f"sudo iptables -D INPUT -m mac --mac-source {mac} -j DROP 2>/dev/null",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            f"sudo iptables -D FORWARD -m mac --mac-source {mac} -j DROP 2>/dev/null",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        
        # Update database
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("UPDATE blocked_devices SET status='unblocked', unblocked_at=? WHERE mac=?",
                 (datetime.now(), mac))
        conn.commit()
        conn.close()
        
        print(f"✅ Successfully unblocked {mac}")
        return True
    except Exception as e:
        print(f"❌ Error unblocking {mac}: {e}")
        return False

# ========== INTRUSION DETECTION LOGIC ==========
def check_intrusion(packet):
    """Check if packet indicates intrusion"""
    mac = packet.get('mac', '').upper()
    ssid = packet.get('ssid', '')
    attack_type = packet.get('attack_type', '')
    rssi = packet.get('rssi', -99)
    
    # Skip if authorized
    if mac in authorized_macs:
        return None
    
    intrusion_reasons = []
    
    # Check various attack types
    if attack_type == "auth_attempt" and ssid == YOUR_SSID:
        intrusion_reasons.append(f"Authentication attempt on {YOUR_SSID}")
    
    if attack_type == "association" and ssid == YOUR_SSID:
        intrusion_reasons.append(f"Association request on {YOUR_SSID}")
    
    if attack_type == "deauth_attack":
        intrusion_reasons.append("Deauthentication attack detected")
    
    if attack_type == "probe_request" and ssid == YOUR_SSID:
        intrusion_reasons.append(f"Probing for {YOUR_SSID}")
    
    if intrusion_reasons:
        reason = " | ".join(intrusion_reasons)
        
        # Log threat
        threat_log.append({
            'time': datetime.now(),
            'mac': mac,
            'type': attack_type,
            'reason': reason,
            'rssi': rssi
        })
        
        return {
            'mac': mac,
            'attack_type': attack_type,
            'ssid': ssid,
            'rssi': rssi,
            'reason': reason,
            'timestamp': datetime.now().isoformat()
        }
    
    return None

# ========== AUTO-BLOCKING THREAD ==========
def auto_blocking_thread():
    """Background thread for auto-blocking"""
    print("🛡️ Auto-blocking thread started")
    
    while True:
        try:
            # Process recent packets for intrusions
            for packet in packets[-100:]:  # Check last 100 packets
                intrusion = check_intrusion(packet)
                
                if intrusion:
                    mac = intrusion['mac']
                    reason = intrusion['reason']
                    
                    # Auto-block for critical attacks
                    if intrusion['attack_type'] in ['auth_attempt', 'association', 'deauth_attack']:
                        if block_with_iptables(mac, reason):
                            # Send email alert
                            send_intrusion_alert(
                                mac, 
                                intrusion['attack_type'],
                                intrusion['ssid'],
                                intrusion['rssi']
                            )
            
            time.sleep(5)  # Check every 5 seconds
            
        except Exception as e:
            print(f"❌ Error in auto-blocking thread: {e}")
            time.sleep(10)

# ========== FLASK ROUTES ==========
@app.route('/')
def dashboard():
    """Main dashboard"""
    with open('dashboard.html', 'r') as f:
        html = f.read()
    return render_template_string(html, 
                                 server_ip=get_ip(),
                                 server_port=8000,
                                 your_ssid=YOUR_SSID)

@app.route('/api/packet', methods=['POST'])
def receive_packet():
    """Receive packet from ESP32"""
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data'}), 400
        
        # Add metadata
        data['received_at'] = datetime.now().isoformat()
        data['client_ip'] = request.remote_addr
        
        # Store packet
        packets.append(data)
        if len(packets) > 1000:
            packets.pop(0)
        
        # Update device info
        mac = data.get('mac', '').upper()
        if mac:
            if mac not in devices:
                devices[mac] = {
                    'mac': mac,
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'packet_count': 1,
                    'rssi': data.get('rssi', -99),
                    'channel': data.get('channel', 0),
                    'attack_types': set([data.get('attack_type', 'unknown')]),
                    'authorized': mac in authorized_macs
                }
            else:
                devices[mac]['last_seen'] = datetime.now()
                devices[mac]['packet_count'] += 1
                if 'attack_type' in data:
                    devices[mac]['attack_types'].add(data['attack_type'])
        
        print(f"📦 Packet: {mac} | {data.get('attack_type', 'unknown')}")
        
        return jsonify({
            'status': 'received',
            'authorized': mac in authorized_macs,
            'message': f'Packet from {mac} received'
        })
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices')
def get_devices():
    """Get all detected devices"""
    device_list = []
    for mac, info in devices.items():
        # Only include recent devices
        if (datetime.now() - info['last_seen']).seconds < 3600:
            device_list.append({
                'mac': mac,
                'first_seen': info['first_seen'].isoformat(),
                'last_seen': info['last_seen'].isoformat(),
                'packet_count': info['packet_count'],
                'rssi': info['rssi'],
                'channel': info['channel'],
                'attack_types': list(info.get('attack_types', [])),
                'authorized': info['authorized'],
                'blocked': is_mac_blocked(mac)
            })
    
    return jsonify(device_list)

@app.route('/api/block/<mac>', methods=['POST'])
def block_device(mac):
    """Manually block a device"""
    reason = request.json.get('reason', 'manual_block') if request.json else 'manual_block'
    
    if block_with_iptables(mac, reason):
        return jsonify({'status': 'blocked', 'mac': mac})
    else:
        return jsonify({'error': 'Failed to block'}), 500

@app.route('/api/unblock/<mac>', methods=['POST'])
def unblock_device(mac):
    """Unblock a device"""
    if unblock_mac(mac):
        return jsonify({'status': 'unblocked', 'mac': mac})
    else:
        return jsonify({'error': 'Failed to unblock'}), 500

@app.route('/api/blocked')
def list_blocked():
    """Get list of blocked devices"""
    return jsonify(get_blocked_devices())

@app.route('/api/threats')
def get_threats():
    """Get recent threats"""
    recent_threats = threat_log[-50:]
    formatted = []
    for threat in recent_threats:
        formatted.append({
            'time': threat['time'].isoformat(),
            'mac': threat['mac'],
            'type': threat['type'],
            'reason': threat['reason'],
            'rssi': threat['rssi']
        })
    return jsonify(formatted)

@app.route('/api/stats')
def get_stats():
    """Get system statistics"""
    # Count devices
    total = 0
    authorized = 0
    blocked = len(get_blocked_devices())
    
    for info in devices.values():
        if (datetime.now() - info['last_seen']).seconds < 3600:
            total += 1
            if info['authorized']:
                authorized += 1
    
    return jsonify({
        'total_devices': total,
        'authorized_devices': authorized,
        'unauthorized_devices': total - authorized,
        'blocked_devices': blocked,
        'total_packets': len(packets),
        'recent_threats': len(threat_log[-24:]),
        'server_time': datetime.now().isoformat()
    })

@app.route('/api/test_email', methods=['POST'])
def test_email():
    """Test email configuration"""
    test_subject = "✅ WIDS Test Email"
    test_body = "This is a test email from your WIDS system. If you receive this, email configuration is working correctly!"
    
    if send_email_alert(test_subject, test_body):
        return jsonify({'status': 'sent', 'message': 'Test email sent successfully'})
    else:
        return jsonify({'error': 'Failed to send test email'}), 500

def is_mac_blocked(mac):
    """Check if MAC is blocked"""
    blocked = get_blocked_devices()
    for device in blocked:
        if device['mac'].upper() == mac.upper():
            return True
    return False

def get_ip():
    """Get server IP"""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '127.0.0.1'

# ========== INITIALIZATION ==========
if __name__ == '__main__':
    print("\n" + "="*70)
    print("🚀 WIDS SERVER WITH AUTO-BLOCKING & EMAIL")
    print("="*70)
    
    # Initialize
    load_authorized_macs()
    init_database()
    
    # Start auto-blocking thread
    blocker_thread = threading.Thread(target=auto_blocking_thread, daemon=True)
    blocker_thread.start()
    
    print(f"📡 Protecting SSID: {YOUR_SSID}")
    print(f"📧 Email alerts: {'ENABLED' if EMAIL_CONFIG['enabled'] else 'DISABLED'}")
    print(f"🏠 Dashboard: http://{get_ip()}:8000")
    print(f"🔧 IPTables auto-blocking: ACTIVE")
    print("\n⚠️  IMPORTANT CONFIGURATION NEEDED:")
    print("   1. Update EMAIL_CONFIG in server.py with your email credentials")
    print("   2. Add your device MACs to authorized_macs.json")
    print("   3. Run with sudo for iptables access: sudo python3 server.py")
    print("="*70 + "\n")
    
    app.run(host='0.0.0.0', port=8000, debug=False, threaded=True)
