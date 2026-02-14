#!/usr/bin/env python3
"""
WIDS SERVER WITH AUTO-BLOCKING & EMAIL NOTIFICATIONS
Run with: sudo python3 server.py
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
import socket

app = Flask(__name__)

# ========== CONFIGURATION - CHANGE THESE VALUES ==========
YOUR_SSID = "Airtel_sath_0300"  # Your router SSID to protect

# Email Configuration (REQUIRED for notifications)
EMAIL_CONFIG = {
    'enabled': True,  # Set to False to disable email
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'your_email@gmail.com',  # CHANGE THIS
    'sender_password': 'your_app_password',  # CHANGE THIS (Google App Password)
    'recipient_email': 'your_email@gmail.com'  # CHANGE THIS
}

# Files and paths
AUTHORIZED_MACS_FILE = "authorized_macs.json"
DB_FILE = "wids_database.db"
BLOCK_LOG_FILE = "blocked_devices.log"
DASHBOARD_FILE = "dashboard.html"

# ========== DATA STORAGE ==========
devices = {}          # MAC -> device info
packets = []          # Recent packets (limit 1000)
authorized_macs = set()  # Authorized MACs from file
sensors = {}          # Sensor info
threat_log = []       # Threat detection log (limit 100)
packet_rates = defaultdict(list)

# ========== LOAD CONFIG ==========
def load_authorized_macs():
    """Load authorized MACs from file"""
    global authorized_macs
    try:
        if os.path.exists(AUTHORIZED_MACS_FILE):
            with open(AUTHORIZED_MACS_FILE, 'r') as f:
                data = json.load(f)
                authorized_macs = set(data.get('authorized_macs', []))
            print(f"✅ Loaded {len(authorized_macs)} authorized MACs")
        else:
            authorized_macs = set()
            # Create default file
            save_authorized_macs()
            print("📝 Created new authorized_macs.json file")
    except Exception as e:
        print(f"❌ Error loading authorized MACs: {e}")
        authorized_macs = set()

def save_authorized_macs():
    """Save authorized MACs to file"""
    try:
        with open(AUTHORIZED_MACS_FILE, 'w') as f:
            json.dump({
                'authorized_macs': list(authorized_macs),
                'updated': datetime.now().isoformat()
            }, f, indent=2)
        print(f"💾 Saved {len(authorized_macs)} authorized MACs")
        return True
    except Exception as e:
        print(f"❌ Error saving authorized MACs: {e}")
        return False

# ========== DATABASE FUNCTIONS ==========
def init_database():
    """Initialize SQLite database"""
    try:
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
        return True
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False

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
        c.execute("SELECT mac, reason, blocked_at FROM blocked_devices WHERE status='blocked' ORDER BY blocked_at DESC")
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
    except Exception as e:
        print(f"Error getting blocked devices: {e}")
        return []

def unblock_mac_in_db(mac):
    """Mark MAC as unblocked in database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("UPDATE blocked_devices SET status='unblocked', unblocked_at=? WHERE mac=?",
                 (datetime.now(), mac.upper()))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error unblocking in DB: {e}")
        return False

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
    subject = f"🚨 WIDS ALERT: {attack_type} detected on {ssid}"
    
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
                <p>Check dashboard for more details: http://{get_ip()}:8000</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return send_email_alert(subject, body_html, is_html=True)

# ========== IPTABLES BLOCKING FUNCTIONS (FIXED - NO SUDO) ==========
def block_with_iptables(mac, reason):
    """Block MAC address using iptables"""
    try:
        mac = mac.upper()
        
        # Check if already blocked - NO SUDO NEEDED
        check = subprocess.run(
            f"iptables -L INPUT -n 2>/dev/null | grep -i {mac}",
            shell=True, capture_output=True, text=True
        )
        
        if check.returncode != 0:  # Not blocked yet
            print(f"[{datetime.now()}] 🚨 BLOCKING {mac} - {reason}")
            
            # Block incoming traffic - NO SUDO
            result1 = subprocess.run(
                f"iptables -A INPUT -m mac --mac-source {mac} -j DROP",
                shell=True, capture_output=True, text=True
            )
            
            # Block forwarded traffic - NO SUDO
            result2 = subprocess.run(
                f"iptables -A FORWARD -m mac --mac-source {mac} -j DROP",
                shell=True, capture_output=True, text=True
            )
            
            # Try to save iptables rules - NO SUDO
            try:
                subprocess.run(
                    "iptables-save > /etc/iptables/rules.v4 2>/dev/null",
                    shell=True, timeout=5
                )
            except:
                pass  # Saving might fail, but blocking still works
            
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
        
        # Remove iptables rules - NO SUDO
        subprocess.run(
            f"iptables -D INPUT -m mac --mac-source {mac} -j DROP 2>/dev/null",
            shell=True
        )
        subprocess.run(
            f"iptables -D FORWARD -m mac --mac-source {mac} -j DROP 2>/dev/null",
            shell=True
        )
        
        # Update database
        unblock_mac_in_db(mac)
        
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
    
    # Skip if no MAC
    if not mac or mac == '00:00:00:00:00:00':
        return None
    
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
        
        # Keep only last 100 threats
        if len(threat_log) > 100:
            threat_log.pop(0)
        
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
            processed_macs = set()
            for packet in packets[-100:]:  # Check last 100 packets
                intrusion = check_intrusion(packet)
                
                if intrusion:
                    mac = intrusion['mac']
                    
                    # Skip if already processed in this cycle
                    if mac in processed_macs:
                        continue
                    
                    processed_macs.add(mac)
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
            
        except KeyboardInterrupt:
            print("\n🛑 Stopping auto-blocking thread")
            break
        except Exception as e:
            print(f"❌ Error in auto-blocking thread: {e}")
            time.sleep(10)

# ========== FLASK ROUTES ==========
@app.route('/')
def dashboard():
    """Main dashboard"""
    try:
        # Check if dashboard.html exists
        if not os.path.exists(DASHBOARD_FILE):
            return "Error: dashboard.html not found. Please create it.", 404
            
        with open(DASHBOARD_FILE, 'r') as f:
            html = f.read()
            
        return render_template_string(html, 
                                     server_ip=get_ip(),
                                     server_port=8000,
                                     your_ssid=YOUR_SSID)
    except Exception as e:
        return f"Error loading dashboard: {e}", 500

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
        if mac and mac != '00:00:00:00:00:00':
            if mac not in devices:
                devices[mac] = {
                    'mac': mac,
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'packet_count': 1,
                    'rssi': data.get('rssi', -99),
                    'channel': data.get('channel', 0),
                    'attack_types': set(),
                    'authorized': mac in authorized_macs
                }
            else:
                devices[mac]['last_seen'] = datetime.now()
                devices[mac]['packet_count'] += 1
                devices[mac]['rssi'] = data.get('rssi', devices[mac]['rssi'])
            
            if 'attack_type' in data and data['attack_type']:
                devices[mac]['attack_types'].add(data['attack_type'])
        
        print(f"📦 Packet: {mac} | {data.get('attack_type', 'unknown')}")
        
        return jsonify({
            'status': 'received',
            'authorized': mac in authorized_macs,
            'message': f'Packet from {mac} received'
        })
        
    except Exception as e:
        print(f"❌ Error processing packet: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices', methods=['GET'])
def get_devices():
    """Get all detected devices"""
    try:
        device_list = []
        now = datetime.now()
        
        for mac, info in devices.items():
            # Only include recent devices (last hour)
            if (now - info['last_seen']).total_seconds() < 3600:
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
        
        # Sort by last seen (newest first)
        device_list.sort(key=lambda x: x['last_seen'], reverse=True)
        
        return jsonify(device_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/packets', methods=['GET'])
def get_packets():
    """Get recent packets"""
    try:
        recent_packets = []
        for p in packets[-50:]:
            recent_packets.append({
                'mac': p.get('mac', 'unknown'),
                'rssi': p.get('rssi', -99),
                'channel': p.get('channel', 0),
                'attack_type': p.get('attack_type', 'unknown'),
                'ssid': p.get('ssid', ''),
                'timestamp': p.get('received_at', '')
            })
        
        return jsonify(recent_packets[::-1])  # Reverse to show newest first
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/authorized', methods=['GET'])
def get_authorized():
    """Get list of authorized MACs"""
    try:
        auth_list = []
        for mac in sorted(authorized_macs):
            auth_list.append({
                'mac': mac,
                'added_at': 'From config'
            })
        return jsonify(auth_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/authorize/<mac>', methods=['POST'])
def authorize_mac(mac):
    """Add MAC to authorized list"""
    try:
        mac_upper = mac.upper()
        
        # Validate MAC format
        if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac_upper):
            return jsonify({'error': 'Invalid MAC format. Use AA:BB:CC:DD:EE:FF'}), 400
        
        authorized_macs.add(mac_upper)
        
        # Update device if it exists
        if mac_upper in devices:
            devices[mac_upper]['authorized'] = True
        
        # Save to file
        save_authorized_macs()
        
        print(f"✅ Authorized MAC: {mac_upper}")
        return jsonify({'status': 'authorized', 'mac': mac_upper})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/unauthorize/<mac>', methods=['POST'])
def unauthorize_mac(mac):
    """Remove MAC from authorized list"""
    try:
        mac_upper = mac.upper()
        authorized_macs.discard(mac_upper)
        
        # Update device if it exists
        if mac_upper in devices:
            devices[mac_upper]['authorized'] = False
        
        # Save to file
        save_authorized_macs()
        
        print(f"❌ Unauthorized MAC: {mac_upper}")
        return jsonify({'status': 'unauthorized', 'mac': mac_upper})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/block/<mac>', methods=['POST'])
def block_device(mac):
    """Manually block a device"""
    try:
        reason = request.json.get('reason', 'manual_block') if request.json else 'manual_block'
        
        if block_with_iptables(mac, reason):
            return jsonify({'status': 'blocked', 'mac': mac, 'message': f'Blocked {mac}'})
        else:
            return jsonify({'error': 'Failed to block'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/unblock/<mac>', methods=['POST'])
def unblock_device(mac):
    """Unblock a device"""
    try:
        if unblock_mac(mac):
            return jsonify({'status': 'unblocked', 'mac': mac, 'message': f'Unblocked {mac}'})
        else:
            return jsonify({'error': 'Failed to unblock'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blocked', methods=['GET'])
def list_blocked():
    """Get list of blocked devices"""
    try:
        return jsonify(get_blocked_devices())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get recent threats"""
    try:
        recent_threats = []
        for threat in threat_log[-50:]:
            recent_threats.append({
                'time': threat['time'].isoformat(),
                'mac': threat['mac'],
                'type': threat['type'],
                'reason': threat['reason'],
                'rssi': threat['rssi']
            })
        return jsonify(recent_threats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get system statistics"""
    try:
        # Count devices
        total = 0
        authorized = 0
        now = datetime.now()
        
        for info in devices.values():
            if (now - info['last_seen']).total_seconds() < 3600:
                total += 1
                if info['authorized']:
                    authorized += 1
        
        blocked = len(get_blocked_devices())
        
        return jsonify({
            'total_devices': total,
            'authorized_devices': authorized,
            'unauthorized_devices': total - authorized,
            'blocked_devices': blocked,
            'total_packets': len(packets),
            'recent_threats': len(threat_log[-24:]),
            'server_time': datetime.now().isoformat(),
            'server_ip': get_ip(),
            'protected_ssid': YOUR_SSID
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test_email', methods=['POST'])
def test_email():
    """Test email configuration"""
    try:
        test_subject = "✅ WIDS Test Email"
        test_body = "This is a test email from your WIDS system. If you receive this, email configuration is working correctly!"
        
        if send_email_alert(test_subject, test_body):
            return jsonify({'status': 'sent', 'message': 'Test email sent successfully'})
        else:
            return jsonify({'error': 'Failed to send test email'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get system status"""
    return jsonify({
        'status': 'running',
        'time': datetime.now().isoformat(),
        'email_enabled': EMAIL_CONFIG['enabled'],
        'authorized_count': len(authorized_macs),
        'device_count': len(devices),
        'packet_count': len(packets),
        'blocked_count': len(get_blocked_devices())
    })

# ========== UTILITY FUNCTIONS ==========
def is_mac_blocked(mac):
    """Check if MAC is blocked"""
    blocked = get_blocked_devices()
    for device in blocked:
        if device['mac'].upper() == mac.upper():
            return True
    return False

def get_ip():
    """Get server IP address"""
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
    
    # Check if running as root (required for iptables)
    if os.geteuid() != 0:
        print("❌ ERROR: Must run with sudo for iptables access!")
        print("   Run: sudo python3 server.py")
        sys.exit(1)
    
    # Load configuration
    load_authorized_macs()
    init_database()
    
    # Start auto-blocking thread
    blocker_thread = threading.Thread(target=auto_blocking_thread, daemon=True)
    blocker_thread.start()
    
    print(f"\n📡 Protecting SSID: {YOUR_SSID}")
    print(f"📧 Email alerts: {'ENABLED' if EMAIL_CONFIG['enabled'] else 'DISABLED'}")
    print(f"🏠 Dashboard URL: http://{get_ip()}:8000")
    print(f"🔧 IPTables auto-blocking: ACTIVE")
    print(f"📁 Database: {DB_FILE}")
    print(f"📝 Log file: {BLOCK_LOG_FILE}")
    
    print("\n⚠️  IMPORTANT CONFIGURATION:")
    print("   1. Edit EMAIL_CONFIG in server.py with your credentials")
    print("   2. Add your device MACs via dashboard (Authorized MACs tab)")
    print("   3. Make sure dashboard.html exists in current directory")
    print("\n✅ Server starting... Press Ctrl+C to stop")
    print("="*70 + "\n")
    
    # Run Flask
    app.run(host='0.0.0.0', port=8000, debug=False, threaded=True)
