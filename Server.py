#!/usr/bin/env python3
"""
WIDS SERVER with iptables auto-blocking and MAC authorization
"""
from flask import Flask, request, jsonify, render_template_string
from datetime import datetime, timedelta
from collections import defaultdict
import json
import subprocess
import threading
import time
import os

app = Flask(__name__)

# ========== CONFIGURATION ==========
WHITELIST_MACS = [
    "AA:BB:CC:DD:EE:FF",  # Example: Your laptop MAC
    "11:22:33:44:55:66",  # Example: Your phone MAC
]

BLOCK_DURATION = 3600  # Block for 1 hour (seconds)
AUTO_BLOCK_THRESHOLD = 10  # Auto-block if packets/sec > this

# ========== DATA STORAGE ==========
devices = {}          # MAC -> device info
packets = []          # Recent packets
blocked_macs = set()  # Manually blocked devices
sensors = {}          # Sensor info
authorized_macs = set(WHITELIST_MACS)  # Authorized MACs
packet_rates = defaultdict(list)  # MAC -> list of timestamps for rate calculation

# ========== IPTABLES MANAGER ==========
class IPTablesManager:
    def __init__(self):
        self.iptables_chain = "WIDS_BLOCK"  # Custom iptables chain
        self.setup_iptables_chain()
    
    def setup_iptables_chain(self):
        """Create custom iptables chain if not exists"""
        try:
            # Check if chain exists
            result = subprocess.run(
                ["sudo", "iptables", "-L", self.iptables_chain, "-n"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                # Create chain
                subprocess.run(["sudo", "iptables", "-N", self.iptables_chain], check=True)
                print(f"✅ Created iptables chain: {self.iptables_chain}")
                
                # Add chain to INPUT and FORWARD
                subprocess.run(
                    ["sudo", "iptables", "-I", "INPUT", "-j", self.iptables_chain],
                    check=True
                )
                subprocess.run(
                    ["sudo", "iptables", "-I", "FORWARD", "-j", self.iptables_chain],
                    check=True
                )
                print("✅ Added chain to INPUT and FORWARD")
        except Exception as e:
            print(f"⚠️ Warning: Could not setup iptables chain: {e}")
    
    def block_mac(self, mac_address, duration=BLOCK_DURATION):
        """Block a MAC address using iptables"""
        try:
            # Convert MAC to lowercase without colons for iptables
            mac_clean = mac_address.lower().replace(':', '')
            
            # Check if already blocked
            check_cmd = [
                "sudo", "iptables", "-C", self.iptables_chain,
                "-m", "mac", "--mac-source", mac_address,
                "-j", "DROP"
            ]
            
            result = subprocess.run(check_cmd, capture_output=True, text=True)
            
            if result.returncode != 0:  # Not already blocked
                # Add blocking rule
                block_cmd = [
                    "sudo", "iptables", "-A", self.iptables_chain,
                    "-m", "mac", "--mac-source", mac_address,
                    "-j", "DROP"
                ]
                subprocess.run(block_cmd, check=True)
                
                print(f"🚫 iptables: Blocked MAC {mac_address}")
                
                # Schedule unblock
                if duration > 0:
                    threading.Timer(
                        duration,
                        self.unblock_mac,
                        args=[mac_address]
                    ).start()
                
                return True
            else:
                print(f"ℹ️ MAC {mac_address} already blocked in iptables")
                return False
                
        except Exception as e:
            print(f"❌ Error blocking MAC {mac_address}: {e}")
            return False
    
    def unblock_mac(self, mac_address):
        """Unblock a MAC address from iptables"""
        try:
            # Remove blocking rule
            unblock_cmd = [
                "sudo", "iptables", "-D", self.iptables_chain,
                "-m", "mac", "--mac-source", mac_address,
                "-j", "DROP"
            ]
            
            result = subprocess.run(unblock_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"✅ iptables: Unblocked MAC {mac_address}")
                return True
            else:
                # Rule might not exist, try alternative removal
                print(f"⚠️ Could not find rule for MAC {mac_address}, cleaning up...")
                self.cleanup_rules()
                return False
                
        except Exception as e:
            print(f"❌ Error unblocking MAC {mac_address}: {e}")
            return False
    
    def cleanup_rules(self):
        """Remove all rules from WIDS chain"""
        try:
            # Flush the chain (remove all rules)
            subprocess.run(["sudo", "iptables", "-F", self.iptables_chain], check=True)
            print("🧹 Cleaned up iptables WIDS rules")
            return True
        except Exception as e:
            print(f"❌ Error cleaning iptables: {e}")
            return False
    
    def list_blocked(self):
        """List currently blocked MACs"""
        try:
            result = subprocess.run(
                ["sudo", "iptables", "-L", self.iptables_chain, "-n", "-v"],
                capture_output=True,
                text=True
            )
            
            blocked = []
            for line in result.stdout.split('\n'):
                if "MAC" in line and "DROP" in line:
                    # Extract MAC address from line
                    parts = line.split()
                    for part in parts:
                        if ":" in part and len(part) == 17:  # MAC address
                            blocked.append(part)
            
            return blocked
        except Exception as e:
            print(f"❌ Error listing blocked MACs: {e}")
            return []
    
    def is_blocked(self, mac_address):
        """Check if MAC is currently blocked"""
        blocked = self.list_blocked()
        return mac_address in blocked

# Initialize iptables manager
iptables = IPTablesManager()

# ========== THREAT DETECTION ==========
class ThreatDetector:
    def __init__(self):
        self.suspicious_patterns = [
            "deauth", "disassoc", "auth", "probe", "beacon_flood"
        ]
    
    def analyze_packet(self, packet_data):
        """Analyze packet for suspicious patterns"""
        threats = []
        
        # Check for deauthentication packets (simplified)
        if packet_data.get('packet_type') == 'deauth':
            threats.append({
                'type': 'deauthentication_attack',
                'severity': 'high',
                'description': 'Deauthentication packet detected'
            })
        
        # Check packet rate
        mac = packet_data.get('mac', '')
        if mac:
            current_time = time.time()
            packet_rates[mac].append(current_time)
            
            # Keep only last 10 seconds of packets
            packet_rates[mac] = [
                t for t in packet_rates[mac] 
                if current_time - t < 10
            ]
            
            # Calculate packets per second
            pps = len(packet_rates[mac]) / 10.0
            
            if pps > AUTO_BLOCK_THRESHOLD:
                threats.append({
                    'type': 'packet_flood',
                    'severity': 'critical',
                    'description': f'High packet rate: {pps:.1f} packets/sec'
                })
        
        # Check if MAC is in whitelist
        if mac not in authorized_macs:
            threats.append({
                'type': 'unauthorized_device',
                'severity': 'medium',
                'description': 'Device not in authorized list'
            })
        
        return threats

threat_detector = ThreatDetector()

# ========== DASHBOARD HTML (UPDATED) ==========
HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>WIDS Dashboard with Auto-Blocking</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f1f5f9; }
        
        /* Header */
        .header { background: linear-gradient(135deg, #1e40af 0%, #1e3a8a 100%); 
                 padding: 20px; border-bottom: 3px solid #3b82f6; }
        .header h1 { font-size: 28px; margin-bottom: 5px; }
        .header p { color: #94a3b8; font-size: 14px; }
        
        /* Stats Cards */
        .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 20px; padding: 20px; }
        .stat-card { background: #1e293b; padding: 20px; border-radius: 10px; border-left: 4px solid #3b82f6; }
        .stat-card.critical { border-left-color: #ef4444; }
        .stat-card.warning { border-left-color: #f59e0b; }
        .stat-card.success { border-left-color: #10b981; }
        .stat-card h3 { font-size: 32px; color: #60a5fa; margin-bottom: 5px; }
        .stat-card.critical h3 { color: #ef4444; }
        .stat-card.warning h3 { color: #f59e0b; }
        .stat-card.success h3 { color: #10b981; }
        .stat-card p { color: #94a3b8; font-size: 14px; }
        
        /* Tabs */
        .tabs { display: flex; background: #1e293b; margin: 0 20px; border-radius: 10px 10px 0 0; overflow: hidden; }
        .tab { flex: 1; padding: 15px; text-align: center; cursor: pointer; border-bottom: 3px solid transparent; }
        .tab.active { background: #334155; border-bottom-color: #3b82f6; }
        .tab:hover { background: #2d3748; }
        
        /* Main Content */
        .main-content { padding: 0 20px 20px; }
        .tab-content { display: none; background: #1e293b; border-radius: 0 0 10px 10px; overflow: hidden; }
        .tab-content.active { display: block; }
        
        /* Tables */
        .panel-header { background: #334155; padding: 15px; border-bottom: 1px solid #475569; }
        .panel-header h3 { font-size: 18px; }
        
        table { width: 100%; border-collapse: collapse; }
        th { background: #334155; padding: 12px 15px; text-align: left; font-size: 14px; color: #cbd5e1; }
        td { padding: 12px 15px; border-bottom: 1px solid #334155; }
        tr:hover { background: #2d3748; }
        
        /* Buttons */
        .btn { border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; margin: 2px; }
        .btn-block { background: #ef4444; color: white; }
        .btn-unblock { background: #10b981; color: white; }
        .btn-authorize { background: #3b82f6; color: white; }
        .btn-unauthorize { background: #f59e0b; color: white; }
        
        /* Status badges */
        .status { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .status-authorized { background: #10b98120; color: #10b981; }
        .status-unauthorized { background: #f59e0b20; color: #f59e0b; }
        .status-blocked { background: #ef444420; color: #ef4444; }
        .status-active { background: #3b82f620; color: #3b82f6; }
        
        /* Log entries */
        .log-entry { padding: 10px 15px; border-bottom: 1px solid #334155; font-size: 13px; }
        .log-entry.critical { background: #ef444410; border-left: 3px solid #ef4444; }
        .log-entry.warning { background: #f59e0b10; border-left: 3px solid #f59e0b; }
        .log-entry.info { background: #3b82f610; border-left: 3px solid #3b82f6; }
        .log-time { color: #94a3b8; font-size: 12px; }
        .log-message { margin-top: 3px; }
        
        /* Forms */
        .form-group { padding: 15px; }
        .form-input { width: 100%; padding: 10px; background: #334155; border: 1px solid #475569; border-radius: 4px; color: white; margin-bottom: 10px; }
        .form-label { display: block; margin-bottom: 5px; color: #cbd5e1; }
        
        /* Footer */
        .footer { text-align: center; padding: 15px; color: #64748b; font-size: 12px; border-top: 1px solid #334155; margin-top: 20px; }
        
        /* Refresh button */
        .refresh-btn { background: #3b82f6; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; margin: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ WIDS Dashboard with Auto-Blocking</h1>
        <p>Wireless Intrusion Detection System | iptables Auto-Block | MAC Authorization</p>
        <button class="refresh-btn" onclick="loadDashboard()">🔄 Refresh</button>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <h3 id="totalDevices">0</h3>
            <p>Devices Detected</p>
        </div>
        <div class="stat-card">
            <h3 id="totalPackets">0</h3>
            <p>Packets Received</p>
        </div>
        <div class="stat-card warning">
            <h3 id="unauthorizedDevices">0</h3>
            <p>Unauthorized</p>
        </div>
        <div class="stat-card critical">
            <h3 id="blockedDevices">0</h3>
            <p>Blocked (iptables)</p>
        </div>
        <div class="stat-card success">
            <h3 id="authorizedDevices">0</h3>
            <p>Authorized</p>
        </div>
    </div>
    
    <div class="tabs">
        <div class="tab active" onclick="switchTab('devices')">📱 Devices</div>
        <div class="tab" onclick="switchTab('authorized')">✅ Authorized MACs</div>
        <div class="tab" onclick="switchTab('blocked')">🚫 Blocked Devices</div>
        <div class="tab" onclick="switchTab('threats')">⚠️ Threat Log</div>
        <div class="tab" onclick="switchTab('settings')">⚙️ Settings</div>
    </div>
    
    <div class="main-content">
        <!-- Devices Tab -->
        <div id="tab-devices" class="tab-content active">
            <div class="panel-header">
                <h3>Detected Devices</h3>
            </div>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>MAC Address</th>
                            <th>Signal</th>
                            <th>Channel</th>
                            <th>Packets</th>
                            <th>Rate</th>
                            <th>Status</th>
                            <th>Authorization</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="deviceTable"></tbody>
                </table>
            </div>
        </div>
        
        <!-- Authorized MACs Tab -->
        <div id="tab-authorized" class="tab-content">
            <div class="panel-header">
                <h3>Authorized MAC Addresses</h3>
            </div>
            <div class="form-group">
                <input type="text" id="newMac" class="form-input" placeholder="AA:BB:CC:DD:EE:FF">
                <button class="btn btn-authorize" onclick="addAuthorizedMac()">Add Authorized MAC</button>
            </div>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>MAC Address</th>
                            <th>Added At</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="authorizedTable"></tbody>
                </table>
            </div>
        </div>
        
        <!-- Blocked Devices Tab -->
        <div id="tab-blocked" class="tab-content">
            <div class="panel-header">
                <h3>Blocked Devices (iptables)</h3>
            </div>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>MAC Address</th>
                            <th>Blocked At</th>
                            <th>Reason</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="blockedTable"></tbody>
                </table>
            </div>
        </div>
        
        <!-- Threat Log Tab -->
        <div id="tab-threats" class="tab-content">
            <div class="panel-header">
                <h3>Threat Detection Log</h3>
            </div>
            <div id="threatLog" style="max-height: 500px; overflow-y: auto;">
                <div class="log-entry info">
                    <div class="log-time" id="currentTime">--:--:--</div>
                    <div class="log-message">✅ Threat detection system active</div>
                </div>
            </div>
        </div>
        
        <!-- Settings Tab -->
        <div id="tab-settings" class="tab-content">
            <div class="panel-header">
                <h3>System Settings</h3>
            </div>
            <div class="form-group">
                <label class="form-label">Auto-block Threshold (packets/sec)</label>
                <input type="number" id="blockThreshold" class="form-input" value="10" min="1" max="100">
                
                <label class="form-label">Block Duration (seconds)</label>
                <input type="number" id="blockDuration" class="form-input" value="3600" min="60" max="86400">
                
                <button class="btn btn-authorize" onclick="updateSettings()">Update Settings</button>
                <button class="btn" onclick="clearAllBlocks()" style="background: #ef4444;">Clear All Blocks</button>
            </div>
        </div>
    </div>
    
    <div class="footer">
        <p>WIDS System v2.0 | Auto-Blocking with iptables | Server: {{ server_ip }}:{{ server_port }}</p>
    </div>
    
    <script>
        let currentTab = 'devices';
        
        // Update current time
        function updateTime() {
            const now = new Date();
            document.getElementById('currentTime').textContent = now.toLocaleTimeString();
        }
        setInterval(updateTime, 1000);
        updateTime();
        
        // Tab switching
        function switchTab(tabName) {
            currentTab = tabName;
            
            // Update tab buttons
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            event.target.classList.add('active');
            
            // Update tab content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(`tab-${tabName}`).classList.add('active');
            
            // Load tab data
            loadTabData(tabName);
        }
        
        // Load dashboard data
        async function loadDashboard() {
            try {
                // Load stats
                const statsRes = await fetch('/api/stats');
                const stats = await statsRes.json();
                
                document.getElementById('totalDevices').textContent = stats.device_count;
                document.getElementById('totalPackets').textContent = stats.packet_count;
                document.getElementById('unauthorizedDevices').textContent = stats.unauthorized_count;
                document.getElementById('blockedDevices').textContent = stats.blocked_count;
                document.getElementById('authorizedDevices').textContent = stats.authorized_count;
                
                // Load current tab data
                loadTabData(currentTab);
                
                addLogEntry('info', '🔄 Dashboard refreshed');
                
            } catch (error) {
                console.error('Error loading dashboard:', error);
                addLogEntry('critical', '❌ Error loading data');
            }
        }
        
        // Load specific tab data
        async function loadTabData(tabName) {
            switch(tabName) {
                case 'devices':
                    await loadDevices();
                    break;
                case 'authorized':
                    await loadAuthorizedMacs();
                    break;
                case 'blocked':
                    await loadBlockedDevices();
                    break;
                case 'threats':
                    await loadThreatLog();
                    break;
            }
        }
        
        // Load devices
        async function loadDevices() {
            try {
                const devicesRes = await fetch('/api/devices');
                const devices = await devicesRes.json();
                
                const tbody = document.getElementById('deviceTable');
                tbody.innerHTML = '';
                
                devices.forEach(device => {
                    const row = tbody.insertRow();
                    
                    // Calculate packet rate
                    const rate = device.packet_rate ? device.packet_rate.toFixed(1) : '0.0';
                    
                    // Determine status
                    let statusClass, statusText;
                    if (device.blocked) {
                        statusClass = 'status-blocked';
                        statusText = 'BLOCKED';
                    } else if (device.authorized) {
                        statusClass = 'status-authorized';
                        statusText = 'AUTHORIZED';
                    } else {
                        statusClass = 'status-unauthorized';
                        statusText = 'UNAUTHORIZED';
                    }
                    
                    // Determine threat level
                    let threatClass = '';
                    if (device.threat_level === 'critical') threatClass = 'critical';
                    if (device.threat_level === 'warning') threatClass = 'warning';
                    
                    row.innerHTML = `
                        <td><code style="font-family: monospace;">${device.mac}</code></td>
                        <td>${device.rssi || -99} dBm</td>
                        <td>${device.channel || 0}</td>
                        <td>${device.packet_count || 1}</td>
                        <td>${rate} pps</td>
                        <td><span class="status ${statusClass} ${threatClass}">${statusText}</span></td>
                        <td>
                            <button class="btn ${device.authorized ? 'btn-unauthorize' : 'btn-authorize'}" 
                                    onclick="toggleAuthorization('${device.mac}')">
                                ${device.authorized ? 'Remove Auth' : 'Authorize'}
                            </button>
                        </td>
                        <td>
                            <button class="btn ${device.blocked ? 'btn-unblock' : 'btn-block'}" 
                                    onclick="toggleBlock('${device.mac}')">
                                ${device.blocked ? 'Unblock' : 'Block'}
                            </button>
                        </td>
                    `;
                });
                
            } catch (error) {
                console.error('Error loading devices:', error);
            }
        }
        
        // Load authorized MACs
        async function loadAuthorizedMacs() {
            try {
                const authRes = await fetch('/api/authorized');
                const authorized = await authRes.json();
                
                const tbody = document.getElementById('authorizedTable');
                tbody.innerHTML = '';
                
                authorized.forEach(mac => {
                    const row = tbody.insertRow();
                    row.innerHTML = `
                        <td><code style="font-family: monospace;">${mac.mac}</code></td>
                        <td>${mac.added_at || 'Unknown'}</td>
                        <td>
                            <button class="btn btn-unauthorize" onclick="removeAuthorizedMac('${mac.mac}')">
                                Remove
                            </button>
                        </td>
                    `;
                });
                
            } catch (error) {
                console.error('Error loading authorized MACs:', error);
            }
        }
        
        // Load blocked devices
        async function loadBlockedDevices() {
            try {
                const blockedRes = await fetch('/api/blocked');
                const blocked = await blockedRes.json();
                
                const tbody = document.getElementById('blockedTable');
                tbody.innerHTML = '';
                
                blocked.forEach(device => {
                    const row = tbody.insertRow();
                    row.innerHTML = `
                        <td><code style="font-family: monospace;">${device.mac}</code></td>
                        <td>${device.blocked_at || 'Unknown'}</td>
                        <td>${device.reason || 'Manual block'}</td>
                        <td>
                            <button class="btn btn-unblock" onclick="unblockDevice('${device.mac}')">
                                Unblock
                            </button>
                        </td>
                    `;
                });
                
            } catch (error) {
                console.error('Error loading blocked devices:', error);
            }
        }
        
        // Load threat log
        async function loadThreatLog() {
            try {
                const threatsRes = await fetch('/api/threats');
                const threats = await threatsRes.json();
                
                const logDiv = document.getElementById('threatLog');
                
                // Clear existing logs (keep first info message)
                while (logDiv.children.length > 1) {
                    logDiv.removeChild(logDiv.lastChild);
                }
                
                // Add new threat logs
                threats.forEach(threat => {
                    addLogEntry(threat.severity || 'info', threat.message);
                });
                
            } catch (error) {
                console.error('Error loading threats:', error);
            }
        }
        
        // Add authorized MAC
        async function addAuthorizedMac() {
            const macInput = document.getElementById('newMac');
            const mac = macInput.value.trim().toUpperCase();
            
            if (!mac.match(/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/)) {
                alert('Invalid MAC address format. Use AA:BB:CC:DD:EE:FF');
                return;
            }
            
            try {
                const response = await fetch(`/api/authorize/${mac}`, {
                    method: 'POST'
                });
                const result = await response.json();
                
                if (response.ok) {
                    macInput.value = '';
                    loadAuthorizedMacs();
                    loadDashboard();
                    addLogEntry('info', `✅ Authorized MAC: ${mac}`);
                } else {
                    alert(result.error || 'Failed to authorize MAC');
                }
            } catch (error) {
                console.error('Error authorizing MAC:', error);
            }
        }
        
        // Remove authorized MAC
        async function removeAuthorizedMac(mac) {
            if (!confirm(`Remove ${mac} from authorized list?`)) return;
            
            try {
                const response = await fetch(`/api/unauthorize/${mac}`, {
                    method: 'POST'
                });
                
                if (response.ok) {
                    loadAuthorizedMacs();
                    loadDashboard();
                    addLogEntry('warning', `⚠️ Removed authorization: ${mac}`);
                }
            } catch (error) {
                console.error('Error removing authorized MAC:', error);
            }
        }
        
        // Toggle authorization
        async function toggleAuthorization(mac) {
            try {
                const response = await fetch(`/api/device/${mac}/toggle_auth`, {
                    method: 'POST'
                });
                const result = await response.json();
                
                loadDashboard();
                addLogEntry('info', 
                    result.authorized ? `✅ Authorized: ${mac}` : `⚠️ Unauthorized: ${mac}`
                );
            } catch (error) {
                console.error('Error toggling authorization:', error);
            }
        }
        
        // Toggle block
        async function toggleBlock(mac) {
            try {
                const response = await fetch(`/api/device/${mac}/toggle_block`, {
                    method: 'POST'
                });
                const result = await response.json();
                
                loadDashboard();
                addLogEntry(result.status === 'blocked' ? 'critical' : 'info',
                    result.status === 'blocked' ? `🚫 Blocked: ${mac}` : `✅ Unblocked: ${mac}`
                );
            } catch (error) {
                console.error('Error toggling block:', error);
            }
        }
        
        // Unblock device
        async function unblockDevice(mac) {
            try {
                const response = await fetch(`/api/unblock/${mac}`, {
                    method: 'POST'
                });
                
                if (response.ok) {
                    loadBlockedDevices();
                    loadDashboard();
                    addLogEntry('info', `✅ Unblocked: ${mac}`);
                }
            } catch (error) {
                console.error('Error unblocking device:', error);
            }
        }
        
        // Update settings
        async function updateSettings() {
            const threshold = document.getElementById('blockThreshold').value;
            const duration = document.getElementById('blockDuration').value;
            
            try {
                const response = await fetch('/api/settings', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        threshold: parseInt(threshold),
                        duration: parseInt(duration)
                    })
                });
                
                if (response.ok) {
                    addLogEntry('info', '✅ Settings updated');
                }
            } catch (error) {
                console.error('Error updating settings:', error);
            }
        }
        
        // Clear all blocks
        async function clearAllBlocks() {
            if (!confirm('Clear ALL iptables blocks? This will unblock all devices.')) return;
            
            try {
                const response = await fetch('/api/clear_blocks', {
                    method: 'POST'
                });
                
                if (response.ok) {
                    loadDashboard();
                    addLogEntry('info', '🧹 Cleared all iptables blocks');
                }
            } catch (error) {
                console.error('Error clearing blocks:', error);
            }
        }
        
        // Add log entry
        function addLogEntry(type, message) {
            const logDiv = document.getElementById('threatLog');
            const entry = document.createElement('div');
            entry.className = `log-entry ${type}`;
            
            const time = new Date().toLocaleTimeString();
            entry.innerHTML = `
                <div class="log-time">${time}</div>
                <div class="log-message">${message}</div>
            `;
            
            // Add to top
            logDiv.insertBefore(entry, logDiv.children[1]);
            
            // Keep only last 50 entries
            while (logDiv.children.length > 51) {
                logDiv.removeChild(logDiv.lastChild);
            }
        }
        
        // Auto-refresh every 3 seconds
        setInterval(loadDashboard, 3000);
        
        // Initial load
        loadDashboard();
    </script>
</body>
</html>
"""

# ========== THREAT LOG ==========
threat_log = []

def log_threat(mac, threat_type, severity, description):
    """Log a threat detection"""
    entry = {
        'timestamp': datetime.now().isoformat(),
        'mac': mac,
        'type': threat_type,
        'severity': severity,
        'message': description
    }
    threat_log.append(entry)
    
    # Keep only last 100 threats
    if len(threat_log) > 100:
        threat_log.pop(0)
    
    # Print to console
    print(f"⚠️ THREAT: {mac} - {threat_type} ({severity}): {description}")
    
    return entry

# ========== ROUTES ==========
@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template_string(HTML, server_ip=get_ip(), server_port=8000)

@app.route('/api/packet', methods=['POST'])
def receive_packet():
    """Receive packet from ESP32"""
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data'}), 400
        
        client_ip = request.remote_addr
        mac = data.get('mac', '00:00:00:00:00:00')
        sensor_id = data.get('sensor_id', 'unknown')
        
        print(f"📦 Packet from {client_ip} - MAC: {mac}")
        
        # Add timestamp
        data['received_at'] = datetime.now().isoformat()
        data['client_ip'] = client_ip
        
        # Store packet
        packets.append(data)
        
        # Keep last 1000 packets only
        if len(packets) > 1000:
            packets.pop(0)
        
        # Update device info
        if mac not in devices:
            devices[mac] = {
                'mac': mac,
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat(),
                'packet_count': 1,
                'rssi': data.get('rssi', -99),
                'channel': data.get('channel', 0),
                'authorized': mac in authorized_macs,
                'threat_level': 'normal',
                'sensor': sensor_id
            }
            print(f"🆕 New device: {mac}")
        else:
            devices[mac]['last_seen'] = datetime.now().isoformat()
            devices[mac]['packet_count'] += 1
            devices[mac]['rssi'] = data.get('rssi', devices[mac]['rssi'])
            devices[mac]['channel'] = data.get('channel', devices[mac]['channel'])
        
        # Check if blocked in iptables
        iptables_blocked = iptables.is_blocked(mac)
        devices[mac]['blocked'] = iptables_blocked or (mac in blocked_macs)
        
        # Run threat detection
        threats = threat_detector.analyze_packet(data)
        
        # Process threats
        auto_blocked = False
        for threat in threats:
            # Log the threat
            log_threat(mac, threat['type'], threat['severity'], threat['description'])
            
            # Auto-block for critical threats
            if threat['severity'] == 'critical' and not devices[mac]['authorized']:
                if iptables.block_mac(mac, BLOCK_DURATION):
                    devices[mac]['blocked'] = True
                    blocked_macs.add(mac)
                    auto_blocked = True
                    print(f"🚫 AUTO-BLOCKED {mac} - {threat['description']}")
        
        # Update threat level
        if threats:
            devices[mac]['threat_level'] = threats[0]['severity']
        
        # Calculate packet rate
        current_time = time.time()
        if mac not in packet_rates:
            packet_rates[mac] = []
        packet_rates[mac].append(current_time)
        
        # Clean old timestamps (keep last 30 seconds)
        packet_rates[mac] = [t for t in packet_rates[mac] if current_time - t < 30]
        
        print(f"✅ Packet #{len(packets)} from {mac} processed")
        
        return jsonify({
            'status': 'received',
            'packet_id': len(packets),
            'blocked': devices[mac]['blocked'],
            'authorized': devices[mac]['authorized'],
            'auto_blocked': auto_blocked,
            'threats_detected': len(threats),
            'message': f'Packet processed, {len(threats)} threats detected'
        })
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices')
def get_devices():
    """Get list of all detected devices"""
    device_list = []
    current_time = time.time()
    
    for mac, info in devices.items():
        # Only include devices seen in last hour
        last_seen = datetime.fromisoformat(info['last_seen'].replace('Z', '+00:00'))
        if datetime.now() - last_seen < timedelta(hours=1):
            
            # Calculate packet rate
            rate = 0.0
            if mac in packet_rates:
                # Count packets in last 10 seconds
                recent_packets = [t for t in packet_rates[mac] if current_time - t < 10]
                rate = len(recent_packets) / 10.0
            
            device_list.append({
                'mac': mac,
                'first_seen': info['first_seen'],
                'last_seen': info['last_seen'],
                'packet_count': info['packet_count'],
                'rssi': info.get('rssi', -99),
                'channel': info.get('channel', 0),
                'authorized': info.get('authorized', False),
                'blocked': info.get('blocked', False),
                'threat_level': info.get('threat_level', 'normal'),
                'packet_rate': rate,
                'sensor': info.get('sensor', 'unknown')
            })
    
    return jsonify(device_list)

@app.route('/api/authorized')
def get_authorized():
    """Get list of authorized MACs"""
    auth_list = []
    for mac in authorized_macs:
        auth_list.append({
            'mac': mac,
            'added_at': 'Unknown'  # Could store timestamps
        })
    return jsonify(auth_list)

@app.route('/api/authorize/<mac>', methods=['POST'])
def authorize_mac(mac):
    """Add MAC to authorized list"""
    mac_upper = mac.upper()
    authorized_macs.add(mac_upper)
    
    # Unblock if currently blocked
    if mac_upper in blocked_macs:
        blocked_macs.discard(mac_upper)
        iptables.unblock_mac(mac_upper)
    
    if mac_upper in devices:
        devices[mac_upper]['authorized'] = True
        devices[mac_upper]['blocked'] = False
    
    print(f"✅ Authorized MAC: {mac_upper}")
    return jsonify({'status': 'authorized', 'mac': mac_upper})

@app.route('/api/unauthorize/<mac>', methods=['POST'])
def unauthorize_mac(mac):
    """Remove MAC from authorized list"""
    mac_upper = mac.upper()
    authorized_macs.discard(mac_upper)
    
    if mac_upper in devices:
        devices[mac_upper]['authorized'] = False
    
    print(f"⚠️ Unauthorized MAC: {mac_upper}")
    return jsonify({'status': 'unauthorized', 'mac': mac_upper})

@app.route('/api/device/<mac>/toggle_auth', methods=['POST'])
def toggle_authorization(mac):
    """Toggle authorization status"""
    mac_upper = mac.upper()
    
    if mac_upper in authorized_macs:
        authorized_macs.discard(mac_upper)
        status = 'unauthorized'
        if mac_upper in devices:
            devices[mac_upper]['authorized'] = False
    else:
        authorized_macs.add(mac_upper)
        status = 'authorized'
        if mac_upper in devices:
            devices[mac_upper]['authorized'] = True
    
    print(f"🔄 Toggled authorization for {mac_upper}: {status}")
    return jsonify({'status': status, 'authorized': status == 'authorized', 'mac': mac_upper})

@app.route('/api/device/<mac>/toggle_block', methods=['POST'])
def toggle_block(mac):
    """Toggle block status for a device"""
    mac_upper = mac.upper()
    
    if mac_upper in blocked_macs or iptables.is_blocked(mac_upper):
        # Unblock
        blocked_macs.discard(mac_upper)
        iptables.unblock_mac(mac_upper)
        status = 'unblocked'
        if mac_upper in devices:
            devices[mac_upper]['blocked'] = False
    else:
        # Block
        blocked_macs.add(mac_upper)
        iptables.block_mac(mac_upper, BLOCK_DURATION)
        status = 'blocked'
        if mac_upper in devices:
            devices[mac_upper]['blocked'] = True
    
    print(f"🔄 Toggled block for {mac_upper}: {status}")
    return jsonify({'status': status, 'blocked': status == 'blocked', 'mac': mac_upper})

@app.route('/api/unblock/<mac>', methods=['POST'])
def unblock_device(mac):
    """Unblock a specific device"""
    mac_upper = mac.upper()
    
    blocked_macs.discard(mac_upper)
    iptables.unblock_mac(mac_upper)
    
    if mac_upper in devices:
        devices[mac_upper]['blocked'] = False
    
    print(f"✅ Unblocked device: {mac_upper}")
    return jsonify({'status': 'unblocked', 'mac': mac_upper})

@app.route('/api/blocked')
def get_blocked():
    """Get list of blocked devices"""
    blocked_list = []
    
    # Get iptables blocked MACs
    iptables_blocked = iptables.list_blocked()
    
    for mac in set(list(blocked_macs) + iptables_blocked):
        blocked_list.append({
            'mac': mac,
            'blocked_at': 'Unknown',  # Could store timestamps
            'reason': 'Manual block' if mac in blocked_macs else 'Auto-block'
        })
    
    return jsonify(blocked_list)

@app.route('/api/threats')
def get_threats():
    """Get threat log"""
    return jsonify(threat_log[-50:])  # Last 50 threats

@app.route('/api/stats')
def get_stats():
    """Get system statistics"""
    # Count devices by status
    total_devices = 0
    authorized_count = 0
    blocked_count = 0
    unauthorized_count = 0
    
    for info in devices.values():
        last_seen = datetime.fromisoformat(info['last_seen'].replace('Z', '+00:00'))
        if datetime.now() - last_seen < timedelta(hours=1):
            total_devices += 1
            if info.get('authorized'):
                authorized_count += 1
            elif info.get('blocked'):
                blocked_count += 1
            else:
                unauthorized_count += 1
    
    # Count iptables blocks
    iptables_count = len(iptables.list_blocked())
    
    return jsonify({
        'device_count': total_devices,
        'packet_count': len(packets),
        'authorized_count': authorized_count,
        'blocked_count': max(blocked_count, iptables_count),
        'unauthorized_count': unauthorized_count,
        'threat_count': len(threat_log),
        'iptables_blocks': iptables_count,
        'uptime': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'server_ip': get_ip(),
        'auto_block_threshold': AUTO_BLOCK_THRESHOLD,
        'block_duration': BLOCK_DURATION
    })

@app.route('/api/settings', methods=['POST'])
def update_settings():
    """Update system settings"""
    global AUTO_BLOCK_THRESHOLD, BLOCK_DURATION
    
    data = request.json
    if data.get('threshold'):
        AUTO_BLOCK_THRESHOLD = int(data['threshold'])
    if data.get('duration'):
        BLOCK_DURATION = int(data['duration'])
    
    print(f"⚙️ Updated settings: threshold={AUTO_BLOCK_THRESHOLD}, duration={BLOCK_DURATION}")
    return jsonify({
        'status': 'updated',
        'threshold': AUTO_BLOCK_THRESHOLD,
        'duration': BLOCK_DURATION
    })

@app.route('/api/clear_blocks', methods=['POST'])
def clear_all_blocks():
    """Clear all iptables blocks"""
    iptables.cleanup_rules()
    blocked_macs.clear()
    
    # Update device status
    for mac in devices:
        devices[mac]['blocked'] = False
    
    print("🧹 Cleared all iptables blocks")
    return jsonify({'status': 'cleared'})

@app.route('/api/test', methods=['POST'])
def test_endpoint():
    """Test endpoint for debugging"""
    data = request.json or {}
    print(f"Test endpoint called with: {data}")
    return jsonify({
        'status': 'test_ok',
        'message': 'Server is working!',
        'timestamp': datetime.now().isoformat()
    })

# ========== UTILITIES ==========
def get_ip():
    """Get server IP address"""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

# ========== MAIN ==========
if __name__ == '__main__':
    print("\n" + "="*70)
    print("🚀 WIDS SERVER WITH IPTABLES AUTO-BLOCKING")
    print("="*70)
    print(f"📊 Dashboard: http://{get_ip()}:8000")
    print(f"🏠 Local:     http://127.0.0.1:8000")
    print("\n🛡️ Features:")
    print("  • iptables auto-blocking for threats")
    print("  • MAC address authorization whitelist")
    print("  • Threat detection with packet rate analysis")
    print("  • Real-time dashboard with threat logs")
    print("\n📡 API Endpoints:")
    print("  GET  /                         - Dashboard")
    print("  POST /api/packet               - Receive ESP32 packets")
    print("  GET  /api/devices              - List detected devices")
    print("  GET  /api/authorized           - List authorized MACs")
    print("  GET  /api/blocked              - List blocked devices")
    print("  GET  /api/threats              - Threat detection log")
    print("  POST /api/authorize/<mac>      - Authorize a MAC")
    print("  POST /api/device/<mac>/toggle_block - Block/Unblock")
    print("  POST /api/clear_blocks         - Clear all iptables blocks")
    print("\n⚠️ Note: Requires sudo privileges for iptables commands")
    print("Run with: sudo python3 server.py (or add user to sudoers)")
    print("\n⏳ Waiting for ESP32 packets...")
    print("="*70 + "\n")
    
    app.run(host='0.0.0.0', port=8000, debug=True)
