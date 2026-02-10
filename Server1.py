#!/usr/bin/env python3
"""
WIDS SERVER - FIXED VERSION
Dashboard shows devices, MACs added in dashboard update server.py
"""
from flask import Flask, request, jsonify, render_template_string
from datetime import datetime, timedelta
from collections import defaultdict
import json
import subprocess
import threading
import time
import os
import re

app = Flask(__name__)

# ========== CONFIGURATION ==========
WHITELIST_MACS = [
    "AA:BB:CC:DD:EE:FF",  # Example: Your laptop MAC
    "11:22:33:44:55:66",  # Example: Your phone MAC
]

# File to persist authorized MACs
AUTHORIZED_MACS_FILE = "authorized_macs.json"

# ========== DATA STORAGE ==========
devices = {}          # MAC -> device info
packets = []          # Recent packets
blocked_macs = set()  # Manually blocked devices
sensors = {}          # Sensor info
authorized_macs = set()  # Authorized MACs (loaded from file)
packet_rates = defaultdict(list)  # MAC -> list of timestamps
threat_log = []       # Threat detection log

# ========== LOAD AUTHORIZED MACS FROM FILE ==========
def load_authorized_macs():
    """Load authorized MACs from file"""
    global authorized_macs
    try:
        if os.path.exists(AUTHORIZED_MACS_FILE):
            with open(AUTHORIZED_MACS_FILE, 'r') as f:
                data = json.load(f)
                authorized_macs = set(data.get('authorized_macs', WHITELIST_MACS))
            print(f"✅ Loaded {len(authorized_macs)} authorized MACs from file")
        else:
            authorized_macs = set(WHITELIST_MACS)
            save_authorized_macs()
    except Exception as e:
        print(f"❌ Error loading authorized MACs: {e}")
        authorized_macs = set(WHITELIST_MACS)

def save_authorized_macs():
    """Save authorized MACs to file"""
    try:
        with open(AUTHORIZED_MACS_FILE, 'w') as f:
            json.dump({
                'authorized_macs': list(authorized_macs),
                'last_updated': datetime.now().isoformat()
            }, f, indent=2)
        print(f"💾 Saved {len(authorized_macs)} authorized MACs to file")
        
        # Also update server.py file with new MACs
        update_server_py_with_macs()
        
    except Exception as e:
        print(f"❌ Error saving authorized MACs: {e}")

def update_server_py_with_macs():
    """Update server.py file with current authorized MACs"""
    try:
        # Read current server.py
        with open(__file__, 'r') as f:
            content = f.read()
        
        # Create MAC list string
        mac_list_str = "[\n"
        for mac in sorted(authorized_macs):
            mac_list_str += f'    "{mac}",  # Added via dashboard\n'
        mac_list_str += "]"
        
        # Update the WHITELIST_MACS definition
        pattern = r'WHITELIST_MACS\s*=\s*\[[^\]]*\]'
        new_content = re.sub(pattern, f'WHITELIST_MACS = {mac_list_str}', content)
        
        # Write back
        with open(__file__, 'w') as f:
            f.write(new_content)
        
        print(f"📝 Updated server.py with {len(authorized_macs)} authorized MACs")
    except Exception as e:
        print(f"⚠️ Could not update server.py: {e}")

# Load authorized MACs on startup
load_authorized_macs()

# ========== DASHBOARD HTML ==========
HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>WIDS Dashboard</title>
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
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; padding: 20px; }
        .stat-card { background: #1e293b; padding: 20px; border-radius: 10px; border-left: 4px solid #3b82f6; }
        .stat-card h3 { font-size: 32px; color: #60a5fa; margin-bottom: 5px; }
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
        .log-entry.info { background: #3b82f610; border-left: 3px solid #3b82f6; }
        .log-entry.success { background: #10b98110; border-left: 3px solid #10b981; }
        .log-entry.warning { background: #f59e0b10; border-left: 3px solid #f59e0b; }
        .log-entry.error { background: #ef444410; border-left: 3px solid #ef4444; }
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
        
        /* Manual test section */
        .test-section { background: #1e293b; padding: 20px; margin: 20px; border-radius: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>📡 WIDS Dashboard</h1>
        <p>Wireless Intrusion Detection System | Real-time Monitoring</p>
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
        <div class="stat-card">
            <h3 id="authorizedDevices">0</h3>
            <p>Authorized</p>
        </div>
        <div class="stat-card">
            <h3 id="unauthorizedDevices">0</h3>
            <p>Unauthorized</p>
        </div>
    </div>
    
    <!-- Manual Test Section -->
    <div class="test-section">
        <h3>📡 Manual Packet Test</h3>
        <p>Use this to test if server is receiving packets:</p>
        <div class="form-group">
            <input type="text" id="testMac" class="form-input" placeholder="AA:BB:CC:DD:EE:FF" value="AA:BB:CC:DD:EE:FF">
            <input type="number" id="testRSSI" class="form-input" placeholder="RSSI" value="-65">
            <input type="number" id="testChannel" class="form-input" placeholder="Channel" value="6">
            <button class="btn btn-authorize" onclick="sendTestPacket()">Send Test Packet</button>
        </div>
        <p id="testResult" style="margin-top: 10px; color: #94a3b8;"></p>
    </div>
    
    <div class="tabs">
        <div class="tab active" onclick="switchTab('devices')">📱 Devices</div>
        <div class="tab" onclick="switchTab('authorized')">✅ Authorized MACs</div>
        <div class="tab" onclick="switchTab('packets')">📦 Packet Log</div>
        <div class="tab" onclick="switchTab('logs')">📝 System Log</div>
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
                            <th>Last Seen</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="deviceTable">
                        <tr><td colspan="7" style="text-align: center; padding: 20px;">No devices detected yet. Send a test packet above.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Authorized MACs Tab -->
        <div id="tab-authorized" class="tab-content">
            <div class="panel-header">
                <h3>Authorized MAC Addresses</h3>
                <p style="color: #94a3b8; font-size: 12px; margin-top: 5px;">
                    MACs added here will be saved to server.py file
                </p>
            </div>
            <div class="form-group">
                <input type="text" id="newMac" class="form-input" placeholder="Enter MAC (AA:BB:CC:DD:EE:FF)">
                <button class="btn btn-authorize" onclick="addAuthorizedMac()">Add Authorized MAC</button>
                <button class="btn" onclick="reloadAuthorizedMacs()" style="background: #8b5cf6;">Reload from File</button>
            </div>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>MAC Address</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="authorizedTable"></tbody>
                </table>
            </div>
        </div>
        
        <!-- Packet Log Tab -->
        <div id="tab-packets" class="tab-content">
            <div class="panel-header">
                <h3>Recent Packets</h3>
            </div>
            <div id="packetLog" style="max-height: 500px; overflow-y: auto; padding: 15px;">
                <div class="log-entry info">
                    <div class="log-time">--:--:--</div>
                    <div class="log-message">Waiting for packets...</div>
                </div>
            </div>
        </div>
        
        <!-- System Log Tab -->
        <div id="tab-logs" class="tab-content">
            <div class="panel-header">
                <h3>System Activity Log</h3>
            </div>
            <div id="systemLog" style="max-height: 500px; overflow-y: auto; padding: 15px;">
                <div class="log-entry info">
                    <div class="log-time" id="currentTime">--:--:--</div>
                    <div class="log-message">System started</div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="footer">
        <p>WIDS System v2.0 | Server: {{ server_ip }}:{{ server_port }} | Last Update: <span id="lastUpdate">--:--:--</span></p>
    </div>
    
    <script>
        let currentTab = 'devices';
        let activityLog = [];
        
        // Update current time
        function updateTime() {
            const now = new Date();
            document.getElementById('currentTime').textContent = now.toLocaleTimeString();
            document.getElementById('lastUpdate').textContent = now.toLocaleTimeString();
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
                console.log('Loading dashboard data...');
                
                // Load stats
                const statsRes = await fetch('/api/stats');
                if (!statsRes.ok) throw new Error(`HTTP ${statsRes.status}`);
                const stats = await statsRes.json();
                
                document.getElementById('totalDevices').textContent = stats.device_count || 0;
                document.getElementById('totalPackets').textContent = stats.packet_count || 0;
                document.getElementById('authorizedDevices').textContent = stats.authorized_count || 0;
                document.getElementById('unauthorizedDevices').textContent = stats.unauthorized_count || 0;
                
                // Load current tab data
                loadTabData(currentTab);
                
                addLog('info', 'Dashboard refreshed');
                
            } catch (error) {
                console.error('Error loading dashboard:', error);
                addLog('error', `Failed to load dashboard: ${error.message}`);
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
                case 'packets':
                    await loadPacketLog();
                    break;
                case 'logs':
                    // Already loaded via addLog
                    break;
            }
        }
        
        // Load devices
        async function loadDevices() {
            try {
                const devicesRes = await fetch('/api/devices');
                if (!devicesRes.ok) throw new Error(`HTTP ${devicesRes.status}`);
                const devices = await devicesRes.json();
                
                const tbody = document.getElementById('deviceTable');
                
                if (devices.length === 0) {
                    tbody.innerHTML = `
                        <tr><td colspan="7" style="text-align: center; padding: 20px; color: #94a3b8;">
                            No devices detected yet. Send a test packet above or wait for ESP32 packets.
                        </td></tr>`;
                    return;
                }
                
                tbody.innerHTML = '';
                
                devices.forEach(device => {
                    const row = tbody.insertRow();
                    
                    // Format last seen time
                    const lastSeen = new Date(device.last_seen).toLocaleTimeString();
                    
                    // Determine status
                    let statusClass, statusText;
                    if (device.authorized) {
                        statusClass = 'status-authorized';
                        statusText = 'AUTHORIZED';
                    } else {
                        statusClass = 'status-unauthorized';
                        statusText = 'UNAUTHORIZED';
                    }
                    
                    row.innerHTML = `
                        <td><code style="font-family: monospace;">${device.mac}</code></td>
                        <td>${device.rssi || -99} dBm</td>
                        <td>${device.channel || 0}</td>
                        <td>${device.packet_count || 1}</td>
                        <td>${lastSeen}</td>
                        <td><span class="status ${statusClass}">${statusText}</span></td>
                        <td>
                            <button class="btn ${device.authorized ? 'btn-unauthorize' : 'btn-authorize'}" 
                                    onclick="toggleAuthorization('${device.mac}')">
                                ${device.authorized ? 'Remove Auth' : 'Authorize'}
                            </button>
                        </td>
                    `;
                });
                
            } catch (error) {
                console.error('Error loading devices:', error);
                addLog('error', `Failed to load devices: ${error.message}`);
            }
        }
        
        // Load authorized MACs
        async function loadAuthorizedMacs() {
            try {
                const authRes = await fetch('/api/authorized');
                if (!authRes.ok) throw new Error(`HTTP ${authRes.status}`);
                const authorized = await authRes.json();
                
                const tbody = document.getElementById('authorizedTable');
                tbody.innerHTML = '';
                
                if (authorized.length === 0) {
                    tbody.innerHTML = `
                        <tr><td colspan="3" style="text-align: center; padding: 20px; color: #94a3b8;">
                            No authorized MACs. Add some using the form above.
                        </td></tr>`;
                    return;
                }
                
                authorized.forEach(mac => {
                    const row = tbody.insertRow();
                    row.innerHTML = `
                        <td><code style="font-family: monospace;">${mac.mac}</code></td>
                        <td><span class="status status-authorized">AUTHORIZED</span></td>
                        <td>
                            <button class="btn btn-unauthorize" onclick="removeAuthorizedMac('${mac.mac}')">
                                Remove
                            </button>
                        </td>
                    `;
                });
                
            } catch (error) {
                console.error('Error loading authorized MACs:', error);
                addLog('error', `Failed to load authorized MACs: ${error.message}`);
            }
        }
        
        // Load packet log
        async function loadPacketLog() {
            try {
                const packetsRes = await fetch('/api/packets');
                if (!packetsRes.ok) throw new Error(`HTTP ${packetsRes.status}`);
                const packets = await packetsRes.json();
                
                const logDiv = document.getElementById('packetLog');
                logDiv.innerHTML = '';
                
                if (packets.length === 0) {
                    logDiv.innerHTML = `
                        <div class="log-entry info">
                            <div class="log-time">--:--:--</div>
                            <div class="log-message">No packets received yet</div>
                        </div>`;
                    return;
                }
                
                packets.forEach(packet => {
                    const entry = document.createElement('div');
                    entry.className = 'log-entry info';
                    
                    const time = new Date(packet.timestamp).toLocaleTimeString();
                    entry.innerHTML = `
                        <div class="log-time">${time}</div>
                        <div class="log-message">
                            📦 MAC: ${packet.mac} | RSSI: ${packet.rssi}dBm | Channel: ${packet.channel}
                        </div>
                    `;
                    
                    logDiv.appendChild(entry);
                });
                
            } catch (error) {
                console.error('Error loading packets:', error);
                addLog('error', `Failed to load packets: ${error.message}`);
            }
        }
        
        // Send test packet
        async function sendTestPacket() {
            const mac = document.getElementById('testMac').value.trim().toUpperCase();
            const rssi = document.getElementById('testRSSI').value;
            const channel = document.getElementById('testChannel').value;
            const resultDiv = document.getElementById('testResult');
            
            // Validate MAC
            if (!mac.match(/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/)) {
                resultDiv.innerHTML = '<span style="color: #ef4444;">❌ Invalid MAC format. Use AA:BB:CC:DD:EE:FF</span>';
                return;
            }
            
            try {
                resultDiv.innerHTML = '<span style="color: #f59e0b;">⏳ Sending test packet...</span>';
                
                const response = await fetch('/api/packet', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        sensor_id: 'manual_test',
                        mac: mac,
                        rssi: parseInt(rssi),
                        channel: parseInt(channel),
                        timestamp: Date.now()
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    resultDiv.innerHTML = `<span style="color: #10b981;">✅ Packet sent successfully! Packet ID: ${data.packet_id}</span>`;
                    addLog('success', `Test packet sent: ${mac}`);
                    
                    // Refresh devices immediately
                    setTimeout(loadDevices, 500);
                    setTimeout(loadDashboard, 500);
                } else {
                    resultDiv.innerHTML = `<span style="color: #ef4444;">❌ Error: ${data.error || 'Unknown error'}</span>`;
                    addLog('error', `Failed to send packet: ${data.error}`);
                }
                
            } catch (error) {
                console.error('Error sending test packet:', error);
                resultDiv.innerHTML = `<span style="color: #ef4444;">❌ Network error: ${error.message}</span>`;
                addLog('error', `Network error: ${error.message}`);
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
                    addLog('success', `Authorized MAC: ${mac}`);
                    loadAuthorizedMacs();
                    loadDashboard();
                    
                    // Show success message
                    alert(`✅ MAC ${mac} added to authorized list and saved to server.py`);
                } else {
                    alert(`❌ Error: ${result.error || 'Failed to authorize MAC'}`);
                    addLog('error', `Failed to authorize MAC: ${result.error}`);
                }
            } catch (error) {
                console.error('Error authorizing MAC:', error);
                alert(`❌ Network error: ${error.message}`);
                addLog('error', `Network error: ${error.message}`);
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
                    addLog('warning', `Removed authorization: ${mac}`);
                    loadAuthorizedMacs();
                    loadDashboard();
                }
            } catch (error) {
                console.error('Error removing authorized MAC:', error);
                addLog('error', `Failed to remove MAC: ${error.message}`);
            }
        }
        
        // Reload authorized MACs from file
        async function reloadAuthorizedMacs() {
            try {
                const response = await fetch('/api/reload_authorized', {
                    method: 'POST'
                });
                
                if (response.ok) {
                    addLog('info', 'Reloaded authorized MACs from file');
                    loadAuthorizedMacs();
                    alert('✅ Reloaded authorized MACs from file');
                }
            } catch (error) {
                console.error('Error reloading authorized MACs:', error);
                addLog('error', `Failed to reload MACs: ${error.message}`);
            }
        }
        
        // Toggle authorization
        async function toggleAuthorization(mac) {
            try {
                const response = await fetch(`/api/device/${mac}/toggle_auth`, {
                    method: 'POST'
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    addLog('info', 
                        result.authorized ? `Authorized: ${mac}` : `Unauthorized: ${mac}`
                    );
                    loadDevices();
                    loadAuthorizedMacs();
                }
            } catch (error) {
                console.error('Error toggling authorization:', error);
                addLog('error', `Failed to toggle authorization: ${error.message}`);
            }
        }
        
        // Add log entry
        function addLog(type, message) {
            const logDiv = document.getElementById('systemLog');
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
            
            // Add to activity log array
            activityLog.unshift({type, message, time});
            if (activityLog.length > 100) activityLog.pop();
        }
        
        // Auto-refresh every 5 seconds
        setInterval(loadDashboard, 5000);
        
        // Initial load
        loadDashboard();
        addLog('info', 'Dashboard loaded successfully');
        addLog('info', 'Send test packets using the manual test section');
    </script>
</body>
</html>
"""

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
        
        print(f"📦 Packet received from {client_ip}")
        print(f"   MAC: {mac}, RSSI: {data.get('rssi')}, Channel: {data.get('channel')}")
        
        # Add timestamp
        data['received_at'] = datetime.now().isoformat()
        data['client_ip'] = client_ip
        data['timestamp'] = datetime.now().isoformat()
        
        # Store packet
        packets.append(data)
        
        # Keep last 100 packets only
        if len(packets) > 100:
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
                'sensor': sensor_id
            }
            print(f"🆕 New device detected: {mac}")
        else:
            devices[mac]['last_seen'] = datetime.now().isoformat()
            devices[mac]['packet_count'] += 1
            devices[mac]['rssi'] = data.get('rssi', devices[mac]['rssi'])
            devices[mac]['channel'] = data.get('channel', devices[mac]['channel'])
        
        print(f"✅ Packet #{len(packets)} stored successfully")
        
        return jsonify({
            'status': 'received',
            'packet_id': len(packets),
            'authorized': mac in authorized_macs,
            'message': f'Packet from {mac} received successfully'
        })
        
    except Exception as e:
        print(f"❌ Error processing packet: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices')
def get_devices():
    """Get list of all detected devices"""
    device_list = []
    
    for mac, info in devices.items():
        # Only include devices seen in last hour
        last_seen = datetime.fromisoformat(info['last_seen'].replace('Z', '+00:00'))
        if datetime.now() - last_seen < timedelta(hours=1):
            device_list.append({
                'mac': mac,
                'first_seen': info['first_seen'],
                'last_seen': info['last_seen'],
                'packet_count': info['packet_count'],
                'rssi': info.get('rssi', -99),
                'channel': info.get('channel', 0),
                'authorized': info.get('authorized', False),
                'sensor': info.get('sensor', 'unknown')
            })
    
    # Sort by last seen (newest first)
    device_list.sort(key=lambda x: x['last_seen'], reverse=True)
    
    return jsonify(device_list)

@app.route('/api/packets')
def get_packets():
    """Get recent packets"""
    # Return last 50 packets
    recent_packets = packets[-50:]
    
    # Format for display
    formatted_packets = []
    for p in recent_packets:
        formatted_packets.append({
            'mac': p.get('mac', 'unknown'),
            'rssi': p.get('rssi', -99),
            'channel': p.get('channel', 0),
            'timestamp': p.get('received_at', p.get('timestamp', '')),
            'sensor': p.get('sensor_id', 'unknown')
        })
    
    return jsonify(formatted_packets[::-1])  # Reverse to show newest first

@app.route('/api/authorized')
def get_authorized():
    """Get list of authorized MACs"""
    auth_list = []
    for mac in sorted(authorized_macs):
        auth_list.append({
            'mac': mac,
            'added_at': 'From server.py'  # Could store actual timestamps
        })
    return jsonify(auth_list)

@app.route('/api/authorize/<mac>', methods=['POST'])
def authorize_mac(mac):
    """Add MAC to authorized list"""
    mac_upper = mac.upper()
    
    # Validate MAC format
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac_upper):
        return jsonify({'error': 'Invalid MAC format'}), 400
    
    authorized_macs.add(mac_upper)
    
    # Update device if it exists
    if mac_upper in devices:
        devices[mac_upper]['authorized'] = True
    
    # Save to file and update server.py
    save_authorized_macs()
    
    print(f"✅ Authorized MAC: {mac_upper} (saved to file)")
    return jsonify({'status': 'authorized', 'mac': mac_upper})

@app.route('/api/unauthorize/<mac>', methods=['POST'])
def unauthorize_mac(mac):
    """Remove MAC from authorized list"""
    mac_upper = mac.upper()
    authorized_macs.discard(mac_upper)
    
    # Update device if it exists
    if mac_upper in devices:
        devices[mac_upper]['authorized'] = False
    
    # Save to file and update server.py
    save_authorized_macs()
    
    print(f"⚠️ Unauthorized MAC: {mac_upper} (updated in file)")
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
    
    # Save to file
    save_authorized_macs()
    
    print(f"🔄 Toggled authorization for {mac_upper}: {status}")
    return jsonify({'status': status, 'authorized': status == 'authorized', 'mac': mac_upper})

@app.route('/api/reload_authorized', methods=['POST'])
def reload_authorized():
    """Reload authorized MACs from file"""
    load_authorized_macs()
    print("🔄 Reloaded authorized MACs from file")
    return jsonify({'status': 'reloaded', 'count': len(authorized_macs)})

@app.route('/api/stats')
def get_stats():
    """Get system statistics"""
    # Count devices by status
    total_devices = 0
    authorized_count = 0
    unauthorized_count = 0
    
    for info in devices.values():
        last_seen = datetime.fromisoformat(info['last_seen'].replace('Z', '+00:00'))
        if datetime.now() - last_seen < timedelta(hours=1):
            total_devices += 1
            if info.get('authorized'):
                authorized_count += 1
            else:
                unauthorized_count += 1
    
    return jsonify({
        'device_count': total_devices,
        'packet_count': len(packets),
        'authorized_count': authorized_count,
        'unauthorized_count': unauthorized_count,
        'total_authorized': len(authorized_macs),
        'server_ip': get_ip(),
        'server_time': datetime.now().isoformat()
    })

@app.route('/api/test', methods=['POST'])
def test_endpoint():
    """Test endpoint for debugging"""
    data = request.json or {}
    print(f"Test endpoint called with: {data}")
    return jsonify({
        'status': 'test_ok',
        'message': 'Server is working!',
        'received_data': data,
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
    print("🚀 WIDS SERVER - FIXED VERSION")
    print("="*70)
    print(f"📊 Dashboard: http://{get_ip()}:8000")
    print(f"🏠 Local:     http://127.0.0.1:8000")
    print(f"✅ Loaded {len(authorized_macs)} authorized MACs from file")
    print("\n📡 Features:")
    print("  • Dashboard shows real-time devices")
    print("  • Manual packet testing section")
    print("  • MAC authorization management")
    print("  • Authorized MACs saved to server.py file")
    print("\n🔧 To test the system:")
    print("  1. Open dashboard in browser")
    print("  2. Use 'Manual Packet Test' section")
    print("  3. Add MACs to authorized list")
    print("  4. MACs are saved to server.py automatically")
    print("\n⏳ Waiting for ESP32 packets...")
    print("="*70 + "\n")
    
    app.run(host='0.0.0.0', port=8000, debug=True)
