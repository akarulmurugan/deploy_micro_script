#!/usr/bin/env python3
"""
MINIMAL WIDS SERVER
No ML, just packet collection and dashboard
"""
from flask import Flask, request, jsonify, render_template_string
from datetime import datetime, timedelta
from collections import defaultdict
import json

app = Flask(__name__)

# ========== DATA STORAGE ==========
devices = {}          # MAC -> device info
packets = []          # Recent packets
blocked_macs = set()  # Manually blocked devices
sensors = {}          # Sensor info

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
        
        /* Main Content */
        .main-content { display: flex; gap: 20px; padding: 0 20px 20px; }
        .devices-panel { flex: 2; background: #1e293b; border-radius: 10px; overflow: hidden; }
        .log-panel { flex: 1; background: #1e293b; border-radius: 10px; overflow: hidden; }
        
        /* Table */
        .panel-header { background: #334155; padding: 15px; border-bottom: 1px solid #475569; }
        .panel-header h3 { font-size: 18px; }
        
        table { width: 100%; border-collapse: collapse; }
        th { background: #334155; padding: 12px 15px; text-align: left; font-size: 14px; color: #cbd5e1; }
        td { padding: 12px 15px; border-bottom: 1px solid #334155; }
        tr:hover { background: #2d3748; }
        
        /* Buttons */
        .btn-block { background: #ef4444; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; }
        .btn-unblock { background: #10b981; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; }
        
        /* Status badges */
        .status { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .status-active { background: #10b98120; color: #10b981; }
        .status-blocked { background: #ef444420; color: #ef4444; }
        
        /* Log entries */
        .log-entry { padding: 10px 15px; border-bottom: 1px solid #334155; font-size: 13px; }
        .log-entry.new { background: #1e40af20; border-left: 3px solid #3b82f6; }
        .log-time { color: #94a3b8; font-size: 12px; }
        .log-message { margin-top: 3px; }
        
        /* Footer */
        .footer { text-align: center; padding: 15px; color: #64748b; font-size: 12px; border-top: 1px solid #334155; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>📡 WIDS Dashboard</h1>
        <p>Wireless Intrusion Detection System | Real-time Monitoring</p>
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
            <h3 id="blockedDevices">0</h3>
            <p>Blocked Devices</p>
        </div>
        <div class="stat-card">
            <h3 id="activeSensors">0</h3>
            <p>Active Sensors</p>
        </div>
    </div>
    
    <div class="main-content">
        <div class="devices-panel">
            <div class="panel-header">
                <h3>📱 Detected Devices</h3>
            </div>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>MAC Address</th>
                            <th>Signal</th>
                            <th>Channel</th>
                            <th>Packets</th>
                            <th>First Seen</th>
                            <th>Last Seen</th>
                            <th>Status</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody id="deviceTable"></tbody>
                </table>
            </div>
        </div>
        
        <div class="log-panel">
            <div class="panel-header">
                <h3>📝 Recent Activity</h3>
            </div>
            <div id="activityLog" style="max-height: 500px; overflow-y: auto;"></div>
        </div>
    </div>
    
    <div class="footer">
        <p>WIDS System v1.0 | Server: {{ server_ip }}:{{ server_port }} | Last Update: <span id="lastUpdate">--:--:--</span></p>
    </div>
    
    <script>
        let lastUpdateTime = '--:--:--';
        
        // Load initial data
        async function loadDashboard() {
            try {
                // Load stats
                const statsRes = await fetch('/api/stats');
                const stats = await statsRes.json();
                
                document.getElementById('totalDevices').textContent = stats.device_count;
                document.getElementById('totalPackets').textContent = stats.packet_count;
                document.getElementById('blockedDevices').textContent = stats.blocked_count;
                document.getElementById('activeSensors').textContent = stats.sensor_count;
                
                // Load devices
                const devicesRes = await fetch('/api/devices');
                const devices = await devicesRes.json();
                
                const tbody = document.getElementById('deviceTable');
                tbody.innerHTML = '';
                
                devices.forEach(device => {
                    const row = tbody.insertRow();
                    
                    // Format time
                    const firstSeen = new Date(device.first_seen).toLocaleTimeString();
                    const lastSeen = new Date(device.last_seen).toLocaleTimeString();
                    
                    // Status badge
                    const statusClass = device.blocked ? 'status-blocked' : 'status-active';
                    const statusText = device.blocked ? 'BLOCKED' : 'ACTIVE';
                    
                    row.innerHTML = `
                        <td><code style="font-family: monospace;">${device.mac}</code></td>
                        <td>${device.rssi || -99} dBm</td>
                        <td>${device.channel || 0}</td>
                        <td>${device.packet_count || 1}</td>
                        <td>${firstSeen}</td>
                        <td>${lastSeen}</td>
                        <td><span class="status ${statusClass}">${statusText}</span></td>
                        <td>
                            <button class="${device.blocked ? 'btn-unblock' : 'btn-block'}" 
                                    onclick="toggleBlock('${device.mac}')">
                                ${device.blocked ? 'UNBLOCK' : 'BLOCK'}
                            </button>
                        </td>
                    `;
                });
                
                // Update timestamp
                lastUpdateTime = new Date().toLocaleTimeString();
                document.getElementById('lastUpdate').textContent = lastUpdateTime;
                
            } catch (error) {
                console.error('Error loading dashboard:', error);
            }
        }
        
        // Toggle block/unblock
        async function toggleBlock(mac) {
            const action = confirm(`Are you sure you want to ${mac}?`);
            if (!action) return;
            
            try {
                const response = await fetch(`/api/device/${mac}/toggle_block`, {
                    method: 'POST'
                });
                const result = await response.json();
                
                // Add to activity log
                addLogEntry(`${result.action === 'blocked' ? '🚫 Blocked' : '✅ Unblocked'} device: ${mac}`);
                
                // Reload dashboard
                loadDashboard();
            } catch (error) {
                console.error('Error toggling block:', error);
            }
        }
        
        // Add entry to activity log
        function addLogEntry(message) {
            const logDiv = document.getElementById('activityLog');
            const entry = document.createElement('div');
            entry.className = 'log-entry new';
            
            const time = new Date().toLocaleTimeString();
            entry.innerHTML = `
                <div class="log-time">${time}</div>
                <div class="log-message">${message}</div>
            `;
            
            // Add to top
            logDiv.insertBefore(entry, logDiv.firstChild);
            
            // Remove old entries (keep last 20)
            while (logDiv.children.length > 20) {
                logDiv.removeChild(logDiv.lastChild);
            }
            
            // Remove 'new' class after 2 seconds
            setTimeout(() => entry.classList.remove('new'), 2000);
        }
        
        // Auto-refresh every 3 seconds
        setInterval(loadDashboard, 3000);
        
        // Initial load
        loadDashboard();
        
        // WebSocket for real-time updates
        const ws = new WebSocket(`ws://${window.location.host}/ws`);
        
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            
            if (data.type === 'new_packet') {
                addLogEntry(`📡 Packet from ${data.mac} (Ch:${data.channel}, RSSI:${data.rssi}dBm)`);
            }
            else if (data.type === 'device_blocked') {
                addLogEntry(`🚫 Auto-blocked: ${data.mac} - ${data.reason}`);
            }
            else if (data.type === 'sensor_connected') {
                addLogEntry(`🔌 Sensor connected: ${data.sensor_id}`);
            }
        };
        
        // Add some initial log entries
        addLogEntry('✅ Dashboard loaded successfully');
        addLogEntry('🔍 Starting wireless monitoring...');
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
        
        # Add timestamp
        data['received_at'] = datetime.now().isoformat()
        
        # Store packet
        packets.append(data)
        
        # Keep last 1000 packets only
        if len(packets) > 1000:
            packets.pop(0)
        
        # Update device info
        mac = data.get('mac', '00:00:00:00:00:00')
        sensor_id = data.get('sensor_id', 'unknown')
        
        # Update sensor info
        sensors[sensor_id] = {
            'last_seen': datetime.now().isoformat(),
            'packet_count': sensors.get(sensor_id, {}).get('packet_count', 0) + 1
        }
        
        # Update device info
        if mac not in devices:
            devices[mac] = {
                'mac': mac,
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat(),
                'packet_count': 1,
                'rssi': data.get('rssi', -99),
                'channel': data.get('channel', 0),
                'blocked': mac in blocked_macs,
                'sensor': sensor_id
            }
        else:
            devices[mac]['last_seen'] = datetime.now().isoformat()
            devices[mac]['packet_count'] += 1
            devices[mac]['rssi'] = data.get('rssi', devices[mac]['rssi'])
            devices[mac]['channel'] = data.get('channel', devices[mac]['channel'])
        
        # Broadcast new packet via WebSocket
        broadcast_ws({
            'type': 'new_packet',
            'mac': mac,
            'channel': data.get('channel', 0),
            'rssi': data.get('rssi', -99),
            'sensor': sensor_id
        })
        
        return jsonify({
            'status': 'received',
            'packet_id': len(packets),
            'blocked': mac in blocked_macs
        })
        
    except Exception as e:
        print(f"Error: {e}")
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
                'blocked': info.get('blocked', False),
                'sensor': info.get('sensor', 'unknown')
            })
    
    return jsonify(device_list)

@app.route('/api/device/<mac>/toggle_block', methods=['POST'])
def toggle_block(mac):
    """Toggle block status for a device"""
    if mac in blocked_macs:
        blocked_macs.discard(mac)
        if mac in devices:
            devices[mac]['blocked'] = False
        action = 'unblocked'
    else:
        blocked_macs.add(mac)
        if mac in devices:
            devices[mac]['blocked'] = True
        action = 'blocked'
    
    # Broadcast via WebSocket
    broadcast_ws({
        'type': 'device_blocked' if action == 'blocked' else 'device_unblocked',
        'mac': mac,
        'action': action
    })
    
    return jsonify({'status': action, 'mac': mac})

@app.route('/api/stats')
def get_stats():
    """Get system statistics"""
    # Count active devices (seen in last hour)
    active_devices = 0
    for info in devices.values():
        last_seen = datetime.fromisoformat(info['last_seen'].replace('Z', '+00:00'))
        if datetime.now() - last_seen < timedelta(hours=1):
            active_devices += 1
    
    # Count active sensors (seen in last 5 minutes)
    active_sensors = 0
    for sensor_id, info in sensors.items():
        last_seen = datetime.fromisoformat(info['last_seen'].replace('Z', '+00:00'))
        if datetime.now() - last_seen < timedelta(minutes=5):
            active_sensors += 1
    
    return jsonify({
        'device_count': active_devices,
        'packet_count': len(packets),
        'blocked_count': len(blocked_macs),
        'sensor_count': active_sensors,
        'uptime': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'server_time': datetime.now().isoformat()
    })

@app.route('/api/sensors')
def get_sensors():
    """Get sensor information"""
    sensor_list = []
    for sensor_id, info in sensors.items():
        last_seen = datetime.fromisoformat(info['last_seen'].replace('Z', '+00:00'))
        if datetime.now() - last_seen < timedelta(minutes=5):
            sensor_list.append({
                'sensor_id': sensor_id,
                'last_seen': info['last_seen'],
                'packet_count': info.get('packet_count', 0),
                'status': 'active'
            })
    
    return jsonify(sensor_list)

# ========== WEB SOCKET ==========
from flask_socketio import SocketIO, emit
socketio = SocketIO(app, cors_allowed_origins="*")

@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")
    emit('connected', {'message': 'Connected to WIDS server'})

def broadcast_ws(data):
    """Broadcast data to all WebSocket clients"""
    socketio.emit('update', data)

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
    print("\n" + "="*50)
    print("🚀 WIDS SERVER STARTING")
    print("="*50)
    print(f"Dashboard: http://{get_ip()}:8000")
    print(f"Local:     http://127.0.0.1:8000")
    print("\nAPI Endpoints:")
    print("  GET  /              - Dashboard")
    print("  POST /api/packet    - Receive packets")
    print("  GET  /api/devices   - List devices")
    print("  GET  /api/stats     - Statistics")
    print("  POST /api/device/<mac>/toggle_block - Block/Unblock")
    print("\nWaiting for ESP32 packets...")
    print("="*50 + "\n")
    
    socketio.run(app, host='0.0.0.0', port=8000, debug=True)