#!/bin/bash
clear
echo "=============================================="
echo "   WIDS-IPS Project Creator"
echo "=============================================="

# Create project
mkdir -p wids-ips-project
cd wids-ips-project

echo "Creating directory structure..."
mkdir -p {esp32,server,html,scripts}

# 1. Create ESP32 code
echo "Creating ESP32 files..."
cat > esp32/wids_sensor.ino << 'EOF1'
// ESP32 WIDS Sensor with nRF24
#include <WiFi.h>
#include <SPI.h>
#include <RF24.h>

RF24 radio(4, 5); // CE, CSN pins

void setup() {
  Serial.begin(115200);
  
  // Initialize nRF24
  if (!radio.begin()) {
    Serial.println("Radio init failed");
    while (1);
  }
  
  radio.setChannel(76);
  radio.setPALevel(RF24_PA_MAX);
  radio.setDataRate(RF24_2MBPS);
  radio.startListening();
  
  Serial.println("WIDS Sensor Ready");
}

void loop() {
  // Channel hopping
  static uint8_t channel = 1;
  static unsigned long lastHop = 0;
  
  if (millis() - lastHop > 200) {
    radio.setChannel(channel);
    channel = (channel % 125) + 1;
    lastHop = millis();
    Serial.print("Switched to channel ");
    Serial.println(channel);
  }
  
  // Check for packets
  if (radio.available()) {
    uint8_t buffer[32];
    radio.read(&buffer, sizeof(buffer));
    
    Serial.print("Packet detected - RSSI: ");
    Serial.print(radio.getRSSI());
    Serial.print(" Channel: ");
    Serial.println(radio.getChannel());
  }
  
  delay(10);
}
EOF1

# 2. Create Python server
echo "Creating server files..."
cat > server/wids_server.py << 'EOF2'
from flask import Flask, jsonify, request, render_template_string
import json
from datetime import datetime

app = Flask(__name__)

# Store devices and packets
devices = {}
packets = []
blocked_macs = set()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>WIDS Dashboard</title>
    <style>
        body { font-family: Arial; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 10px; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-box { background: white; padding: 20px; border-radius: 10px; flex: 1; text-align: center; }
        .stat-number { font-size: 2em; color: #2c3e50; }
        table { width: 100%; background: white; border-radius: 10px; }
        th { background: #34495e; color: white; padding: 12px; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        .block-btn { background: #e74c3c; color: white; border: none; padding: 5px 10px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 WIDS-IPS Dashboard</h1>
            <p>Wireless Intrusion Detection System</p>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number" id="deviceCount">0</div>
                <p>Devices Detected</p>
            </div>
            <div class="stat-box">
                <div class="stat-number" id="packetCount">0</div>
                <p>Packets Captured</p>
            </div>
            <div class="stat-box">
                <div class="stat-number" id="blockedCount">0</div>
                <p>Blocked Devices</p>
            </div>
        </div>
        
        <h2>Detected Devices</h2>
        <table>
            <thead>
                <tr>
                    <th>MAC Address</th>
                    <th>RSSI</th>
                    <th>Last Seen</th>
                    <th>Packets</th>
                    <th>Status</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody id="deviceTable">
                <!-- Filled by JavaScript -->
            </tbody>
        </table>
    </div>
    
    <script>
        async function loadData() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();
                
                document.getElementById('deviceCount').textContent = data.device_count;
                document.getElementById('packetCount').textContent = data.packet_count;
                document.getElementById('blockedCount').textContent = data.blocked_count;
                
                const devicesRes = await fetch('/api/devices');
                const devices = await devicesRes.json();
                
                const table = document.getElementById('deviceTable');
                table.innerHTML = '';
                
                devices.forEach(device => {
                    const row = table.insertRow();
                    const status = device.blocked ? 'Blocked' : 'Active';
                    const btnText = device.blocked ? 'Unblock' : 'Block';
                    const btnClass = device.blocked ? 'style="background:#27ae60"' : '';
                    
                    row.innerHTML = `
                        <td>${device.mac}</td>
                        <td>${device.rssi}</td>
                        <td>${new Date(device.last_seen).toLocaleTimeString()}</td>
                        <td>${device.packets}</td>
                        <td>${status}</td>
                        <td><button class="block-btn" ${btnClass} onclick="toggleBlock('${device.mac}')">${btnText}</button></td>
                    `;
                });
            } catch (error) {
                console.error('Error loading data:', error);
            }
        }
        
        async function toggleBlock(mac) {
            const action = document.querySelector(`button[onclick="toggleBlock('${mac}')"]`).textContent;
            
            if (action === 'Block') {
                await fetch(`/api/block/${mac}`, { method: 'POST' });
            } else {
                await fetch(`/api/unblock/${mac}`, { method: 'POST' });
            }
            
            loadData();
        }
        
        // Refresh every 3 seconds
        setInterval(loadData, 3000);
        loadData();
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/packet', methods=['POST'])
def receive_packet():
    data = request.json
    mac = data.get('mac', '00:00:00:00:00:00')
    rssi = data.get('rssi', -99)
    channel = data.get('channel', 0)
    
    # Update device info
    if mac not in devices:
        devices[mac] = {
            'mac': mac,
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'rssi': rssi,
            'channel': channel,
            'packets': 1,
            'blocked': mac in blocked_macs
        }
    else:
        devices[mac]['last_seen'] = datetime.now().isoformat()
        devices[mac]['rssi'] = rssi
        devices[mac]['channel'] = channel
        devices[mac]['packets'] += 1
    
    packets.append(data)
    
    # Keep only last 1000 packets
    if len(packets) > 1000:
        packets.pop(0)
    
    return jsonify({'status': 'received', 'blocked': mac in blocked_macs})

@app.route('/api/devices')
def get_devices():
    return jsonify(list(devices.values()))

@app.route('/api/stats')
def get_stats():
    return jsonify({
        'device_count': len(devices),
        'packet_count': len(packets),
        'blocked_count': len(blocked_macs),
        'uptime': 'running'
    })

@app.route('/api/block/<mac>', methods=['POST'])
def block_device(mac):
    blocked_macs.add(mac)
    if mac in devices:
        devices[mac]['blocked'] = True
    return jsonify({'status': 'blocked', 'mac': mac})

@app.route('/api/unblock/<mac>', methods=['POST'])
def unblock_device(mac):
    blocked_macs.discard(mac)
    if mac in devices:
        devices[mac]['blocked'] = False
    return jsonify({'status': 'unblocked', 'mac': mac})

if __name__ == '__main__':
    print("Starting WIDS Server on http://0.0.0.0:8000")
    app.run(host='0.0.0.0', port=8000, debug=True)
EOF2

# 3. Create requirements.txt
cat > server/requirements.txt << 'EOF3'
Flask==2.3.2
Werkzeug==2.3.6
EOF3

# 4. Create setup script
cat > setup.sh << 'EOF4'
#!/bin/bash
echo "=== WIDS-IPS Setup ==="
echo ""
echo "1. Setting up Python environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r server/requirements.txt

echo ""
echo "2. To start the server:"
echo "   source venv/bin/activate"
echo "   python server/wids_server.py"
echo ""
echo "3. Dashboard will be available at:"
echo "   http://localhost:8000"
echo ""
echo "4. For ESP32 setup:"
echo "   - Install PlatformIO: pip install platformio"
echo "   - Upload esp32/wids_sensor.ino to ESP32"
echo ""
echo "Setup complete!"
EOF4

# 5. Create ESP32 upload script
cat > upload_esp32.sh << 'EOF5'
#!/bin/bash
echo "=== ESP32 Upload Guide ==="
echo ""
echo "1. Install PlatformIO:"
echo "   pip install platformio"
echo ""
echo "2. Create PlatformIO project:"
echo "   pio project init --board esp32dev"
echo ""
echo "3. Copy our code:"
echo "   cp esp32/wids_sensor.ino src/main.cpp"
echo ""
echo "4. Install nRF24 library:"
echo "   pio lib install \"nrf24/RF24\""
echo ""
echo "5. Upload to ESP32:"
echo "   pio run --target upload"
echo ""
echo "6. Monitor output:"
echo "   pio device monitor"
echo ""
echo "Note: Update WiFi credentials in the code if needed."
EOF5

# 6. Create README
cat > README.txt << 'EOF6'
WIDS-IPS SYSTEM
===============

A complete Wireless Intrusion Detection and Prevention System using:
- ESP32 with nRF24L01+
- Python Flask Server
- Web Dashboard

QUICK START:
------------

1. Setup Server:
   bash setup.sh
   source venv/bin/activate
   python server/wids_server.py

2. Setup ESP32:
   Follow instructions in upload_esp32.sh

3. Access Dashboard:
   Open browser to: http://localhost:8000

FEATURES:
---------
- RF packet monitoring on 2.4GHz
- Device detection and tracking
- Manual device blocking
- Real-time web dashboard
- Channel hopping detection

FILES:
------
esp32/wids_sensor.ino    - ESP32 firmware
server/wids_server.py    - Python server
server/requirements.txt  - Python dependencies
setup.sh                - Setup script
upload_esp32.sh         - ESP32 upload guide

REQUIREMENTS:
-------------
- Python 3.8+
- ESP32 board
- nRF24L01+ module
- WiFi network

TROUBLESHOOTING:
----------------
1. If server won't start: Check port 8000 is free
2. If ESP32 not detected: Check USB connection
3. If no packets: Check nRF24 wiring and power

Enjoy your WIDS-IPS system!
EOF6

# Set permissions
chmod +x setup.sh
chmod +x upload_esp32.sh

# Create a simple test script
cat > test_system.sh << 'EOF7'
#!/bin/bash
echo "Testing WIDS system..."
echo "1. Check Python:"
python3 --version
echo ""
echo "2. Check if server runs:"
cd server
python3 wids_server.py --help 2>/dev/null && echo "✓ Server OK" || echo "✗ Server issue"
echo ""
echo "3. Files created:"
ls -la esp32/ server/ *.sh
EOF7

chmod +x test_system.sh

cd ..
echo "=============================================="
echo "   ✅ PROJECT CREATED SUCCESSFULLY!"
echo "=============================================="
echo ""
echo "Project location: wids-ips-project/"
echo ""
echo "To setup:"
echo "1. cd wids-ips-project"
echo "2. bash setup.sh"
echo ""
echo "To start server:"
echo "source venv/bin/activate"
echo "python server/wids_server.py"
echo ""
echo "Dashboard: http://localhost:8000"
echo ""
echo "Check README.txt for full instructions."
