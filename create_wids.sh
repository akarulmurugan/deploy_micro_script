#!/bin/bash
# WIDS-IPS Project Creator - Fixed Version

echo "=============================================="
echo "   WIDS-IPS System Project Creator"
echo "=============================================="

PROJECT_NAME="wids-ips-system"
mkdir -p $PROJECT_NAME
cd $PROJECT_NAME

echo "[1/4] Creating project structure..."

# Create directory structure
mkdir -p {firmware/sensor_node/src,server/{app/{database,ml_engine/models,ips/rules,api,sensors,dashboard/{static/{css,js,images},templates}},scripts},database/migrations,docs,tests}

echo "[2/4] Creating essential files..."

# Create ESP32 main.cpp
cat > firmware/sensor_node/src/main.cpp << 'EOF'
#include <Arduino.h>
#include <WiFi.h>
#include <SPI.h>
#include <RF24.h>
#include <ArduinoJson.h>

// Pin configuration
#define NRF24_CE_PIN 4
#define NRF24_CSN_PIN 5

// WiFi configuration
const char* ssid = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";

// Server configuration
const char* serverIP = "192.168.1.100";
const int serverPort = 8000;

RF24 radio(NRF24_CE_PIN, NRF24_CSN_PIN);

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("\n=== WIDS-IPS Sensor Node ===");
    
    // Initialize nRF24
    if (!radio.begin()) {
        Serial.println("nRF24 initialization failed!");
        while (1);
    }
    
    radio.setChannel(76);
    radio.setPALevel(RF24_PA_MAX);
    radio.setDataRate(RF24_2MBPS);
    radio.setAutoAck(false);
    radio.startListening();
    
    // Connect to WiFi
    WiFi.begin(ssid, password);
    Serial.print("Connecting to WiFi");
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nWiFi connected!");
    
    Serial.println("System initialized successfully");
}

void loop() {
    // Monitor RF channels
    static uint8_t currentChannel = 1;
    static unsigned long lastChannelHop = 0;
    
    // Channel hopping every 200ms
    if (millis() - lastChannelHop > 200) {
        radio.setChannel(currentChannel);
        currentChannel = (currentChannel % 125) + 1;
        lastChannelHop = millis();
    }
    
    // Check for packets
    if (radio.available()) {
        uint8_t buffer[32];
        radio.read(&buffer, sizeof(buffer));
        
        // Extract MAC address (simplified)
        uint8_t mac[6];
        memcpy(mac, buffer, 6);
        
        // Create JSON packet
        DynamicJsonDocument doc(256);
        doc["timestamp"] = millis();
        doc["rssi"] = radio.getRSSI();
        doc["channel"] = radio.getChannel();
        
        char macStr[18];
        snprintf(macStr, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        doc["mac"] = macStr;
        
        // Send to server via HTTP
        sendToServer(doc);
    }
    
    delay(10);
}

void sendToServer(DynamicJsonDocument& doc) {
    if (WiFi.status() == WL_CONNECTED) {
        WiFiClient client;
        if (client.connect(serverIP, serverPort)) {
            String jsonStr;
            serializeJson(doc, jsonStr);
            
            client.println("POST /api/v1/events HTTP/1.1");
            client.println("Host: " + String(serverIP));
            client.println("Content-Type: application/json");
            client.println("Connection: close");
            client.print("Content-Length: ");
            client.println(jsonStr.length());
            client.println();
            client.println(jsonStr);
            
            delay(10);
            client.stop();
        }
    }
}
EOF

# Create platformio.ini
cat > firmware/sensor_node/platformio.ini << 'EOF'
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
monitor_speed = 115200
lib_deps = 
    nrf24/RF24@^1.4.7
    bblanchon/ArduinoJson@^6.21.2

upload_port = /dev/ttyUSB0
EOF

# Create server requirements.txt
cat > server/requirements.txt << 'EOF'
fastapi==0.104.1
uvicorn[standard]==0.24.0
python-socketio==5.10.0
sqlalchemy==2.0.23
psycopg2-binary==2.9.9
scikit-learn==1.3.2
xgboost==2.0.1
pandas==2.1.3
numpy==1.24.4
jinja2==3.1.2
python-dotenv==1.0.0
pydantic==2.5.0
EOF

# Create server main.py
cat > server/app/main.py << 'EOF'
#!/usr/bin/env python3
from fastapi import FastAPI, WebSocket, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List, Optional
import asyncio
import json
from datetime import datetime

app = FastAPI(title="WIDS-IPS System", version="1.0.0")

# Add CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class RFEvent(BaseModel):
    sensor_id: str = "default"
    timestamp: int
    rssi: int
    channel: int
    mac: str
    packet_type: Optional[str] = "unknown"

class Device(BaseModel):
    mac: str
    first_seen: datetime
    last_seen: datetime
    threat_level: int = 0
    is_blocked: bool = False

# In-memory storage (use database in production)
events = []
devices = {}
blocked_macs = set()

# WebSocket connections
connections = []

@app.get("/")
async def root():
    return {"message": "WIDS-IPS System", "status": "operational"}

@app.post("/api/v1/events")
async def receive_event(event: RFEvent):
    """Receive events from ESP32 sensors"""
    events.append(event.dict())
    
    # Update device info
    if event.mac not in devices:
        devices[event.mac] = {
            "mac": event.mac,
            "first_seen": datetime.now(),
            "last_seen": datetime.now(),
            "packet_count": 1,
            "threat_level": 0
        }
    else:
        devices[event.mac]["last_seen"] = datetime.now()
        devices[event.mac]["packet_count"] += 1
    
    # Check if MAC is blocked
    if event.mac in blocked_macs:
        return {"status": "blocked", "message": "Device is blocked"}
    
    # Run ML detection (simplified)
    threat_score = detect_threat(event)
    if threat_score > 0.8:
        blocked_macs.add(event.mac)
        await broadcast_alert(f"Device {event.mac} blocked - threat score: {threat_score}")
    
    return {"status": "received", "threat_score": threat_score}

@app.get("/api/v1/devices")
async def get_devices():
    """Get list of all detected devices"""
    return list(devices.values())

@app.post("/api/v1/devices/{mac}/block")
async def block_device(mac: str, duration: int = 3600):
    """Manually block a device"""
    blocked_macs.add(mac)
    await broadcast_alert(f"Device {mac} manually blocked for {duration} seconds")
    return {"status": "blocked", "mac": mac, "duration": duration}

@app.post("/api/v1/devices/{mac}/unblock")
async def unblock_device(mac: str):
    """Unblock a device"""
    blocked_macs.discard(mac)
    return {"status": "unblocked", "mac": mac}

@app.get("/api/v1/stats")
async def get_stats():
    """Get system statistics"""
    return {
        "total_devices": len(devices),
        "blocked_devices": len(blocked_macs),
        "total_events": len(events),
        "uptime": "running"
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connections.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle incoming messages
            await handle_websocket_message(data, websocket)
    except:
        connections.remove(websocket)

async def handle_websocket_message(data: str, websocket: WebSocket):
    """Handle WebSocket messages"""
    try:
        message = json.loads(data)
        if message.get("type") == "subscribe":
            # Send current state
            await websocket.send_json({
                "type": "state",
                "devices": list(devices.values()),
                "blocked": list(blocked_macs)
            })
    except:
        pass

async def broadcast_alert(message: str):
    """Broadcast alert to all connected WebSocket clients"""
    for connection in connections:
        try:
            await connection.send_json({
                "type": "alert",
                "message": message,
                "timestamp": datetime.now().isoformat()
            })
        except:
            pass

def detect_threat(event: RFEvent) -> float:
    """Simple threat detection (replace with ML model)"""
    threat_score = 0.0
    
    # Rule 1: High RSSI (close proximity)
    if event.rssi > -50:
        threat_score += 0.3
    
    # Rule 2: Channel hopping
    recent_events = [e for e in events[-10:] if e["mac"] == event.mac]
    if len(recent_events) >= 3:
        channels = [e["channel"] for e in recent_events]
        unique_channels = len(set(channels))
        if unique_channels > 2:
            threat_score += 0.4
    
    # Rule 3: High packet rate
    if len(recent_events) > 5:
        threat_score += 0.3
    
    return min(threat_score, 1.0)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
EOF

# Create dashboard HTML
cat > server/app/dashboard/templates/dashboard.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WIDS-IPS Dashboard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f0f2f5; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { background: #1a237e; color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-card h3 { font-size: 2em; color: #1a237e; }
        .devices, .alerts { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .block-btn { background: #f44336; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; }
        .alert { padding: 10px; margin: 5px 0; border-left: 4px solid #ff9800; background: #fff3e0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> WIDS-IPS Dashboard</h1>
            <p>Wireless Intrusion Detection & Prevention System</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3 id="totalDevices">0</h3>
                <p>Devices Detected</p>
            </div>
            <div class="stat-card">
                <h3 id="blockedDevices">0</h3>
                <p>Blocked Devices</p>
            </div>
            <div class="stat-card">
                <h3 id="totalEvents">0</h3>
                <p>Packets Captured</p>
            </div>
            <div class="stat-card">
                <h3 id="threatLevel">0</h3>
                <p>Threat Level</p>
            </div>
        </div>
        
        <div class="devices">
            <h2>Detected Devices</h2>
            <table id="devicesTable">
                <thead>
                    <tr><th>MAC Address</th><th>First Seen</th><th>Last Seen</th><th>Packets</th><th>Threat</th><th>Action</th></tr>
                </thead>
                <tbody id="devicesBody"></tbody>
            </table>
        </div>
        
        <div class="alerts">
            <h2>Recent Alerts</h2>
            <div id="alertsContainer"></div>
        </div>
    </div>
    
    <script>
        class Dashboard {
            constructor() {
                this.ws = null;
                this.initWebSocket();
                this.loadStats();
                this.loadDevices();
                setInterval(() => this.loadStats(), 5000);
            }
            
            initWebSocket() {
                const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                this.ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
                
                this.ws.onopen = () => {
                    this.ws.send(JSON.stringify({type: 'subscribe'}));
                };
                
                this.ws.onmessage = (event) => {
                    const data = JSON.parse(event.data);
                    if (data.type === 'alert') {
                        this.showAlert(data.message);
                    } else if (data.type === 'state') {
                        this.updateDevices(data.devices);
                    }
                };
            }
            
            async loadStats() {
                try {
                    const response = await fetch('/api/v1/stats');
                    const stats = await response.json();
                    
                    document.getElementById('totalDevices').textContent = stats.total_devices;
                    document.getElementById('blockedDevices').textContent = stats.blocked_devices;
                    document.getElementById('totalEvents').textContent = stats.total_events;
                } catch (error) {
                    console.error('Error loading stats:', error);
                }
            }
            
            async loadDevices() {
                try {
                    const response = await fetch('/api/v1/devices');
                    const devices = await response.json();
                    this.updateDevices(devices);
                } catch (error) {
                    console.error('Error loading devices:', error);
                }
            }
            
            updateDevices(devices) {
                const tbody = document.getElementById('devicesBody');
                tbody.innerHTML = '';
                
                devices.forEach(device => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td><code>${device.mac}</code></td>
                        <td>${new Date(device.first_seen).toLocaleTimeString()}</td>
                        <td>${new Date(device.last_seen).toLocaleTimeString()}</td>
                        <td>${device.packet_count || 1}</td>
                        <td>${device.threat_level || 0}</td>
                        <td><button class="block-btn" onclick="dashboard.blockDevice('${device.mac}')">Block</button></td>
                    `;
                    tbody.appendChild(row);
                });
            }
            
            async blockDevice(mac) {
                try {
                    const response = await fetch(`/api/v1/devices/${mac}/block`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'}
                    });
                    
                    if (response.ok) {
                        this.showAlert(`Device ${mac} blocked`);
                        this.loadStats();
                        this.loadDevices();
                    }
                } catch (error) {
                    console.error('Error blocking device:', error);
                }
            }
            
            showAlert(message) {
                const container = document.getElementById('alertsContainer');
                const alert = document.createElement('div');
                alert.className = 'alert';
                alert.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${new Date().toLocaleTimeString()} - ${message}`;
                container.insertBefore(alert, container.firstChild);
                
                // Keep only last 10 alerts
                if (container.children.length > 10) {
                    container.removeChild(container.lastChild);
                }
            }
        }
        
        // Initialize dashboard
        window.dashboard = new Dashboard();
    </script>
</body>
</html>
EOF

# Create setup script
cat > server/setup.sh << 'EOF'
#!/bin/bash
echo "=== Setting up WIDS-IPS Server ==="

# Update system
sudo apt update
sudo apt upgrade -y

# Install Python
sudo apt install -y python3 python3-pip python3-venv

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

echo "=== Setup complete! ==="
echo ""
echo "To start the server:"
echo "1. source venv/bin/activate"
echo "2. uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo "Access dashboard at: http://localhost:8000/"
echo "Note: Make sure to update ESP32 code with your server IP"
EOF

# Create ESP32 setup guide
cat > firmware/setup_guide.md << 'EOF'
# ESP32 Setup Guide

## Hardware Connections:
ESP32    -> nRF24L01+
3.3V     -> VCC
GND      -> GND
GPIO4    -> CE
GPIO5    -> CSN
GPIO23   -> MOSI
GPIO19   -> MISO
GPIO18   -> SCK

## Installation:
1. Install PlatformIO:
   pip install platformio

2. Configure WiFi in main.cpp:
   - Update ssid and password
   - Update serverIP to your server's IP

3. Upload to ESP32:
   cd firmware/sensor_node
   pio run --target upload

4. Monitor output:
   pio device monitor
EOF

# Create README
cat > README.md << 'EOF'
# WIDS-IPS System
## Wireless Intrusion Detection and Prevention System

### Quick Start:

1. **Server Setup:**
   ```bash
   cd server
   chmod +x setup.sh
   ./setup.sh
   source venv/bin/activate
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
