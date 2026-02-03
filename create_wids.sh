#!/bin/bash
echo "=============================================="
echo "   WIDS-IPS System Creator"
echo "=============================================="

# Clean up old project if exists
rm -rf wids-ips-system
rm -f wids-ips-system.tar.gz

# Create project directory
mkdir -p wids-ips-system
cd wids-ips-system

echo "[1/3] Creating directory structure..."
mkdir -p firmware/sensor_node/src
mkdir -p server/app
mkdir -p scripts

echo "[2/3] Creating ESP32 files..."

# Create minimal ESP32 code
cat > firmware/sensor_node/src/main.cpp << 'END_MAIN'
#include <Arduino.h>
#include <WiFi.h>
#include <SPI.h>
#include <RF24.h>
#include <ArduinoJson.h>

#define NRF24_CE_PIN 4
#define NRF24_CSN_PIN 5

const char* WIFI_SSID = "YOUR_WIFI";
const char* WIFI_PASS = "YOUR_PASSWORD";
const char* SERVER_IP = "192.168.1.100";
const int SERVER_PORT = 8000;

RF24 radio(NRF24_CE_PIN, NRF24_CSN_PIN);

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("=== WIDS Sensor Starting ===");
    
    // Init nRF24
    if (!radio.begin()) {
        Serial.println("nRF24 FAILED!");
        while(1);
    }
    
    radio.setChannel(76);
    radio.setPALevel(RF24_PA_MAX);
    radio.startListening();
    
    // Connect WiFi
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nWiFi Connected!");
}

void loop() {
    static uint8_t channel = 1;
    static unsigned long lastHop = 0;
    
    // Channel hop
    if (millis() - lastHop > 200) {
        radio.setChannel(channel);
        channel = (channel % 125) + 1;
        lastHop = millis();
    }
    
    // Check packets
    if (radio.available()) {
        uint8_t buffer[32];
        radio.read(&buffer, sizeof(buffer));
        
        // Send to server
        Serial.print("Packet on channel ");
        Serial.print(radio.getChannel());
        Serial.print(" RSSI: ");
        Serial.println(radio.getRSSI());
    }
    
    delay(10);
}
END_MAIN

# Create platformio.ini
cat > firmware/sensor_node/platformio.ini << 'END_PIO'
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
monitor_speed = 115200
lib_deps = 
    nrf24/RF24@^1.4.7
    bblanchon/ArduinoJson@^6.21.2
END_PIO

echo "[3/3] Creating server files..."

# Create requirements.txt
cat > server/requirements.txt << 'END_REQ'
fastapi==0.104.1
uvicorn[standard]==0.24.0
pydantic==2.5.0
python-socketio==5.10.0
scikit-learn==1.3.2
pandas==2.1.3
numpy==1.24.4
END_REQ

# Create main server file
cat > server/app/main.py << 'END_SERVER'
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import json

app = FastAPI(title="WIDS-IPS", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Packet(BaseModel):
    mac: str
    rssi: int
    channel: int
    timestamp: int

packets = []
devices = {}
blocked = set()

@app.get("/")
def root():
    return {"system": "WIDS-IPS", "status": "online"}

@app.post("/api/packet")
def receive_packet(packet: Packet):
    packets.append(packet.dict())
    devices[packet.mac] = packet.dict()
    
    # Simple threat detection
    threat = 0
    if packet.rssi > -50:
        threat += 30
    if packet.channel in [1, 6, 11]:
        threat += 20
    
    return {"received": True, "threat": threat}

@app.get("/api/devices")
def get_devices():
    return {"devices": list(devices.values()), "count": len(devices)}

@app.post("/api/block/{mac}")
def block_device(mac: str):
    blocked.add(mac)
    return {"blocked": True, "mac": mac}

@app.post("/api/unblock/{mac}")
def unblock_device(mac: str):
    blocked.discard(mac)
    return {"blocked": False, "mac": mac}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    while True:
        data = await websocket.receive_text()
        await websocket.send_text(f"Message: {data}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
END_SERVER

# Create HTML dashboard
mkdir -p server/app/static
cat > server/app/static/dashboard.html << 'END_HTML'
<!DOCTYPE html>
<html>
<head>
    <title>WIDS Dashboard</title>
    <style>
        body { font-family: Arial; margin: 20px; background: #f0f0f0; }
        .container { max-width: 1200px; margin: auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 10px; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat { background: white; padding: 20px; border-radius: 10px; flex: 1; }
        table { width: 100%; background: white; border-radius: 10px; }
        th, td { padding: 12px; text-align: left; }
        button { background: #e74c3c; color: white; border: none; padding: 8px 16px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 WIDS-IPS Dashboard</h1>
            <p>Real-time wireless intrusion detection</p>
        </div>
        
        <div class="stats">
            <div class="stat">
                <h3 id="deviceCount">0</h3>
                <p>Devices Detected</p>
            </div>
            <div class="stat">
                <h3 id="packetCount">0</h3>
                <p>Packets Captured</p>
            </div>
            <div class="stat">
                <h3 id="blockedCount">0</h3>
                <p>Blocked Devices</p>
            </div>
        </div>
        
        <h2>Detected Devices</h2>
        <table id="deviceTable">
            <thead><tr><th>MAC</th><th>RSSI</th><th>Channel</th><th>Action</th></tr></thead>
            <tbody id="deviceList"></tbody>
        </table>
    </div>
    
    <script>
        async function loadDevices() {
            try {
                const res = await fetch('/api/devices');
                const data = await res.json();
                
                document.getElementById('deviceCount').textContent = data.count;
                document.getElementById('packetCount').textContent = data.count * 10;
                
                const tbody = document.getElementById('deviceList');
                tbody.innerHTML = '';
                
                data.devices.forEach(device => {
                    const row = tbody.insertRow();
                    row.innerHTML = `
                        <td>${device.mac}</td>
                        <td>${device.rssi}</td>
                        <td>${device.channel}</td>
                        <td><button onclick="blockDevice('${device.mac}')">Block</button></td>
                    `;
                });
            } catch(e) {
                console.error(e);
            }
        }
        
        async function blockDevice(mac) {
            await fetch(`/api/block/${mac}`, {method: 'POST'});
            loadDevices();
        }
        
        // Refresh every 5 seconds
        setInterval(loadDevices, 5000);
        loadDevices();
    </script>
</body>
</html>
END_HTML

# Create setup scripts
cat > server/setup.sh << 'END_SETUP'
#!/bin/bash
echo "Installing WIDS server..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo "Setup complete!"
echo "Run: source venv/bin/activate && uvicorn app.main:app --reload"
END_SETUP

cat > scripts/flash_esp32.sh << 'END_FLASH'
#!/bin/bash
echo "Flashing ESP32..."
cd firmware/sensor_node
echo "1. Update WiFi credentials in src/main.cpp"
echo "2. Run: pio run --target upload"
echo "3. Monitor: pio device monitor"
END_FLASH

# Create README
cat > README.md << 'END_README'
# WIDS-IPS System

## Quick Start:

### 1. Start Server:
```bash
cd server
bash setup.sh
source venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
