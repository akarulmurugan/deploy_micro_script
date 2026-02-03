#!/bin/bash
# WIDS-IPS System Project Creation Script
# Save this as create_wids_ips_project.sh and run: bash create_wids_ips_project.sh

set -e

echo "=============================================="
echo "   WIDS-IPS System Project Creator"
echo "=============================================="

PROJECT_NAME="wids-ips-system"
mkdir -p $PROJECT_NAME
cd $PROJECT_NAME

echo "[1/4] Creating project structure..."

# Create complete directory structure
mkdir -p firmware/sensor_node/src
mkdir -p firmware/sensor_node/data
mkdir -p firmware/jammer_node/src
mkdir -p server/app/database
mkdir -p server/app/ml_engine/models
mkdir -p server/app/ips/rules
mkdir -p server/app/api
mkdir -p server/app/sensors
mkdir -p server/app/dashboard/static/css
mkdir -p server/app/dashboard/static/js
mkdir -p server/app/dashboard/static/images
mkdir -p server/app/dashboard/templates
mkdir -p database/migrations
mkdir -p docs
mkdir -p scripts
mkdir -p tests

echo "[2/4] Creating configuration files..."

# 1. Create platformio.ini for ESP32
cat > firmware/sensor_node/platformio.ini << 'EOF'
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
monitor_speed = 115200
lib_deps = 
    nrf24/RF24@^1.4.7
    bblanchon/ArduinoJson@^6.21.2
    knolleary/PubSubClient@^2.8
    olikraus/U8g2@^2.34.22

build_flags = 
    -DWIFI_SSID=\"YourSSID\"
    -DWIFI_PASSWORD=\"YourPassword\"
    -DSERVER_IP=\"192.168.1.100\"
    -DSERVER_PORT=8080

upload_port = /dev/ttyUSB0
EOF

# 2. Create ESP32 secrets.h
cat > firmware/sensor_node/src/secrets.h << 'EOF'
#ifndef SECRETS_H
#define SECRETS_H

// WiFi Credentials
#define WIFI_SSID "Your_WiFi_SSID"
#define WIFI_PASSWORD "Your_WiFi_Password"

// Server Configuration
#define SERVER_IP "192.168.1.100"
#define SERVER_PORT 8080
#define SERVER_API_KEY "your-secret-api-key"

// Sensor ID (Unique for each ESP32)
#define SENSOR_ID "ESP32_SENSOR_01"
#define SENSOR_LOCATION "Front_Gate"

// nRF24 Configuration
#define NRF24_CE_PIN 4
#define NRF24_CSN_PIN 5
#define NRF24_CHANNEL 76
#define NRF24_PA_LEVEL RF24_PA_MAX

#endif
EOF

# 3. Create ESP32 config.h
cat > firmware/sensor_node/src/config.h << 'EOF'
#ifndef CONFIG_H
#define CONFIG_H

#include <Arduino.h>

// System Configuration
const uint32_t HEARTBEAT_INTERVAL = 60000; // 1 minute
const uint32_t PACKET_BUFFER_SIZE = 1000;
const uint32_t MAX_BLOCKED_DEVICES = 50;

// RF Monitoring Configuration
const uint8_t MONITOR_CHANNELS[] = {1, 6, 11, 36, 40, 44, 48};
const uint8_t NUM_CHANNELS = 7;
const uint16_t CHANNEL_HOP_INTERVAL = 200; // ms

// Packet Types
enum PacketType {
    PKT_BEACON = 0x01,
    PKT_DATA = 0x02,
    PKT_MGMT = 0x03,
    PKT_CONTROL = 0x04,
    PKT_DEAUTH = 0x05,
    PKT_PROBE = 0x06
};

// Device States
enum DeviceState {
    STATE_MONITORING,
    STATE_BLOCKING,
    STATE_JAMMING,
    STATE_SLEEP
};

// Block Actions
enum BlockAction {
    ACTION_NONE = 0,
    ACTION_LOG_ONLY = 1,
    ACTION_ALERT = 2,
    ACTION_DEAUTH = 3,
    ACTION_BLOCK = 4,
    ACTION_JAM = 5
};

// Packet Structure
#pragma pack(push, 1)
typedef struct {
    uint32_t timestamp;
    int16_t rssi;
    uint8_t channel;
    uint8_t packet_type;
    uint8_t payload[32];
    uint8_t mac_address[6];
    uint8_t sequence_number;
} RF_Packet;
#pragma pack(pop)

#endif
EOF

# 4. Create main.cpp for ESP32
cat > firmware/sensor_node/src/main.cpp << 'EOF'
#include <Arduino.h>
#include <WiFi.h>
#include <SPI.h>
#include <RF24.h>
#include <ArduinoJson.h>

// Include our headers
#include "packet_monitor.h"
#include "wifi_manager.h"
#include "blocker_engine.h"
#include "config.h"
#include "secrets.h"

// Global Objects
PacketMonitor packetMonitor;
WifiManager wifiManager;
BlockerEngine blockerEngine;

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("\n=== WIDS-IPS Sensor Node ===");
    Serial.printf("Sensor ID: %s\n", SENSOR_ID);
    Serial.printf("Location: %s\n", SENSOR_LOCATION);
    
    // Initialize components
    packetMonitor.init(NRF24_CE_PIN, NRF24_CSN_PIN, NRF24_CHANNEL);
    wifiManager.connect(WIFI_SSID, WIFI_PASSWORD);
    blockerEngine.init();
    
    Serial.println("System initialized successfully");
    Serial.println("Starting monitoring...");
}

void loop() {
    // Main monitoring loop
    static uint32_t lastHeartbeat = 0;
    static uint8_t currentChannelIndex = 0;
    
    // Channel hopping
    if (millis() - lastHeartbeat > 200) {
        uint8_t channel = MONITOR_CHANNELS[currentChannelIndex];
        packetMonitor.setChannel(channel);
        currentChannelIndex = (currentChannelIndex + 1) % NUM_CHANNELS;
        lastHeartbeat = millis();
    }
    
    // Check for packets
    if (packetMonitor.available()) {
        RF_Packet packet;
        if (packetMonitor.readPacket(&packet)) {
            // Process packet
            if (!blockerEngine.isBlocked(packet.mac_address)) {
                // Send to server
                wifiManager.sendPacketToServer(packet);
            }
        }
    }
    
    delay(10);
}
EOF

# 5. Create server requirements.txt
cat > server/requirements.txt << 'EOF'
# Web Framework
fastapi==0.104.1
uvicorn[standard]==0.24.0
python-socketio==5.10.0
aiohttp==3.9.1

# Database
sqlalchemy==2.0.23
asyncpg==0.29.0
psycopg2-binary==2.9.9
redis==5.0.1
aioredis==2.0.1
alembic==1.12.1

# Machine Learning
scikit-learn==1.3.2
xgboost==2.0.1
pandas==2.1.3
numpy==1.24.4
scipy==1.11.4
joblib==1.3.2

# Data Processing
pyshark==0.6
scapy==2.5.0
dpkt==1.9.8

# Utilities
python-dotenv==1.0.0
pydantic==2.5.0
pydantic-settings==2.1.0
celery==5.3.4
flower==2.0.1

# Dashboard
jinja2==3.1.2
aiofiles==23.2.1

# Monitoring
prometheus-client==0.19.0

# Security
bcrypt==4.1.2
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4

# Development
black==23.11.0
pytest==7.4.3
pytest-asyncio==0.21.1
EOF

# 6. Create main server application
cat > server/app/main.py << 'EOF'
#!/usr/bin/env python3
# WIDS-IPS Main Server Application

import asyncio
import logging
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="WIDS-IPS System", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="app/dashboard/static"), name="static")

# Templates
templates = Jinja2Templates(directory="app/dashboard/templates")

@app.get("/")
async def root():
    return {"message": "WIDS-IPS System API", "status": "operational"}

@app.get("/dashboard")
async def dashboard():
    return templates.TemplateResponse("dashboard.html", {"request": {}})

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_text(f"Message received: {data}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
EOF

# 7. Create database models
cat > server/app/database/models.py << 'EOF'
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid

class Sensor:
    __tablename__ = "sensors"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sensor_id = Column(String(50), unique=True, nullable=False)
    location = Column(String(100))
    ip_address = Column(String(45))
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    is_active = Column(Boolean, default=True)

class RFEvent:
    __tablename__ = "rf_events"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sensor_id = Column(String(50), nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    rssi = Column(Integer)
    channel = Column(Integer)
    source_mac = Column(String(17))
    packet_type = Column(String(20))
    is_malicious = Column(Boolean, default=False)

class Device:
    __tablename__ = "devices"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    mac_address = Column(String(17), unique=True, nullable=False)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    is_blacklisted = Column(Boolean, default=False)
    threat_level = Column(Integer, default=0)

class Alert:
    __tablename__ = "alerts"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    alert_type = Column(String(50))
    severity = Column(String(20))
    source_mac = Column(String(17))
    description = Column(String(500))
    resolved = Column(Boolean, default=False)
EOF

# 8. Create ML engine
cat > server/app/ml_engine/anomaly_detector.py << 'EOF'
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.is_trained = False
    
    def train(self, data):
        """Train anomaly detection model"""
        try:
            # Extract features
            features = self.extract_features(data)
            
            # Train Isolation Forest
            self.model = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42
            )
            self.model.fit(features)
            
            self.is_trained = True
            return True
        except Exception as e:
            print(f"Training error: {e}")
            return False
    
    def detect(self, data):
        """Detect anomalies in data"""
        if not self.is_trained:
            return []
        
        features = self.extract_features(data)
        predictions = self.model.predict(features)
        
        anomalies = []
        for i, pred in enumerate(predictions):
            if pred == -1:  # Anomaly
                anomalies.append({
                    'index': i,
                    'score': self.model.decision_function([features[i]])[0]
                })
        
        return anomalies
    
    def extract_features(self, data):
        """Extract features from RF data"""
        # Simplified feature extraction
        features = []
        for item in data:
            feature_vector = [
                item.get('rssi', 0),
                item.get('channel', 0),
                len(item.get('payload', ''))
            ]
            features.append(feature_vector)
        
        return np.array(features)
    
    def save_model(self, path):
        """Save trained model"""
        if self.model:
            joblib.dump(self.model, path)
    
    def load_model(self, path):
        """Load pre-trained model"""
        self.model = joblib.load(path)
        self.is_trained = True
EOF

# 9. Create dashboard HTML
cat > server/app/dashboard/templates/dashboard.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WIDS-IPS Dashboard</title>
    <link rel="stylesheet" href="/static/css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="logo">
                <i class="fas fa-shield-alt"></i>
                <h1>WIDS-IPS System</h1>
            </div>
            <div class="status">
                <span class="status-dot active"></span>
                <span>System Active</span>
            </div>
        </header>

        <div class="main-content">
            <div class="stats">
                <div class="stat-card">
                    <h3 id="active-sensors">0</h3>
                    <p>Active Sensors</p>
                </div>
                <div class="stat-card">
                    <h3 id="total-devices">0</h3>
                    <p>Devices Detected</p>
                </div>
                <div class="stat-card">
                    <h3 id="blocked-devices">0</h3>
                    <p>Blocked Devices</p>
                </div>
                <div class="stat-card">
                    <h3 id="active-alerts">0</h3>
                    <p>Active Alerts</p>
                </div>
            </div>

            <div class="charts">
                <div class="chart-container">
                    <h3>Network Traffic</h3>
                    <canvas id="trafficChart"></canvas>
                </div>
                <div class="chart-container">
                    <h3>Threat Levels</h3>
                    <canvas id="threatChart"></canvas>
                </div>
            </div>

            <div class="alerts">
                <h3>Recent Alerts</h3>
                <div id="alerts-list">
                    <!-- Alerts will be populated by JavaScript -->
                </div>
            </div>
        </div>

        <footer class="footer">
            <p>WIDS-IPS System v1.0.0</p>
        </footer>
    </div>

    <script src="/static/js/dashboard.js"></script>
</body>
</html>
EOF

# 10. Create dashboard JavaScript
cat > server/app/dashboard/static/js/dashboard.js << 'EOF'
class Dashboard {
    constructor() {
        this.initCharts();
        this.initWebSocket();
        this.loadData();
    }
    
    initCharts() {
        // Traffic chart
        const trafficCtx = document.getElementById('trafficChart').getContext('2d');
        this.trafficChart = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets/sec',
                    data: [],
                    borderColor: 'rgb(75, 192, 192)',
                    tension: 0.1
                }]
            }
        });
        
        // Threat chart
        const threatCtx = document.getElementById('threatChart').getContext('2d');
        this.threatChart = new Chart(threatCtx, {
            type: 'doughnut',
            data: {
                labels: ['Normal', 'Low', 'Medium', 'High'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#10B981', '#3B82F6', '#F59E0B', '#EF4444']
                }]
            }
        });
    }
    
    initWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        this.ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
        
        this.ws.onmessage = (event) => {
            this.handleMessage(JSON.parse(event.data));
        };
    }
    
    async loadData() {
        try {
            const response = await fetch('/api/v1/stats');
            const data = await response.json();
            this.updateDashboard(data);
        } catch (error) {
            console.error('Error loading data:', error);
        }
    }
    
    updateDashboard(data) {
        // Update stats
        document.getElementById('active-sensors').textContent = data.active_sensors || 0;
        document.getElementById('total-devices').textContent = data.total_devices || 0;
        document.getElementById('blocked-devices').textContent = data.blocked_devices || 0;
        document.getElementById('active-alerts').textContent = data.active_alerts || 0;
        
        // Update charts
        if (data.traffic_data) {
            this.updateTrafficChart(data.traffic_data);
        }
        
        if (data.threat_data) {
            this.updateThreatChart(data.threat_data);
        }
    }
    
    updateTrafficChart(trafficData) {
        const chart = this.trafficChart;
        
        if (chart.data.labels.length >= 20) {
            chart.data.labels.shift();
            chart.data.datasets[0].data.shift();
        }
        
        chart.data.labels.push(new Date().toLocaleTimeString());
        chart.data.datasets[0].data.push(trafficData.packets_per_second);
        chart.update();
    }
    
    updateThreatChart(threatData) {
        this.threatChart.data.datasets[0].data = [
            threatData.normal || 0,
            threatData.low || 0,
            threatData.medium || 0,
            threatData.high || 0
        ];
        this.threatChart.update();
    }
    
    handleMessage(message) {
        switch (message.type) {
            case 'alert':
                this.showAlert(message.data);
                break;
            case 'stats':
                this.updateDashboard(message.data);
                break;
        }
    }
    
    showAlert(alert) {
        const alertsList = document.getElementById('alerts-list');
        const alertElement = document.createElement('div');
        alertElement.className = `alert severity-${alert.severity}`;
        alertElement.innerHTML = `
            <div class="alert-header">
                <i class="fas fa-exclamation-triangle"></i>
                <strong>${alert.alert_type}</strong>
                <span class="time">${new Date(alert.timestamp).toLocaleTimeString()}</span>
            </div>
            <div class="alert-body">
                <p>${alert.description}</p>
                <small>Device: ${alert.source_mac}</small>
            </div>
        `;
        
        alertsList.insertBefore(alertElement, alertsList.firstChild);
        
        // Keep only last 10 alerts
        if (alertsList.children.length > 10) {
            alertsList.removeChild(alertsList.lastChild);
        }
    }
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new Dashboard();
});
EOF

# 11. Create dashboard CSS
cat > server/app/dashboard/static/css/style.css << 'EOF
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
    background-color: #f5f5f5;
    color: #333;
}

.container {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

.header {
    background-color: #1a237e;
    color: white;
    padding: 1rem 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.logo {
    display: flex;
    align-items: center;
    gap: 1rem;
}

.logo i {
    font-size: 2rem;
}

.status {
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.status-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background-color: #ccc;
}

.status-dot.active {
    background-color: #4caf50;
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0% { opacity: 1; }
    50% { opacity: 0.5; }
    100% { opacity: 1; }
}

.main-content {
    flex: 1;
    padding: 2rem;
    max-width: 1400px;
    margin: 0 auto;
    width: 100%;
}

.stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
}

.stat-card {
    background-color: white;
    padding: 1.5rem;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    text-align: center;
}

.stat-card h3 {
    font-size: 2rem;
    color: #1a237e;
    margin-bottom: 0.5rem;
}

.stat-card p {
    color: #666;
    font-size: 0.9rem;
}

.charts {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
    gap: 2rem;
    margin-bottom: 2rem;
}

.chart-container {
    background-color: white;
    padding: 1.5rem;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.chart-container h3 {
    margin-bottom: 1rem;
    color: #1a237e;
}

.alerts {
    background-color: white;
    padding: 1.5rem;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.alerts h3 {
    margin-bottom: 1rem;
    color: #1a237e;
}

#alerts-list {
    max-height: 300px;
    overflow-y: auto;
}

.alert {
    padding: 1rem;
    margin-bottom: 0.5rem;
    border-left: 4px solid #ccc;
    border-radius: 4px;
    background-color: #f9f9f9;
}

.alert.severity-high {
    border-left-color: #ef4444;
    background-color: #fee2e2;
}

.alert.severity-medium {
    border-left-color: #f59e0b;
    background-color: #fef3c7;
}

.alert.severity-low {
    border-left-color: #3b82f6;
    background-color: #dbeafe;
}

.alert-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.5rem;
}

.alert-header .time {
    margin-left: auto;
    font-size: 0.8rem;
    color: #666;
}

.footer {
    background-color: #1a237e;
    color: white;
    padding: 1rem 2rem;
    text-align: center;
    margin-top: auto;
}
EOF

# 12. Create setup script
cat > server/setup.sh << 'EOF'
#!/bin/bash
# WIDS-IPS Server Setup Script

echo "=== Setting up WIDS-IPS Server ==="

# Update system
sudo apt update
sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip python3-venv
sudo apt install -y postgresql postgresql-contrib
sudo apt install -y nginx

# Create database
sudo -u postgres psql -c "CREATE DATABASE widsips;"
sudo -u postgres psql -c "CREATE USER widsuser WITH PASSWORD 'wids123';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE widsips TO widsuser;"

# Setup Python environment
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "=== Setup complete ==="
echo "To start the server:"
echo "1. source venv/bin/activate"
echo "2. uvicorn app.main:app --reload"
echo ""
echo "Access dashboard at: http://localhost:8000/dashboard"
EOF

# 13. Create flash ESP32 script
cat > scripts/flash_esp32.sh << 'EOF'
#!/bin/bash
# Flash ESP32 WIDS Sensor

echo "=== Flashing ESP32 WIDS Sensor ==="

echo "Please update the following in firmware/sensor_node/src/secrets.h:"
echo "1. WIFI_SSID"
echo "2. WIFI_PASSWORD"
echo "3. SERVER_IP"
echo "4. SERVER_API_KEY"
echo ""
echo "Then run:"
echo "cd firmware/sensor_node"
echo "pio run --target upload"
echo ""
echo "For serial monitoring:"
echo "pio device monitor"
EOF

# 14. Create README
cat > README.md << 'EOF'
# WIDS-IPS System
## Wireless Intrusion Detection and Prevention System

### Overview
A complete WIDS-IPS system using ESP32 with nRF24, Ubuntu server, and Machine Learning for automated threat detection and blocking.

### Architecture
- **ESP32 Sensors**: Monitor 2.4GHz RF traffic using nRF24L01+PA+LNA
- **Ubuntu Server**: Central processing, ML engine, and dashboard
- **ML Engine**: Anomaly detection using Isolation Forest and XGBoost
- **IPS System**: Automated blocking and deauthentication

### Quick Start

#### 1. Server Setup
```bash
cd server
bash setup.sh
source venv/bin/activate
uvicorn app.main:app --reload
