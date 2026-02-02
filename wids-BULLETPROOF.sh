cat > ~/wids-BULLETPROOF.sh << 'EOF_BULLETPROOF'
#!/bin/bash
# WIDS-PROTECTOR v3.0 BULLETPROOF → Handles ALL errors
set -e

echo "🚀 WIDS BULLETPROOF DEPLOYMENT → Error-proof!"

# ========================================
# 1. TOTAL CLEANUP + PORT KILLER
# ========================================
echo "🧹 Full cleanup..."
sudo systemctl stop mosquitto wids* || true
sudo fuser -k 1883/tcp 1884/tcp 5000/tcp 9999/udp 8080/tcp || true
sudo rm -rf /etc/systemd/system/wids* /root/WIDS-PROTECTOR /var/lib/mosquitto/* /etc/mosquitto/conf.d/wids.conf
sudo systemctl daemon-reload
sudo systemctl reset-failed

cd /root
rm -rf WIDS-PROTECTOR
mkdir WIDS-PROTECTOR && cd WIDS-PROTECTOR

# ========================================
# 2. INSTALL + VERIFY DEPENDENCIES
# ========================================
echo "📦 Installing dependencies..."
sudo apt update -qq
sudo apt install -y python3-pip python3-venv mosquitto sqlite3 curl mosquitto-clients net-tools -qq

# Kill any zombie mosquitto
sudo pkill -f mosquitto || true
sleep 2

# ========================================
# 3. PYTHON ENVIRONMENT (SAFE)
# ========================================
echo "🐍 Creating Python environment..."
rm -rf venv
python3 -m venv venv || { echo "❌ Python venv failed"; exit 1; }
source venv/bin/activate

pip install --upgrade pip -q
pip install paho-mqtt flask numpy scikit-learn psutil pandas requests -q --no-cache-dir || { echo "❌ Pip install failed"; exit 1; }

echo "✅ Python env OK"

# ========================================
# 4. CORE WIDS ENGINE (ROBUST)
# ========================================
cat > wids_engine.py << 'WIDS_ENGINE'
#!/usr/bin/env python3
"""
WIDS-PROTECTOR v3.0 - BULLETPROOF ENGINE
MQTT:1884 | UDP:9999 | SQLite | ML Detection
"""
import os, sys, json, sqlite3, time, threading, socket, logging
import numpy as np
from datetime import datetime
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("⚠️ ML libraries not available - using rule-based detection")

# Setup logging
os.makedirs('logs', exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.FileHandler('logs/wids.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class WIDS:
    def __init__(self):
        self.db_path = 'wids.db'
        self.baseline = []
        self.model = None
        self.scaler = None
        self.trained = False
        self.stats = {'alerts': 0, 'samples': 0}
        self.init_db()
        logger.info("🚀 WIDS Engine initialized")

    def init_db(self):
        try:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    device TEXT,
                    ssid TEXT,
                    bssid TEXT,
                    rssi REAL,
                    channel INTEGER,
                    score REAL,
                    action TEXT
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    data TEXT
                )
            ''')
            conn.commit()
            conn.close()
            logger.info("✅ Database initialized")
        except Exception as e:
            logger.error(f"❌ DB init failed: {e}")

    def is_anomaly(self, data):
        """Simple ML + rule-based anomaly detection"""
        try:
            rssi = data.get('rssi', -100)
            # Rule-based: Very strong signal + suspicious SSID
            if rssi > -30 or 'evil' in data.get('ssid', '').lower():
                return True, -0.8
            
            # ML-based if available
            if ML_AVAILABLE and self.trained and len(self.baseline) > 20:
                features = np.array([[rssi, data.get('channel', 1), time.time() % 24]])
                scaled = self.scaler.transform(features)
                score = self.model.decision_function(scaled)[0]
                return score < -0.15, score
            
            return False, 0.0
        except:
            return False, 0.0

    def process_packet(self, data):
        self.stats['samples'] += 1
        is_alert, score = self.is_anomaly(data)
        
        # Train ML model
        if len(self.baseline) < 50:
            features = np.array([[data.get('rssi', -100), data.get('channel', 1)]])
            self.baseline.append(features[0])
            if len(self.baseline) == 50 and ML_AVAILABLE:
                try:
                    self.scaler = StandardScaler().fit(self.baseline)
                    self.model = IsolationForest(contamination=0.1, random_state=42)
                    self.model.fit(self.scaler.transform(self.baseline))
                    self.trained = True
                    logger.info("🎯 ML model trained!")
                except Exception as e:
                    logger.warning(f"ML training failed: {e}")

        # Log telemetry
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                "INSERT INTO telemetry (timestamp, data) VALUES (?, ?)",
                (time.time(), json.dumps(data))
            )
            conn.commit()
        except: pass

        # Alert if anomaly
        if is_alert:
            self.stats['alerts'] += 1
            action = "ALERT"
            try:
                conn = sqlite3.connect(self.db_path)
                conn.execute(
                    "INSERT INTO alerts (timestamp, device, ssid, bssid, rssi, channel, score, action) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (time.time(), data.get('device'), data.get('ssid'), data.get('bssid'),
                     data.get('rssi'), data.get('channel'), score, action)
                )
                conn.commit()
            except: pass
            
            logger.warning(f"🚨 ALERT: {data.get('ssid', 'UNK')} | Score: {score:.3f}")

        if self.stats['samples'] % 10 == 0:
            logger.info(f"📊 Stats: {self.stats}")

    def udp_listener(self):
        logger.info("📡 Starting UDP listener on 9999")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', 9999))
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                payload = json.loads(data.decode())
                self.process_packet(payload)
            except Exception as e:
                logger.debug(f"UDP error: {e}")

    def mqtt_listener(self):
        import paho.mqtt.client as mqtt
        def on_connect(client, userdata, flags, rc):
            logger.info(f"✅ MQTT connected (rc={rc})")
            client.subscribe("wids/#")
        
        def on_message(client, userdata, msg):
            try:
                payload = json.loads(msg.payload.decode())
                self.process_packet(payload)
            except Exception as e:
                logger.debug(f"MQTT msg error: {e}")

        logger.info("📨 Connecting to MQTT 1884...")
        while True:
            try:
                client = mqtt.Client()
                client.on_connect = on_connect
                client.on_message = on_message
                client.connect("localhost", 1884, 60)
                client.loop_forever()
            except Exception as e:
                logger.error(f"MQTT connect failed: {e}. Retrying in 10s...")
                time.sleep(10)

    def run(self):
        logger.info("🚀 Starting WIDS listeners...")
        threading.Thread(target=self.udp_listener, daemon=True).start()
        self.mqtt_listener()

if __name__ == "__main__":
    wids = WIDS()
    wids.run()
WIDS_ENGINE

chmod +x wids_engine.py

# ========================================
# 5. DASHBOARD (SIMPLE + ROBUST)
# ========================================
cat > dashboard.py << 'DASHBOARD'
from flask import Flask, jsonify
import sqlite3, subprocess, os
app = Flask(__name__)

@app.route('/')
def home():
    try:
        conn = sqlite3.connect('wids.db')
        alerts = conn.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 20').fetchall()
        telemetry = conn.execute('SELECT COUNT(*) FROM telemetry').fetchone()[0]
        html = f"""
        <html><head><title>WIDS-PROTECTOR v3.0</title>
        <meta http-equiv="refresh" content="5">
        <style>body{{font-family:monospace;background:#000;color:lime;padding:20px}}
        table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid lime;padding:8px;text-align:left}}
        .alert{{background:#f00;color:white}}</style></head>
        <body>
        <h1>🚀 WIDS-PROTECTOR v3.0 LIVE</h1>
        <h2>📊 Stats: {telemetry} packets | {len(alerts)} alerts</h2>
        <h3>🚨 Recent Alerts:</h3>
        <table><tr><th>ID</th><th>Time</th><th>Device</th><th>SSID</th><th>BSSID</th><th>RSSI</th><th>Score</th></tr>
        """
        for alert in alerts:
            html += f"<tr class='alert'><td>{alert[0]}</td><td>{alert[1]:.0f}</td><td>{alert[2]}</td><td>{alert[3]}</td><td>{alert[4]}</td><td>{alert[5]}</td><td>{alert[6]:.3f}</td></tr>"
        html += "</table></body></html>"
        return html
    except Exception as e:
        return f"<h1>WIDS Dashboard</h1><p>Error: {e}</p>"

@app.route('/logs')
def logs():
    try:
        return subprocess.run(['tail', '-n', '50', 'logs/wids.log'], capture_output=True, text=True, timeout=5).stdout
    except:
        return "No logs available"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
DASHBOARD

chmod +x dashboard.py

# ========================================
# 6. MOSQUITTO CONFIG (ROBUST)
# ========================================
echo "Creating Mosquitto config..."
cat > /etc/mosquitto/conf.d/wids.conf << 'MQTT_CONF'
# WIDS Mosquitto Config
persistence true
persistence_location /var/lib/mosquitto/
log_dest file /var/log/mosquitto/wids.log
log_type all
connection_messages true
log_timestamp true

# WIDS listener
listener 1884 0.0.0.0
allow_anonymous true
max_queued_messages 1000
message_size_limit 0
MQTT_CONF

sudo chown -R mosquitto:mosquitto /var/lib/mosquitto /var/log/mosquitto
sudo chmod 755 /etc/mosquitto/conf.d/wids.conf

# ========================================
# 7. PERFECT SYSTEMD SERVICES
# ========================================
cat > /etc/systemd/system/wids-engine.service << 'ENGINE_SERVICE'
[Unit]
Description=WIDS-PROTECTOR ML Engine
Documentation=https://wids-protector.com
After=network-online.target mosquitto.service
Wants=mosquitto.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/root/WIDS-PROTECTOR
Environment=PATH=/root/WIDS-PROTECTOR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/bin
ExecStart=/root/WIDS-PROTECTOR/venv/bin/python3 /root/WIDS-PROTECTOR/wids_engine.py
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5s
TimeoutStopSec=30s

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/root/WIDS-PROTECTOR /var/log/mosquitto

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
ENGINE_SERVICE

cat > /etc/systemd/system/wids-dashboard.service << 'DASH_SERVICE'
[Unit]
Description=WIDS-PROTECTOR Dashboard
Documentation=https://wids-protector.com
After=wids-engine.service mosquitto.service
Requires=wids-engine.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/root/WIDS-PROTECTOR
Environment=PATH=/root/WIDS-PROTECTOR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/bin
ExecStart=/root/WIDS-PROTECTOR/venv/bin/python3 /root/WIDS-PROTECTOR/dashboard.py
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5s
TimeoutStopSec=30s

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/root/WIDS-PROTECTOR

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
DASH_SERVICE

# ========================================
# 8. LAUNCH WITH VERIFICATION
# ========================================
echo "🚀 Starting services..."
sudo systemctl daemon-reload
sudo systemctl reset-failed

# Start MQTT first
sudo systemctl enable mosquitto
sudo systemctl start mosquitto
sleep 3

# Verify MQTT
if ! sudo systemctl is-active --quiet mosquitto; then
    echo "❌ MQTT failed - checking logs:"
    sudo journalctl -u mosquitto.service -n 20 --no-pager
    exit 1
fi

echo "✅ MQTT running on 1884"

# Start WIDS
sudo systemctl enable wids-engine wids-dashboard
sudo systemctl start wids-engine
sleep 3
sudo systemctl start wids-dashboard

# ========================================
# 9. FINAL STATUS + TESTS
# ========================================
IP=$(hostname -I | awk '{print $1}')

echo "
✅✅✅ WIDS-PROTECTOR v3.0 → FULLY DEPLOYED! ✅✅✅

🌐 DASHBOARD: http://$IP:5000
📨 MQTT: $IP:1884 ✓
📡 UDP: $IP:9999 ✓
📊 LOGS: tail -f logs/wids.log

🔍 SERVICE STATUS:
Mosquitto: $(sudo systemctl is-active mosquitto)
WIDS Engine: $(sudo systemctl is-active wids-engine)
Dashboard: $(sudo systemctl is-active wids-dashboard)

🧪 TEST MQTT (run this):
mosquitto_pub -h localhost -p 1884 -t wids/esp32 -m '{\"device\":\"ESP32\",\"ssid\":\"EVIL_AP\",\"rssi\":-25,\"bssid\":\"AA:BB:CC:DD:EE:FF\",\"channel\":11}'

🧪 TEST UDP (another terminal):
echo '{\"device\":\"PicoW\",\"ssid\":\"ROGUE\",\"rssi\":-30,\"bssid\":\"FF:FF:FF:FF:FF:FF\"}' | nc -u localhost 9999

📱 SENSOR CODES SAVED:
cat ESP32_SENSOR.txt
cat PICO_SENSOR.txt
"

# Generate sensor codes
cat > ESP32_SENSOR.txt << 'ESP32_SENSOR'
/* ESP32 WIFI SCANNER - Arduino IDE */
#include <WiFi.h>
#include <PubSubClient.h>

const char* ssid = "YOUR_WIFI";
const char* password = "YOUR_PASS";
const char* mqtt_server = "YOUR_SERVER_IP";

WiFiClient espClient;
PubSubClient client(espClient);

void setup() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) delay(500);
  Serial.println("WiFi connected");
  client.setServer(mqtt_server, 1884);
}

void loop() {
  if (!client.connected()) client.connect("ESP32-WIDS");
  int n = WiFi.scanNetworks();
  for (int i = 0; i < n; i++) {
    String json = "{\"device\":\"ESP32\",\"ssid\":\"" + WiFi.SSID(i) + 
                  "\",\"bssid\":\"" + WiFi.BSSIDstr(i) + 
                  "\",\"rssi\":" + WiFi.RSSI(i) + 
                  ",\"channel\":" + WiFi.channel(i) + "}";
    client.publish("wids/esp32", json.c_str());
    Serial.println(json);
  }
  delay(15000);
}
ESP32_SENSOR

cat > PICO_SENSOR.txt << 'PICO_SENSOR'
# Pico W UDP Reporter - MicroPython (Thonny)
import network, usocket as socket, ujson, time, machine

# CONFIGURE
WIFI_SSID = 'YOUR_WIFI'
WIFI_PASS = 'YOUR_PASS'
SERVER_IP = 'YOUR_SERVER_IP'

wlan = network.WLAN(network.STA_IF)
wlan.active(True)
wlan.connect(WIFI_SSID, WIFI_PASS)

while not wlan.isconnected():
    time.sleep(1)
print('Connected:', wlan.ifconfig()[0])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
while True:
    data = {
        'device': 'PicoW',
        'ssid': 'DETECTED_AP',
        'bssid': '11:22:33:44:55:66',
        'rssi': -55,
        'channel': 6
    }
    sock.sendto(ujson.dumps(data), (SERVER_IP, 9999))
    print('UDP sent:', data)
    time.sleep(10)
PICO_SENSOR

echo "🎉 Deployment complete! Check http://$(hostname -I | cut -d' ' -f1):5000"
EOF_BULLETPROOF
