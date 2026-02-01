cat > deploy_complete.sh << 'EOFIXED'
#!/bin/bash
set -e

cd ~/WIDS-PROTECTOR
echo "🚀 WIDS-PROTECTOR v3.0"

# 1. SYSTEM RESET (SAFE)
sudo systemctl stop wids-pro mosquitto wids-dashboard || true
docker rm -f tb || true
sudo rm -rf tb_data venv logs wids_pro.db
sudo rm -f /etc/systemd/system/{wids-pro,wids-dashboard}.service
sudo systemctl daemon-reload

# 2. PACKAGES
sudo apt update -qq >/dev/null 2>&1
sudo apt install -y python3-pip python3-venv mosquitto sqlite3 docker.io \
    net-tools ufw curl iptables-persistent mosquitto-clients htop jq \
    python3-full fail2ban -qq

sudo systemctl enable --now docker mosquitto ufw fail2ban

# 3. PYTHON ENVIRONMENT
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip >/dev/null 2>&1
pip install paho-mqtt scikit-learn==1.3.2 numpy pandas requests flask \
    prometheus-client psutil -q

# 4. WIDS ENGINE (UNCHANGED)
cat > wids_pro.py << 'PY3'
#!/usr/bin/env python3
"""
WIDS-PROTECTOR v3.0 - IEEE Enterprise Wireless IDS
"""

import paho.mqtt.client as mqtt
import socket, json, sqlite3, time, threading, logging, os, subprocess, sys
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import psutil
from datetime import datetime
from collections import deque

CONFIG = {
    'MQTT_HOST': 'localhost',
    'MQTT_PORT': 1884,
    'UDP_PORT': 9999,
    'BASELINE_SAMPLES': 100,
    'ANOMALY_THRESHOLD': -0.15,
    'CONTAINMENT_ENABLED': True,
    'DB_PATH': 'wids_pro.db',
    'LOG_PATH': 'logs/wids_pro.log'
}

baseline_features = []
scaler = StandardScaler()
model = None
is_trained = False
blocked_macs = set()
recent_alerts = deque(maxlen=100)
db_lock = threading.Lock()

os.makedirs('logs', exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)7s | %(message)s',
    handlers=[logging.FileHandler(CONFIG['LOG_PATH']), logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

DB = sqlite3.connect(CONFIG['DB_PATH'], check_same_thread=False)
DB.execute('''
CREATE TABLE IF NOT EXISTS telemetry (id INTEGER PRIMARY KEY, timestamp REAL, device TEXT, ssid TEXT, bssid TEXT, rssi REAL, channel INTEGER, features TEXT, anomaly_score REAL);
CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, timestamp REAL, threat_type TEXT, ssid TEXT, bssid TEXT, rssi REAL, anomaly_score REAL, action TEXT, evidence TEXT);
CREATE INDEX IF NOT EXISTS idx_telemetry_time ON telemetry(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp);
''')
DB.commit()

class WIDS_Engine:
    def __init__(self):
        self.stats = {'samples_seen': 0, 'alerts_generated': 0, 'macs_blocked': 0, 'cpu_usage': 0.0}
    
    def extract_features(self, data):
        try:
            rssi = float(data.get('rssi', -100))
            channel = int(data.get('channel', 1))
            hour = datetime.now().hour
            device_type = 1.0 if data.get('device') == 'ESP32' else 0.0
            ssid_len = len(data.get('ssid', ''))
            return np.array([[rssi, channel, hour, device_type, ssid_len, rssi * channel, abs(rssi) / (channel + 1)]])
        except:
            return None
    
    def train_model(self):
        global model, scaler, is_trained
        if len(baseline_features) >= CONFIG['BASELINE_SAMPLES']:
            X = np.array(baseline_features)
            scaler.fit(X)
            X_scaled = scaler.transform(X)
            model = IsolationForest(contamination=0.03, n_estimators=100, max_samples=0.8, random_state=42)
            model.fit(X_scaled)
            is_trained = True
            logger.info(f"🎯 ML TRAINED | Samples: {len(baseline_features)}")
    
    def detect_anomaly(self, features):
        if not is_trained or features is None: return False, 0.0
        try:
            features_scaled = scaler.transform(features)
            score = model.decision_function(features_scaled)[0]
            is_outlier = model.predict(features_scaled)[0] == -1
            return is_outlier and score < CONFIG['ANOMALY_THRESHOLD'], score
        except:
            return False, 0.0
    
    def contain_threat(self, mac):
        if not CONFIG['CONTAINMENT_ENABLED'] or mac in blocked_macs: return False
        try:
            cmd = ['iptables', '-I', 'INPUT', '1', '-m', 'mac', '--mac-source', mac, '-j', 'DROP', '-m', 'comment', '--comment', 'WIDS_v3.0']
            subprocess.run(cmd, check=True, capture_output=True)
            blocked_macs.add(mac)
            self.stats['macs_blocked'] += 1
            logger.warning(f"🔒 BLOCKED: {mac}")
            return True
        except:
            logger.error(f"Containment failed: {mac}")
            return False
    
    def log_telemetry(self, data, score):
        with db_lock:
            DB.execute('INSERT INTO telemetry (timestamp, device, ssid, bssid, rssi, channel, features, anomaly_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (
                time.time(), data.get('device', 'unknown'), data.get('ssid', ''), data.get('bssid', ''), data.get('rssi', 0),
                data.get('channel', 0), json.dumps(data.get('features', [])), score))
            DB.commit()
    
    def log_alert(self, data, score):
        threat = {'threat_id': f"WIDS-{int(time.time())}", 'type': 'rogue_ap', 'action': 'blocked' if self.contain_threat(data.get('bssid', '')) else 'alerted'}
        with db_lock:
            DB.execute('INSERT INTO alerts (timestamp, threat_type, ssid, bssid, rssi, anomaly_score, action, evidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (
                time.time(), threat['type'], data.get('ssid', ''), data.get('bssid', ''), data.get('rssi', 0), score, threat['action'], json.dumps(data)))
            DB.commit()
        self.stats['alerts_generated'] += 1
        logger.critical(f"🚨 ALERT: {data.get('ssid')} | Score: {score:.3f} | {threat['action']}")

engine = WIDS_Engine()

def udp_sensor_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', CONFIG['UDP_PORT']))
    logger.info(f"🔌 UDP: {CONFIG['UDP_PORT']}")
    while True:
        try:
            data, addr = sock.recvfrom(2048)
            payload = json.loads(data.decode())
            payload['source'] = f"UDP:{addr[0]}"
            process_telemetry(payload)
        except: pass

def mqtt_callback(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        process_telemetry(payload)
    except: pass

def process_telemetry(data):
    engine.stats['samples_seen'] += 1
    features = engine.extract_features(data)
    if features is None: return
    if len(baseline_features) < CONFIG['BASELINE_SAMPLES']:
        baseline_features.append(features[0].tolist())
        logger.info(f"🧠 Baseline [{len(baseline_features)}/{CONFIG['BASELINE_SAMPLES']}]")
        engine.train_model()
        return
    is_anomaly, score = engine.detect_anomaly(features)
    engine.log_telemetry(data, score)
    if is_anomaly:
        engine.log_alert(data, score)

def status_monitor():
    while True:
        engine.stats['cpu_usage'] = psutil.cpu_percent()
        logger.info(f"📊 Samples={engine.stats['samples_seen']} Alerts={engine.stats['alerts_generated']} Blocked={len(blocked_macs)} CPU={engine.stats['cpu_usage']:.1f}%")
        time.sleep(60)

def main():
    logger.info("="*70)
    logger.info("🚀 WIDS-PROTECTOR v3.0 ENTERPRISE STARTED")
    logger.info(f"🎯 VM_IP: {socket.gethostbyname(socket.gethostname())}")
    logger.info("="*70)
    threading.Thread(target=udp_sensor_listener, daemon=True).start()
    threading.Thread(target=status_monitor, daemon=True).start()
    client = mqtt.Client("wids_siem_v3")
    client.on_message = mqtt_callback
    client.connect(CONFIG['MQTT_HOST'], CONFIG['MQTT_PORT'])
    client.subscribe("wids/#")
    client.loop_forever()

if __name__ == "__main__":
    main()
PY3

chmod +x wids_pro.py

# 5. DASHBOARD (MINIFIED)
cat > dashboard.py << 'DASH'
from flask import Flask, render_template_string, jsonify
import sqlite3, time, subprocess

app = Flask(__name__)
DB_PATH = 'wids_pro.db'

@app.route('/')
def dashboard():
    conn = sqlite3.connect(DB_PATH)
    alerts = conn.execute('SELECT timestamp, ssid, bssid, rssi, anomaly_score, action FROM alerts ORDER BY timestamp DESC LIMIT 20').fetchall()
    alerts = [{'timestamp': time.ctime(a[0]), 'ssid': a[1], 'bssid': a[2], 'rssi': a[3], 'anomaly_score': a[4], 'action': a[5]} for a in alerts]
    blocked = subprocess.run(['iptables', '-L', 'INPUT', '-n'], capture_output=True, text=True).stdout
    return '''
<!DOCTYPE html><html><head><title>WIDS v3.0</title><meta http-equiv="refresh" content="5">
<style>body{font-family:monospace;background:#000;color:#0f0;padding:20px}.alert{background:#f44;color:#fff;padding:10px;margin:10px 0}.metric{background:#111;padding:15px;margin:5px 0;border-left:5px solid #0f0}table{width:100%;border-collapse:collapse}th,td{padding:8px;border-bottom:1px solid #333}th{background:#222}</style></head>
<body><h1>🚀 WIDS-PROTECTOR v3.0 LIVE</h1>
<div class="metric"><h3>📊 METRICS</h3><pre>''' + subprocess.run(['journalctl', '-u', 'wids-pro', '-n', '1'], capture_output=True, text=True).stdout + '''</pre></div>
<div class="metric"><h3>🚨 ALERTS (''' + str(len(alerts)) + ''')</h3>''' + ('''
<table><tr><th>Time</th><th>SSID</th><th>BSSID</th><th>RSSI</th><th>Score</th><th>Action</th></tr>''' + ''.join([f'<tr class="alert"><td>{a["timestamp"]}</td><td>{a["ssid"]}</td><td>{a["bssid"]}</td><td>{a["rssi"]}dBm</td><td style="color:red">{a["anomaly_score"]:.3f}</td><td><b>{a["action"]}</b></td></tr>' for a in alerts]) + '''</table>''' if alerts else '<p>Training baseline...</p>') + '''</div>
<div class="metric"><h3>🔒 BLOCKED</h3><pre>''' + blocked + '''</pre></div></body></html>'''

@app.route('/api/alerts')
def api_alerts():
    conn = sqlite3.connect(DB_PATH)
    alerts = conn.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 50').fetchall()
    return jsonify([dict(zip([c[0] for c in conn.description], row)) for row in alerts])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
DASH

# 6. FIXED THINGSBOARD (VALID IMAGE!)
docker rm -f tb || true
docker pull thingsboard/tb-postgres
mkdir -p tb_data
docker run -d --name tb --restart unless-stopped \
  -p 8080:8080 -p 1883:1883 -p 5683:5683/udp \
  -v ~/WIDS-PROTECTOR/tb_data:/data \
  -e TB_DATABASE_TYPE=postgres \
  thingsboard/tb-postgres

# 7. MQTT CONFIG
echo "listener 1884
allow_anonymous true
max_connections 1000" | sudo tee /etc/mosquitto/conf.d/wids.conf
sudo systemctl restart mosquitto

# 8. FIREWALL
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh && sudo ufw allow 8080/tcp && sudo ufw allow 1884/tcp && sudo ufw allow 9999/udp && sudo ufw allow 5000/tcp
sudo ufw --reload

# 9. SYSTEMD SERVICES
sudo tee /etc/systemd/system/wids-pro.service > /dev/null << SVC
[Unit]
Description=WIDS-PROTECTOR v3.0
After=network.target mosquitto.service docker.service
Requires=mosquitto.service docker.service
[Service]
Type=simple
WorkingDirectory=/root/WIDS-PROTECTOR
Environment=PATH=/root/WIDS-PROTECTOR/venv/bin:\$PATH
ExecStart=/root/WIDS-PROTECTOR/venv/bin/python wids_pro.py
Restart=always
User=root
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
SVC

sudo tee /etc/systemd/system/wids-dashboard.service > /dev/null << DSVC
[Unit]
Description=WIDS Dashboard
After=wids-pro.service
Requires=wids-pro.service
[Service]
WorkingDirectory=/root/WIDS-PROTECTOR
Environment=PATH=/root/WIDS-PROTECTOR/venv/bin:\$PATH
ExecStart=/root/WIDS-PROTECTOR/venv/bin/python dashboard.py
Restart=always
User=root
[Install]
WantedBy=multi-user.target
DSVC

sudo systemctl daemon-reload
sudo systemctl enable --now wids-pro wids-dashboard mosquitto

VM_IP=$(hostname -I | awk '{print \$1}')
sleep 30  # Wait startup
cat << EOF

✅✅✅ WIDS-PROTECTOR v3.0 LIVE! ✅✅✅

📊 MAIN DASHBOARD:     http://$VM_IP:5000  ← OPEN THIS FIRST!
📈 THINGSBOARD:        http://$VM_IP:8080  (sysadmin@thingsboard.org / sysadmin)
📜 ENGINE LOGS:        sudo journalctl -u wids-pro -f
🔍 BLOCKED DEVICES:    sudo iptables -L INPUT -n | grep WIDS
📋 DATABASE:           sqlite3 ~/WIDS-PROTECTOR/wids_pro.db "SELECT * FROM alerts;"
🎯 STATUS:             sudo systemctl status wids-pro wids-dashboard

TEST: mosquitto_pub -h localhost -p 1884 -t wids/esp32 -m '{"device":"TEST","ssid":"EVIL_AP","bssid":"AA:BB:CC:DD:EE:FF","rssi":-50,"channel":11}'

🚀 Sensors: ESP32(MQTT:1884) + PicoW(UDP:9999)
EOF
EOFIXED

chmod +x deploy_complete.sh && ./deploy_complete.sh
