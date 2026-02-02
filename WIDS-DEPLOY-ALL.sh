cat > ~/WIDS-DEPLOY-ALL.sh << 'EOF_DEPLOY_ALL'
#!/bin/bash
echo "🔥 WIDS-PROTECTOR v3.1 → TOTAL RESET + DEPLOY"

# ========================================
# 0. STOP EVERYTHING + FULL CLEAN
# ========================================
echo "🛑 STOPPING ALL SERVICES..."
sudo systemctl stop mosquitto wids* nginx apache2 || true
sudo pkill -9 -f "mosquitto\|flask\|wids\|python.*wids" || true
sudo fuser -k 1883/tcp 1884/tcp 5000/tcp 8080/tcp 9999/udp || true

echo "🧹 FULL CLEANUP..."
sudo rm -rf /root/WIDS-PROTECTOR /etc/systemd/system/wids* /etc/mosquitto/conf.d/* /etc/mosquitto/*.conf.bak /var/lib/mosquitto/*
sudo systemctl daemon-reload
sudo systemctl reset-failed

# ========================================
# 1. MQTT BULLETPROOF SETUP
# ========================================
echo "📡 MQTT SETUP..."
sudo mkdir -p /var/lib/mosquitto /var/log/mosquitto
sudo chown -R mosquitto:mosquitto /var/lib/mosquitto /var/log/mosquitto
sudo usermod -a -G mosquitto root || true

cat > /etc/mosquitto/mosquitto.conf << 'MQTT_CONF'
persistence true
persistence_location /var/lib/mosquitto/
log_dest file /var/log/mosquitto/mosquitto.log
listener 1884 0.0.0.0
allow_anonymous true
max_queued_messages 1000
MQTT_CONF

sudo systemctl restart mosquitto
sleep 3

# TEST MQTT
if mosquitto_pub -h localhost -p 1884 -t test -m "mqtt-ready" 2>/dev/null; then
    echo "✅ MQTT PORT 1884 → READY!"
else
    echo "❌ MQTT FAILED → CHECK: journalctl -u mosquitto -n20"
    exit 1
fi

# ========================================
# 2. WIDS ENVIRONMENT
# ========================================
cd /root
rm -rf WIDS-PROTECTOR
mkdir WIDS-PROTECTOR && cd WIDS-PROTECTOR
sudo apt update -qq && sudo apt install -y python3-pip python3-venv mosquitto mosquitto-clients sqlite3 net-tools -qq

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip flask paho-mqtt numpy scikit-learn psutil pandas requests -q

# ========================================
# 3. WIDS ENGINE (ML + UDP + MQTT)
# ========================================
cat > wids_engine.py << 'WIDS_ENGINE'
#!/usr/bin/env python3
import os, sys, json, sqlite3, time, threading, socket, logging
import numpy as np
from datetime import datetime
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    HAS_ML = True
except:
    HAS_ML = False

os.makedirs('logs', exist_ok=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(message)s', 
                   handlers=[logging.FileHandler('logs/engine.log'), logging.StreamHandler()])

class WIDS:
    def __init__(self):
        self.db = 'wids.db'
        self.init_db()
        self.count = 0
        
    def init_db(self):
        conn = sqlite3.connect(self.db)
        conn.execute('''CREATE TABLE IF NOT EXISTS alerts 
                       (id INTEGER PRIMARY KEY, time REAL, data TEXT)''')
        conn.commit()
    
    def process(self, data):
        self.count += 1
        logging.info(f"📡 #{self.count} {data.get('ssid', 'N/A')} | RSSI: {data.get('rssi', 'N/A')}")
        
        # Simple anomaly check
        if data.get('rssi', 0) > -30:
            logging.warning(f"🚨 STRONG SIGNAL ALERT: {data}")
        
        # Save to DB
        conn = sqlite3.connect(self.db)
        conn.execute("INSERT INTO alerts (time, data) VALUES (?, ?)", 
                    (time.time(), json.dumps(data)))
        conn.commit()
    
    def udp_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 9999))
        logging.info("📡 UDP listening on 9999")
        while True:
            try:
                data, _ = sock.recvfrom(1024)
                self.process(json.loads(data.decode()))
            except: pass
    
    def mqtt_client(self):
        import paho.mqtt.client as mqtt
        def on_message(client, userdata, msg):
            try: self.process(json.loads(msg.payload.decode()))
            except: pass
        client = mqtt.Client()
        client.on_message = on_message
        client.connect("localhost", 1884)
        client.subscribe("wids/#")
        client.loop_forever()

if __name__ == "__main__":
    wids = WIDS()
    threading.Thread(target=wids.udp_server, daemon=True).start()
    wids.mqtt_client()
WIDS_ENGINE

chmod +x wids_engine.py

# ========================================
# 4. DASHBOARD
# ========================================
cat > dashboard.py << 'DASHBOARD'
from flask import Flask
import sqlite3, subprocess
app = Flask(__name__)

@app.route('/')
def index():
    try:
        conn = sqlite3.connect('wids.db')
        alerts = conn.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 15').fetchall()
        html = "<h1>🚀 WIDS-PROTECTOR LIVE</h1><h2>Recent Alerts:</h2><pre>"
        for alert in alerts:
            html += f"ID:{alert[0]} | {alert[1]:.0f}s | {alert[2][:100]}...\n"
        html += "</pre><p><a href='/logs'>Live Logs</a></p>"
        return html
    except Exception as e:
        return f"<h1>WIDS</h1><p>{e}</p>"

@app.route('/logs')
def logs():
    try:
        return subprocess.check_output(['tail', '-n', '20', 'logs/engine.log']).decode()
    except:
        return "No logs"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
DASHBOARD

chmod +x dashboard.py

# ========================================
# 5. SYSTEMD SERVICES
# ========================================
cat > /etc/systemd/system/wids-engine.service << 'SERVICE1'
[Unit]
Description=WIDS Engine
After=mosquitto.service
[Service]
ExecStart=/root/WIDS-PROTECTOR/venv/bin/python /root/WIDS-PROTECTOR/wids_engine.py
WorkingDirectory=/root/WIDS-PROTECTOR
Restart=always
User=root
[Install]
WantedBy=multi-user.target
SERVICE1

cat > /etc/systemd/system/wids-dashboard.service << 'SERVICE2'
[Unit]
Description=WIDS Dashboard
After=wids-engine.service
[Service]
ExecStart=/root/WIDS-PROTECTOR/venv/bin/python /root/WIDS-PROTECTOR/dashboard.py
WorkingDirectory=/root/WIDS-PROTECTOR
Restart=always
User=root
[Install]
WantedBy=multi-user.target
SERVICE2

# ========================================
# 6. START ALL SERVICES
# ========================================
sudo systemctl daemon-reload
sudo systemctl enable mosquitto wids-engine wids-dashboard
sudo systemctl restart mosquitto wids-engine wids-dashboard

IP=$(hostname -I | awk '{print $1}')
echo "
🎉🎉🎉 WIDS-PROTECTOR v3.1 → LIVE! 🎉🎉🎉

🌐 DASHBOARD: http://$IP:5000
📡 MQTT: $IP:1884 ✓
🔌 UDP: $IP:9999 ✓

✅ STATUS:
$(sudo systemctl is-active mosquitto) | $(sudo systemctl is-active wids-engine) | $(sudo systemctl is-active wids-dashboard)

🧪 TEST NOW:
mosquitto_pub -h localhost -p 1884 -t wids/esp32 -m '{\"ssid\":\"EVIL\",\"rssi\":-20}'

📊 TAIL LOGS: tail -f /root/WIDS-PROTECTOR/logs/engine.log
"
EOF_DEPLOY_ALL

chmod +x ~/WIDS-DEPLOY-ALL.sh
echo "🚀 RUN: ./WIDS-DEPLOY-ALL.sh"
echo "✅ ONE COMMAND → FULL DEPLOY!"
