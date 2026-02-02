#!/bin/bash
# WIDS-PROTECTOR v3.2 — FULL SINGLE-FILE DEPLOY (ERROR-HANDLED)

set -Eeuo pipefail
trap 'echo "❌ ERROR at line $LINENO"; exit 1' ERR

echo "🔥 WIDS-PROTECTOR v3.2 → FULL DEPLOY START"

# =====================================================
# 1. CLEAN OLD
# =====================================================
echo "🧹 Cleaning old setup..."
systemctl stop mosquitto wids-engine wids-dashboard 2>/dev/null || true
pkill -9 -f wids 2>/dev/null || true
fuser -k 1884/tcp 5000/tcp 9999/udp 2>/dev/null || true
rm -rf /root/WIDS-PROTECTOR /etc/systemd/system/wids-*.service

# =====================================================
# 2. INSTALL DEPENDENCIES
# =====================================================
apt update -qq
apt install -y python3 python3-venv python3-pip \
               mosquitto mosquitto-clients \
               sqlite3 net-tools curl -qq

# =====================================================
# 3. MQTT SAFE CONFIG (1884)
# =====================================================
cat > /etc/mosquitto/conf.d/wids.conf <<EOF
listener 1884
allow_anonymous true
EOF

systemctl restart mosquitto
sleep 2

ss -lnt | grep -q 1884 || { echo "❌ MQTT NOT LISTENING"; exit 1; }
echo "✅ MQTT READY"

# =====================================================
# 4. PROJECT SETUP
# =====================================================
mkdir -p /root/WIDS-PROTECTOR/logs
cd /root/WIDS-PROTECTOR

python3 -m venv venv
venv/bin/pip install --upgrade pip flask paho-mqtt numpy scikit-learn psutil pandas -q

# =====================================================
# 5. WIDS ENGINE (FULL ERROR HANDLING)
# =====================================================
cat > wids_engine.py <<'PY'
#!/usr/bin/env python3
import os, sys, json, time, socket, sqlite3, threading, logging
from datetime import datetime

# ---------- LOGGING ----------
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler("logs/engine.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

DB="wids.db"

def safe(fn):
    def wrapper(*a, **kw):
        try:
            return fn(*a, **kw)
        except Exception:
            logging.exception(f"❌ ERROR in {fn.__name__}")
    return wrapper

class WIDS:
    def __init__(self):
        self.init_db()
        self.count = 0

    def init_db(self):
        with sqlite3.connect(DB) as c:
            c.execute("""CREATE TABLE IF NOT EXISTS alerts(
                id INTEGER PRIMARY KEY,
                time REAL,
                device TEXT,
                ssid TEXT,
                rssi INT
            )""")

    @safe
    def process(self, data):
        if not isinstance(data, dict):
            logging.warning("⚠️ Invalid data format")
            return

        if "ssid" not in data or "rssi" not in data:
            logging.warning(f"⚠️ Missing fields: {data}")
            return

        self.count += 1
        logging.info(f"📡 #{self.count} {data.get('ssid')} RSSI={data.get('rssi')}")

        if data["rssi"] > -30:
            logging.warning(f"🚨 STRONG SIGNAL ALERT: {data}")

        with sqlite3.connect(DB) as c:
            c.execute(
                "INSERT INTO alerts(time,device,ssid,rssi) VALUES (?,?,?,?)",
                (time.time(), data.get("device","unknown"),
                 data["ssid"], data["rssi"])
            )

    @safe
    def udp_server(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", 9999))
        logging.info("📡 UDP listening on 9999")
        while True:
            data,_ = s.recvfrom(2048)
            self.process(json.loads(data.decode()))

    @safe
    def mqtt_client(self):
        import paho.mqtt.client as mqtt

        def on_message(c,u,m):
            self.process(json.loads(m.payload.decode()))

        c = mqtt.Client()
        c.on_message = on_message
        c.connect("localhost",1884)
        c.subscribe("wids/#")
        c.loop_forever()

if __name__ == "__main__":
    w = WIDS()
    threading.Thread(target=w.udp_server, daemon=True).start()
    w.mqtt_client()
PY

chmod +x wids_engine.py

# =====================================================
# 6. DASHBOARD
# =====================================================
cat > dashboard.py <<'PY'
from flask import Flask
import sqlite3, subprocess

app = Flask(__name__)

@app.route("/")
def home():
    with sqlite3.connect("wids.db") as c:
        rows = c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 15").fetchall()
    html = "<h1>🚀 WIDS LIVE</h1><pre>"
    for r in rows:
        html += f"{r}\n"
    return html + "</pre><a href='/logs'>View Logs</a>"

@app.route("/logs")
def logs():
    return subprocess.getoutput("tail -n 20 logs/engine.log")

app.run("0.0.0.0",5000)
PY

chmod +x dashboard.py

# =====================================================
# 7. SYSTEMD SERVICES
# =====================================================
cat > /etc/systemd/system/wids-engine.service <<EOF
[Unit]
Description=WIDS Engine
After=mosquitto.service

[Service]
ExecStart=/root/WIDS-PROTECTOR/venv/bin/python /root/WIDS-PROTECTOR/wids_engine.py
WorkingDirectory=/root/WIDS-PROTECTOR
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/wids-dashboard.service <<EOF
[Unit]
Description=WIDS Dashboard
After=wids-engine.service

[Service]
ExecStart=/root/WIDS-PROTECTOR/venv/bin/python /root/WIDS-PROTECTOR/dashboard.py
WorkingDirectory=/root/WIDS-PROTECTOR
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now mosquitto wids-engine wids-dashboard

IP=$(hostname -I | awk '{print $1}')
echo "
✅ WIDS-PROTECTOR v3.2 LIVE

🌐 Dashboard: http://$IP:5000
📡 MQTT:      $IP:1884
📡 UDP:       $IP:9999

🧪 TEST:
mosquitto_pub -h localhost -p 1884 -t wids/test -m '{\"ssid\":\"EVIL\",\"rssi\":-20}'
"
