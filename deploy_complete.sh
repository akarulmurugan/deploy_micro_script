#!/bin/bash
# COMPLETE WIDS-PROTECTOR v2.0 - IEEE Ready

set -e
cd ~/WIDS-PROTECTOR

echo "🚀 DEPLOYING ENHANCED WIDS-SIEM..."

# 1. INSTALL PACKAGES
sudo apt update
sudo apt install -y python3-pip mosquitto sqlite3 docker.io net-tools \
    ufw curl htop tmux iptables-persistent

pip3 install --user --upgrade paho-mqtt tb-mqtt-client scikit-learn \
    pandas numpy requests pyyaml

# 2. ENHANCED SIEM ENGINE
cat > wids_pro.py << 'EOF'
#!/usr/bin/env python3
"""
IEEE-Grade WIDS-SIEM v2.0
- Multi-Sensor Fusion (ESP32 + Pico W)
- IsolationForest ML Anomaly Detection
- ThingsBoard IoT Dashboard
- VM iptables Containment
- Auto-Baseline Training
"""

import paho.mqtt.client as mqtt
import json, sqlite3, time, threading, os, subprocess, socket
import numpy as np
from sklearn.ensemble import IsolationForest
from tb_mqtt_client import TBDeviceMqttClient
from datetime import datetime
import logging

# LOGGING
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

# STATE
DB_PATH = 'wids_pro.db'
model = IsolationForest(contamination=0.04, random_state=42)
baseline_samples = []
TRAINED = False
BLOCKED_MACS = set()

# DATABASE
def init_db():
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    db.execute('''CREATE TABLE IF NOT EXISTS alerts 
                  (id INTEGER PRIMARY KEY, data TEXT, ts REAL, blocked INTEGER)''')
    db.execute('''CREATE TABLE IF NOT EXISTS baseline 
                  (features TEXT, ts REAL)''')
    db.commit()
    return db

DB = init_db()

# THINGSBOARD
tb_client = TBDeviceMqttClient("localhost", "DEMO_TOKEN")

def send_alert(threat):
    """Enhanced ThingsBoard Telemetry"""
    telemetry = {
        "threat_id": threat.get("threat_id", "unknown"),
        "device": threat["device"],
        "ssid": threat.get("ssid", ""),
        "bssid": threat["bssid"],
        "rssi": threat["rssi"],
        "anomaly_score": threat["anomaly_score"],
        "action": threat["action"],
        "latitude": threat.get("lat", 0),
        "longitude": threat.get("lon", 0),
        "timestamp": int(time.time() * 1000)
    }
    tb_client.send_telemetry(telemetry)
    logger.info(f"📊 ThingsBoard: {threat['ssid']} ({threat['action']})")

def block_mac(mac):
    """Enhanced VM Containment"""
    if mac in BLOCKED_MACS:
        return
    try:
        subprocess.run([
            "sudo", "iptables", "-I", "INPUT", "1",
            "-m", "mac", "--mac-source", mac,
            "-j", "DROP"
        ], check=True, capture_output=True)
        BLOCKED_MACS.add(mac)
        logger.info(f"🔒 BLOCKED: {mac}")
    except Exception as e:
        logger.warning(f"Block failed: {e}")

def udp_listener():
    """Pico W UDP Bridge → MQTT"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", 9999))
    logger.info("🔌 Pico UDP Bridge: 0.0.0.0:9999")
    
    mqttc = mqtt.Client()
    mqttc.connect("localhost", 1883)
    
    while True:
        try:
            data, addr = sock.recvfrom(2048)
            alert = json.loads(data.decode())
            mqttc.publish("wids/picow", json.dumps(alert))
            logger.info(f"PicoW[{addr[0]}]: {alert.get('ssid', 'scan')}")
        except:
            pass

def on_mqtt_message(client, userdata, msg):
    global baseline_samples, TRAINED
    
    try:
        data = json.loads(msg.payload.decode())
        device = data.get("device", "unknown")
        
        # ML FEATURES: RSSI + Channel + Hour + Device Type
        features = np.array([[
            data.get("rssi", -100),
            data.get("channel", 1),
            time.localtime().tm_hour,
            1 if device == "ESP32" else 0  # Sensor type
        ]])
        
        # AUTO-TRAINING (50 samples)
        if len(baseline_samples) < 50:
            baseline_samples.append(features[0].tolist())
            logger.info(f"🧠 Training [{len(baseline_samples)}/50]")
            
            if len(baseline_samples) == 50:
                model.fit(np.array(baseline_samples))
                TRAINED = True
                logger.info("✅ ML MODEL TRAINED - ACTIVE DETECTION")
            return
        
        # ANOMALY DETECTION
        if TRAINED:
            anomaly_score = model.decision_function(features)[0]
            is_anomaly = model.predict(features)[0] == -1
            
            # HIGH-CONFIDENCE THREAT
            if (is_anomaly and anomaly_score < -0.12) or data.get("alert") == "rogue_ap":
                
                threat = {
                    "threat_id": f"{int(time.time())}-{device}",
                    "device": device,
                    "ssid": data.get("ssid", "Hidden"),
                    "bssid": data.get("bssid", ""),
                    "rssi": data.get("rssi", 0),
                    "channel": data.get("channel", 1),
                    "anomaly_score": anomaly_score,
                    "action": "BLOCKED"
                }
                
                # EXECUTE RESPONSE
                mac = threat["bssid"]
                if mac:
                    block_mac(mac)
                
                # ALERTING
                send_alert(threat)
                
                # DATABASE
                DB.execute("INSERT INTO alerts (data, ts, blocked) VALUES (?, ?, ?)",
                          (json.dumps(threat), time.time(), 1))
                DB.commit()
                
                logger.warning(f"🚨 THREAT: {threat['ssid']} | "
                              f"Score: {anomaly_score:.3f} | "
                              f"MAC: {mac}")
        
    except Exception as e:
        logger.error(f"Message Error: {e}")

# INITIALIZE
def main():
    # MQTT
    mqtt_client = mqtt.Client()
    mqtt_client.on_message = on_mqtt_message
    mqtt_client.connect("localhost", 1883, 60)
    mqtt_client.subscribe("wids/#")
    
    # ThingsBoard
    tb_client.connect()
    
    # UDP Bridge
    threading.Thread(target=udp_listener, daemon=True).start()
    
    logger.info("🚀 WIDS-PROTECTOR v2.0 ACTIVE")
    logger.info("📊 Dashboard: http://localhost:8080")
    logger.info("🔌 MQTT: localhost:1883 | UDP: 0.0.0.0:9999")
    
    mqtt_client.loop_forever()

if __name__ == "__main__":
    main()
EOF

chmod +x wids_pro.py

# 3. THINGSBOARD + DASHBOARD
docker run -d --name tb --restart=always -p 8080:8080 \
  -e TB_HOSTNAME=$(hostname) \
  thingsboard/tb

sleep 10

# 4. AUTO-LAUNCH SERVICE
cat > /etc/systemd/system/wids-pro.service << EOF
[Unit]
Description=WIDS-PROTECTOR SIEM
After=multi-user.target docker.service mosquitto.service

[Service]
Type=simple
User=$USER
WorkingDirectory=/home/$USER/WIDS-PROTECTOR
ExecStart=/usr/bin/python3 wids_pro.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wids-pro.service

# 5. UFW + IPTABLES
sudo ufw allow 1883
sudo ufw allow 9999
sudo ufw allow 8080
sudo ufw --force enable

# 6. START
systemctl start wids-pro.service
systemctl start mosquitto

echo "✅ COMPLETE DEPLOYMENT!"
echo "📊 DASHBOARD: http://$(hostname -I | awk '{print $1}'):8080"
echo "🔍 STATUS: systemctl status wids-pro"
echo "📜 LOGS: journalctl -u wids-pro -f"
echo "🧠 ML Status: tail -f ~/WIDS-PROTECTOR/wids_pro.log | grep 'TRAINED'"
EOF

chmod +x deploy_complete.sh
echo "💾 SAVE: ~/WIDS-PROTECTOR/deploy_complete.sh"
echo "🚀 RUN: cd ~/WIDS-PROTECTOR && ./deploy_complete.sh"
