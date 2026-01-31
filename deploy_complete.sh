#!/bin/bash
# =============================================================================
# WIDS-PROTECTOR v2.1 - FULL DEPLOYMENT (Ubuntu VM)
# ESP32 MQTT + Pico UDP → ML SIEM → iptables Block
# =============================================================================

set -euo pipefail
echo "🎯 WIDS-PROTECTOR v2.1 - IEEE GRADE DEPLOYMENT"

# CONFIG
DIR="$HOME/WIDS-PROTECTOR"
LOG_DIR="$DIR/logs"
VM_IP=$(hostname -I | awk '{print $1}')

# 1. ENVIRONMENT SETUP
mkdir -p "$DIR" "$LOG_DIR" && cd "$DIR"
sudo chown -R "$USER:$USER" "$DIR"
export DEBIAN_FRONTEND=noninteractive

# 2. INSTALL PACKAGES
echo "📦 Installing dependencies..."
sudo apt update -qq >/dev/null
sudo apt install -y -qq python3-pip python3-venv mosquitto sqlite3 docker.io \
    net-tools ufw curl iptables-persistent mosquitto-clients htop tmux

# 3. PYTHON ENVIRONMENT
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install paho-mqtt tb-mqtt-client scikit-learn pandas numpy requests

# 4. STOP SERVICES
sudo systemctl stop mosquitto docker wids-pro 2>/dev/null || true
docker rm -f tb 2>/dev/null || true

# 5. CORE SIEM ENGINE
cat > wids_pro.py << 'PYEOF'
#!/usr/bin/env python3
"""
WIDS-PROTECTOR v2.1 - Production Wireless IDS
Multi-sensor ML anomaly detection + automated containment
"""

import paho.mqtt.client as mqtt
import json, sqlite3, time, threading, socket, logging, os, subprocess, sys
import numpy as np
from sklearn.ensemble import IsolationForest
from tb_mqtt_client import TBDeviceMqttClient

# LOGGING (FIXED PATH)
os.makedirs('logs', exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)8s] %(message)s',
    handlers=[
        logging.FileHandler('logs/wids_pro.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# GLOBAL STATE
DB_PATH = 'wids_pro.db'
baseline_samples = []
TRAINED = False
BLOCKED_MACS = set()
model = None
DB = None
tb_client = None

def init_db():
    global DB
    DB = sqlite3.connect(DB_PATH, check_same_thread=False)
    DB.executescript('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data TEXT, ts REAL, blocked INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS baseline (
            features TEXT, ts REAL
        );
        CREATE INDEX IF NOT EXISTS idx_ts ON alerts(ts);
    ''')
    DB.commit()
    logger.info("✅ Database initialized")

def init_dashboard():
    global tb_client
    try:
        tb_client = TBDeviceMqttClient("localhost", "DEMO_TOKEN")
        tb_client.connect()
        logger.info("✅ ThingsBoard dashboard connected")
        return True
    except Exception as e:
        logger.warning(f"Dashboard unavailable: {e}")
        return False

def send_to_dashboard(threat):
    if tb_client:
        try:
            tb_client.send_telemetry({
                "threat_id": threat["threat_id"],
                "timestamp": int(time.time() * 1000),
                "device": threat["device"],
                "ssid": threat["ssid"],
                "bssid": threat["bssid"],
                "rssi": threat["rssi"],
                "channel": threat["channel"],
                "anomaly_score": threat["anomaly_score"],
                "action": threat["action"]
            })
        except Exception as e:
            logger.debug(f"Dashboard send failed: {e}")

def block_threat_mac(mac_addr):
    if mac_addr not in BLOCKED_MACS:
        try:
            subprocess.run([
                "iptables", "-I", "INPUT", "1",
                "-m", "mac", "--mac-source", mac_addr,
                "-j", "DROP", "-m", "comment", "--comment", "WIDS-BLOCK"
            ], check=True, capture_output=True)
            BLOCKED_MACS.add(mac_addr)
            logger.warning(f"🔒 BLOCKED: {mac_addr}")
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables block failed: {e}")

def pico_udp_listener():
    """High-speed UDP from Raspberry Pi Pico W"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 9999))
    
    mqttc = mqtt.Client()
    mqttc.connect("localhost", 1883, 60)
    logger.info("🔌 Pico UDP listener:9999")
    
    while True:
        try:
            data, addr = sock.recvfrom(2048)
            scan_data = json.loads(data.decode())
            mqttc.publish("wids/picow", json.dumps(scan_data))
            logger.info(f"PicoW[{addr[0]}]: {scan_data.get('ssid', 'scan')}")
        except Exception as e:
            logger.debug(f"UDP error: {e}")

def mqtt_message_handler(client, userdata, msg):
    """Core ML anomaly detection pipeline"""
    global baseline_samples, TRAINED, model
    
    try:
        telemetry = json.loads(msg.payload.decode())
        device_id = telemetry.get("device", "unknown")
        
        # Feature engineering: [RSSI, Channel, Hour, DeviceType]
        features = np.array([[
            float(telemetry.get("rssi", -100.0)),
            float(telemetry.get("channel", 1.0)),
            float(time.localtime().tm_hour),
            1.0 if device_id == "ESP32" else 0.0
        ]])
        
        ssid = telemetry.get('ssid', 'Hidden')
        rssi_db = features[0, 0]
        
        logger.info(f"📡 {device_id:<6} {ssid:<20} rssi={rssi_db:+3.0f}dBm")
        
        # PHASE 1: Environment Baseline (50 samples)
        if len(baseline_samples) < 50:
            baseline_samples.append(features[0].tolist())
            progress = f"[{len(baseline_samples)}/50]"
            logger.info(f"🧠 Training {progress} rssi={rssi_db:+3.0f}")
            
            if len(baseline_samples) == 50:
                model = IsolationForest(
                    contamination=0.04,  # 4% expected anomalies
                    random_state=42
                )
                model.fit(np.array(baseline_samples))
                TRAINED = True
                logger.info("🎯 ML MODEL TRAINED - THREAT DETECTION ACTIVE!")
            return
        
        # PHASE 2: Real-time Anomaly Detection
        if TRAINED and model is not None:
            anomaly_score = model.decision_function(features)[0]
            is_outlier = model.predict(features)[0] == -1
            
            logger.info(f"🤖 ML score={anomaly_score:+.3f} outlier={is_outlier}")
            
            # THREAT TRIGGER (score < -0.12 OR explicit rogue flag)
            threat_detected = (
                is_outlier and anomaly_score < -0.12 or
                telemetry.get("alert") == "rogue_ap"
            )
            
            if threat_detected:
                threat = {
                    "threat_id": f"T{int(time.time())}-{device_id}",
                    "device": device_id,
                    "ssid": ssid,
                    "bssid": telemetry.get("bssid", ""),
                    "rssi": int(rssi_db),
                    "channel": int(telemetry.get("channel", 1)),
                    "anomaly_score": round(anomaly_score, 3),
                    "action": "BLOCKED"
                }
                
                # AUTOMATED CONTAINMENT
                bssid_mac = threat["bssid"]
                if bssid_mac:
                    block_threat_mac(bssid_mac)
                
                # RECORD + NOTIFY
                send_to_dashboard(threat)
                DB.execute(
                    "INSERT INTO alerts (data, ts, blocked) VALUES (?, ?, ?)",
                    (json.dumps(threat), time.time(), 1)
                )
                DB.commit()
                
                logger.warning(f"🚨 THREAT BLOCKED: {ssid} "
                              f"({bssid_mac}) score={anomaly_score:+.3f}")
                
    except json.JSONDecodeError:
        logger.debug("Invalid JSON received")
    except Exception as e:
        logger.error(f"Processing error: {e}")

def main():
    logger.info("=" * 60)
    logger.info("🚀 WIDS-PROTECTOR v2.1 PRODUCTION STARTUP")
    logger.info(f"📍 VM IP: {os.uname()[1]}")
    logger.info("=" * 60)
    
    # INITIALIZATION
    init_db()
    init_dashboard()
    
    # MQTT BROKER
    mqtt_client = mqtt.Client(client_id="wids_siem")
    mqtt_client.on_message = mqtt_message_handler
    mqtt_client.connect("localhost", 1883, 60)
    mqtt_client.subscribe("wids/#")
    logger.info("✅ MQTT broker connected")
    
    # UDP SENSOR FEED (Pico W)
    sensor_thread = threading.Thread(target=pico_udp_listener, daemon=True)
    sensor_thread.start()
    
    # OPERATIONAL
    logger.info("🎯 ALL SYSTEMS OPERATIONAL")
    logger.info("📊 Dashboard: http://localhost:8080")
    logger.info("📜 Logs: tail -f logs/wids_pro.log")
    logger.info("🔍 Database: sqlite3 wids_pro.db")
    
    mqtt_client.loop_forever()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Shutdown requested")
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
PYEOF

chmod +x wids_pro.py

# 6. THINGSBOARD DASHBOARD
echo "📊 Starting ThingsBoard..."
docker run -d \
  --name tb \
  --restart unless-stopped \
  -p 8080:8080 \
  -p 1883:1883 \
  -v "$DIR/tb_data:/data" \
  -e TB_HOSTNAME=wids-siem \
  thingsboard/tb:3.5.1

sleep 30  # Dashboard startup

# 7. MOSQUITTO MQTT BROKER
sudo tee /etc/mosquitto/conf.d/wids.conf << 'MQTT'
listener 1883
allow_anonymous true
persistence true
persistence_location /var/lib/mosquitto/
log_dest file /var/log/mosquitto/wids_mqtt.log
MQTT

sudo systemctl restart mosquitto
sudo systemctl enable mosquitto

# 8. SYSTEMD SERVICE (PRODUCTION)
sudo tee /etc/systemd/system/wids-pro.service << 'SVC' > /dev/null
[Unit]
Description=WIDS-PROTECTOR SIEM Engine v2.1
Documentation=https://wids-protector.com
After=network.target docker.service mosquitto.service
Wants=docker.service mosquitto.service

[Service]
Type=simple
User=root
WorkingDirectory=/root/WIDS-PROTECTOR
Environment=PATH=/root/WIDS-PROTECTOR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/root/WIDS-PROTECTOR/venv/bin/python wids_pro.py
Restart=always
RestartSec=5
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
SVC

sudo systemctl daemon-reload
sudo systemctl enable wids-pro
sudo systemctl start wids-pro

# 9. FIREWALL + IPTABLES
sudo ufw --force enable
sudo ufw allow 22,80,8080,1883/tcp,9999/udp from 192.168.0.0/16
sudo iptables -P INPUT DROP
sudo iptables -A INPUT -i lo -j ACCEPT
sudo netfilter-persistent save

# 10. FINAL STATUS
echo "
✅ ✅ ✅ DEPLOYMENT 100% COMPLETE ✅ ✅ ✅

📊 DASHBOARD: http://$VM_IP:8080
   Login: demo@thingsboard.cloud / demo

📜 LIVE LOGS:
   tail -f $DIR/logs/wids_pro.log

🔍 SERVICE STATUS:
   sudo systemctl status wids-pro

🧠 ML STATUS:
   tail -f $DIR/logs/wids_pro.log | grep -E 'Baseline|TRAINED|THREAT'

📱 DATABASE:
   sqlite3 $DIR/wids_pro.db 'SELECT * FROM alerts ORDER BY ts DESC LIMIT 5;'

🌐 NETWORK:
   netstat -tulnp | grep -E '1883|9999|8080'

🚨 BLOCKED DEVS:
   sudo iptables -L INPUT -v -n | grep WIDS

🎯 NEXT STEPS:
1. Flash ESP32 + Pico W (VM_IP = $VM_IP)
2. Watch ML train: 🧠 [50/50] → 🎯 TRAINED
3. Test: Phone hotspot → 🚨 THREAT BLOCKED

🏆 IEEE-GRADE WIDS LIVE!
"
