#!/bin/bash
# WIDS-PROTECTOR v2.1 - PRODUCTION READY

cd ~/WIDS-PROTECTOR

echo "🚀 Installing packages..."
sudo apt update -qq >/dev/null
sudo apt install -y python3-pip python3-venv mosquitto sqlite3 docker.io \
    net-tools ufw curl iptables-persistent mosquitto-clients -qq

echo "🐍 Python environment..."
python3 -m venv venv
source venv/bin/activate
pip install paho-mqtt scikit-learn numpy pandas requests --quiet

echo "🧠 Creating SIEM engine..."
cat > wids_pro.py << 'PYEOF'
#!/usr/bin/env python3
import paho.mqtt.client as mqtt
import json, sqlite3, time, threading, socket, logging, os, subprocess, sys, numpy as np
from sklearn.ensemble import IsolationForest

os.makedirs('logs', exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)8s] %(message)s',
    handlers=[logging.FileHandler('logs/wids_pro.log'), logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# STATE
baseline_samples = []
TRAINED = False
model = None
BLOCKED_MACS = set()
DB = sqlite3.connect('wids_pro.db', check_same_thread=False)

DB.executescript('''
CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, data TEXT, ts REAL, blocked INTEGER);
CREATE TABLE IF NOT EXISTS baseline (features TEXT, ts REAL);
''')

def block_mac(mac):
    if mac not in BLOCKED_MACS:
        try:
            subprocess.run([
                'iptables', '-I', 'INPUT', '1', '-m', 'mac', 
                '--mac-source', mac, '-j', 'DROP', '-m', 'comment', '--comment', 'WIDS'
            ], check=True, capture_output=True)
            BLOCKED_MACS.add(mac)
            logger.warning(f'🔒 BLOCKED MAC: {mac}')
        except:
            logger.error(f'Block failed: {mac}')

def udp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 9999))
    mqttc = mqtt.Client()
    mqttc.connect('localhost', 1883)
    logger.info('🔌 UDP Pico listener:9999')
    while True:
        try:
            data, addr = sock.recvfrom(2048)
            mqttc.publish('wids/picow', data.decode())
        except: pass

def mqtt_handler(client, userdata, msg):
    global baseline_samples, TRAINED, model
    try:
        data = json.loads(msg.payload.decode())
        
        # FEATURES: RSSI, Channel, Hour, DeviceType
        features = np.array([[
            data.get('rssi', -100.0),
            data.get('channel', 1.0),
            time.localtime().tm_hour,
            1.0 if data.get('device') == 'ESP32' else 0.0
        ]])
        
        ssid = data.get('ssid', 'Unknown')
        rssi = features[0,0]
        logger.info(f'📡 {data.get("device", "?"):<6} {ssid:<20} RSSI={rssi:+3.0f}dBm')
        
        # BASELINE TRAINING
        if len(baseline_samples) < 50:
            baseline_samples.append(features[0].tolist())
            logger.info(f'🧠 Baseline [{len(baseline_samples)}/50]')
            if len(baseline_samples) == 50:
                model = IsolationForest(contamination=0.04, random_state=42)
                model.fit(np.array(baseline_samples))
                TRAINED = True
                logger.info('🎯 ML MODEL TRAINED - THREATS AUTO-BLOCKED!')
            return
        
        # ANOMALY DETECTION
        if TRAINED:
            score = model.decision_function(features)[0]
            outlier = model.predict(features)[0] == -1
            
            logger.info(f'🤖 Score: {score:+.3f} Outlier: {outlier}')
            
            if outlier and score < -0.12:
                mac = data.get('bssid', '')
                threat = {
                    'threat_id': f'T{int(time.time())}',
                    'ssid': ssid,
                    'bssid': mac,
                    'rssi': int(rssi),
                    'score': round(score, 3),
                    'action': 'BLOCKED'
                }
                
                if mac:
                    block_mac(mac)
                
                DB.execute('INSERT INTO alerts(data,ts,blocked) VALUES(?,?,1)',
                          (json.dumps(threat), time.time()))
                DB.commit()
                logger.warning(f'🚨 THREAT BLOCKED: {ssid} | Score: {score:+.3f}')
                
    except Exception as e:
        logger.debug(f'Parse error: {e}')

def main():
    logger.info('='*60)
    logger.info('🚀 WIDS-PROTECTOR v2.1 STARTED')
    logger.info('='*60)
    
    # MQTT
    client = mqtt.Client('wids_siem')
    client.on_message = mqtt_handler
    client.connect('localhost', 1883)
    client.subscribe('wids/#')
    
    # UDP Pico sensor
    threading.Thread(target=udp_listener, daemon=True).start()
    
    logger.info('📊 Dashboard: http://localhost:8080')
    logger.info('📜 Logs: tail -f logs/wids_pro.log')
    logger.info('🔍 Blocks: sudo iptables -L INPUT | grep WIDS')
    
    client.loop_forever()

if __name__ == '__main__':
    main()
PYEOF

chmod +x wids_pro.py

# THINGSBOARD
docker rm -f tb 2>/dev/null || true
docker run -d --name tb --restart unless-stopped -p 8080:8080 \
  -v ~/WIDS-PROTECTOR/tb_data:/data thingsboard/tb:3.5.1

# MQTT + FIREWALL
sudo tee /etc/mosquitto/conf.d/wids.conf << MQTT
listener 1883
allow_anonymous true
MQTT
sudo systemctl restart mosquitto

sudo ufw allow 8080,1883/tcp,9999/udp from 192.168.0.0/16

# SYSTEMD SERVICE
sudo tee /etc/systemd/system/wids-pro.service << SVC
[Unit]
Description=WIDS-PROTECTOR v2.1
After=network.target mosquitto.service docker.service

[Service]
Type=simple
WorkingDirectory=/root/WIDS-PROTECTOR
Environment=PATH=/root/WIDS-PROTECTOR/venv/bin:\$PATH
ExecStart=/root/WIDS-PROTECTOR/venv/bin/python wids_pro.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
SVC

sudo systemctl daemon-reload
sudo systemctl enable --now wids-pro mosquitto

echo "✅ DEPLOYMENT COMPLETE!"
echo "VM_IP: $VM_IP"
echo "📊 DASHBOARD: http://$VM_IP:8080"
echo "📜 LOGS: tail -f ~/WIDS-PROTECTOR/logs/wids_pro.log"
echo "🎯 STATUS: sudo systemctl status wids-pro"
