#!/bin/bash
apt update && apt install -y python3-pip mosquitto sqlite3 docker.io -y
pip3 install paho-mqtt thingsboard-python-client scikit-learn pandas

mkdir -p ~/wids && cd ~/wids
cat > wids_micro.py << 'EOF'
#!/usr/bin/env python3
# COMPLETE MICRO WIDS (ESP32 + Pico W)
import paho.mqtt.client as mqtt
import json, sqlite3, time, subprocess
from tb_device_api import DeviceApi
from sklearn.ensemble import IsolationForest
import numpy as np

class MicroWIDS:
    def __init__(self):
        self.db = sqlite3.connect('wids.db', check_same_thread=False)
        self.db.execute('''CREATE TABLE IF NOT EXISTS alerts 
                          (id INTEGER PRIMARY KEY, data TEXT, ts REAL)''')
        self.model = IsolationForest(contamination=0.05)
        self.thingsboard = DeviceApi("localhost:8080", "DEMO_TOKEN")
        self.mqtt = mqtt.Client()
        self.mqtt.on_message = self.on_alert
        self.mqtt.connect("localhost", 1883)
        self.mqtt.subscribe("wids/+")
        self.mqtt.loop_start()
        print("🚀 Micro WIDS Active")
    
    def on_alert(self, client, userdata, msg):
        data = json.loads(msg.payload.decode())
        self.process_threat(data)
    
    def process_threat(self, data):
        # ML Anomaly Detection
        features = np.array([[data.get('rssi',0), data.get('channel',1)]])
        anomaly = self.model.predict(features)[0] == -1
        
        # Block Threat
        if anomaly or data.get('alert') == 'rogue_ap':
            ip = data.get('ip', '0.0.0.0')
            subprocess.run(['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'])
            
            # ThingsBoard Alert
            self.thingsboard.send_telemetry({
                'rssi': data.get('rssi'),
                'blocked': True,
                'anomaly': anomaly,
                'device': data.get('device'),
                'ts': int(time.time()*1000)
            })
            
            print(f"🚨 BLOCKED: {data.get('ssid', 'Unknown')}")
        
        # Log
        self.db.execute("INSERT INTO alerts (data, ts) VALUES (?, ?)", 
                       (json.dumps(data), time.time()))
        self.db.commit()

if __name__ == "__main__":
    wids = MicroWIDS()
    while True: time.sleep(1)
EOF

chmod +x wids_micro.py

# ThingsBoard Docker
docker run -d -p 8080:8080 --name tb thingsboard/tb

# Auto-start
nohup python3 wids_micro.py > wids.log 2>&1 &

echo "✅ Deployed! Dashboard: http://$(hostname -I | awk '{print $1}'):8080"
echo "📊 Logs: tail -f wids.log"
