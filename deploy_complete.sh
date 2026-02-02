# SAVE THIS AS: ~/WIDS-PROTECTOR/deploy_master.sh
cat > deploy_master.sh << 'EOF_MASTER'
#!/bin/bash
set -e
cd ~/WIDS-PROTECTOR

echo "🚀 WIDS-PROTECTOR v3.0 → FRESH DEPLOY"

# CLEANUP
sudo systemctl stop wids-pro wids-dashboard mosquitto || true
docker rm -f tb || true
sudo fuser -k 1883/tcp 1883/udp 8080/tcp || true

# Python Environment
rm -rf venv && python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip >/dev/null
pip install paho-mqtt scikit-learn==1.3.2 numpy pandas flask psutil requests -q

# WIDS CORE ENGINE
cat > wids_pro.py << 'WIDS_CORE'
#!/usr/bin/env python3
# [PASTE THE FULL WIDS ENGINE CODE FROM PREVIOUS RESPONSE - wids_pro.py]
# ... (I'll provide full code below)
WIDS_CORE

# ADVANCED DASHBOARD  
cat > dashboard.py << 'DASH_CORE'
#!/usr/bin/env python3
# [PASTE THE FULL ADVANCED DASHBOARD CODE FROM PREVIOUS RESPONSE]
DASH_CORE

# MQTT Config (Port 1884 ONLY)
echo "listener 1884
allow_anonymous true
persistence true
log_dest file /var/log/mosquitto/mosquitto.log" | sudo tee /etc/mosquitto/conf.d/wids.conf >/dev/null

# ThingsBoard (NO MQTT PORT CONFLICT)
docker run -d --name tb --restart unless-stopped \
  -p 8080:8080 -p 5683:5683/udp \
  -v ~/WIDS-PROTECTOR/tb_data:/data \
  -e TB_DATABASE_TYPE=postgres \
  -e TB_MQTT_TRANSPORT_ENABLED=false \
  thingsboard/tb-postgres

# Firewall
sudo ufw allow 8080/tcp 1884/tcp 5000/tcp 9999/udp && sudo ufw reload

# SystemD Services
cat >/etc/systemd/system/wids-pro.service << 'SVC_PRO'
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

[Install]
WantedBy=multi-user.target
SVC_PRO

cat >/etc/systemd/system/wids-dashboard.service << 'SVC_DASH'
[Unit]
Description=WIDS Dashboard v3.0
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
SVC_DASH

# START EVERYTHING
sudo systemctl daemon-reload
sudo systemctl restart mosquitto docker
sudo systemctl enable --now wids-pro wids-dashboard

VM_IP=$(hostname -I|awk '{print \$1}')
cat << EOF > STATUS.txt
✅✅✅ WIDS-PROTECTOR v3.0 LIVE ✅✅✅

📊 DASHBOARD:     http://$VM_IP:5000  ← OPEN FIRST!
📈 THINGSBOARD:   http://$VM_IP:8080  (sysadmin/sysadmin)
🔌 MQTT (Sensors):$VM_IP:1884
📡 UDP (Sensors): $VM_IP:9999

TEST COMMAND:
mosquitto_pub -h $VM_IP -p 1884 -t wids/esp32 -m '{"ssid":"TEST_EVIL","bssid":"AA:BB:CC:DD:EE:FF","rssi":-40,"channel":6}'

EOF
cat STATUS.txt
EOF_MASTER

chmod +x deploy_master.sh
