#!/bin/bash
# WIDS Server Setup Script - FIXED VERSION

echo "========================================"
echo "     WIDS SERVER SETUP - FIXED"
echo "========================================"

# Update system
echo "[1/7] Updating system..."
sudo apt update
sudo apt upgrade -y

# Install Python and pip
echo "[2/7] Installing Python and dependencies..."
sudo apt install -y python3 python3-pip python3-venv git curl

# Install required Python packages
echo "[3/7] Installing Python packages..."
pip3 install flask pyserial requests

# Install Arduino IDE for ESP32 programming
echo "[4/7] Installing Arduino IDE..."
sudo apt install -y arduino

# Create directory structure
echo "[5/7] Creating directories..."
mkdir -p ~/wids-system
mkdir -p ~/wids-system/logs
mkdir -p ~/wids-system/data
mkdir -p ~/wids-system/esp32-code

# Copy files
echo "[6/7] Setting up files..."
# Assuming server.py is in current directory
cp server.py ~/wids-system/
cp monitor_esp32.py ~/wids-system/

# Fix monitor_esp32.py for Ubuntu
echo "[6.5/7] Fixing monitor_esp32.py for Ubuntu..."
sed -i 's|/dev/ttyUSB{i}|/dev/ttyUSB*|g' ~/wids-system/monitor_esp32.py
sed -i 's|f"/dev/ttyUSB{i}" for i in range(5)|glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*")|g' ~/wids-system/monitor_esp32.py

# Create systemd service
echo "[7/7] Creating system services..."

# Server service
sudo tee /etc/systemd/system/wids-server.service << EOF
[Unit]
Description=WIDS Server
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/home/$USER/wids-system
ExecStart=/usr/bin/python3 /home/$USER/wids-system/server.py
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# Monitor service
sudo tee /etc/systemd/system/wids-monitor.service << EOF
[Unit]
Description=WIDS ESP32 Monitor
After=wids-server.service
Requires=wids-server.service

[Service]
Type=simple
User=$USER
WorkingDirectory=/home/$USER/wids-system
ExecStart=/usr/bin/python3 /home/$USER/wids-system/monitor_esp32.py
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# Enable and start services
sudo systemctl daemon-reload
sudo systemctl enable wids-server
sudo systemctl enable wids-monitor
sudo systemctl start wids-server
sudo systemctl start wids-monitor

# Fix permissions for serial port
echo "Setting up serial port permissions..."
sudo usermod -a -G dialout $USER
sudo usermod -a -G tty $USER

echo "========================================"
echo "     SETUP COMPLETE!"
echo "========================================"
echo ""
echo "Server Dashboard: http://$(hostname -I | awk '{print $1}'):8000"
echo ""
echo "Commands:"
echo "  sudo systemctl status wids-server    # Check server status"
echo "  sudo systemctl status wids-monitor   # Check monitor status"
echo "  sudo journalctl -u wids-server -f    # View server logs"
echo "  sudo journalctl -u wids-monitor -f   # View monitor logs"
echo "  ls /dev/ttyUSB*                      # Check ESP32 port"
echo ""
echo "IMPORTANT NEXT STEPS:"
echo "1. Reboot or logout/login to apply serial port permissions"
echo "2. Upload ESP32 code (see esp32_wids_client.ino below)"
echo "3. Connect ESP32 via USB"
echo "4. Find ESP32 port: ls /dev/ttyUSB*"
echo "5. Update monitor_esp32.py with correct port"
echo "========================================"
