#!/bin/bash
# WIDS Server Setup Script

echo "========================================"
echo "     WIDS SERVER SETUP"
echo "========================================"

# Update system
echo "[1/6] Updating system..."
sudo apt update
sudo apt upgrade -y

# Install Python and pip
echo "[2/6] Installing Python..."
sudo apt install -y python3 python3-pip python3-venv

# Install required packages
echo "[3/6] Installing Python packages..."
pip3 install flask flask-socketio

# Create directory structure
echo "[4/6] Creating directories..."
mkdir -p ~/wids-server
mkdir -p ~/wids-server/logs
mkdir -p ~/wids-server/data

# Copy server files
echo "[5/6] Setting up server files..."
cp server.py ~/wids-server/
chmod +x ~/wids-server/server.py

# Create systemd service
echo "[6/6] Creating system service..."
sudo tee /etc/systemd/system/wids.service << EOF
[Unit]
Description=WIDS Server
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/home/$USER/wids-server
Environment=PATH=/usr/bin:/usr/local/bin
ExecStart=/usr/bin/python3 /home/$USER/wids-server/server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable wids
sudo systemctl start wids

echo "========================================"
echo "     SETUP COMPLETE!"
echo "========================================"
echo ""
echo "Server is running at: http://$(hostname -I | awk '{print $1}'):8000"
echo ""
echo "Commands:"
echo "  sudo systemctl status wids    # Check status"
echo "  sudo journalctl -u wids -f    # View logs"
echo "  sudo systemctl restart wids   # Restart server"
echo ""
echo "Next steps:"
echo "1. Update ESP32 code with your server IP"
echo "2. Upload ESP32 code to your board"
echo "3. Access the dashboard above"
echo "========================================"