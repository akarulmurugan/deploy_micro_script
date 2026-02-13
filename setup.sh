#!/bin/bash
# WIDS Complete Setup Script

echo "========================================"
echo "WIDS Auto-Blocking System Setup"
echo "========================================"

# Update system
echo "📦 Updating system packages..."
sudo apt update

# Install dependencies
echo "📦 Installing Python and dependencies..."
sudo apt install -y python3 python3-pip python3-venv sqlite3 iptables iptables-persistent

# Install Python packages
echo "📦 Installing Python packages..."
pip3 install flask pyopenssl cryptography requests

# Create directory structure
echo "📁 Creating directory structure..."
mkdir -p ~/wids-system
cd ~/wids-system

# Create database
echo "🗄️ Initializing database..."
sqlite3 wids_database.db "CREATE TABLE IF NOT EXISTS blocked_devices (id INTEGER PRIMARY KEY, mac TEXT, reason TEXT, blocked_at TIMESTAMP, unblocked_at TIMESTAMP, status TEXT DEFAULT 'blocked');"
sqlite3 wids_database.db "CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, alert_type TEXT, mac TEXT, message TEXT, severity TEXT, created_at TIMESTAMP, email_sent BOOLEAN DEFAULT 0);"

# Create authorized MACs file
echo "📝 Creating authorized MACs file..."
echo '{"authorized_macs": [], "updated": "'$(date -Iseconds)'"}' > authorized_macs.json

# Create empty log file
touch blocked_devices.log

# Set permissions
chmod 755 ~/wids-system
chmod 644 ~/wids-system/*

# Create systemd service
echo "⚙️ Creating systemd service..."
sudo bash -c 'cat > /etc/systemd/system/wids.service << EOF
[Unit]
Description=WIDS Auto-Blocking Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/wids-system
ExecStart=/usr/bin/python3 /root/wids-system/server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF'

echo ""
echo "========================================"
echo "✅ WIDS System Setup Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "1. Edit server.py and update EMAIL_CONFIG with your credentials"
echo "2. Place server.py and dashboard.html in ~/wids-system/"
echo "3. Add your device MACs via the dashboard"
echo "4. Run: cd ~/wids-system && sudo python3 server.py"
echo "5. Open browser: http://YOUR_SERVER_IP:8000"
echo ""
echo "To run as service:"
echo "  sudo systemctl enable wids"
echo "  sudo systemctl start wids"
echo "  sudo systemctl status wids"
echo "========================================"
