#!/bin/bash
# Debug script for WIDS system

echo "========================================"
echo "           WIDS DEBUG SCRIPT"
echo "========================================"

echo "1. Checking system status..."
sudo systemctl status wids-server --no-pager
echo ""
sudo systemctl status wids-monitor --no-pager

echo ""
echo "2. Checking network..."
ifconfig | grep inet
echo ""

echo "3. Checking serial ports..."
ls -la /dev/ttyUSB* /dev/ttyACM* /dev/serial/by-id/* 2>/dev/null
echo ""

echo "4. Checking Python dependencies..."
python3 -c "import flask, serial, requests; print('✅ All imports successful')"

echo ""
echo "5. Checking server logs (last 10 lines)..."
sudo journalctl -u wids-server -n 10 --no-pager

echo ""
echo "6. Checking monitor logs (last 10 lines)..."
sudo journalctl -u wids-monitor -n 10 --no-pager

echo ""
echo "7. Testing server endpoint..."
curl -s http://localhost:8000/api/test -X POST -H "Content-Type: application/json" -d '{"test":"debug"}' || echo "❌ Server not reachable"

echo ""
echo "========================================"
echo "           DEBUG COMPLETE"
echo "========================================"
