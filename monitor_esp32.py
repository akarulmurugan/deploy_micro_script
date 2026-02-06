#!/usr/bin/env python3
"""
FIXED ESP32 Connection Monitor for Ubuntu
Better port detection and error handling
"""
import serial
import time
import os
import sys
import glob
import requests
import subprocess
from datetime import datetime

class ESP32Monitor:
    def __init__(self, server_url="http://127.0.0.1:8000", port=None):
        self.esp32 = None
        self.server_url = server_url
        self.connected = False
        self.ready = False
        self.port = port
        
    def get_serial_ports(self):
        """Get all available serial ports on Ubuntu"""
        ports = []
        
        # Check for USB serial devices
        usb_ports = glob.glob('/dev/ttyUSB*')
        acm_ports = glob.glob('/dev/ttyACM*')
        
        # Also check serial by-id (more stable)
        by_id_ports = glob.glob('/dev/serial/by-id/*')
        
        all_ports = usb_ports + acm_ports + by_id_ports
        
        print("🔍 Scanning for serial ports...")
        
        if not all_ports:
            print("   No serial ports found!")
            # Try to list with dmesg
            print("   Checking dmesg for USB devices...")
            try:
                result = subprocess.run(['dmesg | grep -i "tty\|usb" | tail -20'], 
                                      shell=True, capture_output=True, text=True)
                print(result.stdout)
            except:
                pass
        else:
            for port in all_ports:
                ports.append(port)
                print(f"   Found: {port}")
        
        return ports
    
    def test_port(self, port):
        """Test if this port is an ESP32"""
        try:
            print(f"🔌 Testing port: {port}")
            
            # Try to open serial port
            self.esp32 = serial.Serial(
                port=port,
                baudrate=115200,
                timeout=1,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE
            )
            
            # Wait for ESP32 to boot if just connected
            time.sleep(2)
            
            # Clear any existing data
            self.esp32.reset_input_buffer()
            self.esp32.reset_output_buffer()
            
            # Send a test command
            self.esp32.write(b'\n')
            time.sleep(0.5)
            
            # Try to read for 3 seconds
            start_time = time.time()
            while time.time() - start_time < 3:
                if self.esp32.in_waiting:
                    line = self.esp32.readline().decode('utf-8', errors='ignore').strip()
                    if line:
                        print(f"    Received: {line}")
                        if "ESP32" in line.upper() or "WIFI" in line.upper() or "READY" in line.upper():
                            print(f"✅ Looks like ESP32 on {port}")
                            return True
                
                time.sleep(0.1)
            
            # Close if not ESP32
            self.esp32.close()
            self.esp32 = None
            
        except serial.SerialException as e:
            print(f"    ❌ Error: {e}")
            if self.esp32:
                self.esp32.close()
                self.esp32 = None
        except Exception as e:
            print(f"    ❌ Unexpected error: {e}")
            if self.esp32:
                self.esp32.close()
                self.esp32 = None
        
        return False
    
    def connect_esp32(self):
        """Connect to ESP32"""
        if self.port:
            # Use specified port
            ports_to_try = [self.port]
        else:
            # Auto-detect
            ports_to_try = self.get_serial_ports()
        
        if not ports_to_try:
            print("❌ No serial ports available!")
            print("   Please connect ESP32 via USB cable")
            return False
        
        for port in ports_to_try:
            if self.test_port(port):
                self.port = port
                self.wait_for_ready()
                return True
        
        print("❌ Could not find ESP32 on any port")
        return False
    
    def wait_for_ready(self):
        """Wait for ESP32 ready signal"""
        if not self.esp32:
            return False
        
        print("⏳ Waiting for ESP32 ready signal... (20 seconds)")
        
        start_time = time.time()
        while time.time() - start_time < 20:
            if self.esp32.in_waiting:
                line = self.esp32.readline().decode('utf-8', errors='ignore').strip()
                if line:
                    print(f"  📥 {line}")
                    
                    # Check for various ready signals
                    if any(keyword in line.upper() for keyword in ["READY", "ESP32_WIDS", "CONNECTED", "STARTING"]):
                        print(f"\n✅ ESP32 is READY!")
                        self.connected = True
                        self.ready = True
                        
                        # Send ready notification to server
                        self.notify_ready()
                        
                        return True
            
            time.sleep(0.1)
        
        print("⚠️ ESP32 connected but no ready signal received")
        print("   ESP32 might not be running WIDS code")
        return False
    
    def notify_ready(self):
        """Send notification that ESP32 is ready"""
        message = "🚀 ESP32 WIDS is connected and ready for packet capture!"
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        print(f"\n{'='*60}")
        print(f"✅ ESP32 WIDS READY - {timestamp}")
        print(f"{'='*60}")
        print(f"📡 Port: {self.port}")
        print(f"📦 Packets will be sent to: {self.server_url}")
        print(f"📊 Dashboard: {self.server_url.replace('/api/packet', '')}")
        print(f"{'='*60}\n")
        
        # Send system notification
        try:
            os.system(f'notify-send "ESP32 Ready" "{message}" --urgency=normal')
        except:
            pass
        
        # Send test packet to server
        self.send_test_packet()
    
    def send_test_packet(self):
        """Send a test packet to confirm server is receiving"""
        try:
            print("📡 Sending test packet to server...")
            
            test_data = {
                "sensor_id": "esp32_monitor",
                "mac": "00:11:22:33:44:55",
                "rssi": -65,
                "channel": 6,
                "timestamp": int(time.time() * 1000),
                "message": "ESP32 monitor test - device connected"
            }
            
            response = requests.post(f"{self.server_url}/api/packet", 
                                    json=test_data, 
                                    timeout=5)
            
            if response.status_code == 200:
                print(f"✅ Test packet sent successfully!")
                print(f"   Response: {response.json()}")
            else:
                print(f"⚠️ Server responded with: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Could not reach server: {e}")
            print("   Make sure WIDS server is running: sudo systemctl status wids-server")
    
    def monitor_serial(self):
        """Monitor ESP32 serial output and forward packets"""
        if not self.esp32:
            print("❌ Not connected to ESP32")
            return
        
        print("\n📡 Monitoring ESP32 output... (Press Ctrl+C to stop)")
        print("-" * 60)
        
        try:
            packet_count = 0
            
            while True:
                if self.esp32.in_waiting:
                    line = self.esp32.readline().decode('utf-8', errors='ignore').strip()
                    if line:
                        # Display in console
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        print(f"[{timestamp}] {line}")
                        
                        # Try to parse as packet data
                        if "MAC:" in line or "RSSI:" in line or "Channel:" in line:
                            self.parse_and_forward_packet(line)
                            packet_count += 1
                
                # Also check for button presses or other events
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            print("\n🛑 Monitoring stopped by user")
            print(f"📊 Total packets forwarded: {packet_count}")
        except Exception as e:
            print(f"\n❌ Error monitoring: {e}")
        finally:
            if self.esp32:
                self.esp32.close()
                print("🔌 Serial port closed")
    
    def parse_and_forward_packet(self, line):
        """Parse packet from serial and forward to server"""
        try:
            # Simple parsing - adjust based on your ESP32 output format
            import re
            
            # Look for MAC address pattern
            mac_match = re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', line, re.I)
            rssi_match = re.search(r'RSSI[:\s]*(-?\d+)', line, re.I)
            channel_match = re.search(r'Channel[:\s]*(\d+)', line, re.I)
            
            if mac_match:
                mac = mac_match.group(0).upper()
                rssi = int(rssi_match.group(1)) if rssi_match else -99
                channel = int(channel_match.group(1)) if channel_match else 0
                
                packet_data = {
                    "sensor_id": "esp32_sensor",
                    "mac": mac,
                    "rssi": rssi,
                    "channel": channel,
                    "timestamp": int(time.time() * 1000),
                    "raw_line": line
                }
                
                # Forward to server
                try:
                    response = requests.post(f"{self.server_url}/api/packet", 
                                           json=packet_data, 
                                           timeout=2)
                    if response.status_code == 200:
                        print(f"   📤 Forwarded packet: {mac}")
                except:
                    pass  # Silently fail if server not reachable
                    
        except Exception as e:
            print(f"   ⚠️ Could not parse packet: {e}")

def main():
    """Main function"""
    print("\n" + "="*60)
    print("           ESP32 WIDS MONITOR - FIXED")
    print("="*60)
    
    # Get server URL from user
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "127.0.0.1"
    
    print(f"Detected local IP: {local_ip}")
    server_ip = input(f"Enter server IP [{local_ip}]: ").strip()
    if not server_ip:
        server_ip = local_ip
    
    server_url = f"http://{server_ip}:8000/api/packet"
    
    # Get port from user
    print("\nChecking available ports...")
    monitor = ESP32Monitor(server_url)
    available_ports = monitor.get_serial_ports()
    
    if available_ports:
        print(f"\nAvailable ports: {', '.join(available_ports)}")
        port_choice = input("Enter port (or press Enter to auto-detect): ").strip()
    else:
        print("\n⚠️ No serial ports detected!")
        port_choice = input("Enter port manually (e.g., /dev/ttyUSB0): ").strip()
    
    if port_choice:
        monitor.port = port_choice
    
    # Try to connect
    if monitor.connect_esp32():
        # Start monitoring
        monitor.monitor_serial()
    else:
        print("\n💡 Troubleshooting tips:")
        print("1. Make sure ESP32 is connected via USB")
        print("2. Check USB cable (some cables only charge, no data)")
        print("3. Check if ESP32 has power (LED should blink)")
        print("4. Run: ls /dev/ttyUSB*  # to check ports")
        print("5. Run: dmesg | grep tty  # to see USB connection logs")
        print("6. You might need to install CH340 driver:")
        print("   sudo apt install linux-modules-extra-$(uname -r)")
        print("\nRun again with: python3 monitor_esp32.py")

if __name__ == "__main__":
    main()
