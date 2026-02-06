#!/usr/bin/env python3
"""
ESP32 WIDS MONITOR - CH340 COMPATIBLE
Monitors ESP32 output and forwards packets to server
"""

import serial
import time
import json
import requests
import sys
import os
import threading
from datetime import datetime
import re

class ESP32Monitor:
    def __init__(self, port='/dev/ttyUSB0', server_url='http://192.168.1.3:8000'):
        self.port = port
        self.server_url = f"{server_url}/api/packet"
        self.ser = None
        self.running = False
        self.ready = False
        self.packet_count = 0
        self.devices_detected = set()
        
    def connect(self):
        """Connect to ESP32 with CH340"""
        print(f"🔌 Connecting to ESP32 on {self.port}...")
        
        # Try different baud rates
        baud_rates = [115200, 9600, 74880, 57600, 38400]
        
        for baud in baud_rates:
            print(f"  Trying {baud} baud...", end=" ")
            
            try:
                self.ser = serial.Serial(
                    port=self.port,
                    baudrate=baud,
                    timeout=2,
                    bytesize=serial.EIGHTBITS,
                    parity=serial.PARITY_NONE,
                    stopbits=serial.STOPBITS_ONE,
                    xonxoff=False,
                    rtscts=False,
                    dsrdtr=False
                )
                
                # Wait for CH340 initialization
                time.sleep(3)
                
                # Clear buffers
                self.ser.reset_input_buffer()
                self.ser.reset_output_buffer()
                
                # Send newline to trigger output
                self.ser.write(b'\n')
                time.sleep(0.5)
                
                # Test communication
                if self.test_connection():
                    print(f"✅ Connected at {baud} baud!")
                    return True
                else:
                    self.ser.close()
                    self.ser = None
                    print("No response")
                    
            except Exception as e:
                print(f"Error: {str(e)[:40]}")
                continue
        
        print("❌ Could not connect to ESP32")
        return False
    
    def test_connection(self):
        """Test if ESP32 is responding"""
        start_time = time.time()
        
        while time.time() - start_time < 3:
            if self.ser.in_waiting:
                try:
                    line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                    if line:
                        print(f"    Got: {line[:60]}...")
                        if "ESP32" in line or "WIDS" in line or "WiFi" in line:
                            return True
                except:
                    continue
        
        return False
    
    def forward_to_server(self, packet_data):
        """Forward packet to WIDS server"""
        try:
            response = requests.post(
                self.server_url,
                json=packet_data,
                timeout=3
            )
            
            if response.status_code == 200:
                return True, response.json()
            else:
                return False, f"HTTP {response.status_code}"
                
        except requests.exceptions.RequestException as e:
            return False, str(e)
    
    def parse_packet_line(self, line):
        """Parse human-readable packet line"""
        # Example: "🎯 DETECTED DEVICE: MAC:AA:BB:CC:DD:EE:FF RSSI:-65dBm CHANNEL:6"
        
        # Look for MAC address pattern
        mac_match = re.search(r'MAC:([0-9A-F:]{17})', line, re.IGNORECASE)
        if not mac_match:
            # Try another pattern
            mac_match = re.search(r'([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})', line, re.IGNORECASE)
        
        if mac_match:
            mac = mac_match.group(1).upper()
            
            # Extract RSSI
            rssi_match = re.search(r'RSSI:(-?\d+)', line, re.IGNORECASE)
            if not rssi_match:
                rssi_match = re.search(r'(-?\d+)dBm', line)
            
            rssi = int(rssi_match.group(1)) if rssi_match else -99
            
            # Extract channel
            channel_match = re.search(r'CHANNEL:(\d+)', line, re.IGNORECASE)
            if not channel_match:
                channel_match = re.search(r'CH:(\d+)', line, re.IGNORECASE)
            if not channel_match:
                channel_match = re.search(r'Ch:(\d+)', line, re.IGNORECASE)
            
            channel = int(channel_match.group(1)) if channel_match else 0
            
            # Determine packet type
            packet_type = "detected"
            if "INIT" in line or "init" in line.lower():
                packet_type = "init"
            
            # Create packet
            packet = {
                "sensor_id": "esp32_ch340",
                "mac": mac,
                "rssi": rssi,
                "channel": channel,
                "type": packet_type,
                "timestamp": int(time.time() * 1000),
                "source": "esp32_monitor"
            }
            
            return packet
        
        return None
    
    def process_line(self, line):
        """Process a line from ESP32"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Print to console
        print(f"[{timestamp}] {line}")
        
        # Check for ready signal
        if "ESP32_WIDS_READY" in line and not self.ready:
            print("\n" + "="*60)
            print("✅ ESP32 WIDS IS READY AND CAPTURING PACKETS!")
            print("="*60)
            self.ready = True
            
            # Send ready notification to server
            self.send_ready_notification()
        
        # Check for WiFi status
        elif "WiFi Connected" in line or "✅ WiFi Connected" in line:
            print("🌐 WiFi connection established")
        
        # Check for server response
        elif "Server response:" in line or "✅ Server response:" in line:
            print("📡 Packet successfully sent to server")
        
        # Check for packets
        elif ("MAC:" in line and "RSSI:" in line) or ("DETECTED DEVICE:" in line):
            print("📦 Packet detected - forwarding to server...")
            
            # Parse packet
            packet = self.parse_packet_line(line)
            if packet:
                self.devices_detected.add(packet['mac'])
                
                # Forward to server
                success, result = self.forward_to_server(packet)
                
                if success:
                    self.packet_count += 1
                    print(f"   ✅ Forwarded: {packet['mac']} (Total: {self.packet_count})")
                else:
                    print(f"   ❌ Failed: {result}")
            else:
                print(f"   ⚠️ Could not parse packet: {line[:50]}...")
    
    def send_ready_notification(self):
        """Send ready notification to server"""
        try:
            ready_packet = {
                "sensor_id": "esp32_monitor",
                "mac": "READY_SIGNAL",
                "rssi": -50,
                "channel": 1,
                "type": "system",
                "timestamp": int(time.time() * 1000),
                "message": "ESP32 WIDS system is ready and monitoring"
            }
            
            success, result = self.forward_to_server(ready_packet)
            if success:
                print("📨 Server notified of ready status")
            else:
                print(f"⚠️ Could not notify server: {result}")
                
        except Exception as e:
            print(f"Error sending ready notification: {e}")
    
    def monitor(self):
        """Main monitoring loop"""
        if not self.ser:
            print("❌ Not connected to ESP32")
            return
        
        print("\n📡 Starting ESP32 WIDS Monitor...")
        print("   Press Ctrl+C to stop")
        print("="*60)
        
        self.running = True
        
        # Clear initial data
        self.ser.reset_input_buffer()
        
        # Buffer for incomplete lines
        buffer = ""
        
        try:
            while self.running:
                if self.ser.in_waiting:
                    try:
                        # Read raw data
                        raw_data = self.ser.read(self.ser.in_waiting)
                        
                        # Decode to text
                        try:
                            text = raw_data.decode('utf-8', errors='ignore')
                            
                            # Add to buffer
                            buffer += text
                            
                            # Process complete lines
                            while '\n' in buffer:
                                line, buffer = buffer.split('\n', 1)
                                line = line.strip()
                                
                                if line:
                                    self.process_line(line)
                        
                        except UnicodeDecodeError:
                            # Skip invalid UTF-8
                            pass
                            
                    except Exception as e:
                        print(f"⚠️ Read error: {e}")
                
                # Small delay to prevent CPU overload
                time.sleep(0.01)
        
        except KeyboardInterrupt:
            print("\n🛑 Monitoring stopped by user")
        
        except Exception as e:
            print(f"\n❌ Error: {e}")
        
        finally:
            self.running = False
            if self.ser:
                self.ser.close()
            
            # Print summary
            print("\n" + "="*60)
            print("📊 MONITORING SUMMARY")
            print("="*60)
            print(f"Total packets forwarded: {self.packet_count}")
            print(f"Unique devices detected: {len(self.devices_detected)}")
            print(f"ESP32 ready: {'Yes' if self.ready else 'No'}")
            print("="*60)

def get_local_ip():
    """Get local IP address"""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def main():
    print("\n" + "="*60)
    print("     ESP32 WIDS MONITOR - CH340 VERSION")
    print("="*60)
    
    # Get available ports
    import glob
    ports = glob.glob('/dev/ttyUSB*') + glob.glob('/dev/ttyACM*')
    
    if not ports:
        print("❌ No serial ports found!")
        print("Connect ESP32 via USB and check:")
        print("  ls /dev/ttyUSB*")
        print("  lsusb | grep CH340")
        return
    
    print(f"Available ports: {', '.join(ports)}")
    
    # Select port
    if len(ports) == 1:
        port = ports[0]
        print(f"Using: {port}")
    else:
        print("\nSelect serial port:")
        for i, p in enumerate(ports):
            print(f"  {i+1}. {p}")
        
        try:
            choice = int(input(f"Enter choice [1-{len(ports)}]: "))
            port = ports[choice-1]
        except:
            port = ports[0]
            print(f"Using default: {port}")
    
    # Get server URL
    local_ip = get_local_ip()
    print(f"\nLocal IP detected: {local_ip}")
    
    server_ip = input(f"Enter server IP [{local_ip}]: ").strip()
    if not server_ip:
        server_ip = local_ip
    
    # Create monitor
    monitor = ESP32Monitor(port=port, server_url=f"http://{server_ip}:8000")
    
    # Try to connect
    if monitor.connect():
        monitor.monitor()
    else:
        print("\n💡 TROUBLESHOOTING:")
        print("="*60)
        print("1. Press ESP32 RESET button")
        print("2. Check USB cable (data cable, not charge-only)")
        print("3. Try different USB port")
        print("4. Fix permissions: sudo chmod 666 /dev/ttyUSB0")
        print("5. Check if ESP32 has power (LED should be on)")
        print("\nDebug commands:")
        print("  dmesg | tail -20")
        print("  stty -F /dev/ttyUSB0 115200 && cat /dev/ttyUSB0")
        print("="*60)

if __name__ == "__main__":
    # Check dependencies
    try:
        import serial
        import requests
    except ImportError:
        print("❌ Missing dependencies!")
        print("Install with: pip3 install pyserial requests")
        sys.exit(1)
    
    main()
