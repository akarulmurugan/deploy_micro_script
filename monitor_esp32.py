#!/usr/bin/env python3
"""
ESP32 WIDS Monitor for Ubuntu
Fixed for CH340 with continuous monitoring
"""
import serial
import time
import os
import sys
import requests
import threading
from datetime import datetime

class ESP32ContinuousMonitor:
    def __init__(self, port='/dev/ttyUSB0', server_url='http://192.168.1.3:8000'):
        self.port = port
        self.server_url = server_url
        self.esp32 = None
        self.monitoring = False
        self.packet_count = 0
        
    def connect(self):
        """Connect to ESP32"""
        print(f"🔌 Connecting to ESP32 on {self.port}...")
        
        # Try different baud rates
        baud_rates = [115200, 9600, 57600, 74880]
        
        for baud in baud_rates:
            try:
                print(f"  Trying baud {baud}...")
                self.esp32 = serial.Serial(
                    port=self.port,
                    baudrate=baud,
                    timeout=1,
                    bytesize=serial.EIGHTBITS,
                    parity=serial.PARITY_NONE,
                    stopbits=serial.STOPBITS_ONE
                )
                
                # Wait for connection
                time.sleep(2)
                
                # Test communication
                self.esp32.reset_input_buffer()
                self.esp32.write(b'\n')
                time.sleep(0.5)
                
                # Look for ESP32 output
                start_time = time.time()
                while time.time() - start_time < 3:
                    if self.esp32.in_waiting:
                        line = self.esp32.readline().decode('utf-8', errors='ignore').strip()
                        if line and 'ESP32' in line.upper():
                            print(f"✅ Connected at {baud} baud")
                            return True
                
                self.esp32.close()
                
            except Exception as e:
                print(f"    Error: {e}")
                continue
        
        print("❌ Could not connect to ESP32")
        return False
    
    def send_heartbeat(self):
        """Send periodic heartbeat to server"""
        while self.monitoring:
            try:
                data = {
                    "sensor_id": "esp32_monitor",
                    "mac": "00:00:00:00:00:00",
                    "rssi": -99,
                    "channel": 0,
                    "timestamp": int(time.time() * 1000),
                    "message": f"Monitor active - Packets: {self.packet_count}"
                }
                
                requests.post(f"{self.server_url}/api/packet", 
                             json=data, timeout=2)
            except:
                pass
            
            time.sleep(60)  # Every minute
    
    def monitor(self):
        """Monitor ESP32 output continuously"""
        if not self.esp32:
            print("❌ Not connected to ESP32")
            return
        
        print("\n📡 Starting continuous monitoring...")
        print("   Press Ctrl+C to stop")
        print("="*60)
        
        self.monitoring = True
        
        # Start heartbeat thread
        heartbeat_thread = threading.Thread(target=self.send_heartbeat, daemon=True)
        heartbeat_thread.start()
        
        last_ready_check = time.time()
        ready_notified = False
        
        try:
            while self.monitoring:
                if self.esp32.in_waiting:
                    try:
                        line = self.esp32.readline().decode('utf-8', errors='ignore').strip()
                        if line:
                            # Print with timestamp
                            timestamp = datetime.now().strftime("%H:%M:%S")
                            print(f"[{timestamp}] {line}")
                            
                            # Check for ready signal
                            if "ESP32_WIDS_READY" in line and not ready_notified:
                                print("\n" + "="*60)
                                print("✅ ESP32 IS READY AND CAPTURING PACKETS!")
                                print("="*60 + "\n")
                                ready_notified = True
                                
                                # Notify server
                                self.notify_ready()
                            
                            # Count packets
                            if any(marker in line for marker in ["Packet", "MAC:", "Detected:"]):
                                self.packet_count += 1
                            
                            # Parse and forward packets
                            if "MAC:" in line or "Detected:" in line:
                                self.parse_and_forward(line)
                    
                    except UnicodeDecodeError:
                        continue
                    except Exception as e:
                        print(f"Read error: {e}")
                
                # Small delay to prevent CPU overload
                time.sleep(0.01)
        
        except KeyboardInterrupt:
            print("\n🛑 Monitoring stopped by user")
        
        finally:
            self.monitoring = False
            if self.esp32:
                self.esp32.close()
            print(f"📊 Total packets forwarded: {self.packet_count}")
    
    def notify_ready(self):
        """Notify server that ESP32 is ready"""
        try:
            print("📨 Notifying server...")
            
            data = {
                "sensor_id": "esp32_monitor",
                "mac": "READY_SIGNAL",
                "rssi": -50,
                "channel": 6,
                "timestamp": int(time.time() * 1000),
                "message": "ESP32 WIDS is ready and capturing packets"
            }
            
            response = requests.post(f"{self.server_url}/api/packet", 
                                   json=data, timeout=5)
            
            if response.status_code == 200:
                print("✅ Server notified")
            else:
                print(f"⚠️ Server response: {response.status_code}")
        
        except Exception as e:
            print(f"❌ Could not notify server: {e}")
    
    def parse_and_forward(self, line):
        """Parse packet line and forward to server"""
        try:
            # Simple parsing - adjust based on your ESP32 output format
            import re
            
            # Look for MAC address
            mac_match = re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', line, re.I)
            
            if mac_match:
                mac = mac_match.group(0).upper()
                
                # Extract RSSI
                rssi_match = re.search(r'RSSI[:\s]*(-?\d+)', line, re.I)
                rssi = int(rssi_match.group(1)) if rssi_match else -99
                
                # Extract channel
                channel_match = re.search(r'Ch[:\s]*(\d+)', line, re.I)
                if not channel_match:
                    channel_match = re.search(r'Channel[:\s]*(\d+)', line, re.I)
                channel = int(channel_match.group(1)) if channel_match else 0
                
                # Create packet
                packet = {
                    "sensor_id": "esp32_wifi_sniffer",
                    "mac": mac,
                    "rssi": rssi,
                    "channel": channel,
                    "timestamp": int(time.time() * 1000),
                    "source": "serial_monitor"
                }
                
                # Send to server (non-blocking)
                try:
                    requests.post(f"{self.server_url}/api/packet", 
                                json=packet, timeout=1)
                except:
                    pass  # Silently fail if server unreachable
        
        except Exception as e:
            pass  # Silently ignore parse errors

def main():
    """Main function"""
    print("\n" + "="*60)
    print("     ESP32 WIDS CONTINUOUS MONITOR")
    print("="*60)
    
    # Get port
    import glob
    ports = glob.glob('/dev/ttyUSB*') + glob.glob('/dev/ttyACM*')
    
    if ports:
        print(f"Available ports: {', '.join(ports)}")
        port_choice = input(f"Enter port [{ports[0]}]: ").strip()
        port = port_choice if port_choice else ports[0]
    else:
        print("⚠️ No serial ports detected!")
        port = input("Enter port manually: ").strip()
    
    # Get server URL
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "127.0.0.1"
    
    print(f"Local IP: {local_ip}")
    server_ip = input(f"Server IP [{local_ip}]: ").strip() or local_ip
    server_url = f"http://{server_ip}:8000"
    
    # Create and run monitor
    monitor = ESP32ContinuousMonitor(port, server_url)
    
    if monitor.connect():
        monitor.monitor()
    else:
        print("\n💡 TROUBLESHOOTING:")
        print("1. Check ESP32 is powered (LED should be on)")
        print("2. Press ESP32 RESET button")
        print("3. Try different USB cable/port")
        print("4. Check permissions: sudo chmod 666 /dev/ttyUSB0")
        print("5. Test with: screen /dev/ttyUSB0 115200")

if __name__ == "__main__":
    main()
