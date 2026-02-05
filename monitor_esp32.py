#!/usr/bin/env python3
"""
ESP32 Connection Monitor
Checks if ESP32 is connected and ready, then sends notification
"""
import serial
import time
import os
import platform
import requests
from datetime import datetime

class ESP32Monitor:
    def __init__(self, server_url="http://127.0.0.1:8000"):
        self.esp32 = None
        self.server_url = server_url
        self.connected = False
        self.ready = False
        
    def scan_ports(self):
        """Scan all possible serial ports for ESP32"""
        ports = []
        
        if platform.system() == "Windows":
            ports = [f"COM{i}" for i in range(1, 10)]
        elif platform.system() == "Darwin":  # macOS
            ports = [f"/dev/tty.usbserial-*", "/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyACM0"]
        else:  # Linux
            ports = [f"/dev/ttyUSB{i}" for i in range(5)] + ["/dev/ttyACM0", "/dev/ttyACM1"]
        
        return ports
    
    def connect_esp32(self, port=None):
        """Connect to ESP32 on specified port or auto-detect"""
        if port:
            ports_to_try = [port]
        else:
            ports_to_try = self.scan_ports()
        
        for port in ports_to_try:
            try:
                print(f"🔍 Trying {port}...")
                self.esp32 = serial.Serial(port, 115200, timeout=1)
                time.sleep(2)  # Wait for ESP32 boot
                
                # Clear buffer
                self.esp32.reset_input_buffer()
                
                # Wait for ready signal
                print("⏳ Waiting for ESP32 ready signal...")
                start_time = time.time()
                
                while time.time() - start_time < 10:
                    if self.esp32.in_waiting:
                        line = self.esp32.readline().decode('utf-8', errors='ignore').strip()
                        print(f"  📥 Received: {line}")
                        
                        if "ESP32_WIDS_READY" in line or "ESP32 is ready" in line:
                            print(f"\n✅ ESP32 detected on {port} and READY!")
                            self.connected = True
                            self.ready = True
                            self.notify_ready()
                            return True
                    
                    time.sleep(0.1)
                
                self.esp32.close()
                
            except Exception as e:
                continue
        
        print("❌ ESP32 not found or not ready")
        return False
    
    def notify_ready(self):
        """Send notification that ESP32 is ready"""
        message = "🚀 ESP32 WIDS is connected and ready for packet capture!"
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        print(f"\n{'='*60}")
        print(f"✅ ESP32 WIDS READY - {timestamp}")
        print(f"{'='*60}")
        print(f"📡 Packets will be sent to: {self.server_url}")
        print(f"📊 Open dashboard: {self.server_url.replace('api/packet', '')}")
        print(f"{'='*60}\n")
        
        # System notification
        if platform.system() == "Windows":
            os.system(f'powershell -Command "New-BurntToastNotification -Text \\"{message}\\" -Sound \\"Default\\""')
        elif platform.system() == "Darwin":  # macOS
            os.system(f'''osascript -e 'display notification "{message}" with title "ESP32 Ready"' ''')
            os.system(f'afplay /System/Library/Sounds/Ping.aiff')  # Play sound
        else:  # Linux
            os.system(f'notify-send "ESP32 Ready" "{message}" --urgency=critical')
            os.system(f'paplay /usr/share/sounds/freedesktop/stereo/complete.oga')
        
        # Send test packet to server
        self.send_test_packet()
    
    def send_test_packet(self):
        """Send a test packet to confirm server is receiving"""
        try:
            print("📡 Sending test packet to server...")
            
            test_data = {
                "sensor_id": "monitor_test",
                "mac": "AA:BB:CC:DD:EE:FF",
                "rssi": -65,
                "channel": 6,
                "timestamp": int(time.time() * 1000),
                "message": "ESP32 ready notification test"
            }
            
            response = requests.post(f"{self.server_url}/api/packet", 
                                    json=test_data, 
                                    timeout=5)
            
            if response.status_code == 200:
                print(f"✅ Test packet sent successfully! Response: {response.json()}")
            else:
                print(f"⚠️ Server responded with: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Could not reach server: {e}")
            print("   Make sure the WIDS server is running!")
    
    def monitor_serial(self):
        """Monitor ESP32 serial output"""
        if not self.esp32:
            return
        
        print("\n📡 Monitoring ESP32 output... (Press Ctrl+C to stop)")
        print("-" * 50)
        
        try:
            while True:
                if self.esp32.in_waiting:
                    line = self.esp32.readline().decode('utf-8', errors='ignore').strip()
                    if line:  # Only print non-empty lines
                        print(f"[ESP32] {line}")
                
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            print("\n👋 Monitoring stopped by user")
        except Exception as e:
            print(f"❌ Error monitoring: {e}")
        finally:
            if self.esp32:
                self.esp32.close()

def main():
    """Main function"""
    print("\n" + "="*60)
    print("           ESP32 WIDS MONITOR")
    print("="*60)
    
    # Get server URL from user
    server_ip = input("Enter server IP [127.0.0.1]: ").strip()
    if not server_ip:
        server_ip = "127.0.0.1"
    
    server_url = f"http://{server_ip}:8000/api/packet"
    
    monitor = ESP32Monitor(server_url)
    
    # Ask for port or auto-detect
    port_choice = input("Enter COM port (or press Enter to auto-detect): ").strip()
    
    if monitor.connect_esp32(port_choice if port_choice else None):
        # Start monitoring
        monitor.monitor_serial()
    else:
        print("\n💡 Troubleshooting tips:")
        print("1. Make sure ESP32 is connected via USB")
        print("2. Check if correct drivers are installed")
        print("3. Verify ESP32 is powered on")
        print("4. Try specifying the port manually")
        print("5. Check Device Manager (Windows) or ls /dev/tty* (Mac/Linux)")

if __name__ == "__main__":
    main()
