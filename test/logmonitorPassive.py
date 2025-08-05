#!/usr/bin/env python3
"""
Windows HTTP Traffic Interceptor
Uses Windows-specific methods to capture HTTP traffic on actual ports
Requires administrative privileges for some features
"""

import os
import sys
import subprocess
import threading
import time
import json
import socket
import ctypes
from datetime import datetime
import re


class WindowsTrafficInterceptor:
    """Advanced Windows HTTP traffic interceptor"""
    
    def __init__(self):
        self.running = False
        self.target_ports = [3001, 5173]
        
    def get_timestamp(self):
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    def is_admin(self):
        """Check if running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def run_netsh_trace(self):
        """Use Windows netsh to capture HTTP traffic (requires admin)"""
        if not self.is_admin():
            print("⚠️  netsh trace requires administrator privileges")
            return
            
        print("🔍 Starting Windows netsh trace...")
        
        try:
            # Start network trace
            trace_file = "http_trace.etl"
            
            start_cmd = [
                "netsh", "trace", "start",
                "capture=yes",
                f"tracefile={trace_file}",
                "provider=Microsoft-Windows-HttpService",
                "keywords=0xFFFFFFFF",
                "level=0xFF"
            ]
            
            subprocess.run(start_cmd, check=True)
            print(f"✅ Network trace started, file: {trace_file}")
            
            # Let it run for a while
            print("📊 Capturing traffic... Make some HTTP requests now")
            time.sleep(30)
            
            # Stop trace
            stop_cmd = ["netsh", "trace", "stop"]
            subprocess.run(stop_cmd, check=True)
            print(f"🛑 Network trace stopped")
            
            # Convert trace (requires additional tools)
            print(f"📁 Trace file saved: {trace_file}")
            print("💡 Use Windows Performance Analyzer or Message Analyzer to view")
            
        except subprocess.CalledProcessError as e:
            print(f"❌ netsh error: {e}")
        except Exception as e:
            print(f"❌ Trace error: {e}")
    
    def monitor_with_powershell(self):
        """Use PowerShell to monitor network connections"""
        print("🔷 Using PowerShell for network monitoring...")
        
        powershell_script = f'''
        while ($true) {{
            $connections = Get-NetTCPConnection | Where-Object {{
                $_.LocalPort -eq 3001 -or $_.LocalPort -eq 5173 -or
                $_.RemotePort -eq 3001 -or $_.RemotePort -eq 5173
            }}
            
            foreach ($conn in $connections) {{
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                $processName = if ($process) {{ $process.ProcessName }} else {{ "Unknown" }}
                
                Write-Host "[$timestamp] CONNECTION EVENT"
                Write-Host "  Local: $($conn.LocalAddress):$($conn.LocalPort)"
                Write-Host "  Remote: $($conn.RemoteAddress):$($conn.RemotePort)"
                Write-Host "  State: $($conn.State)"
                Write-Host "  Process: $processName (PID: $($conn.OwningProcess))"
                Write-Host "  ---"
            }}
            
            Start-Sleep -Seconds 2
        }}
        '''
        
        try:
            process = subprocess.Popen([
                "powershell", "-Command", powershell_script
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            while self.running:
                output = process.stdout.readline()
                if output:
                    print(output.strip())
                time.sleep(0.1)
                
        except Exception as e:
            print(f"❌ PowerShell monitoring error: {e}")
    
    def simple_port_monitor(self):
        """Simple port connection monitoring"""
        print("📊 Simple port connection monitoring...")
        
        previous_connections = set()
        
        while self.running:
            try:
                current_connections = set()
                
                # Use netstat to get current connections
                result = subprocess.run([
                    'netstat', '-an'
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        if 'TCP' in line:
                            for port in self.target_ports:
                                if f':{port}' in line:
                                    # Parse the connection
                                    parts = line.split()
                                    if len(parts) >= 4:
                                        local_addr = parts[1]
                                        remote_addr = parts[2]
                                        state = parts[3]
                                        
                                        conn_id = f"{local_addr}-{remote_addr}-{state}"
                                        current_connections.add(conn_id)
                                        
                                        # Check for new connections
                                        if conn_id not in previous_connections:
                                            service_name = "BACKEND" if port == 3001 else "FRONTEND"
                                            print(f"\n[{self.get_timestamp()}] 🆕 NEW {service_name} CONNECTION")
                                            print(f"  Local:  {local_addr}")
                                            print(f"  Remote: {remote_addr}")
                                            print(f"  State:  {state}")
                
                # Check for closed connections
                closed_connections = previous_connections - current_connections
                for conn in closed_connections:
                    print(f"\n[{self.get_timestamp()}] 🔴 CONNECTION CLOSED: {conn}")
                
                previous_connections = current_connections
                time.sleep(2)
                
            except Exception as e:
                print(f"❌ Port monitoring error: {e}")
                time.sleep(5)
    
    def http_request_simulator(self):
        """Simulate HTTP request detection by checking service health"""
        print("🌐 HTTP service health monitoring...")
        
        service_status = {}
        
        while self.running:
            try:
                for port in self.target_ports:
                    service_name = "BACKEND" if port == 3001 else "FRONTEND"
                    
                    try:
                        # Quick connection test
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(2)
                        result = sock.connect_ex(('127.0.0.1', port))
                        sock.close()
                        
                        current_status = result == 0
                        previous_status = service_status.get(port, None)
                        
                        if previous_status is None:
                            # First check
                            if current_status:
                                print(f"[{self.get_timestamp()}] ✅ {service_name} service is running on port {port}")
                            else:
                                print(f"[{self.get_timestamp()}] ❌ {service_name} service not found on port {port}")
                        
                        elif previous_status != current_status:
                            # Status changed
                            if current_status:
                                print(f"[{self.get_timestamp()}] 🟢 {service_name} service started on port {port}")
                            else:
                                print(f"[{self.get_timestamp()}] 🔴 {service_name} service stopped on port {port}")
                        
                        service_status[port] = current_status
                        
                    except Exception as e:
                        print(f"[{self.get_timestamp()}] ❌ Error checking {service_name}: {e}")
                
                time.sleep(5)
                
            except Exception as e:
                print(f"❌ Service monitoring error: {e}")
                time.sleep(10)
    
    def start_monitoring(self):
        """Start the traffic interceptor"""
        print("="*100)
        print("WINDOWS HTTP TRAFFIC INTERCEPTOR")
        print("="*100)
        print("🪟 Advanced Windows network monitoring")
        print("📡 Attempts to capture actual HTTP traffic")
        print("⚠️  Limited by Windows security and networking stack")
        print("="*100)
        
        is_admin = self.is_admin()
        print(f"👤 Administrator privileges: {'✅ YES' if is_admin else '❌ NO'}")
        
        if is_admin:
            print("🔧 Advanced monitoring features available")
        else:
            print("⚠️  Some features require 'Run as Administrator'")
            print("💡 For basic monitoring, this will work fine")
        
        print("="*100)
        print("🚀 MONITORING METHODS:")
        print("1. 📊 Port Connection Monitoring")
        print("2. 🌐 Service Health Monitoring")
        if is_admin:
            print("3. 🔷 PowerShell Network Monitoring")
            print("4. 📈 Windows Network Tracing")
        print("="*100)
        
        self.running = True
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self.simple_port_monitor, daemon=True),
            threading.Thread(target=self.http_request_simulator, daemon=True)
        ]
        
        if is_admin:
            threads.append(threading.Thread(target=self.monitor_with_powershell, daemon=True))
        
        for thread in threads:
            thread.start()
        
        print(f"\n🔍 Monitoring started on ports: {self.target_ports}")
        print(f"📊 Make HTTP requests to see connection events:")
        print(f"   curl http://127.0.0.1:3001/api/status")
        print(f"   curl http://127.0.0.1:5173/")
        print("="*100)
        print("\n⏳ Monitoring... Press Ctrl+C to stop\n")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n[{self.get_timestamp()}] 🛑 Stopping interceptor...")
            self.running = False
            print("✅ Interceptor stopped.")


def main():
    """Main function with options"""
    print("\n" + "="*80)
    print("WINDOWS HTTP MONITORING SOLUTIONS")
    print("="*80)
    print("🔍 Choose your monitoring approach:")
    print()
    print("1. 🌐 Traffic Interceptor (Current)")
    print("   - Monitors connection events")
    print("   - Limited HTTP content visibility")
    print("   - Works with original URLs")
    print()
    print("2. 📡 HTTP Proxy Monitor (Recommended)")
    print("   - Full HTTP request/response capture")
    print("   - Requires URL routing through proxy")
    print("   - Complete visibility into HTTP data")
    print()
    print("3. 🔧 Application-Level Logging")
    print("   - Modify your applications to log requests")
    print("   - Most reliable method")
    print("   - Requires code changes")
    print("="*80)
    
    choice = input("Choose option (1, 2, or 3): ").strip()
    
    if choice == "2":
        print("\n📡 For complete HTTP monitoring, use the proxy method:")
        print("   1. Run: python http_monitor.py")
        print("   2. Send requests to proxy ports:")
        print("      - Backend:  http://127.0.0.1:13001/api/status")
        print("      - Frontend: http://127.0.0.1:15173/")
        return
    elif choice == "3":
        print("\n🔧 Application-level logging suggestions:")
        print("   Backend: Add middleware to log all requests/responses")
        print("   Frontend: Add interceptors to log all HTTP calls")
        print("   This provides the most detailed and reliable logging")
        return
    
    # Option 1: Traffic Interceptor
    interceptor = WindowsTrafficInterceptor()
    interceptor.start_monitoring()


if __name__ == "__main__":
    main()