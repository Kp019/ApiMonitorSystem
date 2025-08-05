#!/usr/bin/env python3
"""
Network Traffic Monitor
Captures HTTP requests/responses on multiple ports without modifying applications
"""

import socket
import threading
import time
import json
from datetime import datetime
import sys
import re
import select


class HTTPPacketParser:
    """Parse HTTP packets from raw network data"""
    
    @staticmethod
    def parse_http_request(data):
        """Parse HTTP request from raw bytes"""
        try:
            lines = data.decode('utf-8', errors='ignore').split('\r\n')
            if not lines:
                return None
                
            # Parse request line
            request_line = lines[0]
            if not request_line:
                return None
                
            parts = request_line.split(' ')
            if len(parts) < 3:
                return None
                
            method = parts[0]
            path = parts[1]
            version = parts[2]
            
            # Parse headers
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Parse body
            body = ''
            if body_start < len(lines):
                body = '\r\n'.join(lines[body_start:])
            
            return {
                'method': method,
                'path': path,
                'version': version,
                'headers': headers,
                'body': body.strip()
            }
        except Exception as e:
            return None
    
    @staticmethod
    def parse_http_response(data):
        """Parse HTTP response from raw bytes"""
        try:
            lines = data.decode('utf-8', errors='ignore').split('\r\n')
            if not lines:
                return None
                
            # Parse status line
            status_line = lines[0]
            if not status_line:
                return None
                
            parts = status_line.split(' ', 2)
            if len(parts) < 2:
                return None
                
            version = parts[0]
            status_code = parts[1]
            status_text = parts[2] if len(parts) > 2 else ''
            
            # Parse headers
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Parse body
            body = ''
            if body_start < len(lines):
                body = '\r\n'.join(lines[body_start:])
            
            return {
                'version': version,
                'status_code': status_code,
                'status_text': status_text,
                'headers': headers,
                'body': body.strip()
            }
        except Exception as e:
            return None


class PortMonitor:
    """Monitor HTTP traffic on a specific port"""
    
    def __init__(self, port, service_name):
        self.port = port
        self.service_name = service_name
        self.running = False
        self.parser = HTTPPacketParser()
    
    def get_timestamp(self):
        """Get formatted timestamp"""
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    def log_request(self, client_addr, request_data):
        """Log HTTP request"""
        parsed = self.parser.parse_http_request(request_data)
        if not parsed:
            return
            
        print(f"\n{'='*80}")
        print(f"[{self.get_timestamp()}] {self.service_name.upper()} REQUEST (Port {self.port})")
        print(f"{'='*80}")
        print(f"Client: {client_addr[0]}:{client_addr[1]}")
        print(f"Method: {parsed['method']}")
        print(f"Path: {parsed['path']}")
        print(f"Version: {parsed['version']}")
        print(f"Headers:")
        for key, value in parsed['headers'].items():
            print(f"  {key}: {value}")
        
        if parsed['body']:
            print(f"Body ({len(parsed['body'])} chars):")
            try:
                # Try to format JSON
                json_data = json.loads(parsed['body'])
                print(json.dumps(json_data, indent=2))
            except json.JSONDecodeError:
                # Print as plain text
                if len(parsed['body']) > 1000:
                    print(f"{parsed['body'][:1000]}... (truncated)")
                else:
                    print(parsed['body'])
        else:
            print("Body: (empty)")
    
    def log_response(self, response_data):
        """Log HTTP response"""
        parsed = self.parser.parse_http_response(response_data)
        if not parsed:
            return
            
        is_error = parsed['status_code'].startswith('4') or parsed['status_code'].startswith('5')
        log_type = f"{self.service_name.upper()} ERROR RESPONSE" if is_error else f"{self.service_name.upper()} RESPONSE"
        
        print(f"\n{'-'*80}")
        print(f"[{self.get_timestamp()}] {log_type} (Port {self.port})")
        print(f"{'-'*80}")
        print(f"Status: {parsed['status_code']} {parsed['status_text']}")
        print(f"Headers:")
        for key, value in parsed['headers'].items():
            print(f"  {key}: {value}")
        
        if parsed['body']:
            print(f"Body ({len(parsed['body'])} chars):")
            try:
                # Try to format JSON
                json_data = json.loads(parsed['body'])
                print(json.dumps(json_data, indent=2))
            except json.JSONDecodeError:
                # Print as plain text
                if len(parsed['body']) > 1000:
                    print(f"{parsed['body'][:1000]}... (truncated)")
                else:
                    print(parsed['body'])
        else:
            print("Body: (empty)")
    
    def handle_connection(self, client_socket, client_addr):
        """Handle individual connection"""
        try:
            # Set socket timeout
            client_socket.settimeout(10.0)
            
            # Read request data
            request_data = b''
            while True:
                try:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    request_data += chunk
                    
                    # Check if we have a complete HTTP request
                    if b'\r\n\r\n' in request_data:
                        break
                        
                except socket.timeout:
                    break
                except Exception:
                    break
            
            if request_data:
                # Log the request
                self.log_request(client_addr, request_data)
                
                # Forward to actual service
                try:
                    # Connect to the actual service
                    service_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    service_socket.connect(('localhost', self.port))
                    service_socket.send(request_data)
                    
                    # Read response
                    response_data = b''
                    service_socket.settimeout(10.0)
                    
                    while True:
                        try:
                            chunk = service_socket.recv(4096)
                            if not chunk:
                                break
                            response_data += chunk
                            
                            # For HTTP/1.1, we need to check Content-Length or chunked encoding
                            # For simplicity, we'll read until connection closes or timeout
                            
                        except socket.timeout:
                            break
                        except Exception:
                            break
                    
                    service_socket.close()
                    
                    if response_data:
                        # Log the response
                        self.log_response(response_data)
                        
                        # Send response back to client
                        client_socket.send(response_data)
                    
                except Exception as e:
                    error_response = f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nService unavailable: {e}"
                    client_socket.send(error_response.encode('utf-8'))
                    print(f"[{self.get_timestamp()}] ERROR: Cannot connect to {self.service_name} on port {self.port}: {e}")
            
        except Exception as e:
            print(f"[{self.get_timestamp()}] ERROR: Connection handling error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def start_monitoring(self):
        """Start monitoring the port"""
        # Create intercept socket on port + 10000 (e.g., 13001 for backend, 15173 for frontend)
        intercept_port = self.port + 10000
        
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('localhost', intercept_port))
            server_socket.listen(5)
            
            print(f"✅ Monitoring {self.service_name} traffic")
            print(f"   Original: localhost:{self.port}")
            print(f"   Monitor:  localhost:{intercept_port}")
            print(f"   Send requests to localhost:{intercept_port} to see logs")
            
            self.running = True
            
            while self.running:
                try:
                    client_socket, client_addr = server_socket.accept()
                    # Handle each connection in a separate thread
                    thread = threading.Thread(
                        target=self.handle_connection,
                        args=(client_socket, client_addr)
                    )
                    thread.daemon = True
                    thread.start()
                    
                except Exception as e:
                    if self.running:
                        print(f"[{self.get_timestamp()}] ERROR: Accept error: {e}")
                    break
                    
        except Exception as e:
            print(f"ERROR: Cannot start monitoring on port {intercept_port}: {e}")
        finally:
            try:
                server_socket.close()
            except:
                pass
    
    def stop(self):
        """Stop monitoring"""
        self.running = False


def main():
    """Main function to start monitoring multiple ports"""
    print("="*100)
    print("NETWORK TRAFFIC MONITOR")
    print("="*100)
    print("This tool monitors HTTP traffic on your application ports")
    print("WITHOUT modifying your applications!")
    print("="*100)
    
    # Define ports to monitor
    monitors = [
        PortMonitor(3001, "Backend API"),
        PortMonitor(5173, "Frontend React")
    ]
    
    # Start monitoring threads
    threads = []
    for monitor in monitors:
        thread = threading.Thread(target=monitor.start_monitoring)
        thread.daemon = True
        thread.start()
        threads.append(thread)
    
    print(f"\n📊 Traffic Monitor Status:")
    print(f"   Backend Monitor:  localhost:13001 → localhost:3001")
    print(f"   Frontend Monitor: localhost:15173 → localhost:5173")
    print(f"\n🔧 Usage:")
    print(f"   1. Keep your apps running on original ports (3001, 5173)")
    print(f"   2. Send requests to monitor ports to see logs:")
    print(f"      curl http://localhost:13001/api/status  # Logs backend traffic")
    print(f"      curl http://localhost:15173/           # Logs frontend traffic")
    print(f"\n⚠️  Note: This monitors requests sent TO the monitor ports only")
    print(f"   Direct requests to 3001/5173 won't be logged")
    print("="*100)
    print("\nMonitoring... Press Ctrl+C to stop\n")
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Shutting down monitors...")
        
        for monitor in monitors:
            monitor.stop()
        
        print("All monitors stopped.")


if __name__ == "__main__":
    main()