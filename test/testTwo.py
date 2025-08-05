#!/usr/bin/env python3
"""
HTTP Reverse Proxy with Comprehensive Logging
Captures logs from React frontend (port 5173) and backend (port 3001)
"""

import json
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import requests
import threading
import sys


class ProxyHandler(BaseHTTPRequestHandler):
    # Configuration for different services
    BACKEND_PORT = 3001
    FRONTEND_PORT = 5173
    BACKEND_URL = f'http://localhost:{BACKEND_PORT}'
    FRONTEND_URL = f'http://localhost:{FRONTEND_PORT}'
    
    def log_message(self, format, *args):
        """Override to prevent default logging"""
        pass
    
    def get_timestamp(self):
        """Get formatted timestamp"""
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    def log_request_details(self, method, full_url, headers, body, service_type="PROXY"):
        """Log incoming request details"""
        print(f"\n{'='*70}")
        print(f"[{self.get_timestamp()}] {service_type} REQUEST")
        print(f"{'='*70}")
        print(f"Method: {method}")
        print(f"URL: {full_url}")
        print(f"Client: {self.client_address[0]}:{self.client_address[1]}")
        print(f"Headers:")
        for header, value in headers.items():
            print(f"  {header}: {value}")
        
        if body:
            print(f"Body ({len(body)} bytes):")
            try:
                parsed = json.loads(body.decode('utf-8'))
                print(json.dumps(parsed, indent=2))
            except (json.JSONDecodeError, UnicodeDecodeError):
                body_str = body.decode('utf-8', errors='replace')
                if len(body_str) > 1000:
                    print(f"{body_str[:1000]}... (truncated)")
                else:
                    print(body_str)
        else:
            print("Body: (empty)")
    
    def log_response_details(self, status_code, headers, body, service_type="PROXY", is_error=False):
        """Log response details"""
        log_type = f"{service_type} ERROR RESPONSE" if is_error else f"{service_type} RESPONSE"
        print(f"\n{'-'*70}")
        print(f"[{self.get_timestamp()}] {log_type}")
        print(f"{'-'*70}")
        print(f"Status: {status_code}")
        print(f"Headers:")
        for header, value in headers.items():
            print(f"  {header}: {value}")
        
        if body:
            print(f"Body ({len(body)} bytes):")
            try:
                parsed = json.loads(body)
                print(json.dumps(parsed, indent=2))
            except json.JSONDecodeError:
                if len(body) > 1000:
                    print(f"{body[:1000]}... (truncated)")
                else:
                    print(body)
        else:
            print("Body: (empty)")
    
    def log_frontend_message(self, log_data):
        """Log frontend console errors, logs, and network requests"""
        log_type = log_data.get('type', 'unknown').upper()
        print(f"\n{'*'*70}")
        print(f"[{self.get_timestamp()}] FRONTEND {log_type}")
        print(f"{'*'*70}")
        
        if log_data.get('type') == 'network':
            # Log network requests from frontend
            print(f"Method: {log_data.get('method', 'unknown')}")
            print(f"URL: {log_data.get('url', 'unknown')}")
            print(f"Status: {log_data.get('status', 'unknown')}")
            if log_data.get('duration'):
                print(f"Duration: {log_data['duration']}ms")
            if log_data.get('requestHeaders'):
                print("Request Headers:")
                for header, value in log_data['requestHeaders'].items():
                    print(f"  {header}: {value}")
            if log_data.get('responseHeaders'):
                print("Response Headers:")
                for header, value in log_data['responseHeaders'].items():
                    print(f"  {header}: {value}")
            if log_data.get('requestBody'):
                print("Request Body:")
                print(json.dumps(log_data['requestBody'], indent=2))
            if log_data.get('responseBody'):
                print("Response Body:")
                print(json.dumps(log_data['responseBody'], indent=2))
        
        elif log_data.get('type') in ['error', 'console', 'log', 'warn', 'info']:
            # Log console messages and errors
            print(f"Message: {log_data.get('message', 'No message')}")
            
            if log_data.get('stack'):
                print(f"Stack Trace:")
                print(log_data['stack'])
            
            if log_data.get('line') is not None:
                print(f"Line: {log_data['line']}")
            
            if log_data.get('column') is not None:
                print(f"Column: {log_data['column']}")
            
            if log_data.get('url'):
                print(f"Source URL: {log_data['url']}")
        
        if log_data.get('timestamp'):
            print(f"Frontend Timestamp: {log_data['timestamp']}")
        
        # Log any additional data
        excluded_keys = {'type', 'message', 'stack', 'line', 'column', 'url', 'timestamp', 
                        'method', 'status', 'duration', 'requestHeaders', 'responseHeaders',
                        'requestBody', 'responseBody'}
        additional_data = {k: v for k, v in log_data.items() if k not in excluded_keys}
        if additional_data:
            print(f"Additional Data:")
            print(json.dumps(additional_data, indent=2))
    
    def handle_log_endpoint(self):
        """Handle POST requests to /log endpoint"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error(400, "No content provided")
                return
            
            body = self.rfile.read(content_length)
            
            try:
                log_data = json.loads(body.decode('utf-8'))
                self.log_frontend_message(log_data)
                
                # Send success response
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                response = {'status': 'success', 'message': 'Log received'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                
            except json.JSONDecodeError as e:
                print(f"[{self.get_timestamp()}] ERROR: Invalid JSON in /log request: {e}")
                self.send_error(400, f"Invalid JSON: {e}")
                
        except Exception as e:
            print(f"[{self.get_timestamp()}] ERROR: Exception in /log handler: {e}")
            self.send_error(500, f"Internal server error: {e}")
    
    def determine_target_service(self):
        """Determine whether to proxy to frontend or backend based on request"""
        # API requests go to backend
        if (self.path.startswith('/api/') or 
            self.path.startswith('/auth/') or
            self.path.startswith('/v1/') or
            'application/json' in self.headers.get('content-type', '').lower()):
            return self.BACKEND_URL, "BACKEND"
        
        # Everything else goes to frontend (React dev server)
        return self.FRONTEND_URL, "FRONTEND"
    
    def proxy_request(self, method):
        """Proxy the request to the appropriate service"""
        try:
            # Determine target service
            target_url, service_type = self.determine_target_service()
            full_url = f"{target_url}{self.path}"
            
            # Get request headers
            headers = {}
            for header, value in self.headers.items():
                if header.lower() not in ['host', 'connection', 'upgrade']:
                    headers[header] = value
            
            # Read request body
            body = b''
            if 'Content-Length' in self.headers:
                content_length = int(self.headers['Content-Length'])
                body = self.rfile.read(content_length)
            
            # Log request details
            self.log_request_details(method, full_url, dict(self.headers.items()), body, service_type)
            
            # Make request to target service
            response = requests.request(
                method=method,
                url=full_url,
                headers=headers,
                data=body,
                allow_redirects=False,
                timeout=30
            )
            
            # Check if this is an error response
            is_error = response.status_code >= 400
            
            # Log response details
            self.log_response_details(
                response.status_code,
                dict(response.headers),
                response.text,
                service_type,
                is_error
            )
            
            # Send response back to client
            self.send_response(response.status_code)
            
            # Forward response headers
            for header, value in response.headers.items():
                if header.lower() not in ['connection', 'transfer-encoding', 'content-encoding']:
                    self.send_header(header, value)
            
            self.end_headers()
            
            # Forward response body
            if response.content:
                self.wfile.write(response.content)
                
        except requests.exceptions.RequestException as e:
            error_msg = f"Service connection error: {e}"
            print(f"[{self.get_timestamp()}] ERROR: {error_msg}")
            self.send_error(502, error_msg)
            
        except Exception as e:
            error_msg = f"Proxy error: {e}"
            print(f"[{self.get_timestamp()}] ERROR: {error_msg}")
            self.send_error(500, error_msg)
    
    def do_GET(self):
        """Handle GET requests"""
        self.proxy_request('GET')
    
    def do_POST(self):
        """Handle POST requests"""
        if self.path == '/log':
            self.handle_log_endpoint()
        else:
            self.proxy_request('POST')
    
    def do_PUT(self):
        """Handle PUT requests"""
        self.proxy_request('PUT')
    
    def do_PATCH(self):
        """Handle PATCH requests"""
        self.proxy_request('PATCH')
    
    def do_DELETE(self):
        """Handle DELETE requests"""
        self.proxy_request('DELETE')
    
    def do_OPTIONS(self):
        """Handle OPTIONS requests (for CORS)"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        self.send_header('Access-Control-Max-Age', '86400')
        self.end_headers()


class ThreadedHTTPServer(HTTPServer):
    """HTTPServer that handles requests in separate threads"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.daemon_threads = True


def run_proxy_server():
    """Run the reverse proxy server"""
    server_address = ('', 3000)
    
    try:
        httpd = ThreadedHTTPServer(server_address, ProxyHandler)
        
        print("="*80)
        print("FULL-STACK LOGGING PROXY")
        print("="*80)
        print(f"Proxy Server: http://localhost:3000")
        print(f"React Frontend: http://localhost:5173 (proxied)")
        print(f"Backend API: http://localhost:3001 (proxied)")
        print(f"Frontend Log Endpoint: POST http://localhost:3000/log")
        print("="*80)
        print("SETUP INSTRUCTIONS:")
        print("1. Keep your React app running on port 5173")
        print("2. Keep your backend running on port 3001") 
        print("3. Access your app through: http://localhost:3000")
        print("4. Add frontend logging code (see below)")
        print("="*80)
        print("\nServer is running... Press Ctrl+C to stop\n")
        
        httpd.serve_forever()
        
    except KeyboardInterrupt:
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Shutting down proxy server...")
        httpd.shutdown()
        print("Server stopped.")
        
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"ERROR: Port 3000 is already in use.")
        else:
            print(f"ERROR: {e}")
        sys.exit(1)
        
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    run_proxy_server()