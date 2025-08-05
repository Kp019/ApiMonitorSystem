def packet_callback(self, packet) -> None:
        """Callback function to process captured packets."""
        # Check if we should stop
        if self.stop_sniffing:
            return
            
        try:
            if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
                return
            
            packet_info = {
                'src': packet[IP].src if packet.haslayer(IP) else 'Unknown',
                'dst': packet[IP].dst if packet.haslayer(IP) else 'Unknown',
                'sport': packet[TCP].sport,
                'dport': packet[TCP].dport,
            }
            
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                payload = packet[Raw].load.decode('latin1', errors='ignore')
            
            if not any(keyword in payload for keyword in ['HTTP/', 'GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ']):
                return
            
            self.packet_count += 1
            parsed_http = self._parse_http_headers(payload)
            
            # Check if we should only monitor errors
            if self.monitor_errors_only:
                try:
                    status_code = int(parsed_http.get('status_code', 0))
                    if status_code < self.error_threshold:
                        return  # Skip non-error responses
                except (ValueError, TypeError):
                    return  # Skip if status code can't be parsed
            
            # Display packet information
            formatted_output = self._format_output(packet_info, parsed_http)
            print(formatted_output)
            
            # Analyze HTTP status codes for errors
            self._analyze_http_status(parsed_http, packet_info)
            
        except Exception as e:
            if not self._handle_error(e, f"Processing packet #{self.packet_count + 1}"):
                self.stop_sniffing = True#!/usr/bin/env python3
"""
AI-Enhanced Network Packet Sniffer with Ollama Integration
Captures and analyzes HTTP traffic with intelligent error analysis using Gemma3 model.
"""

import sys
import json
import re
import requests
import traceback
import signal
import threading
from datetime import datetime
from typing import Optional, Dict, Any, List
from scapy.all import sniff, TCP, Raw, get_if_list, IP
import argparse
import time


class OllamaAnalyzer:
    """Integration with Ollama Gemma3 model for error analysis."""
    
    def __init__(self, model_name: str = "gemma2", ollama_url: str = "http://localhost:11434"):
        self.model_name = model_name
        self.ollama_url = ollama_url
        self.api_url = f"{ollama_url}/api/generate"
        
    def _check_ollama_connection(self) -> bool:
        """Check if Ollama service is running and model is available."""
        try:
            # Check if Ollama is running
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if response.status_code != 200:
                return False
            
            # Check if the model is available
            models = response.json().get('models', [])
            model_names = [model['name'] for model in models]
            
            # Check for exact match or partial match
            available = any(self.model_name in name for name in model_names)
            if not available:
                print(f"Available models: {model_names}")
                print(f"Requested model '{self.model_name}' not found.")
            
            return available
            
        except Exception as e:
            print(f"Failed to connect to Ollama: {e}")
            return False
    
    def analyze_error(self, error_type: str, error_message: str, context: str = "") -> Dict[str, str]:
        """Analyze error using Gemma3 model and provide meaningful description and solution."""
        if not self._check_ollama_connection():
            return {
                "analysis": "Ollama service is not available for error analysis.",
                "solution": "Please ensure Ollama is running and the Gemma3 model is installed.",
                "severity": "high"
            }
        
        prompt = f"""
You are an expert network security analyst. Analyze the following error from a network packet sniffer application:

Error Type: {error_type}
Error Message: {error_message}
Context: {context}

Please provide:
1. A clear, meaningful description of what this error means
2. The potential impact or severity (low/medium/high)
3. Specific solutions or troubleshooting steps to resolve this issue
4. Prevention measures to avoid this error in the future

Format your response as a structured analysis focusing on practical solutions for network monitoring applications.
"""

        try:
            payload = {
                "model": self.model_name,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.3,
                    "top_p": 0.9,
                    "max_tokens": 1000
                }
            }
            
            response = requests.post(
                self.api_url,
                json=payload,
                timeout=30,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                result = response.json()
                ai_response = result.get('response', 'No response from AI model')
                
                # Parse the AI response to extract structured information
                return self._parse_ai_response(ai_response)
            else:
                return {
                    "analysis": f"AI analysis failed with status code: {response.status_code}",
                    "solution": "Check Ollama service and model availability",
                    "severity": "medium"
                }
                
        except requests.exceptions.Timeout:
            return {
                "analysis": "AI analysis timed out",
                "solution": "The AI model is taking too long to respond. Try again or check system resources.",
                "severity": "low"
            }
        except Exception as e:
            return {
                "analysis": f"Failed to get AI analysis: {str(e)}",
                "solution": "Check Ollama service connection and model availability",
                "severity": "medium"
            }
    
    def analyze_http_error(self, status_code: int, status_message: str, context: str = "") -> Dict[str, str]:
        """Analyze HTTP error status codes using Gemma3 model."""
        if not self._check_ollama_connection():
            return {
                "severity": "medium",
                "root_cause": "AI analysis unavailable",
                "impact": "Unable to perform detailed analysis",
                "recommendations": "Ensure Ollama service is running"
            }
        
        prompt = f"""
You are an expert web application security analyst and HTTP protocol specialist. Analyze this HTTP error response:

Status Code: {status_code}
Status Message: {status_message}
Context Information: {context}

Please provide a comprehensive analysis in the following format:

SEVERITY: (critical/high/medium/low)
ROOT CAUSE: What likely caused this error and why it occurred
IMPACT: What this error means for the application/service and users
RECOMMENDATIONS: Specific actionable steps to investigate and resolve this issue

Focus on practical troubleshooting steps and consider both client-side and server-side causes. Include security implications if relevant.
"""

        try:
            payload = {
                "model": self.model_name,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "top_p": 0.8,
                    "max_tokens": 800
                }
            }
            
            response = requests.post(
                self.api_url,
                json=payload,
                timeout=25,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                result = response.json()
                ai_response = result.get('response', 'No response from AI model')
                return self._parse_http_analysis(ai_response)
            else:
                return self._get_fallback_http_analysis(status_code)
                
        except Exception as e:
            return self._get_fallback_http_analysis(status_code)
    
    def _parse_http_analysis(self, ai_response: str) -> Dict[str, str]:
        """Parse AI response for HTTP error analysis."""
        # Default values
        analysis = {
            "severity": "medium",
            "root_cause": "Unknown cause",
            "impact": "Service disruption possible",
            "recommendations": "Manual investigation required"
        }
        
        try:
            # Extract severity
            severity_match = re.search(r'SEVERITY:\s*(\w+)', ai_response, re.IGNORECASE)
            if severity_match:
                analysis["severity"] = severity_match.group(1).lower()
            
            # Extract root cause
            cause_match = re.search(r'ROOT CAUSE:\s*([^\n]+(?:\n(?!(?:IMPACT|RECOMMENDATIONS):)[^\n]+)*)', ai_response, re.IGNORECASE | re.MULTILINE)
            if cause_match:
                analysis["root_cause"] = cause_match.group(1).strip()
            
            # Extract impact
            impact_match = re.search(r'IMPACT:\s*([^\n]+(?:\n(?!(?:ROOT CAUSE|RECOMMENDATIONS):)[^\n]+)*)', ai_response, re.IGNORECASE | re.MULTILINE)
            if impact_match:
                analysis["impact"] = impact_match.group(1).strip()
            
            # Extract recommendations
            rec_match = re.search(r'RECOMMENDATIONS:\s*([^\n]+(?:\n(?!(?:ROOT CAUSE|IMPACT|SEVERITY):)[^\n]+)*)', ai_response, re.IGNORECASE | re.MULTILINE)
            if rec_match:
                analysis["recommendations"] = rec_match.group(1).strip()
        
        except Exception:
            # If parsing fails, return the full response as root cause
            analysis["root_cause"] = ai_response[:300] + "..." if len(ai_response) > 300 else ai_response
        
        return analysis
    
    def _get_fallback_http_analysis(self, status_code: int) -> Dict[str, str]:
        """Provide fallback analysis when AI is unavailable."""
        fallback_analyses = {
            400: {
                "severity": "medium",
                "root_cause": "Malformed request syntax, invalid parameters, or missing required data",
                "impact": "Client requests are being rejected, affecting user functionality",
                "recommendations": "Check request formatting, validate input parameters, review API documentation"
            },
            401: {
                "severity": "high",
                "root_cause": "Missing or invalid authentication credentials",
                "impact": "Unauthorized access attempts, potential security concern",
                "recommendations": "Verify authentication tokens, check credential expiration, review auth flow"
            },
            403: {
                "severity": "high",
                "root_cause": "Valid authentication but insufficient permissions for requested resource",
                "impact": "Access control working but users cannot access needed resources",
                "recommendations": "Review user permissions, check access control lists, verify authorization logic"
            },
            404: {
                "severity": "medium",
                "root_cause": "Requested resource not found - may be deleted, moved, or URL incorrect",
                "impact": "Users encountering broken links or missing content",
                "recommendations": "Verify URL correctness, check if resource exists, implement proper redirects"
            },
            429: {
                "severity": "medium",
                "root_cause": "Rate limiting triggered - too many requests from client",
                "impact": "Service protection active, legitimate users may be affected",
                "recommendations": "Review rate limiting rules, implement exponential backoff, check for abuse"
            },
            500: {
                "severity": "critical",
                "root_cause": "Internal server error - application logic failure or system issue",
                "impact": "Service functionality compromised, user experience severely affected",
                "recommendations": "Check server logs, review recent deployments, monitor system resources"
            },
            502: {
                "severity": "high",
                "root_cause": "Bad gateway - upstream server returned invalid response",
                "impact": "Service chain broken, requests cannot be properly processed",
                "recommendations": "Check upstream services, verify load balancer config, test service connectivity"
            },
            503: {
                "severity": "high",
                "root_cause": "Service temporarily unavailable - overload or maintenance",
                "impact": "Service temporarily down, users cannot access functionality",
                "recommendations": "Check server capacity, review maintenance schedules, implement circuit breakers"
            },
            504: {
                "severity": "high",
                "root_cause": "Gateway timeout - upstream server failed to respond in time",
                "impact": "Slow response times, requests timing out",
                "recommendations": "Check upstream performance, adjust timeout settings, review network connectivity"
            }
        }
        
        return fallback_analyses.get(status_code, {
            "severity": "medium",
            "root_cause": f"HTTP error {status_code} detected",
            "impact": "Service error condition present",
            "recommendations": "Manual investigation required for this status code"
        })
    
    def _parse_ai_response(self, ai_response: str) -> Dict[str, str]:
        """Parse AI response to extract structured information."""
        # Default values
        analysis = ai_response
        solution = "Refer to the analysis above for guidance"
        severity = "medium"
        
        # Try to extract severity
        severity_keywords = {
            "high": ["critical", "severe", "dangerous", "fatal", "urgent"],
            "low": ["minor", "trivial", "informational", "warning"],
            "medium": ["moderate", "important", "significant"]
        }
        
        ai_lower = ai_response.lower()
        for sev_level, keywords in severity_keywords.items():
            if any(keyword in ai_lower for keyword in keywords):
                severity = sev_level
                break
        
        # Try to split analysis and solution if structured
        if "solution" in ai_lower or "troubleshooting" in ai_lower:
            parts = re.split(r'(?i)(solution|troubleshooting|steps|prevention)', ai_response, 1)
            if len(parts) >= 3:
                analysis = parts[0].strip()
                solution = parts[1] + parts[2].strip()
        
        return {
            "analysis": analysis,
            "solution": solution,
            "severity": severity
        }


class EnhancedHTTPPacketSniffer:
    """Enhanced HTTP packet sniffer with AI-powered error analysis."""
    
    def __init__(self, port: int = 3001, interface: Optional[str] = None, 
                 enable_ai: bool = True, auto_restart: bool = True):
        self.port = port
        self.interface = interface or self._get_default_interface()
        self.packet_count = 0
        self.error_count = 0
        self.http_error_count = 0
        self.enable_ai = enable_ai
        self.auto_restart = auto_restart
        self.ai_analyzer = OllamaAnalyzer() if enable_ai else None
        self.restart_attempts = 0
        self.max_restart_attempts = 3
        
        # HTTP error monitoring options
        self.monitor_errors_only = False
        self.error_threshold = 400
        self.log_errors = False
        
        # Control flags for graceful shutdown
        self.stop_sniffing = False
        self.sniff_thread = None
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            print(f"\n⚠️  Received interrupt signal ({signum}). Stopping sniffer...")
            self.stop_sniffing = True
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def _stop_condition(self, packet):
        """Check if we should stop sniffing."""
        return self.stop_sniffing
        
    def _get_default_interface(self) -> str:
        """Get the default network interface."""
        interfaces = get_if_list()
        if not interfaces:
            raise RuntimeError("No network interfaces found")
        
        # Try to find loopback interface first
        for iface in interfaces:
            if "loopback" in iface.lower() or "lo" in iface.lower():
                return iface
        
        return interfaces[0]
    
    def _handle_error(self, error: Exception, context: str = "") -> bool:
        """Handle errors with AI analysis and return whether to continue."""
        self.error_count += 1
        error_type = type(error).__name__
        error_message = str(error)
        
        print("\n" + "!" * 80)
        print(f"ERROR DETECTED #{self.error_count} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("!" * 80)
        print(f"Error Type: {error_type}")
        print(f"Error Message: {error_message}")
        print(f"Context: {context}")
        
        if self.enable_ai and self.ai_analyzer:
            print("\n🤖 AI Analysis in progress...")
            
            # Get AI analysis
            ai_analysis = self.ai_analyzer.analyze_error(error_type, error_message, context)
            
            print(f"\n📊 AI ANALYSIS:")
            print(f"Severity: {ai_analysis['severity'].upper()}")
            print(f"\n📝 Description:")
            print(ai_analysis['analysis'])
            print(f"\n💡 Solution:")
            print(ai_analysis['solution'])
            
            # Determine if we should continue based on severity
            if ai_analysis['severity'] == 'high':
                print(f"\n⚠️  High severity error detected. Stopping monitoring.")
                return False
            elif ai_analysis['severity'] == 'medium' and not self.auto_restart:
                print(f"\n⚠️  Medium severity error. Auto-restart disabled.")
                return False
        else:
            print("\n💭 AI analysis disabled or unavailable")
            print("📋 Stack trace:")
            traceback.print_exc()
        
        if self.auto_restart and self.restart_attempts < self.max_restart_attempts:
            print(f"\n🔄 Auto-restart enabled. Attempt {self.restart_attempts + 1}/{self.max_restart_attempts}")
            self.restart_attempts += 1
            return True
        elif self.restart_attempts >= self.max_restart_attempts:
            print(f"\n❌ Maximum restart attempts ({self.max_restart_attempts}) reached. Stopping.")
            return False
        
        return False
    
    def _parse_http_headers(self, payload: str) -> Dict[str, Any]:
        """Parse HTTP headers from payload."""
        try:
            lines = payload.split('\r\n')
            if not lines:
                return {}
            
            first_line = lines[0]
            headers = {}
            
            if first_line.startswith('HTTP/'):
                # HTTP Response
                parts = first_line.split(' ', 2)
                headers['type'] = 'response'
                headers['version'] = parts[0] if len(parts) > 0 else 'Unknown'
                headers['status_code'] = parts[1] if len(parts) > 1 else 'Unknown'
                headers['status_message'] = parts[2] if len(parts) > 2 else 'Unknown'
            else:
                # HTTP Request
                parts = first_line.split(' ')
                headers['type'] = 'request'
                headers['method'] = parts[0] if len(parts) > 0 else 'Unknown'
                headers['path'] = parts[1] if len(parts) > 1 else 'Unknown'
                headers['version'] = parts[2] if len(parts) > 2 else 'Unknown'
            
            # Parse headers
            header_section = True
            header_dict = {}
            body_lines = []
            
            for line in lines[1:]:
                if header_section:
                    if line.strip() == '':
                        header_section = False
                        continue
                    if ':' in line:
                        key, value = line.split(':', 1)
                        header_dict[key.strip().lower()] = value.strip()
                else:
                    body_lines.append(line)
            
            headers['headers'] = header_dict
            headers['body'] = '\r\n'.join(body_lines) if body_lines else ''
            
            return headers
            
        except Exception as e:
            raise Exception(f"HTTP parsing failed: {str(e)}")
    
    def _format_output(self, packet_info: Dict[str, Any], parsed_http: Dict[str, Any]) -> str:
        """Format the packet information for readable output."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        output = [
            "=" * 80,
            f"HTTP Packet #{self.packet_count} - {timestamp}",
            "=" * 80,
            f"Source: {packet_info['src']}:{packet_info['sport']} -> "
            f"Destination: {packet_info['dst']}:{packet_info['dport']}",
            ""
        ]
        
        if parsed_http['type'] == 'request':
            output.extend([
                f"HTTP REQUEST:",
                f"  Method: {parsed_http['method']}",
                f"  Path: {parsed_http['path']}",
                f"  Version: {parsed_http['version']}",
                ""
            ])
        else:
            output.extend([
                f"HTTP RESPONSE:",
                f"  Version: {parsed_http['version']}",
                f"  Status: {parsed_http['status_code']} {parsed_http['status_message']}",
                ""
            ])
        
        if parsed_http['headers']:
            output.append("Headers:")
            for key, value in parsed_http['headers'].items():
                display_value = value[:100] + "..." if len(value) > 100 else value
                output.append(f"  {key.title()}: {display_value}")
            output.append("")
        
        if parsed_http['body'] and parsed_http['body'].strip():
            body = parsed_http['body']
            if len(body) > 500:
                body = body[:500] + "\n... (truncated)"
            
            output.extend([
                "Body:",
                body,
                ""
            ])
        
        return '\n'.join(output)
    
    def _analyze_http_status(self, parsed_http: Dict[str, Any], packet_info: Dict[str, Any]) -> None:
        """Analyze HTTP status codes and provide AI insights for error codes."""
        if parsed_http['type'] != 'response':
            return
            
        try:
            status_code = int(parsed_http.get('status_code', 0))
        except (ValueError, TypeError):
            return
        
        # Check for error status codes based on threshold
        if status_code >= self.error_threshold:
            self.http_error_count += 1
            error_category = self._get_error_category(status_code)
            
            print(f"\n🚨 HTTP ERROR DETECTED #{self.http_error_count} - Status Code {status_code}")
            print("=" * 60)
            print(f"Category: {error_category['category']}")
            print(f"Common Meaning: {error_category['meaning']}")
            print(f"Source: {packet_info['src']}:{packet_info['sport']}")
            print(f"Destination: {packet_info['dst']}:{packet_info['dport']}")
            
            # Get additional context from headers and body
            context_info = self._extract_http_context(parsed_http)
            
            if self.enable_ai and self.ai_analyzer:
                print(f"\n🤖 Getting AI analysis for HTTP {status_code} error...")
                
                # Prepare context for AI analysis
                error_context = f"""
HTTP Response Analysis:
- Status Code: {status_code} ({parsed_http.get('status_message', 'Unknown')})
- Source: {packet_info['src']}:{packet_info['sport']}
- Destination: {packet_info['dst']}:{packet_info['dport']}
- Content-Type: {context_info.get('content_type', 'Unknown')}
- Content-Length: {context_info.get('content_length', 'Unknown')}
- Server: {context_info.get('server', 'Unknown')}
- User-Agent: {context_info.get('user_agent', 'Unknown')}
- Request Path: {context_info.get('referer', 'Unknown')}
- Body Preview: {context_info.get('body_preview', 'No body content')}
"""
                
                ai_analysis = self.ai_analyzer.analyze_http_error(
                    status_code, 
                    parsed_http.get('status_message', ''), 
                    error_context
                )
                
                print(f"\n📊 AI ANALYSIS:")
                print(f"Severity: {ai_analysis['severity'].upper()}")
                print(f"Root Cause: {ai_analysis['root_cause']}")
                print(f"Impact: {ai_analysis['impact']}")
                print(f"Recommended Actions: {ai_analysis['recommendations']}")
                
                # Log to file if enabled and it's a critical error
                if self.log_errors and ai_analysis['severity'] in ['high', 'critical']:
                    self._log_critical_error(status_code, parsed_http, packet_info, ai_analysis)
            
            else:
                print(f"\n💭 AI analysis disabled - showing basic error info")
                print(f"Status: {status_code} - {error_category['meaning']}")
                if self.log_errors:
                    basic_analysis = {
                        "severity": "medium",
                        "root_cause": error_category['meaning'],
                        "impact": "HTTP error response detected",
                        "recommendations": "Manual investigation recommended"
                    }
                    self._log_critical_error(status_code, parsed_http, packet_info, basic_analysis)
            
            print("=" * 60)
    
    def _get_error_category(self, status_code: int) -> Dict[str, str]:
        """Get error category and basic meaning for HTTP status codes."""
        error_categories = {
            # 4xx Client Errors
            400: {"category": "Client Error", "meaning": "Bad Request - Invalid syntax"},
            401: {"category": "Client Error", "meaning": "Unauthorized - Authentication required"},
            403: {"category": "Client Error", "meaning": "Forbidden - Access denied"},
            404: {"category": "Client Error", "meaning": "Not Found - Resource doesn't exist"},
            405: {"category": "Client Error", "meaning": "Method Not Allowed - HTTP method not supported"},
            408: {"category": "Client Error", "meaning": "Request Timeout - Client took too long"},
            409: {"category": "Client Error", "meaning": "Conflict - Request conflicts with server state"},
            410: {"category": "Client Error", "meaning": "Gone - Resource permanently unavailable"},
            422: {"category": "Client Error", "meaning": "Unprocessable Entity - Invalid request data"},
            429: {"category": "Client Error", "meaning": "Too Many Requests - Rate limit exceeded"},
            
            # 5xx Server Errors
            500: {"category": "Server Error", "meaning": "Internal Server Error - Generic server fault"},
            501: {"category": "Server Error", "meaning": "Not Implemented - Server doesn't support functionality"},
            502: {"category": "Server Error", "meaning": "Bad Gateway - Invalid response from upstream"},
            503: {"category": "Server Error", "meaning": "Service Unavailable - Server temporarily overloaded"},
            504: {"category": "Server Error", "meaning": "Gateway Timeout - Upstream server timeout"},
            505: {"category": "Server Error", "meaning": "HTTP Version Not Supported"},
        }
        
        if status_code in error_categories:
            return error_categories[status_code]
        elif 400 <= status_code < 500:
            return {"category": "Client Error", "meaning": f"Client error {status_code}"}
        elif 500 <= status_code < 600:
            return {"category": "Server Error", "meaning": f"Server error {status_code}"}
        else:
            return {"category": "Unknown Error", "meaning": f"Unknown status code {status_code}"}
    
    def _extract_http_context(self, parsed_http: Dict[str, Any]) -> Dict[str, str]:
        """Extract relevant context information from HTTP headers and body."""
        headers = parsed_http.get('headers', {})
        body = parsed_http.get('body', '')
        
        context = {
            'content_type': headers.get('content-type', 'Unknown'),
            'content_length': headers.get('content-length', 'Unknown'),
            'server': headers.get('server', 'Unknown'),
            'user_agent': headers.get('user-agent', 'Unknown'),
            'referer': headers.get('referer', 'Unknown'),
            'body_preview': body[:200] + "..." if len(body) > 200 else body
        }
        
        return context
    
    def _log_critical_error(self, status_code: int, parsed_http: Dict[str, Any], 
                           packet_info: Dict[str, Any], ai_analysis: Dict[str, str]) -> None:
        """Log critical HTTP errors to a file for later analysis."""
        try:
            import os
            log_dir = "http_error_logs"
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = os.path.join(log_dir, f"http_error_{status_code}_{timestamp}.json")
            
            log_data = {
                "timestamp": datetime.now().isoformat(),
                "status_code": status_code,
                "status_message": parsed_http.get('status_message', ''),
                "source": f"{packet_info['src']}:{packet_info['sport']}",
                "destination": f"{packet_info['dst']}:{packet_info['dport']}",
                "headers": parsed_http.get('headers', {}),
                "body": parsed_http.get('body', ''),
                "ai_analysis": ai_analysis
            }
            
            with open(log_file, 'w') as f:
                json.dump(log_data, f, indent=2)
            
            print(f"📝 Critical error logged to: {log_file}")
            
        except Exception as e:
            print(f"⚠️  Failed to log error: {e}")

    def packet_callback(self, packet) -> None:
        """Callback function to process captured packets."""
        try:
            if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
                return
            
            packet_info = {
                'src': packet[IP].src if packet.haslayer(IP) else 'Unknown',
                'dst': packet[IP].dst if packet.haslayer(IP) else 'Unknown',
                'sport': packet[TCP].sport,
                'dport': packet[TCP].dport,
            }
            
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                payload = packet[Raw].load.decode('latin1', errors='ignore')
            
            if not any(keyword in payload for keyword in ['HTTP/', 'GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ']):
                return
            
            self.packet_count += 1
            parsed_http = self._parse_http_headers(payload)
            formatted_output = self._format_output(packet_info, parsed_http)
            print(formatted_output)
            
            # Analyze HTTP status codes for errors
            self._analyze_http_status(parsed_http, packet_info)
            
        except Exception as e:
            if not self._handle_error(e, f"Processing packet #{self.packet_count + 1}"):
                raise  # Re-raise to stop sniffing
    
    def start_sniffing(self) -> None:
        """Start the packet sniffing process with improved interrupt handling."""
        print(f"🚀 Starting AI-Enhanced HTTP Packet Sniffer...")
        print(f"📡 Interface: {self.interface}")
        print(f"🔌 Port: {self.port}")
        print(f"🎯 Filter: tcp port {self.port}")
        print(f"🤖 AI Analysis: {'Enabled' if self.enable_ai else 'Disabled'}")
        print(f"🔄 Auto-restart: {'Enabled' if self.auto_restart else 'Disabled'}")
        print(f"⚠️  Error Threshold: HTTP {self.error_threshold}+")
        print(f"🔍 Monitor Mode: {'Errors Only' if self.monitor_errors_only else 'All HTTP Traffic'}")
        print(f"📝 Error Logging: {'Enabled' if self.log_errors else 'Disabled'}")
        print("Press Ctrl+C to stop\n")
        
        while not self.stop_sniffing:
            try:
                print(f"🔄 Starting sniffing session...")
                
                # Use timeout parameter to make sniff more responsive to interrupts
                sniff(
                    iface=self.interface,
                    filter=f"tcp port {self.port}",
                    prn=self.packet_callback,
                    store=0,
                    timeout=1,  # 1 second timeout to check stop condition
                    stop_filter=self._stop_condition
                )
                
                # If we're here and stop_sniffing is True, it's a normal exit
                if self.stop_sniffing:
                    break
                    
                # If we're here without stop_sniffing, continue the loop
                # (timeout reached, but no stop signal)
                
            except KeyboardInterrupt:
                print(f"\n👋 Keyboard interrupt received. Stopping...")
                self.stop_sniffing = True
                break
                
            except Exception as e:
                if not self._handle_error(e, "Packet sniffing"):
                    print(f"\n❌ Sniffer stopped due to unrecoverable error.")
                    break
                else:
                    if self.stop_sniffing:
                        break
                    print(f"⏳ Restarting in 3 seconds...")
                    for i in range(3):
                        if self.stop_sniffing:
                            break
                        time.sleep(1)
                    continue
        
        # Final statistics
        print(f"\n📊 Final Statistics:")
        print(f"   • Total HTTP packets: {self.packet_count}")
        print(f"   • HTTP errors detected: {self.http_error_count}")
        print(f"   • System errors handled: {self.error_count}")
        print(f"👋 Sniffer stopped gracefully.")
    
    def start_sniffing_threaded(self) -> None:
        """Start sniffing in a separate thread for better control."""
        def sniff_worker():
            try:
                while not self.stop_sniffing:
                    try:
                        sniff(
                            iface=self.interface,
                            filter=f"tcp port {self.port}",
                            prn=self.packet_callback,
                            store=0,
                            timeout=1,
                            stop_filter=self._stop_condition
                        )
                        
                        if self.stop_sniffing:
                            break
                            
                    except Exception as e:
                        if not self._handle_error(e, "Packet sniffing"):
                            break
                        if not self.stop_sniffing:
                            time.sleep(1)
                            
            except Exception as e:
                print(f"Critical error in sniffing thread: {e}")
            finally:
                print(f"\n🔌 Sniffing thread terminated.")
        
        # Start sniffing thread
        self.sniff_thread = threading.Thread(target=sniff_worker, daemon=True)
        self.sniff_thread.start()
        
        try:
            # Main thread waits for interrupt
            while not self.stop_sniffing and self.sniff_thread.is_alive():
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            print(f"\n👋 Keyboard interrupt received. Stopping...")
            self.stop_sniffing = True
            
        # Wait for thread to finish
        if self.sniff_thread.is_alive():
            print("⏳ Waiting for sniffing thread to stop...")
            self.sniff_thread.join(timeout=5)
            
        # Final statistics
        print(f"\n📊 Final Statistics:")
        print(f"   • Total HTTP packets: {self.packet_count}")
        print(f"   • HTTP errors detected: {self.http_error_count}")
        print(f"   • System errors handled: {self.error_count}")
        print(f"👋 Sniffer stopped gracefully.")


def main():
    """Main function with enhanced command line argument parsing."""
    parser = argparse.ArgumentParser(description="AI-Enhanced HTTP Packet Sniffer with Ollama Integration")
    parser.add_argument('-p', '--port', type=int, default=3001,
                       help='Port to monitor (default: 3001)')
    parser.add_argument('-i', '--interface', type=str, default=None,
                       help='Network interface to use (default: auto-detect)')
    parser.add_argument('--list-interfaces', action='store_true',
                       help='List available network interfaces and exit')
    parser.add_argument('--disable-ai', action='store_true',
                       help='Disable AI error analysis')
    parser.add_argument('--no-auto-restart', action='store_true',
                       help='Disable automatic restart on errors')
    parser.add_argument('--ollama-model', type=str, default='gemma2',
                       help='Ollama model to use for analysis (default: gemma2)')
    parser.add_argument('--monitor-errors-only', action='store_true',
                       help='Only display HTTP error responses (4xx and 5xx)')
    parser.add_argument('--error-threshold', type=int, default=400,
                       help='Minimum status code to trigger error analysis (default: 400)')
    parser.add_argument('--log-errors', action='store_true',
                       help='Log critical HTTP errors to files')
    parser.add_argument('--threaded', action='store_true',
                       help='Use threaded mode for better interrupt handling')
    
    args = parser.parse_args()
    
    if args.list_interfaces:
        print("Available network interfaces:")
        for i, iface in enumerate(get_if_list(), 1):
            print(f"  {i}. {iface}")
        return
    
    try:
        sniffer = EnhancedHTTPPacketSniffer(
            port=args.port,
            interface=args.interface,
            enable_ai=not args.disable_ai,
            auto_restart=not args.no_auto_restart
        )
        
        if not args.disable_ai:
            sniffer.ai_analyzer.model_name = args.ollama_model
        
        # Set additional options
        sniffer.monitor_errors_only = args.monitor_errors_only
        sniffer.error_threshold = args.error_threshold
        sniffer.log_errors = args.log_errors
        
        # Choose sniffing mode
        if args.threaded:
            print("🧵 Using threaded mode for better interrupt handling")
            sniffer.start_sniffing_threaded()
        else:
            sniffer.start_sniffing()
        
    except Exception as e:
        print(f"❌ Failed to start sniffer: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()