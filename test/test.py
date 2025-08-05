"""
Professional Network Packet Sniffer
Captures and analyzes HTTP traffic on specified ports with formatted output.
"""

import sys
import json
import re
from datetime import datetime
from typing import Optional, Dict, Any
from scapy.all import sniff, TCP, Raw, get_if_list, IP
import argparse


class HTTPPacketSniffer:
    """Professional HTTP packet sniffer with formatted output."""
    
    def __init__(self, port: int = 3001, interface: Optional[str] = None):
        self.port = port
        self.interface = interface or self._get_default_interface()
        self.packet_count = 0
        
    def _get_default_interface(self) -> str:
        """Get the default network interface."""
        interfaces = get_if_list()
        if not interfaces:
            raise RuntimeError("No network interfaces found")
        
        # Try to find loopback interface first
        for iface in interfaces:
            if "loopback" in iface.lower() or "lo" in iface.lower():
                return iface
        
        # Return first available interface
        return interfaces[0]
    
    def _parse_http_headers(self, payload: str) -> Dict[str, Any]:
        """Parse HTTP headers from payload."""
        lines = payload.split('\r\n')
        if not lines:
            return {}
        
        # Parse request/response line
        first_line = lines[0]
        headers = {}
        body = ""
        
        # Determine if it's a request or response
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
        
        # Display important headers
        if parsed_http['headers']:
            output.append("Headers:")
            for key, value in parsed_http['headers'].items():
                # Truncate very long values
                display_value = value[:100] + "..." if len(value) > 100 else value
                output.append(f"  {key.title()}: {display_value}")
            output.append("")
        
        # Display body if present and not too large
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
    
    def packet_callback(self, packet) -> None:
        """Callback function to process captured packets."""
        try:
            if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
                return
            
            # Extract packet information
            packet_info = {
                'src': packet[IP].src if packet.haslayer(IP) else 'Unknown',
                'dst': packet[IP].dst if packet.haslayer(IP) else 'Unknown',
                'sport': packet[TCP].sport,
                'dport': packet[TCP].dport,
            }
            
            # Decode payload
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                payload = packet[Raw].load.decode('latin1', errors='ignore')
            
            # Check if it's HTTP traffic
            if not any(keyword in payload for keyword in ['HTTP/', 'GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ']):
                return
            
            self.packet_count += 1
            
            # Parse HTTP content
            parsed_http = self._parse_http_headers(payload)
            
            # Format and print output
            formatted_output = self._format_output(packet_info, parsed_http)
            print(formatted_output)
            
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def start_sniffing(self) -> None:
        """Start the packet sniffing process."""
        print(f"Starting HTTP packet sniffer...")
        print(f"Interface: {self.interface}")
        print(f"Port: {self.port}")
        print(f"Filter: tcp port {self.port}")
        print("Press Ctrl+C to stop\n")
        
        try:
            sniff(
                iface=self.interface,
                filter=f"tcp port {self.port}",
                prn=self.packet_callback,
                store=0
            )
        except KeyboardInterrupt:
            print(f"\nStopping sniffer... Captured {self.packet_count} HTTP packets.")
        except Exception as e:
            print(f"Error during sniffing: {e}")


def main():
    """Main function with command line argument parsing."""
    parser = argparse.ArgumentParser(description="Professional HTTP Packet Sniffer")
    parser.add_argument('-p', '--port', type=int, default=3001,
                       help='Port to monitor (default: 3001)')
    parser.add_argument('-i', '--interface', type=str, default=None,
                       help='Network interface to use (default: auto-detect)')
    parser.add_argument('--list-interfaces', action='store_true',
                       help='List available network interfaces and exit')
    
    args = parser.parse_args()
    
    if args.list_interfaces:
        print("Available network interfaces:")
        for i, iface in enumerate(get_if_list(), 1):
            print(f"  {i}. {iface}")
        return
    
    try:
        sniffer = HTTPPacketSniffer(port=args.port, interface=args.interface)
        sniffer.start_sniffing()
    except Exception as e:
        print(f"Failed to start sniffer: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()