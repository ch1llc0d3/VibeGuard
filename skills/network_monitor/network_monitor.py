#!/usr/bin/env python3
"""
NetworkMonitor - Scan network connections for security issues
"""

import os
import re
import json
import socket
import argparse
import subprocess
import ipaddress
from datetime import datetime
from collections import defaultdict

class NetworkMonitor:
    def __init__(self):
        self.findings = {
            "listening_ports": [],
            "suspicious_connections": [],
            "unusual_processes": [],
            "insecure_services": []
        }
        self.stats = {
            "total_connections": 0,
            "listening_ports": 0,
            "established_connections": 0,
            "suspicious_count": 0,
            "high_risk_count": 0,
            "medium_risk_count": 0
        }
        self.risk_level = "🟢 Low Risk"
        
        # Initialize data structures
        self._init_data()
    
    def _init_data(self):
        """Initialize reference data for network analysis"""
        
        # Well-known high-risk ports
        self.high_risk_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            111: "RPC",
            135: "MSRPC",
            139: "NetBIOS",
            445: "SMB",
            1433: "MSSQL",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            27017: "MongoDB"
        }
        
        # Insecure plain-text protocols
        self.insecure_protocols = {
            21: "FTP (use SFTP/FTPS instead)",
            23: "Telnet (use SSH instead)",
            25: "SMTP without TLS (use SMTPS/port 465 instead)",
            37: "Time Protocol (use NTP/port 123 instead)",
            43: "WHOIS (unencrypted)",
            69: "TFTP (use SFTP instead)",
            79: "Finger",
            80: "HTTP (use HTTPS/port 443 instead)",
            109: "POP2 (outdated, insecure)",
            110: "POP3 without TLS (use POP3S/port 995 instead)",
            111: "RPC (often exploited)",
            119: "NNTP without TLS (use NNTPS instead)",
            143: "IMAP without TLS (use IMAPS/port 993 instead)",
            161: "SNMP v1/v2 (use SNMPv3 with encryption)",
            512: "rexec (unencrypted remote execution)",
            513: "rlogin (unencrypted remote login)",
            514: "rsyslog (unencrypted logging)",
            873: "rsync without SSH tunnel",
            1521: "Oracle DB listener (should be firewalled)",
            2049: "NFS (unencrypted file system)",
            3306: "MySQL without TLS",
            5432: "PostgreSQL without TLS"
        }
        
        # Private IP ranges
        self.private_ip_ranges = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8"
        ]
        
        # Known suspicious process patterns
        self.suspicious_process_patterns = [
            r"nc\s+-[el]",          # netcat in listening mode
            r"bash\s+-i",           # interactive bash shells
            r"socat.*tcp-listen",   # socat listeners
            r".*[P]roxychain",      # proxychains
            r"miner|monero|xmr",    # crypto miners
            r"tor\d*$",             # tor processes
            r"ngrok",               # ngrok tunnels
            r"reverse[_-]shell"     # reverse shells
        ]
        
        # Services that shouldn't normally be exposed
        self.sensitive_services = {
            1433: "SQL Server",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            9200: "Elasticsearch",
            11211: "Memcached",
            2375: "Docker API",
            2379: "etcd",
            8086: "InfluxDB",
            5984: "CouchDB",
            9000: "Portainer"
        }
    
    def scan_network(self, connections=True, listening=True, suspicious=False, process_info=True):
        """Scan for network connections and security issues"""
        print(f"🔍 Scanning network connections and ports...")
        start_time = datetime.now()
        
        # Get all connections
        connections_data = self._get_network_connections(process_info)
        
        # Process the data
        self._analyze_connections(connections_data, connections, listening, suspicious)
        
        # Determine risk level
        self._determine_risk_level()
        
        duration = datetime.now() - start_time
        print(f"✅ Scan complete! Analyzed {self.stats['total_connections']} connections in {duration.total_seconds():.2f} seconds")
        
        return self.findings, self.stats, self.risk_level
    
    def _get_network_connections(self, process_info):
        """Get all network connections using platform-specific commands"""
        connections = []
        
        try:
            # Try to use netstat or ss command
            if self._command_exists("ss"):
                # Modern Linux systems
                cmd = ["ss", "-tupan"]
                if process_info:
                    cmd.append("-p")
            elif self._command_exists("netstat"):
                # Older systems or macOS
                cmd = ["netstat", "-tunapl"] if process_info else ["netstat", "-tuna"]
            else:
                print("⚠️ Neither ss nor netstat found, using limited Python socket info")
                return self._get_connections_fallback()
            
            # Run the command
            result = subprocess.run(cmd, capture_output=True, text=True)
            output = result.stdout
            
            # Parse the output
            connections = self._parse_connection_output(output, process_info)
            
        except Exception as e:
            print(f"⚠️ Error getting network connections: {str(e)}")
            connections = self._get_connections_fallback()
        
        return connections
    
    def _get_connections_fallback(self):
        """Fallback method to get basic connection info using Python's socket module"""
        connections = []
        
        # This is a very limited fallback that just checks listening ports
        try:
            for port in range(1, 1025):  # Check well-known ports
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex(('127.0.0.1', port))
                if result == 0:
                    # Port is open
                    connections.append({
                        "local_address": f"127.0.0.1:{port}",
                        "remote_address": "*:*",
                        "state": "LISTEN",
                        "protocol": "tcp",
                        "process": "unknown",
                        "pid": None
                    })
                sock.close()
        except:
            pass
            
        return connections
    
    def _parse_connection_output(self, output, process_info):
        """Parse netstat or ss output into structured data"""
        connections = []
        lines = output.splitlines()
        
        # Skip header lines
        data_lines = []
        for line in lines:
            if ("Local Address" in line or "LISTEN" in line or "ESTABLISHED" in line or
                "Proto" in line or "State" in line):
                continue
            if line.strip():
                data_lines.append(line)
        
        for line in data_lines:
            try:
                # Different parsing for ss and netstat
                if "ss -" in output:
                    # ss output format
                    parsed = self._parse_ss_line(line, process_info)
                else:
                    # netstat output format
                    parsed = self._parse_netstat_line(line, process_info)
                
                if parsed:
                    connections.append(parsed)
            except Exception as e:
                # Skip lines that can't be parsed
                continue
        
        return connections
    
    def _parse_ss_line(self, line, process_info):
        """Parse a line from ss command output"""
        parts = line.split()
        
        if len(parts) < 5:
            return None
            
        protocol = parts[0].lower()
        state = parts[1].upper()
        
        # Parse local and remote addresses
        local = parts[4]
        remote = parts[5] if len(parts) > 5 else "*:*"
        
        # Parse process info if available
        process = "unknown"
        pid = None
        if process_info and "users:" in line:
            match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
            if match:
                process = match.group(1)
                pid = int(match.group(2))
        
        return {
            "protocol": protocol,
            "state": state,
            "local_address": local,
            "remote_address": remote,
            "process": process,
            "pid": pid
        }
    
    def _parse_netstat_line(self, line, process_info):
        """Parse a line from netstat command output"""
        parts = line.split()
        
        if len(parts) < 5:
            return None
            
        # Handle different formats between OS versions
        if parts[0].startswith('tcp') or parts[0].startswith('udp'):
            protocol = parts[0].lower()
            local = parts[3]
            remote = parts[4]
            state = parts[5] if len(parts) > 5 else ""
            
            # Process info is at different positions depending on the OS
            process = "unknown"
            pid = None
            if process_info and len(parts) > 6:
                if '/' in parts[-1]:
                    # Linux format: process/pid
                    process_part = parts[-1]
                    if '/' in process_part:
                        process = process_part.split('/')[-1]
                        pid_part = process_part.split('/')[0]
                        if pid_part.isdigit():
                            pid = int(pid_part)
                elif 'LISTENING' in line and len(parts) > 8:
                    # macOS/BSD format
                    process = parts[-1]
                    pid_part = parts[-2]
                    if pid_part.isdigit():
                        pid = int(pid_part)
        else:
            # Unknown format
            return None
        
        return {
            "protocol": protocol,
            "state": state,
            "local_address": local,
            "remote_address": remote,
            "process": process,
            "pid": pid
        }
    
    def _command_exists(self, cmd):
        """Check if a command exists on the system"""
        try:
            subprocess.run(["which", cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except:
            return False
    
    def _analyze_connections(self, connections, show_all, show_listening, show_suspicious):
        """Analyze network connections for security issues"""
        self.stats["total_connections"] = len(connections)
        
        # Process each connection
        for conn in connections:
            protocol = conn.get("protocol", "")
            state = conn.get("state", "").upper()
            local_addr = conn.get("local_address", "")
            remote_addr = conn.get("remote_address", "")
            process = conn.get("process", "unknown")
            
            # Count by state
            if state == "LISTEN" or state == "LISTENING":
                self.stats["listening_ports"] += 1
            elif state == "ESTABLISHED":
                self.stats["established_connections"] += 1
            
            # Parse addresses
            local_ip, local_port = self._parse_address(local_addr)
            remote_ip, remote_port = self._parse_address(remote_addr)
            
            # Check for listening ports
            if state in ("LISTEN", "LISTENING") and show_listening:
                risk_level = "low"
                
                # Check if this is a high-risk port
                port_info = ""
                if local_port in self.high_risk_ports:
                    risk_level = "medium"
                    port_info = f"({self.high_risk_ports[local_port]})"
                
                # Check if this is an insecure protocol
                if local_port in self.insecure_protocols:
                    risk_level = "high"
                    port_info = f"({self.insecure_protocols[local_port]})"
                    
                    # Add to insecure services
                    self.findings["insecure_services"].append({
                        "port": local_port,
                        "protocol": protocol,
                        "service": self.insecure_protocols[local_port],
                        "process": process,
                        "address": local_ip,
                        "risk": risk_level
                    })
                
                # Check if this is a database or sensitive service
                if local_port in self.sensitive_services:
                    is_exposed = not self._is_private_ip(local_ip)
                    if is_exposed or local_ip == "0.0.0.0":
                        risk_level = "high"
                        port_info = f"({self.sensitive_services[local_port]} EXPOSED)"
                        
                        # Add to insecure services
                        self.findings["insecure_services"].append({
                            "port": local_port,
                            "protocol": protocol,
                            "service": self.sensitive_services[local_port],
                            "process": process,
                            "address": local_ip,
                            "risk": "high"
                        })
                
                # Add to listening ports findings
                self.findings["listening_ports"].append({
                    "protocol": protocol,
                    "port": local_port,
                    "address": local_ip,
                    "process": process,
                    "info": port_info,
                    "risk": risk_level
                })
                
                # Update risk counters
                if risk_level == "high":
                    self.stats["high_risk_count"] += 1
                elif risk_level == "medium":
                    self.stats["medium_risk_count"] += 1
            
            # Check for suspicious established connections
            if state == "ESTABLISHED" and (show_all or show_suspicious):
                # Skip if both addresses are private
                if self._is_private_ip(remote_ip) and self._is_private_ip(local_ip) and not show_all:
                    continue
                
                risk_level = "low"
                suspicious_reason = None
                
                # Check suspicious ports in remote connections
                if remote_port in self.high_risk_ports:
                    suspicious_reason = f"Connected to {self.high_risk_ports[remote_port]} service"
                    risk_level = "medium"
                
                # Check if connected to sensitive services
                if remote_port in self.sensitive_services:
                    suspicious_reason = f"Connected to {self.sensitive_services[remote_port]}"
                    risk_level = "medium"
                
                # Check suspicious process patterns
                for pattern in self.suspicious_process_patterns:
                    if re.search(pattern, process, re.IGNORECASE):
                        suspicious_reason = f"Suspicious process: {process}"
                        risk_level = "high"
                        break
                
                # Only add suspicious connections or all if requested
                if suspicious_reason or show_all:
                    conn_info = {
                        "protocol": protocol,
                        "local": f"{local_ip}:{local_port}",
                        "remote": f"{remote_ip}:{remote_port}",
                        "process": process,
                        "risk": risk_level
                    }
                    
                    if suspicious_reason:
                        conn_info["reason"] = suspicious_reason
                        self.stats["suspicious_count"] += 1
                    
                    self.findings["suspicious_connections"].append(conn_info)
                    
                    # Update risk counters
                    if risk_level == "high":
                        self.stats["high_risk_count"] += 1
                    elif risk_level == "medium":
                        self.stats["medium_risk_count"] += 1
        
        # Process unusual process combinations
        self._check_process_combinations(connections)
    
    def _parse_address(self, addr_str):
        """Parse an address string into IP and port"""
        if not addr_str or addr_str == "*" or addr_str == "*:*":
            return "0.0.0.0", 0
            
        try:
            if ":" in addr_str:
                # IPv4 address
                parts = addr_str.rsplit(":", 1)
                if len(parts) == 2:
                    ip = parts[0].replace("*", "0.0.0.0")
                    port = int(parts[1]) if parts[1].isdigit() else 0
                    return ip, port
            
            # Handle IPv6 addresses
            if "[" in addr_str and "]" in addr_str:
                # IPv6
                ip_part = addr_str[addr_str.find("[")+1:addr_str.find("]")]
                port_part = addr_str[addr_str.find("]")+2:] if ":" in addr_str[addr_str.find("]"):] else "0"
                return ip_part, int(port_part) if port_part.isdigit() else 0
        except:
            pass
            
        # Default fallback
        return addr_str, 0
    
    def _is_private_ip(self, ip):
        """Check if an IP address is private"""
        if ip == "0.0.0.0" or ip == "127.0.0.1" or ip == "::1" or ip == "*" or not ip:
            return True
            
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if it's a private address
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except:
            # If we can't parse it, assume it's not private
            return False
    
    def _check_process_combinations(self, connections):
        """Check for unusual process and port combinations"""
        # Map processes to ports they use
        process_ports = defaultdict(set)
        
        for conn in connections:
            process = conn.get("process", "unknown")
            if process == "unknown":
                continue
                
            local_addr = conn.get("local_address", "")
            _, port = self._parse_address(local_addr)
            
            if port > 0:
                process_ports[process].add(port)
        
        # Check for unusual combinations
        for process, ports in process_ports.items():
            # Web servers on unusual ports
            if any(web_server in process.lower() for web_server in ["httpd", "nginx", "apache", "lighttpd"]):
                for port in ports:
                    if port not in [80, 443, 8080, 8443] and port < 1024:
                        self.findings["unusual_processes"].append({
                            "process": process,
                            "port": port,
                            "reason": f"Web server on unusual port {port}",
                            "risk": "medium"
                        })
                        self.stats["medium_risk_count"] += 1
            
            # Database servers listening on all interfaces
            if any(db in process.lower() for db in ["mysql", "postgres", "mongodb", "redis"]):
                for conn in connections:
                    if conn.get("process") == process and conn.get("state", "") in ["LISTEN", "LISTENING"]:
                        local_ip, _ = self._parse_address(conn.get("local_address", ""))
                        if local_ip == "0.0.0.0":
                            self.findings["unusual_processes"].append({
                                "process": process,
                                "address": "0.0.0.0",
                                "reason": f"Database listening on all interfaces",
                                "risk": "high"
                            })
                            self.stats["high_risk_count"] += 1
    
    def _determine_risk_level(self):
        """Determine the overall risk level based on findings"""
        if self.stats["high_risk_count"] > 0:
            self.risk_level = "🔴 High Risk"
        elif self.stats["medium_risk_count"] > 0:
            self.risk_level = "🟡 Medium Risk"
        else:
            self.risk_level = "🟢 Low Risk"
    
    def generate_report(self):
        """Generate a human-friendly report with recommendations"""
        report = []
        
        # Header
        report.append(f"🌐 Network Security Report - {self.risk_level}")
        report.append("=" * 60)
        report.append(f"📊 Summary: Analyzed {self.stats['total_connections']} network connections")
        report.append("")
        
        # Key statistics
        report.append("🔑 Key Findings:")
        report.append(f"  • Listening ports: {self.stats['listening_ports']}")
        report.append(f"  • Established connections: {self.stats['established_connections']}")
        report.append(f"  • Suspicious connections: {self.stats['suspicious_count']}")
        report.append(f"  • High risk issues: {self.stats['high_risk_count']}")
        report.append(f"  • Medium risk issues: {self.stats['medium_risk_count']}")
        report.append("")
        
        # Insecure services
        if self.findings["insecure_services"]:
            report.append("⚠️ INSECURE SERVICES EXPOSED")
            report.append("These services are using insecure protocols or configurations:\n")
            
            for service in self.findings["insecure_services"]:
                risk_icon = "🔴" if service["risk"] == "high" else "🟡"
                report.append(f"{risk_icon} {service['service']} on port {service['port']}/{service['protocol']}")
                report.append(f"  • Process: {service['process']}")
                report.append(f"  • Listening on: {service['address']}")
                
                # Add specific recommendations
                if "EXPOSED" in service.get("service", ""):
                    report.append(f"  • 💡 FIX: Restrict this database to localhost or internal IPs only")
                    report.append(f"      sudo ufw allow from 192.168.1.0/24 to any port {service['port']}")
                else:
                    secure_alt = service.get("service", "").split("(use ")[1].split(")")[0] if "(use " in service.get("service", "") else "a secure alternative"
                    report.append(f"  • 💡 FIX: Replace with {secure_alt}")
                
                report.append("")
        
        # Listening ports
        high_risk_ports = [p for p in self.findings["listening_ports"] if p["risk"] == "high"]
        medium_risk_ports = [p for p in self.findings["listening_ports"] if p["risk"] == "medium"]
        
        if high_risk_ports:
            report.append("🔴 HIGH RISK OPEN PORTS:")
            for port in high_risk_ports:
                report.append(f"  • Port {port['port']}/{port['protocol']} {port['info']}")
                report.append(f"    Process: {port['process']}")
                report.append(f"    Address: {port['address']}")
                report.append("")
        
        if medium_risk_ports:
            report.append("🟡 MEDIUM RISK PORTS:")
            for port in medium_risk_ports[:5]:  # Limit to 5
                report.append(f"  • Port {port['port']}/{port['protocol']} {port['info']}")
                report.append(f"    Process: {port['process']}")
            
            if len(medium_risk_ports) > 5:
                report.append(f"  • ... and {len(medium_risk_ports) - 5} more medium risk ports")
            
            report.append("")
        
        # Suspicious connections
        high_risk_conns = [c for c in self.findings["suspicious_connections"] if c["risk"] == "high"]
        
        if high_risk_conns:
            report.append("🔴 SUSPICIOUS CONNECTIONS:")
            for conn in high_risk_conns:
                report.append(f"  • {conn.get('protocol', 'tcp').upper()} {conn['local']} → {conn['remote']}")
                report.append(f"    Process: {conn['process']}")
                if "reason" in conn:
                    report.append(f"    Reason: {conn['reason']}")
                report.append("")
        
        # Unusual process activities
        if self.findings["unusual_processes"]:
            report.append("⚠️ UNUSUAL PROCESS ACTIVITY:")
            for proc in self.findings["unusual_processes"]:
                risk_icon = "🔴" if proc["risk"] == "high" else "🟡"
                report.append(f"{risk_icon} {proc['reason']}")
                report.append(f"  • Process: {proc['process']}")
                if "port" in proc:
                    report.append(f"  • Port: {proc['port']}")
                if "address" in proc:
                    report.append(f"  • Address: {proc['address']}")
                report.append("")
        
        # Recommendations section
        report.append("💡 Security Recommendations:")
        
        if self.stats["high_risk_count"] > 0:
            # High risk recommendations
            report.append("\n🔒 URGENT SECURITY ACTIONS:")
            report.append("  1. Close or restrict access to insecure services")
            report.append("  2. Replace plaintext protocols with encrypted alternatives")
            report.append("  3. Verify all listening services are authorized")
            report.append("  4. Investigate suspicious processes and connections")
            
            # Add firewall recommendations
            report.append("\n🛡️ FIREWALL RECOMMENDATIONS:")
            report.append("  • Enable and configure your firewall:")
            
            # UFW (Ubuntu/Debian)
            report.append("    ```")
            report.append("    # Enable firewall")
            report.append("    sudo ufw enable")
            report.append("")
            report.append("    # Default policies")
            report.append("    sudo ufw default deny incoming")
            report.append("    sudo ufw default allow outgoing")
            report.append("")
            
            # Add rules for legitimate services
            safe_ports = [p for p in self.findings["listening_ports"] if p["risk"] == "low"]
            for port in safe_ports[:3]:
                report.append(f"    # Allow {port.get('info', 'service')} on port {port['port']}")
                report.append(f"    sudo ufw allow {port['port']}/{port['protocol']}")
            
            report.append("    ```")
        
        elif self.stats["medium_risk_count"] > 0:
            # Medium risk recommendations
            report.append("\n🛡️ SECURITY IMPROVEMENTS NEEDED:")
            report.append("  • Review all listening services:")
            report.append("    - Disable unnecessary services")
            report.append("    - Restrict access to internal networks where possible")
            report.append("    - Update configurations to use secure protocols")
            
            report.append("\n  • Check for updated versions of running services")
            report.append("  • Consider implementing network segmentation")
        
        else:
            # Low risk / best practices
            report.append("\n✅ YOUR NETWORK LOOKS SECURE!")
            report.append("  • Continue good security practices:")
            report.append("    - Regular security scans")
            report.append("    - Keep services updated")
            report.append("    - Monitor for unusual connections")
        
        # Monitoring suggestions
        report.append("\n🔍 ONGOING MONITORING:")
        report.append("  • Set up regular network scans:")
        report.append("    ```")
        report.append("    # Add to your crontab (weekly scan)")
        report.append("    0 0 * * 0 /path/to/net-scan --suspicious --json > /var/log/netscan.json")
        report.append("    ```")
        
        # Common tools
        report.append("\n🧰 USEFUL SECURITY TOOLS:")
        report.append("  • 'netstat -tulpn' - Check listening ports")
        report.append("  • 'ss -tupln' - Modern alternative to netstat")
        report.append("  • 'lsof -i' - List open network files")
        report.append("  • 'nmap -sT -p 1-1000 localhost' - Scan your own ports")
        report.append("  • 'ufw status' - Check firewall status")
        
        return "\n".join(report)

def main():
    """Main function to run network monitoring"""
    parser = argparse.ArgumentParser(description='Scan network connections for security issues')
    parser.add_argument('--connections', action='store_true', help='Show all connections (default: false)')
    parser.add_argument('--listening', action='store_true', help='Show listening ports (default: true)')
    parser.add_argument('--suspicious', action='store_true', help='Focus on suspicious connections')
    parser.add_argument('--process', action='store_true', help='Include process information')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--monitor', help='Run continuous monitoring (e.g., 30m, 1h)')
    
    args = parser.parse_args()
    
    # Default behavior: show listening ports if nothing specific is requested
    show_listening = args.listening or not (args.connections or args.suspicious)
    
    # Run the scan
    monitor = NetworkMonitor()
    findings, stats, risk_level = monitor.scan_network(
        connections=args.connections or args.suspicious,
        listening=show_listening,
        suspicious=args.suspicious,
        process_info=args.process
    )
    
    if args.json:
        output = {
            "risk_level": risk_level,
            "stats": stats,
            "findings": findings,
            "timestamp": datetime.now().isoformat()
        }
        print(json.dumps(output, indent=2))
    else:
        # Print human-readable report
        print(monitor.generate_report())
    
    # Return exit code based on risk level
    if "High Risk" in risk_level:
        return 2
    elif "Medium Risk" in risk_level:
        return 1
    else:
        return 0

if __name__ == "__main__":
    exit(main())