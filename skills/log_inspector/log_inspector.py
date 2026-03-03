#!/usr/bin/env python3
"""
LogInspector - Analyze system logs for security issues and suspicious activity
"""

import os
import re
import json
import argparse
import subprocess
from datetime import datetime, timedelta
from collections import Counter, defaultdict

class LogInspector:
    def __init__(self):
        self.findings = {
            "failed_logins": [],
            "sudo_usage": [],
            "unusual_ips": [],
            "service_failures": [],
            "system_issues": [],
            "suspicious_activities": []
        }
        self.stats = {
            "total_events": 0,
            "failed_logins": 0,
            "sudo_attempts": 0,
            "unique_ips": set(),
            "service_issues": 0,
            "critical_events": 0
        }
        self.risk_level = "🟢 Low Risk"

    def parse_logs(self, days=3, level="warning", services=None):
        """Parse system logs for security events"""
        print(f"🔍 Scanning logs from the past {days} days...")
        
        if services is None:
            services = ["auth", "sudo", "sshd", "system"]
        
        # Get log content
        since_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        
        # Different commands based on system type
        try:
            # Try journalctl first (systemd-based systems)
            log_command = f"journalctl --since='{since_date}' -p {level}..emerg"
            if services:
                service_args = " ".join([f"_SYSTEMD_UNIT={s}.service" for s in services])
                log_command += f" {service_args}"
                
            log_output = subprocess.check_output(log_command, shell=True, text=True)
        except:
            # Fall back to traditional log files
            log_files = [
                "/var/log/auth.log", 
                "/var/log/secure",
                "/var/log/syslog",
                "/var/log/messages"
            ]
            log_output = ""
            for log_file in log_files:
                if os.path.exists(log_file):
                    try:
                        # Use grep to filter by date and common security patterns
                        grep_cmd = f"grep -i -E '(error|fail|denied|invalid|warning|authentication)' {log_file} | grep -i -E '({since_date}|{(datetime.now() - timedelta(days=days-1)).strftime('%b %d')})'"
                        output = subprocess.check_output(grep_cmd, shell=True, text=True)
                        log_output += output + "\n"
                    except:
                        # Continue even if one file fails
                        pass
        
        # Process the logs
        self._analyze_logs(log_output)
        self._determine_risk_level()
        
        return self.findings, self.stats, self.risk_level

    def _analyze_logs(self, log_content):
        """Analyze log content and categorize issues"""
        lines = log_content.splitlines()
        self.stats["total_events"] = len(lines)
        
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        user_pattern = r'user[=\s:]+([a-zA-Z0-9_.-]+)'
        
        ip_counter = Counter()
        user_counter = Counter()
        
        for line in lines:
            # Skip empty lines
            if not line.strip():
                continue
                
            # Extract IPs
            ips = re.findall(ip_pattern, line)
            for ip in ips:
                self.stats["unique_ips"].add(ip)
                ip_counter[ip] += 1
            
            # Extract usernames
            user_match = re.search(user_pattern, line, re.IGNORECASE)
            if user_match:
                username = user_match.group(1)
                user_counter[username] += 1
            
            # Categorize the log entry
            lower_line = line.lower()
            
            # Failed logins
            if any(term in lower_line for term in ["failed password", "authentication failure", "invalid user"]):
                self.findings["failed_logins"].append(line)
                self.stats["failed_logins"] += 1
                
            # Sudo usage
            elif "sudo" in lower_line and any(term in lower_line for term in ["command not allowed", "failed", "incorrect password"]):
                self.findings["sudo_usage"].append(line)
                self.stats["sudo_attempts"] += 1
                
            # Service failures
            elif any(term in lower_line for term in ["service", "daemon", "failed", "error", "stopped"]):
                self.findings["service_failures"].append(line)
                self.stats["service_issues"] += 1
                
            # System issues
            elif any(term in lower_line for term in ["kernel", "panic", "exception", "segfault", "crash"]):
                self.findings["system_issues"].append(line)
                self.stats["critical_events"] += 1
                
            # General suspicious activities
            elif any(term in lower_line for term in ["unusual", "suspicious", "violation", "attack", "exploit", "malware"]):
                self.findings["suspicious_activities"].append(line)
                self.stats["critical_events"] += 1
        
        # Find unusual IPs (those with few occurrences)
        common_ips = [ip for ip, count in ip_counter.most_common(3)]
        unusual_ips = [ip for ip in ip_counter if ip not in common_ips and ip_counter[ip] < 3]
        
        for line in lines:
            for ip in unusual_ips:
                if ip in line:
                    self.findings["unusual_ips"].append(line)
                    break

    def _determine_risk_level(self):
        """Determine the overall risk level based on findings"""
        # Critical conditions
        if (self.stats["failed_logins"] > 10 or 
            self.stats["critical_events"] >= 3 or
            len(self.findings["suspicious_activities"]) >= 2):
            self.risk_level = "🔴 High Risk"
            
        # Medium risk conditions    
        elif (self.stats["failed_logins"] >= 5 or
              self.stats["sudo_attempts"] >= 3 or
              self.stats["service_issues"] >= 5 or
              len(self.findings["unusual_ips"]) >= 3):
            self.risk_level = "🟡 Medium Risk"
        
        # Everything else is low risk
        else:
            self.risk_level = "🟢 Low Risk"
            
    def generate_report(self):
        """Generate a human-friendly report with recommendations"""
        report = []
        
        # Header
        report.append(f"📜 LogInspector Security Report - {self.risk_level}")
        report.append("=" * 60)
        report.append(f"📊 Summary: Analyzed {self.stats['total_events']} log events")
        report.append("")
        
        # Key statistics
        report.append("🔑 Key Findings:")
        report.append(f"  • Failed logins: {self.stats['failed_logins']}")
        report.append(f"  • Sudo issues: {self.stats['sudo_attempts']}")
        report.append(f"  • Unique IPs: {len(self.stats['unique_ips'])}")
        report.append(f"  • Service issues: {self.stats['service_issues']}")
        report.append(f"  • Critical events: {self.stats['critical_events']}")
        report.append("")
        
        # Detailed findings with limited examples
        categories = [
            ("Failed Login Attempts", "failed_logins", "🔒"),
            ("Sudo Usage Issues", "sudo_usage", "👑"),
            ("Connections from Unusual IPs", "unusual_ips", "🌐"),
            ("Service Failures", "service_failures", "🔧"),
            ("System Issues", "system_issues", "💻"),
            ("Suspicious Activities", "suspicious_activities", "⚠️")
        ]
        
        for title, key, emoji in categories:
            if self.findings[key]:
                report.append(f"{emoji} {title}:")
                # Show up to 5 examples
                for i, entry in enumerate(self.findings[key][:5]):
                    report.append(f"  • {entry}")
                if len(self.findings[key]) > 5:
                    report.append(f"  • ... and {len(self.findings[key]) - 5} more similar events")
                report.append("")
        
        # Recommendations based on findings
        report.append("💡 Recommendations:")
        
        if self.stats["failed_logins"] > 0:
            report.append("  • Review login security:")
            report.append("    - Consider fail2ban to block repeated login attempts")
            report.append("    - Disable password authentication for SSH, use key-based auth")
            
        if self.stats["sudo_attempts"] > 0:
            report.append("  • Check sudo configuration:")
            report.append("    - Audit sudo privileges with 'sudo -l'")
            report.append("    - Ensure proper sudoers file configuration")
            
        if self.findings["unusual_ips"]:
            report.append("  • Monitor unusual connections:")
            report.append("    - Set up IP geolocation monitoring")
            report.append("    - Consider restricting SSH access to known IP ranges")
            
        if self.stats["service_issues"] > 0:
            report.append("  • Investigate service issues:")
            report.append("    - Check system resources and performance")
            report.append("    - Review service configurations for errors")
            
        if self.risk_level == "🔴 High Risk":
            report.append("  • URGENT: Consider security incident response:")
            report.append("    - Temporarily restrict remote access")
            report.append("    - Change all critical passwords")
            report.append("    - Run full system malware scan")
        
        return "\n".join(report)

def main():
    """Main function to run log inspection"""
    parser = argparse.ArgumentParser(description='Inspect system logs for security issues')
    parser.add_argument('--days', type=int, default=3, help='Number of days of logs to inspect')
    parser.add_argument('--level', default='warning', help='Minimum log level (info, warning, error, etc)')
    parser.add_argument('--services', help='Comma-separated list of services to check')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    
    args = parser.parse_args()
    
    # Convert services to list if provided
    services = args.services.split(',') if args.services else None
    
    # Run the inspection
    inspector = LogInspector()
    findings, stats, risk_level = inspector.parse_logs(
        days=args.days, 
        level=args.level,
        services=services
    )
    
    if args.json:
        # Convert sets to lists for JSON serialization
        stats_json = stats.copy()
        stats_json["unique_ips"] = list(stats["unique_ips"])
        
        output = {
            "risk_level": risk_level,
            "stats": stats_json,
            "findings": findings
        }
        print(json.dumps(output, indent=2))
    else:
        # Print human-readable report
        print(inspector.generate_report())
    
    # Return exit code based on risk level
    if "High Risk" in risk_level:
        return 2
    elif "Medium Risk" in risk_level:
        return 1
    else:
        return 0

if __name__ == "__main__":
    exit(main())