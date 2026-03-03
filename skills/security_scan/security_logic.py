#!/usr/bin/env python3
"""
VibeGuard Security Scanner Logic
--------------------------------
Simulates a security scanner that returns status information as a JSON report.
"""

import json
import random
import time
import argparse
import sys
from datetime import datetime, timedelta

def generate_random_ip():
    """Generate a random IP address."""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def generate_cve_id():
    """Generate a random CVE ID."""
    year = random.randint(2018, 2026)
    number = random.randint(1000, 99999)
    return f"CVE-{year}-{number}"

def generate_service():
    """Generate a random service name."""
    services = [
        "nginx", "apache", "mysql", "postgresql", "redis", 
        "mongodb", "elasticsearch", "node.js", "react-app",
        "api-gateway", "auth-service", "payment-processor"
    ]
    return random.choice(services)

def generate_port():
    """Generate a random port number."""
    common_ports = [80, 443, 22, 21, 25, 3306, 5432, 27017, 6379, 9200, 8080, 8443]
    return random.choice(common_ports + [random.randint(1024, 65535)])

def generate_vulnerability():
    """Generate a random vulnerability."""
    types = [
        "Outdated Software", 
        "Weak Password", 
        "Missing Patch", 
        "SQL Injection", 
        "XSS Vulnerability",
        "CSRF Vulnerability", 
        "Insecure Direct Object References", 
        "Misconfiguration",
        "Unencrypted Data", 
        "Default Credentials"
    ]
    
    severities = {
        "Critical": {"score": random.uniform(9.0, 10.0), "status": "danger"},
        "High": {"score": random.uniform(7.0, 8.9), "status": "danger"},
        "Medium": {"score": random.uniform(4.0, 6.9), "status": "warning"},
        "Low": {"score": random.uniform(0.1, 3.9), "status": "warning"},
        "Informational": {"score": 0.0, "status": "secure"}
    }
    
    severity_key = random.choice(list(severities.keys()))
    severity_data = severities[severity_key]
    
    return {
        "id": generate_cve_id(),
        "type": random.choice(types),
        "severity": severity_key,
        "score": round(severity_data["score"], 1),
        "status": severity_data["status"],
        "service": generate_service(),
        "port": generate_port(),
        "discovered": (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat(),
        "description": f"A {severity_key.lower()} severity {random.choice(types).lower()} vulnerability was found in {generate_service()}."
    }

def generate_scan_report(num_vulnerabilities=None):
    """Generate a simulated security scan report."""
    
    # If not specified, generate a random number of vulnerabilities (0 to 12)
    if num_vulnerabilities is None:
        num_vulnerabilities = random.randint(0, 12)
    
    vulnerabilities = [generate_vulnerability() for _ in range(num_vulnerabilities)]
    
    # Determine overall status based on highest severity
    overall_status = "secure"
    if any(v["status"] == "danger" for v in vulnerabilities):
        overall_status = "danger"
    elif any(v["status"] == "warning" for v in vulnerabilities):
        overall_status = "warning"
    
    # Count by status
    status_counts = {
        "danger": len([v for v in vulnerabilities if v["status"] == "danger"]),
        "warning": len([v for v in vulnerabilities if v["status"] == "warning"]),
        "secure": len([v for v in vulnerabilities if v["status"] == "secure"])
    }
    
    # Get the highest severity vulnerability for the summary
    highest_severity = None
    if vulnerabilities:
        highest_severity = max(vulnerabilities, key=lambda x: x["score"])
    
    # Create the scan report
    report = {
        "scanId": f"scan-{int(time.time())}",
        "timestamp": datetime.now().isoformat(),
        "duration": f"{random.randint(10, 300)} seconds",
        "systemStatus": overall_status,
        "statusCounts": status_counts,
        "scanSummary": {
            "totalServices": random.randint(5, 20),
            "scannedIps": random.randint(1, 10),
            "openPorts": random.randint(3, 15),
            "vulnerabilitiesFound": num_vulnerabilities
        },
        "highestSeverity": highest_severity,
        "vulnerabilities": vulnerabilities
    }
    
    return report

def main():
    parser = argparse.ArgumentParser(description="Generate a security scan report")
    parser.add_argument("--vulns", type=int, help="Number of vulnerabilities to generate")
    parser.add_argument("--status", choices=["danger", "warning", "secure"], help="Force a specific status")
    parser.add_argument("--output", help="Output file (defaults to stdout)")
    args = parser.parse_args()
    
    # Generate the report
    report = generate_scan_report(args.vulns)
    
    # Force status if specified
    if args.status:
        report["systemStatus"] = args.status
    
    # Output the report
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
    else:
        print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()