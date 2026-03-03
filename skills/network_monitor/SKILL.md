# 🌐 NetworkMonitor Security Skill

This skill monitors your network connections, open ports, and suspicious traffic patterns to identify potential security issues.

## 🎮 Usage

Monitor your network with:

```
/net-scan [options]
```

Optional parameters:
- `--connections`: List all active network connections
- `--listening`: Show only listening ports
- `--suspicious`: Focus on potentially suspicious connections
- `--process`: Include process information for each connection
- `--json`: Output in JSON format for integration

## 🔍 What It Monitors

NetworkMonitor checks for:

- 🔌 **Open Ports**: Identifies services listening on network ports
- 🔄 **Unusual Connections**: Connections to unusual or suspicious IPs
- 🌍 **Geo-Location**: Flags connections to high-risk countries
- ⏱️ **Connection Age**: Identifies long-lived connections that might indicate backdoors
- 📊 **Traffic Patterns**: Unusual data transfer patterns
- 🔒 **Insecure Services**: Plain-text protocols and known insecure services
- 🚪 **Unauthorized Servers**: Web/FTP/SSH servers that shouldn't be running

## 🚦 Risk Levels

- 🔴 **Critical Risk**: Likely malicious connections, backdoors, or unauthorized servers
- 🟡 **Medium Risk**: Suspicious connections or unnecessarily exposed services
- 🟢 **Low Risk**: Normal network activity with properly secured connections

## 💡 Security Recommendations

The skill provides tailored recommendations based on findings:

- How to close unnecessary ports
- Securing required services
- Firewall rule suggestions
- Connection filtering options
- Process monitoring tips

## 📊 Visual Output

Get clear visualizations of your network activity:

- Connection maps showing inbound/outbound traffic
- Port usage summary
- Process-to-connection mapping
- Risk assessment summary

## 🔄 Continuous Monitoring

Run this skill regularly or set up scheduled monitoring:

```
/net-scan --monitor=30m
```

This will alert you when new suspicious connections are established.