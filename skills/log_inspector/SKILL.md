# 📜 LogInspector Security Skill

This skill scans your system logs for suspicious activities, unauthorized access attempts, and security events that need attention.

## 🎮 Usage

Run the log inspection with:

```
/log-inspect
```

Optional parameters:
- `--days=N`: Inspect logs from the past N days (default: 3)
- `--level=warning|error|critical`: Set minimum log level to inspect (default: warning)
- `--services=ssh,sudo,auth`: Comma-separated list of services to check

## 🔍 What It Checks

LogInspector scans for:

- 🔑 Failed login attempts and brute force attacks
- 🔒 Privilege escalation via sudo
- 🚪 SSH connection patterns and unusual IPs
- 🔥 System crashes and kernel issues
- ⚠️ Service failures and restarts
- 🕵️ Unusual user activity or logon times

## 🚦 Risk Levels

- 🔴 **Critical Risk**: Multiple failed root logins, brute force attacks, or unusual admin activity
- 🟡 **Medium Risk**: Several failed logins, odd connection patterns, or service disruptions
- 🟢 **Low Risk**: Normal system activity, occasional failed logins (within acceptable limits)

## 💡 Automatic Analysis

The skill doesn't just show raw logs - it analyzes patterns to detect:

- Time-based patterns (activities happening at odd hours)
- IP-based patterns (connection attempts from unusual locations)
- User-based patterns (activities from rarely-used accounts)
- Service-based patterns (unexpected service failures or restarts)

## 📊 Visual Reports

Get easy-to-understand summaries that highlight the most important findings, with recommendations on what to check and how to strengthen your system security.