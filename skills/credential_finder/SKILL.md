# 🔑 CredentialFinder Security Skill

This skill scans your codebase and configuration files for exposed credentials, API keys, tokens, and secrets that could be compromised.

## 🎮 Usage

Scan for exposed credentials with:

```
/cred-scan [directory]
```

Optional parameters:
- `--thorough`: Scan more deeply, including archives and git history
- `--show-matches`: Show the actual credential values (WARNING: sensitive!)
- `--format=json`: Output in JSON format
- `--githistory`: Also scan git commit history for leaked credentials

## 🔍 What It Detects

CredentialFinder hunts for exposed:

- 🗝️ **API Keys**: AWS, Google, Azure, GitHub, etc.
- 🔐 **Passwords**: Hard-coded in config files, source code, scripts
- 🔒 **Private Keys**: SSH, PGP, SSL certificates
- 🎟️ **Access Tokens**: OAuth, JWT, session tokens
- 💳 **Connection Strings**: Database URLs with credentials
- 🏦 **Crypto Wallets**: Private keys, seed phrases
- 📧 **Email Credentials**: SMTP passwords in configs

## 🚦 Risk Levels

- 🔴 **Critical Risk**: Production credentials, private keys, or high-value API keys exposed
- 🟡 **Medium Risk**: Development/test credentials or keys with limited access
- 🟢 **Low Risk**: No exposed credentials or only sample/placeholder values

## 🛡️ Prevention Tips

The skill provides guidance on secure credential management:

- Using environment variables instead of hardcoding
- Setting up secret management services
- Implementing proper .gitignore rules
- Using encryption for configuration files

## 🧹 Remediation Steps

If credentials are found, the tool provides step-by-step remediation:

1. Immediate steps to secure exposed credentials
2. How to revoke and rotate compromised keys
3. Safe ways to store credentials going forward
4. How to check if credentials were previously exposed

## ⚠️ Important Note

This tool focuses on finding *accidentally exposed* credentials. Always handle the results with care and never use this tool to search repositories you don't own.