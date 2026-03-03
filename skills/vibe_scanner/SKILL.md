# 🛡️ VibeScanner Security Skill

This friendly skill runs a security scan on your workspace, checking for file permission issues, exposed environment files, and other security concerns - all with helpful tips!

## 🎮 Usage

Simply use the command `/vibe-scan` to trigger a security scan of your workspace.

## 🚦 Response Format

The scan returns one of three friendly status indicators:

- 🔴 **High Risk** - Yikes! Critical security issues detected that need fixing ASAP!
- 🟡 **Medium Risk** - Hmm... Some potential security concerns that should be addressed soon.
- 🟢 **Low Risk** - Awesome! Your workspace looks secure and well-configured.

## 🔍 What It Checks

The skill looks for:
- 🔓 Overly permissive file permissions (world-writable files that anyone could modify)
- 🔑 Exposed environment files (.env files that might contain secrets or API keys)
- 🐙 Git config issues (like hardcoded credentials)

## 💡 Helpful Tips

For each issue found, the skill provides:
- Simple explanation of what's wrong
- Suggested commands to fix the problem
- Best practices to prevent similar issues

## 📱 Telegram Integration

Get security alerts wherever you are! Results can be sent directly to Telegram by using the companion script:

```bash
python3 telegram_notifier.py
```

You'll get a nicely formatted message with emojis and fix suggestions right on your phone!