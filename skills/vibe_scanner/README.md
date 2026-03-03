# 🔍 VibeScanner Skill for OpenClaw

A friendly security scanning skill for OpenClaw that checks your workspace for security issues and provides risk assessments with helpful tips.

## 🚀 Installation

1. Clone this repository into your OpenClaw skills directory: 📥

```bash
git clone https://github.com/your-organization/vibe_guard.git
cp -r vibe_guard/skills/vibe_scanner ~/.openclaw/skills/
```

2. Make the scan script executable: ⚙️

```bash
chmod +x ~/.openclaw/skills/vibe_scanner/vibe-scan
```

3. Test the installation: 🧪

```bash
~/.openclaw/skills/vibe_scanner/vibe-scan
```

## 🎮 Usage

Once installed, you can trigger the scan in your OpenClaw chat by sending:

```
/vibe-scan
```

This will run a security scan and report back the results with a friendly summary and helpful tips.

## 📱 Telegram Integration

To enable Telegram notifications, you need to:

1. Install the companion script: 📲

```bash
cp vibe_guard/telegram_notifier.py ~/.openclaw/
```

2. Set your Telegram credentials as environment variables: 🔑

```bash
export TELEGRAM_BOT_TOKEN="your_bot_token"
export TELEGRAM_CHAT_ID="your_chat_id"
```

3. Run the notifier: 🚀

```bash
python3 ~/.openclaw/telegram_notifier.py
```

## ✨ Features

- 🔓 **Permission Check**: Detects world-writable files that could be security risks
- 🔒 **Secret Protection**: Identifies exposed environment files (.env) that might leak credentials
- 🐙 **Git Safety**: Checks for git configuration issues that could expose sensitive info
- 🚦 **Simple Status**: Provides an easy-to-understand risk assessment: 
  - 🔴 High Risk - Needs immediate attention!
  - 🟡 Medium Risk - Should be addressed soon
  - 🟢 Low Risk - Looking good!
- 💾 **JSON Reports**: Saves detailed results for further analysis
- 💡 **Fix Suggestions**: Provides tips on how to fix each issue