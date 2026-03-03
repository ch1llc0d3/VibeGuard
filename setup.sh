#!/bin/bash
# 🛡️ VibeGuard Setup Script

echo "✨ VibeGuard Installation Script ✨"
echo "=================================="
echo 

# Default installation locations
DEFAULT_SKILL_DIR="$HOME/.openclaw/skills"
DEFAULT_WORKSPACE_DIR="$HOME/.openclaw/workspace"

# Create directories if they don't exist
mkdir -p "$DEFAULT_SKILL_DIR"
mkdir -p "$DEFAULT_WORKSPACE_DIR"

# Install VibeScanner skill
echo "🔍 Installing VibeScanner skill..."
cp -r skills/vibe_scanner "$DEFAULT_SKILL_DIR/"
chmod +x "$DEFAULT_SKILL_DIR/vibe_scanner/vibe-scan"
echo "✅ Skill installed to $DEFAULT_SKILL_DIR/vibe_scanner"

# Install Telegram notifier
echo "📱 Installing Telegram notifier..."
cp telegram_notifier.py "$DEFAULT_WORKSPACE_DIR/"
chmod +x "$DEFAULT_WORKSPACE_DIR/telegram_notifier.py"
echo "✅ Notifier installed to $DEFAULT_WORKSPACE_DIR/telegram_notifier.py"

# Setup .env template
if [ ! -f "$DEFAULT_WORKSPACE_DIR/.env" ]; then
    echo "🔑 Creating template .env file..."
    cat > "$DEFAULT_WORKSPACE_DIR/.env.template" << EOF
# 🛡️ VibeGuard Configuration
# Rename this file to .env and fill in your API keys

# 🤖 API Keys
GEMINI_API_KEY=your_gemini_api_key_here
OPENROUTER_API_KEY=your_openrouter_api_key_here

# 📱 Telegram Configuration
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_ceo_chat_id
EOF
    echo "✅ Template created at $DEFAULT_WORKSPACE_DIR/.env.template"
    echo "   Rename to .env and add your actual API keys"
fi

# Run initial scan
echo
echo "🔍 Would you like to run an initial security scan? (y/n)"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    echo "🚀 Running initial scan..."
    "$DEFAULT_SKILL_DIR/vibe_scanner/vibe-scan"
    
    echo
    echo "📱 Would you like to send the results to Telegram? (y/n)"
    read -r send_telegram
    if [[ "$send_telegram" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ]; then
            echo "❌ Telegram credentials not found in environment."
            echo "   Please set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID first."
        else
            python3 "$DEFAULT_WORKSPACE_DIR/telegram_notifier.py"
        fi
    fi
fi

echo
echo "🎉 VibeGuard installation complete! 🎉"
echo "===================================="
echo
echo "🔍 To run a security scan: /vibe-scan"
echo
echo "📚 For more information, see README.md"
echo
echo "🔄 Remember to run scans regularly to keep your workspace secure!"