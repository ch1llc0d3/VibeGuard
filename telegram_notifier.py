#!/usr/bin/env python3
"""
Telegram Notifier for VibeScanner
Sends security scan results to a Telegram chat using Bot API
"""

import os
import json
import argparse
import requests
import subprocess
from datetime import datetime

def send_telegram_message(bot_token, chat_id, message):
    """Send a message to Telegram"""
    api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    
    payload = {
        'chat_id': chat_id,
        'text': message,
        'parse_mode': 'Markdown'
    }
    
    try:
        response = requests.post(api_url, json=payload)
        if response.status_code == 200:
            print("Message sent successfully to Telegram")
            return True
        else:
            print(f"Failed to send message. Status code: {response.status_code}")
            print(response.text)
            return False
    except Exception as e:
        print(f"Error sending message: {e}")
        return False

def run_vibe_scan():
    """Run the vibe-scan tool and get results"""
    try:
        # Try to find the vibe-scan script in different locations
        scan_locations = [
            '/home/node/.openclaw/workspace/vibe_guard/skills/vibe_scanner/vibe-scan',
            '/home/node/.openclaw/skills/vibe_scanner/vibe-scan',
            '/root/.openclaw/skills/vibe_scanner/vibe-scan'
        ]
        
        scan_script = None
        for location in scan_locations:
            if os.path.isfile(location) and os.access(location, os.X_OK):
                scan_script = location
                break
        
        if not scan_script:
            return {
                'risk_level': '🔴 High Risk',
                'error': 'Could not find the vibe-scan script'
            }
            
        # Run the scan script
        result = subprocess.run([scan_script], capture_output=True, text=True)
        
        # Check if we have JSON output
        workspace_dir = os.environ.get('WORKSPACE_DIR', '/home/node/.openclaw/workspace')
        json_output = os.path.join(workspace_dir, 'vibe_guard', 'last_scan.json')
        
        if os.path.isfile(json_output):
            with open(json_output, 'r') as f:
                return json.load(f)
        else:
            # Parse output directly
            output = result.stdout
            risk_level = '🟢 Low Risk'  # Default
            
            if '🔴 High Risk' in output:
                risk_level = '🔴 High Risk'
            elif '🟡 Medium Risk' in output:
                risk_level = '🟡 Medium Risk'
            
            return {
                'risk_level': risk_level,
                'raw_output': output
            }
    except Exception as e:
        return {
            'risk_level': '🔴 High Risk',
            'error': f'Error running scan: {str(e)}'
        }

def format_message(scan_results):
    """Format scan results for Telegram in a friendly way with remediation tips"""
    timestamp = scan_results.get('timestamp', datetime.now().isoformat())
    risk_level = scan_results.get('risk_level', '❓ Unknown')
    
    # Convert ISO timestamp to something more readable
    try:
        dt = datetime.fromisoformat(timestamp)
        friendly_time = dt.strftime("%b %d, %Y at %H:%M")
    except:
        friendly_time = timestamp
    
    message = f"*✨ VibeGuard Security Scan Results ✨*\n\n"
    message += f"*Status:* {risk_level}\n"
    message += f"*Scanned:* {friendly_time}\n\n"
    
    if 'error' in scan_results:
        message += f"*⚠️ Error:*\n{scan_results['error']}\n\n"
        message += "_Try running the scan again or check permissions._"
        return message
        
    if 'raw_output' in scan_results:
        # Just include the raw output if we couldn't parse JSON
        message += f"*Details:*\n```\n{scan_results['raw_output'][:3000]}```"
        return message
    
    # Format structured results with emojis and tips
    has_issues = False
    
    if scan_results.get('permission_issues'):
        has_issues = True
        message += "*🔓 Permission Issues:*\n"
        for issue in scan_results['permission_issues'][:5]:  # Limit to 5
            message += f"• {issue}\n"
        
        if len(scan_results['permission_issues']) > 5:
            message += f"• _...and {len(scan_results['permission_issues']) - 5} more issues_\n"
        
        message += "\n*💡 Quick Fix:*\n"
        message += "• Run `chmod go-w [file]` to remove world-writable permissions\n"
        message += "• Check who created these files and why permissions were set this way\n\n"
        
    if scan_results.get('env_files'):
        has_issues = True
        message += "*🔑 Exposed Environment Files:*\n"
        for env_file in scan_results['env_files'][:5]:  # Limit to 5
            message += f"• {env_file}\n"
        
        if len(scan_results['env_files']) > 5:
            message += f"• _...and {len(scan_results['env_files']) - 5} more files_\n"
        
        message += "\n*💡 Quick Fix:*\n"
        message += "• Add these files to `.gitignore`\n"
        message += "• Check if they're already committed to git with `git ls-files`\n"
        message += "• Consider a secrets manager for production environments\n\n"
        
    if scan_results.get('git_issues'):
        has_issues = True
        message += "*🐙 Git Configuration Issues:*\n"
        for issue in scan_results['git_issues']:
            message += f"• {issue}\n"
        
        message += "\n*💡 Quick Fix:*\n"
        message += "• Remove credentials from git config files\n"
        message += "• Use git credential store instead: `git config --global credential.helper store`\n\n"
    
    if not has_issues:
        message += "🎉 *All Clear!* No security issues detected.\n\n"
        message += "Your workspace looks secure and well-configured. Great job!\n"
        message += "_Remember to scan regularly as part of your security routine._"
    else:
        # Add summary section for issues
        message += "*📋 Next Steps:*\n"
        message += "1. Fix the issues identified above\n"
        message += "2. Run another scan to verify fixes\n"
        message += "3. Consider adding this scan to your CI/CD pipeline\n"
        message += "\n_Need help? Contact your security team or run `/vibe-scan --help`_"
    
    return message

def main():
    parser = argparse.ArgumentParser(description='Send VibeScanner results to Telegram')
    
    parser.add_argument('--bot-token', '-t', 
                        default=os.environ.get('TELEGRAM_BOT_TOKEN'),
                        help='Telegram Bot API token (or set TELEGRAM_BOT_TOKEN env var)')
    
    parser.add_argument('--chat-id', '-c',
                        default=os.environ.get('TELEGRAM_CHAT_ID'), 
                        help='Telegram chat ID to send to (or set TELEGRAM_CHAT_ID env var)')
    
    parser.add_argument('--message', '-m',
                        help='Custom message to send (otherwise will run vibe-scan)')
    
    parser.add_argument('--manual-risk', '-r',
                        choices=['high', 'medium', 'low'],
                        help='Manually set risk level for custom messages')
    
    args = parser.parse_args()
    
    # Validate required arguments
    if not args.bot_token:
        print("Error: Telegram bot token is required (use --bot-token or set TELEGRAM_BOT_TOKEN)")
        return 1
        
    if not args.chat_id:
        print("Error: Telegram chat ID is required (use --chat-id or set TELEGRAM_CHAT_ID)")
        return 1
    
    # Custom message or run vibe-scan
    if args.message:
        risk_emoji = {
            'high': '🔴',
            'medium': '🟡',
            'low': '🟢'
        }.get(args.manual_risk, '❓')
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'risk_level': f"{risk_emoji} {args.manual_risk.title() if args.manual_risk else 'Unknown'} Risk",
            'custom_message': args.message
        }
        
        message = f"*VibeGuard Security Alert*\n\n"
        message += f"*Status:* {results['risk_level']}\n"
        message += f"*Time:* {results['timestamp']}\n\n"
        message += f"{args.message}"
    else:
        # Run the security scan
        results = run_vibe_scan()
        message = format_message(results)
    
    # Send to Telegram
    send_telegram_message(args.bot_token, args.chat_id, message)
    
    # Return exit code based on risk level
    if '🔴 High Risk' in results['risk_level']:
        return 2
    elif '🟡 Medium Risk' in results['risk_level']:
        return 1
    else:
        return 0

if __name__ == "__main__":
    exit(main())