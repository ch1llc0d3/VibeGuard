# VibeScanner Security Skill

This skill runs a security scan on the workspace, checking for file permission issues and exposed environment files.

## Usage

Simply use the command `/vibe-scan` to trigger a security scan of your workspace.

## Response Format

The scan returns one of three status indicators:

- 🔴 High Risk - Critical security issues detected
- 🟡 Medium Risk - Potential security concerns found
- 🟢 Low Risk - No obvious security issues detected

## Implementation Details

The skill checks for:
- Overly permissive file permissions (world-writable files)
- Exposed environment files (.env files that may contain secrets)
- Other common security misconfigurations

## Integration

Results can be piped to the Telegram notification system by using the companion script `telegram_notifier.py`.