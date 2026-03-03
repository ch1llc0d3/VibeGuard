#!/usr/bin/env python3
"""
VibeScanner - A friendly security scanner for workspace environments
"""

import os
import stat
import json
import subprocess
from datetime import datetime

def check_file_permissions(directory):
    """Check for files with unsafe permissions"""
    issues = []
    
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                file_stat = os.stat(filepath)
                # Check for world-writable files (permission & 2)
                if file_stat.st_mode & stat.S_IWOTH:
                    issues.append({
                        "file": filepath,
                        "issue": "World-writable file",
                        "fix": f"chmod o-w \"{filepath}\""
                    })
            except Exception as e:
                pass  # Skip files we can't access
                
    return issues

def check_env_files(directory):
    """Look for potentially exposed .env files"""
    env_files = []
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.env') or file == '.env':
                filepath = os.path.join(root, file)
                env_files.append({
                    "file": filepath,
                    "issue": "Environment file with potential secrets",
                    "fix": f"Add {file} to .gitignore and ensure it's not tracked"
                })
                
    return env_files

def check_git_config(directory):
    """Check for git misconfigurations"""
    issues = []
    
    try:
        # Check if .git/config exists and is readable
        git_config = os.path.join(directory, '.git', 'config')
        if os.path.isfile(git_config):
            # Check for credentials in git config
            with open(git_config, 'r') as f:
                content = f.read()
                if 'password' in content.lower() or 'token' in content.lower():
                    issues.append({
                        "file": git_config,
                        "issue": "Git config may contain credentials",
                        "fix": "Remove tokens from git config and use git-credential-store instead"
                    })
    except Exception:
        pass
        
    return issues

def main():
    workspace_dir = os.environ.get('WORKSPACE_DIR', '/home/node/.openclaw/workspace')
    
    print("🔍 Scanning your workspace...")
    
    permission_issues = check_file_permissions(workspace_dir)
    env_files = check_env_files(workspace_dir)
    git_issues = check_git_config(workspace_dir)
    
    results = {
        'timestamp': datetime.now().isoformat(),
        'permission_issues': permission_issues,
        'env_files': env_files,
        'git_issues': git_issues
    }
    
    # Determine risk level
    risk_level = "🟢 Low Risk"  # Default
    
    if permission_issues:
        risk_level = "🔴 High Risk"
    elif env_files or git_issues:
        risk_level = "🟡 Medium Risk"
        
    results['risk_level'] = risk_level
    
    # Print results
    print(f"\n✨ VibeGuard Security Scan Results - {risk_level} ✨")
    print("=" * 50)
    
    if permission_issues:
        print("\n🔓 Permission Issues:")
        for issue in permission_issues:
            print(f"  • {issue['issue']}: {issue['file']}")
            print(f"    💡 Quick fix: {issue['fix']}")
            
    if env_files:
        print("\n🔑 Potentially Exposed Secrets:")
        for issue in env_files:
            print(f"  • {issue['issue']}: {issue['file']}")
            print(f"    💡 Quick fix: {issue['fix']}")
            
    if git_issues:
        print("\n🐙 Git Configuration Issues:")
        for issue in git_issues:
            print(f"  • {issue['issue']}: {issue['file']}")
            print(f"    💡 Quick fix: {issue['fix']}")
    
    # Save detailed JSON
    results_for_json = {
        'timestamp': datetime.now().isoformat(),
        'permission_issues': [f"{i['issue']}: {i['file']}" for i in permission_issues],
        'env_files': [f"{i['file']}" for i in env_files],
        'git_issues': [f"{i['issue']}: {i['file']}" for i in git_issues],
        'risk_level': risk_level
    }
            
    if not any([permission_issues, env_files, git_issues]):
        print("\n🎉 No security issues detected! Your workspace looks secure.")
        print("   Keep up the good work! Remember to scan regularly.")
    else:
        # General remediation tips
        print("\n🔧 General Recommendations:")
        if permission_issues:
            print("  • Review file permissions regularly")
            print("  • Use 'chmod go-w' to remove world-writable permissions")
            
        if env_files:
            print("  • Always add .env files to .gitignore")
            print("  • Consider using a secrets manager for production")
            
        if git_issues:
            print("  • Use git-credential-store for credentials")
            print("  • Regularly audit your git configs with 'git config --list'")
    
    # Save results to JSON file
    output_file = os.path.join(workspace_dir, 'vibe_guard', 'last_scan.json')
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(results_for_json, f, indent=2)
        
    print(f"\n💾 Detailed results saved to: {output_file}")
    print("\n🔄 Run this scan regularly to keep your workspace secure!")
    
    return results

if __name__ == "__main__":
    main()