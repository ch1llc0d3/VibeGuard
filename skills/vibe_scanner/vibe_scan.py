#!/usr/bin/env python3
"""
VibeScanner - A security scanner for workspace environments
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
                    issues.append(f"World-writable file: {filepath}")
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
                env_files.append(filepath)
                
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
                    issues.append("Git config may contain credentials")
    except Exception:
        pass
        
    return issues

def main():
    workspace_dir = os.environ.get('WORKSPACE_DIR', '/home/node/.openclaw/workspace')
    
    results = {
        'timestamp': datetime.now().isoformat(),
        'permission_issues': check_file_permissions(workspace_dir),
        'env_files': check_env_files(workspace_dir),
        'git_issues': check_git_config(workspace_dir)
    }
    
    # Determine risk level
    risk_level = "🟢 Low Risk"  # Default
    
    if results['permission_issues']:
        risk_level = "🔴 High Risk"
    elif results['env_files'] or results['git_issues']:
        risk_level = "🟡 Medium Risk"
        
    results['risk_level'] = risk_level
    
    # Print results
    print(f"VibeGuard Security Scan Results - {risk_level}")
    print("-" * 50)
    
    if results['permission_issues']:
        print("\nPermission Issues:")
        for issue in results['permission_issues']:
            print(f"- {issue}")
            
    if results['env_files']:
        print("\nPotentially Exposed Environment Files:")
        for env_file in results['env_files']:
            print(f"- {env_file}")
            
    if results['git_issues']:
        print("\nGit Configuration Issues:")
        for issue in results['git_issues']:
            print(f"- {issue}")
            
    if not any([results['permission_issues'], results['env_files'], results['git_issues']]):
        print("\nNo security issues detected! Your workspace looks secure.")
    
    # Save results to JSON file
    output_file = os.path.join(workspace_dir, 'vibe_guard', 'last_scan.json')
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
        
    print(f"\nDetailed results saved to: {output_file}")
    
    return results

if __name__ == "__main__":
    main()