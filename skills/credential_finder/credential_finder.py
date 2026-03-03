#!/usr/bin/env python3
"""
CredentialFinder - Hunt for exposed credentials, API keys, and secrets
"""

import os
import re
import json
import argparse
import subprocess
from datetime import datetime
from collections import defaultdict, Counter

class CredentialFinder:
    def __init__(self):
        self.findings = defaultdict(list)
        self.stats = {
            "files_scanned": 0,
            "matches_found": 0,
            "high_risk_count": 0,
            "medium_risk_count": 0,
            "low_risk_count": 0,
            "skipped_files": 0,
            "skipped_dirs": 0
        }
        self.risk_level = "🟢 Low Risk"
        
        # Initialize patterns
        self._init_patterns()
        
    def _init_patterns(self):
        """Initialize regex patterns for credential detection"""
        
        # AWS
        self.patterns = {
            "aws_access_key": {
                "pattern": r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
                "context": r'(?:AKIA|aws_access|key_id|accesskey|access_key)',
                "confidence": "high",
                "severity": "high",
                "category": "aws",
                "description": "AWS Access Key",
                "remediation": "Rotate key in AWS IAM console and use AWS Secrets Manager"
            },
            "aws_secret_key": {
                "pattern": r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
                "context": r'(?:aws_secret|secret_key|secretkey|secret_access|aws_secret_access_key)',
                "confidence": "high",
                "severity": "high",
                "category": "aws",
                "description": "AWS Secret Key",
                "remediation": "Rotate key in AWS IAM console and use AWS Secrets Manager"
            },
            
            # Google
            "google_api_key": {
                "pattern": r'AIza[0-9A-Za-z-_]{35}',
                "confidence": "high",
                "severity": "high",
                "category": "google",
                "description": "Google API Key",
                "remediation": "Revoke in Google Cloud Console and create new restricted key"
            },
            "google_oauth": {
                "pattern": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
                "confidence": "high",
                "severity": "high",
                "category": "google",
                "description": "Google OAuth Client ID",
                "remediation": "Delete OAuth client in Google Cloud Console and create new one"
            },
            
            # GitHub
            "github_token": {
                "pattern": r'github_pat_[0-9a-zA-Z_]{82}',
                "confidence": "high",
                "severity": "high",
                "category": "github",
                "description": "GitHub Fine-grained PAT",
                "remediation": "Revoke immediately in GitHub Developer Settings > Personal Access Tokens"
            },
            "github_classic_token": {
                "pattern": r'ghp_[0-9a-zA-Z]{36}',
                "confidence": "high",
                "severity": "high",
                "category": "github",
                "description": "GitHub Classic PAT",
                "remediation": "Revoke immediately in GitHub Developer Settings > Personal Access Tokens"
            },
            
            # Generic API keys
            "generic_api_key": {
                "pattern": r'[a-zA-Z0-9_-]{32,64}',
                "context": r'(?:api[_\-]?key|api[_\-]?secret|client[_\-]?secret|access[_\-]?token|auth[_\-]?token)',
                "confidence": "medium",
                "severity": "medium",
                "category": "api",
                "description": "Generic API Key",
                "remediation": "Revoke and rotate this key with the service provider"
            },
            
            # Database URLs with credentials
            "db_url": {
                "pattern": r'(?:postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^/]+',
                "confidence": "high",
                "severity": "high",
                "category": "database",
                "description": "Database Connection String with Credentials",
                "remediation": "Move to environment variables or secure secret manager"
            },
            
            # Private Keys
            "private_key": {
                "pattern": r'-----BEGIN (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----',
                "confidence": "high",
                "severity": "critical",
                "category": "ssh",
                "description": "Private Key",
                "remediation": "Remove immediately, generate new key pair, and revoke old key"
            },
            
            # JWT Tokens
            "jwt_token": {
                "pattern": r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
                "confidence": "medium",
                "severity": "medium",
                "category": "jwt",
                "description": "JWT Token",
                "remediation": "Invalidate token on server side and implement proper token storage"
            },
            
            # Password patterns
            "password": {
                "pattern": r'(?:password|passwd|pwd)["\']?\s*(?::|=>|=|:=)\s*["\']([^"\']{8,})["\']',
                "confidence": "medium",
                "severity": "high",
                "category": "password",
                "description": "Hardcoded Password",
                "remediation": "Replace with environment variable or secure secret manager"
            },
            
            # Stripe API Keys
            "stripe_key": {
                "pattern": r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24}',
                "confidence": "high",
                "severity": "high",
                "category": "stripe",
                "description": "Stripe API Key",
                "remediation": "Revoke in Stripe Dashboard > Developers > API keys"
            },
            
            # Twilio API Keys
            "twilio_key": {
                "pattern": r'SK[0-9a-fA-F]{32}',
                "confidence": "high",
                "severity": "high",
                "category": "twilio",
                "description": "Twilio API Key",
                "remediation": "Revoke in Twilio Console > Settings > API Keys"
            },
            "twilio_secret": {
                "pattern": r'[0-9a-fA-F]{32}',
                "context": r'(?:twilio|account_?sid)',
                "confidence": "high",
                "severity": "high",
                "category": "twilio",
                "description": "Twilio Account Secret",
                "remediation": "Revoke in Twilio Console > Settings > API Keys"
            },
            
            # Slack Tokens
            "slack_token": {
                "pattern": r'xox[baprs]-[0-9a-zA-Z]{10,48}',
                "confidence": "high",
                "severity": "high",
                "category": "slack",
                "description": "Slack API Token",
                "remediation": "Revoke in Slack API Dashboard > Your Apps"
            },
            
            # Mailchimp API Key
            "mailchimp_key": {
                "pattern": r'[0-9a-f]{32}-us[0-9]{1,2}',
                "confidence": "high",
                "severity": "high",
                "category": "mailchimp",
                "description": "Mailchimp API Key",
                "remediation": "Revoke in Mailchimp Dashboard > Account > Extras > API keys"
            },
            
            # PayPal Braintree Access Token
            "paypal_token": {
                "pattern": r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
                "confidence": "high",
                "severity": "critical",
                "category": "paypal",
                "description": "PayPal/Braintree Access Token",
                "remediation": "Revoke immediately in PayPal Developer Dashboard"
            },
            
            # Mailgun API Key
            "mailgun_key": {
                "pattern": r'key-[0-9a-zA-Z]{32}',
                "confidence": "high",
                "severity": "high",
                "category": "mailgun",
                "description": "Mailgun API Key",
                "remediation": "Revoke in Mailgun Dashboard > API Security"
            },
            
            # Credential Files
            "credential_file": {
                "file_pattern": r'\.(?:key|pem|crt|credentials|p12|pkcs12|pfx|passwd|password|htpasswd)$',
                "confidence": "low",
                "severity": "medium",
                "category": "credential_file",
                "description": "Potential Credential File",
                "remediation": "Verify if file contains sensitive data and move to secure storage"
            },
        }
        
        # File patterns to always scan
        self.sensitive_file_patterns = [
            r'(?:config|conf|settings|env)\.(?:js|json|yml|yaml|xml|ini|properties|conf|cfg|env|py)$',
            r'\.env(?:\.|$)',
            r'credentials',
            r'secret',
            r'token',
            r'password',
            r'apikey',
            r'credential',
            r'\.npmrc$',
            r'\.pypirc$',
            r'\.netrc$',
            r'\.dockercfg$',
            r'\.aws/credentials$',
            r'\.ssh/config$'
        ]
        
        # Directories to skip
        self.skip_dirs = {
            'node_modules', 'vendor', 'bower_components', 'jspm_packages', 'packages',
            'target', 'dist', 'build', 'out', 'output', 'bin', 'obj', '.git', '.svn', 
            'venv', 'env', 'site-packages', '__pycache__', 'coverage', '.idea', '.vscode',
            '.pytest_cache', '.bundle'
        }
        
        # File extensions to skip
        self.skip_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.tiff', '.webp', '.svg',
            '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.flv', '.wmv', '.wave', '.ogg',
            '.zip', '.tar', '.gz', '.7z', '.rar', '.jar', '.war', '.ear', '.class', 
            '.dll', '.exe', '.so', '.dylib', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.ppt', '.pptx', '.ttf', '.woff', '.woff2', '.eot', '.pyc', '.pyo'
        }
        
        # Files to always skip
        self.skip_files = {
            'package-lock.json', 'yarn.lock', 'Gemfile.lock', 'composer.lock',
            '.gitkeep', '.gitattributes', 'LICENSE', 'README.md', 'CONTRIBUTING.md'
        }
        
        # Common false positives
        self.false_positive_patterns = [
            r'example',
            r'sample',
            r'placeholder',
            r'dummy',
            r'test',
            r'fake',
            r'mock',
            r'\<placeholder\>',
            r'your-key-here',
            r'xxx+',
            r'INSERT-KEY-HERE',
            r'CHANGE-ME'
        ]
        
    def scan_directory(self, directory, thorough=False, show_matches=False, git_history=False):
        """Scan a directory for credentials"""
        print(f"🔍 Scanning for credentials in: {directory}")
        start_time = datetime.now()
        
        # Convert to absolute path
        directory = os.path.abspath(directory)
        
        # Skip if directory doesn't exist
        if not os.path.exists(directory):
            print(f"❌ Directory does not exist: {directory}")
            return self.findings, self.stats, self.risk_level
        
        # Scan git history if requested
        if git_history and os.path.isdir(os.path.join(directory, '.git')):
            self._scan_git_history(directory, show_matches)
        
        # Walk through directory tree
        for root, dirs, files in os.walk(directory):
            # Skip directories that should be ignored
            dirs[:] = [d for d in dirs if d.lower() not in self.skip_dirs]
            
            # Scan each file
            for file in files:
                if file.lower() in self.skip_files:
                    self.stats["skipped_files"] += 1
                    continue
                    
                _, ext = os.path.splitext(file)
                if ext.lower() in self.skip_extensions and not thorough:
                    self.stats["skipped_files"] += 1
                    continue
                
                file_path = os.path.join(root, file)
                
                # Check if file matches sensitive patterns or we're doing a thorough scan
                is_sensitive = any(re.search(pattern, file, re.IGNORECASE) for pattern in self.sensitive_file_patterns)
                
                if is_sensitive or thorough:
                    self._scan_file(file_path, show_matches)
                    
        # Calculate duration
        duration = datetime.now() - start_time
        
        # Determine risk level
        self._determine_risk_level()
        
        print(f"✅ Scan complete! Processed {self.stats['files_scanned']} files in {duration.total_seconds():.2f} seconds")
        print(f"Found {self.stats['matches_found']} potential credentials")
        
        return self.findings, self.stats, self.risk_level
    
    def _scan_file(self, file_path, show_matches):
        """Scan a single file for credentials"""
        self.stats["files_scanned"] += 1
        
        try:
            # Skip large files
            if os.path.getsize(file_path) > 1 * 1024 * 1024:  # Skip files > 1MB
                self.stats["skipped_files"] += 1
                return
                
            # Check if file is a known credential file
            for pattern_name, pattern_info in self.patterns.items():
                if pattern_name == "credential_file" and "file_pattern" in pattern_info:
                    if re.search(pattern_info["file_pattern"], file_path, re.IGNORECASE):
                        self._add_finding(
                            file_path, 
                            pattern_name, 
                            file_path, 
                            "", 
                            pattern_info["confidence"], 
                            pattern_info["severity"],
                            pattern_info["category"],
                            pattern_info["description"],
                            pattern_info["remediation"],
                            show_matches
                        )
            
            # Read file content and scan for patterns
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # Skip if file appears empty
                if not content.strip():
                    return
                
                for pattern_name, pattern_info in self.patterns.items():
                    if "file_pattern" in pattern_info:
                        continue  # Skip file patterns, we already checked them
                        
                    regex = pattern_info["pattern"]
                    matches = re.findall(regex, content)
                    
                    # If context pattern is defined, check that too
                    if "context" in pattern_info and matches:
                        context_pattern = pattern_info["context"]
                        if not re.search(context_pattern, content, re.IGNORECASE):
                            continue  # Skip if context doesn't match
                    
                    for match in matches:
                        # Skip if it looks like a false positive
                        if any(re.search(fp, content, re.IGNORECASE) for fp in self.false_positive_patterns):
                            continue
                        
                        # Get line number and context
                        line_number, context = self._get_match_context(content, match)
                        
                        # Add finding
                        self._add_finding(
                            file_path,
                            pattern_name,
                            match,
                            context,
                            pattern_info["confidence"],
                            pattern_info["severity"],
                            pattern_info["category"],
                            pattern_info["description"],
                            pattern_info["remediation"],
                            show_matches
                        )
                        
        except Exception as e:
            # Skip files that can't be read
            self.stats["skipped_files"] += 1
    
    def _scan_git_history(self, directory, show_matches):
        """Scan git commit history for credentials"""
        try:
            # Check if git is available
            subprocess.run(['git', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            
            # Get list of all commits
            result = subprocess.run(
                ['git', '-C', directory, 'log', '--pretty=format:%H'],
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                check=True
            )
            
            commits = result.stdout.strip().split('\n')
            
            print(f"🕵️ Scanning git history ({len(commits)} commits)...")
            
            # Sample commits (take first, middle, last and a few random ones for efficiency)
            if len(commits) > 10:
                import random
                sample_size = min(10, len(commits))
                middle_idx = len(commits) // 2
                sampled_commits = [
                    commits[0],  # First commit
                    commits[middle_idx],  # Middle commit
                    commits[-1]  # Latest commit
                ]
                # Add some random commits
                sampled_commits.extend(random.sample(commits, sample_size - 3))
                commits = sampled_commits
            
            # Scan each commit
            for commit in commits:
                # Get commit diff
                result = subprocess.run(
                    ['git', '-C', directory, 'show', commit],
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    text=True
                )
                
                diff = result.stdout
                
                # Scan for credentials in the diff
                for pattern_name, pattern_info in self.patterns.items():
                    if "file_pattern" in pattern_info:
                        continue  # Skip file patterns
                        
                    regex = pattern_info["pattern"]
                    matches = re.findall(regex, diff)
                    
                    # If context pattern is defined, check that too
                    if "context" in pattern_info and matches:
                        context_pattern = pattern_info["context"]
                        if not re.search(context_pattern, diff, re.IGNORECASE):
                            continue  # Skip if context doesn't match
                    
                    for match in matches:
                        # Skip if it looks like a false positive
                        if any(re.search(fp, match, re.IGNORECASE) for fp in self.false_positive_patterns):
                            continue
                        
                        # Skip if match doesn't look like a real credential
                        if len(match) < 8:
                            continue
                        
                        # Add finding
                        self._add_finding(
                            f"Git commit: {commit[:8]}",
                            pattern_name,
                            match,
                            f"Found in git commit {commit[:8]}",
                            pattern_info["confidence"],
                            pattern_info["severity"],
                            pattern_info["category"],
                            pattern_info["description"],
                            pattern_info["remediation"] + " (from git history)",
                            show_matches
                        )
                        
        except Exception as e:
            print(f"⚠️ Could not scan git history: {str(e)}")
    
    def _add_finding(self, file_path, pattern_name, match, context, confidence, severity, category, description, remediation, show_matches):
        """Add a credential finding"""
        self.stats["matches_found"] += 1
        
        # Update risk counters
        if severity == "critical" or severity == "high":
            self.stats["high_risk_count"] += 1
        elif severity == "medium":
            self.stats["medium_risk_count"] += 1
        else:
            self.stats["low_risk_count"] += 1
        
        # Format the matched value for display
        display_match = match
        if not show_matches and isinstance(match, str) and len(match) > 8:
            # Hide most of the credential
            display_match = match[:4] + '*' * (len(match) - 8) + match[-4:]
        
        finding = {
            "file": file_path,
            "type": pattern_name,
            "match": display_match,
            "context": context,
            "confidence": confidence,
            "severity": severity,
            "category": category,
            "description": description,
            "remediation": remediation
        }
        
        self.findings[severity].append(finding)
    
    def _get_match_context(self, content, match):
        """Get the line number and context around a match"""
        lines = content.splitlines()
        line_number = None
        context = ""
        
        for i, line in enumerate(lines):
            if match in line:
                line_number = i + 1
                
                # Get surrounding context (3 lines before and after)
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                
                context_lines = []
                for j in range(start, end):
                    if j == i:
                        # Highlight the line with the match
                        context_lines.append(f"> {lines[j]}")
                    else:
                        context_lines.append(f"  {lines[j]}")
                
                context = "\n".join(context_lines)
                break
                
        return line_number, context
    
    def _determine_risk_level(self):
        """Determine the overall risk level based on findings"""
        if self.stats["high_risk_count"] > 0:
            self.risk_level = "🔴 High Risk"
        elif self.stats["medium_risk_count"] > 0:
            self.risk_level = "🟡 Medium Risk"
        else:
            self.risk_level = "🟢 Low Risk"
    
    def generate_report(self):
        """Generate a human-friendly report with recommendations"""
        report = []
        
        # Header
        report.append(f"🔑 CredentialFinder Report - {self.risk_level}")
        report.append("=" * 60)
        report.append(f"📊 Summary: Scanned {self.stats['files_scanned']} files, found {self.stats['matches_found']} potential credentials")
        report.append("")
        
        # Key statistics
        report.append("📈 Risk Breakdown:")
        report.append(f"  • High risk issues: {self.stats['high_risk_count']}")
        report.append(f"  • Medium risk issues: {self.stats['medium_risk_count']}")
        report.append(f"  • Low risk issues: {self.stats['low_risk_count']}")
        report.append(f"  • Skipped files: {self.stats['skipped_files']}")
        report.append("")
        
        # Group findings by category
        findings_by_category = defaultdict(list)
        
        # Process critical and high severity findings first
        if self.findings.get("critical") or self.findings.get("high"):
            report.append("🚨 HIGH RISK CREDENTIALS FOUND")
            report.append("These require immediate attention!\n")
            
            for finding in self.findings.get("critical", []) + self.findings.get("high", []):
                category = finding["category"]
                findings_by_category[category].append(finding)
        
        # Process medium severity findings
        if self.findings.get("medium"):
            for finding in self.findings.get("medium", []):
                category = finding["category"]
                findings_by_category[category].append(finding)
                
        # Process low severity findings
        if self.findings.get("low"):
            for finding in self.findings.get("low", []):
                category = finding["category"]
                findings_by_category[category].append(finding)
        
        # Display findings by category
        if findings_by_category:
            for category, findings in findings_by_category.items():
                emoji = {
                    "aws": "☁️",
                    "google": "🌐",
                    "github": "🐙",
                    "api": "🔌",
                    "database": "🗄️",
                    "ssh": "🔐",
                    "jwt": "🎟️",
                    "password": "🔒",
                    "stripe": "💳",
                    "twilio": "📱",
                    "slack": "💬",
                    "mailchimp": "📧",
                    "paypal": "💰",
                    "mailgun": "📨",
                    "credential_file": "📄"
                }.get(category, "🔑")
                
                report.append(f"{emoji} {category.upper()} Credentials:")
                
                for i, finding in enumerate(findings[:5]):  # Limit to 5 per category
                    severity_emoji = {
                        "critical": "⛔",
                        "high": "🔴",
                        "medium": "🟡",
                        "low": "🟢"
                    }.get(finding["severity"], "⚠️")
                    
                    report.append(f"  {severity_emoji} {finding['description']} in {finding['file']}")
                    report.append(f"    Found: {finding['match']}")
                    
                    # Show remediation
                    report.append(f"    💡 Fix: {finding['remediation']}")
                
                if len(findings) > 5:
                    report.append(f"    ... and {len(findings) - 5} more {category} credential issues")
                
                report.append("")
        else:
            report.append("✅ No credentials found! Good job keeping your secrets safe.")
            report.append("")
        
        # Recommendations section
        report.append("💡 Secure Credential Management:")
        
        if self.stats["matches_found"] > 0:
            # Specific recommendations when credentials are found
            report.append("\n🔄 IMMEDIATE ACTIONS NEEDED:")
            report.append("  1. Revoke & rotate all exposed credentials")
            report.append("  2. Check access logs for unauthorized usage")
            report.append("  3. Move credentials to a secure storage solution")
            
            report.append("\n🛡️ RECOMMENDED SOLUTIONS:")
            report.append("  • Use environment variables (.env files + .gitignore)")
            report.append("  • Implement a secrets manager:")
            report.append("    - AWS Secrets Manager")
            report.append("    - HashiCorp Vault")
            report.append("    - Azure Key Vault")
            report.append("    - Google Secret Manager")
            
            report.append("\n⚠️ PRE-COMMIT PROTECTION:")
            report.append("  • Install git-secrets or pre-commit hooks")
            report.append("  • Add `git-secrets --install` to your repositories")
            report.append("  • Configure proper .gitignore for credential files")
        else:
            # General best practices when no issues found
            report.append("\n✅ MAINTAIN GOOD PRACTICES:")
            report.append("  • Keep using environment variables")
            report.append("  • Consider secrets managers for production")
            report.append("  • Run regular credential scans")
            report.append("  • Use pre-commit hooks to prevent leaks")
        
        return "\n".join(report)

def main():
    """Main function to run credential finding"""
    parser = argparse.ArgumentParser(description='Scan for exposed credentials, API keys, and secrets')
    parser.add_argument('directory', nargs='?', default=os.getcwd(), help='Directory to scan (default: current directory)')
    parser.add_argument('--thorough', action='store_true', help='Perform a more thorough scan')
    parser.add_argument('--show-matches', action='store_true', help='Show actual credential values (use with caution!)')
    parser.add_argument('--githistory', action='store_true', help='Also scan git commit history')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    
    args = parser.parse_args()
    
    # Run the scan
    finder = CredentialFinder()
    findings, stats, risk_level = finder.scan_directory(
        args.directory, 
        thorough=args.thorough,
        show_matches=args.show_matches,
        git_history=args.githistory
    )
    
    if args.json:
        output = {
            "risk_level": risk_level,
            "stats": stats,
            "findings": findings
        }
        print(json.dumps(output, indent=2))
    else:
        # Print human-readable report
        print(finder.generate_report())
    
    # Return exit code based on risk level
    if "High Risk" in risk_level:
        return 2
    elif "Medium Risk" in risk_level:
        return 1
    else:
        return 0

if __name__ == "__main__":
    exit(main())