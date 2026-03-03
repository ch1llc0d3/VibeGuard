#!/bin/bash
# Script to push to GitHub using a token from .env.github
# IMPORTANT: Do NOT commit this file with your token

if [ ! -f .env.github ]; then
    echo "Error: .env.github file not found"
    echo "Please create it with your GitHub token: echo \"GITHUB_TOKEN=your_token\" > .env.github"
    exit 1
fi

source .env.github

if [ -z "$GITHUB_TOKEN" ]; then
    echo "Error: GITHUB_TOKEN not found in .env.github"
    exit 1
fi

# Configure the repository
git remote add origin https://oauth2:${GITHUB_TOKEN}@github.com/ch1llc0d3/VibeGuard.git || git remote set-url origin https://oauth2:${GITHUB_TOKEN}@github.com/ch1llc0d3/VibeGuard.git

# Push to GitHub
git push -u origin main

echo "Push complete!"