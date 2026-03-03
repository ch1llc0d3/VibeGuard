#!/bin/bash
# Script to test that .gitignore is working correctly

echo "=== Testing Git Configuration ==="
echo ""

echo "1. Checking if test_tracked.md is being tracked (should be UNTRACKED, not ignored):"
git status --porcelain test_tracked.md
if [ $? -eq 0 ] && [ "$(git status --porcelain test_tracked.md | grep -c '??')" -eq 1 ]; then
    echo "✅ Success: test_tracked.md is correctly marked as untracked (not ignored)"
else
    echo "❌ Error: test_tracked.md has unexpected status"
fi

echo ""
echo "2. Checking if .env.test_secret is properly ignored (should NOT appear at all):"
git status --porcelain .env.test_secret
if [ $? -eq 0 ] && [ -z "$(git status --porcelain .env.test_secret)" ]; then
    echo "✅ Success: .env.test_secret is correctly ignored by git"
else
    echo "❌ Error: .env.test_secret is not being ignored"
fi

echo ""
echo "3. Adding test files to git to see if .gitignore prevents adding secrets:"
git add .

echo ""
echo "4. Checking what would actually be committed:"
git status --short
COUNT_SECRET_FILES=$(git status --porcelain | grep -c '.env')
if [ "$COUNT_SECRET_FILES" -eq 0 ]; then
    echo ""
    echo "✅ Success: No .env files are staged for commit"
else
    echo ""
    echo "❌ Error: Some .env files are still staged for commit ($COUNT_SECRET_FILES found)"
fi

# Clean up by unstaging everything
git reset

echo ""
echo "=== Test complete ==="