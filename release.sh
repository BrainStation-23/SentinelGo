#!/bin/bash

# SentinelGo Release Script
# Usage: ./release.sh [version]
# Example: ./release.sh v1.0.0

set -e

VERSION=${1:-"v1.0.0"}

echo "🚀 Creating SentinelGo release: $VERSION"

# Check if we're on main branch (optional - can be skipped)
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "📍 Current branch: $CURRENT_BRANCH"
if [ "$CURRENT_BRANCH" != "main" ]; then
    echo "⚠️  Warning: You're not on the main branch"
    echo "   Current branch: $CURRENT_BRANCH"
    read -p "🤔 Do you want to continue anyway? (y/N): " -n 1 -r response
    if [[ ! $response =~ ^[Yy]$ ]]; then
        echo "❌ Release cancelled - switch to main branch first"
        exit 1
    fi
fi

# Check if working directory is clean
if [ -n "$(git status --porcelain)" ]; then
    echo "❌ Error: Working directory is not clean"
    echo "   Please commit or stash your changes first"
    git status --porcelain
    exit 1
fi

# Build and test locally
echo "🔨 Building and testing locally..."
make clean
make test
make release

echo "✅ Build successful!"

# Show what will be created
echo ""
echo "📦 Release packages that will be created:"
ls -la release/*.tar.gz

# Confirm before proceeding
echo ""
read -p "🤔 Do you want to create and push tag $VERSION? (y/N): " -n 1 -r response
if [[ ! $response =~ ^[Yy]$ ]]; then
    echo "❌ Release cancelled"
    exit 0
fi

# Create and push tag
echo ""
echo "🏷️  Creating and pushing tag..."
git tag -a "$VERSION" -m "Release $VERSION"
git push origin "$VERSION"

echo "✅ Tag $VERSION pushed successfully!"
echo ""
echo "🎉 GitHub Actions will now:"
echo "   1. Build all platform binaries"
echo "   2. Create release packages with installer"
echo "   3. Create a DRAFT release on GitHub"
echo "   4. Generate release notes automatically"
echo ""
echo "📝 After the workflow completes, go to GitHub to:"
echo "   1. Review the draft release"
echo "   2. Make any necessary changes"
echo "   3. Click 'Publish release'"
echo ""
echo "🔗 Release will be available at:"
echo "   https://github.com/$(git config --get remote.origin.url | sed 's/.*:\\/\\/.*/' | sed 's/\\.git$//')/releases"
