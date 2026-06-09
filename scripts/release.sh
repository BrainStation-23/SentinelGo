#!/bin/bash

# SentinelGo Release Script
# Local escape hatch for manual releases.
# Prefer the GitHub Actions "Trigger Release" workflow (workflow_dispatch) for standard releases —
# it auto-bumps the version from the latest tag and triggers the full CI build pipeline.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
GITHUB_OWNER="habib45"
GITHUB_REPO="SentinelGo"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if gh CLI is installed
check_gh_cli() {
    if ! command -v gh &> /dev/null; then
        print_error "GitHub CLI (gh) is not installed. Please install it first."
        print_status "Install from: https://cli.github.com/manual/installation"
        exit 1
    fi
}

# Check if we're in a git repository
check_git_repo() {
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        print_error "Not in a git repository"
        exit 1
    fi
}

# Get version from git tag or argument
get_version() {
    if [ -n "$1" ]; then
        VERSION="$1"
    else
        VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
    fi
    
    if [ "$VERSION" = "dev" ]; then
        print_warning "No git tag found, using 'dev' version"
        print_warning "Consider creating a tag: git tag v1.0.0"
    fi
    
    echo "$VERSION"
}

# Build all platforms
build_release() {
    local version="$1"
    
    print_status "Building release version: $version"
    
    # Clean previous builds
    make clean
    
    # Build all platforms
    make release VERSION="$version"
    
    print_status "Build completed successfully"
}

# Create GitHub release
create_github_release() {
    local version="$1"
    local release_notes="$2"
    
    print_status "Creating GitHub release: $version"
    
    # Create release notes if not provided
    if [ -z "$release_notes" ]; then
        release_notes="Release $version"
        
        # Try to get commit history since last tag
        if git describe --tags --abbrev=0 > /dev/null 2>&1; then
            last_tag=$(git describe --tags --abbrev=0)
            release_notes=$(git log --pretty=format:"- %s" "$last_tag"..HEAD | head -20)
        fi
    fi
    
    # Create release and upload assets
    gh release create "$version" \
        build/windows/sentinelgo-windows-amd64.exe \
        build/linux/sentinelgo-linux-amd64 \
        build/linux/sentinelgo-linux-arm64 \
        build/darwin/sentinelgo-darwin-amd64 \
        build/darwin/sentinelgo-darwin-arm64 \
        installation-doc/install.bat\
        installation-doc/install.sh\
        --title "SentinelGo $version" \
        --notes "$release_notes" \
        --latest
    
    print_status "GitHub release created successfully"
}

# Main function
main() {
    local version=""
    local release_notes=""
    local create_release=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version|-v)
                version="$2"
                shift 2
                ;;
            --notes|-n)
                release_notes="$2"
                shift 2
                ;;
            --release|-r)
                create_release=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -v, --version VERSION    Set version (auto-detected from git tag)"
                echo "  -n, --notes NOTES        Release notes"
                echo "  -r, --release            Create GitHub release"
                echo "  -h, --help               Show this help"
                echo ""
                echo "Examples:"
                echo "  $0                        # Build only"
                echo "  $0 -v v1.0.0             # Build with version"
                echo "  $0 -r -v v1.0.0          # Build and create release"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Pre-flight checks
    check_git_repo
    if [ "$create_release" = true ]; then
        check_gh_cli
    fi
    
    # Get version
    version=$(get_version "$version")
    
    # Build
    build_release "$version"
    
    # Create GitHub release if requested
    if [ "$create_release" = true ]; then
        create_github_release "$version" "$release_notes"
    fi
    
    print_status "Release process completed!"
    print_status "Version: $version"
    print_status "Assets: build/ directory"
}

# Run main function
main "$@"
