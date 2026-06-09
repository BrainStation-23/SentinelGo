# Release Guide

This document explains how to create releases for SentinelGo with automatic version management.

## Quick Release Process

### 1. Automated Release (Recommended)
```bash
# Create and push a git tag
git tag v1.0.0
git push origin v1.0.0

# GitHub Actions will automatically:
# - Run tests
# - Build all platforms with version injection
# - Create GitHub release with assets
```

### 2. Manual Release
```bash
# Build and release manually
./scripts/release.sh --release --version v1.0.0
```

## Version Management

### Version Sources
The build process automatically detects version from:
1. **Git tags** (preferred): `v1.0.0`, `v1.2.3-beta`, etc.
2. **Environment variable**: `VERSION=v1.0.0 make release`
3. **Default**: `dev` (when no tag found)

### Version Injection
Version is automatically injected into the binary during build:
- **Main binary**: `sentinelgo/cmd/sentinelgo.Version`
- **Config module**: `sentinelgo/internal/config.Version`
- **Process detection**: Running processes show their version
- **Service management**: launchd services include version in arguments

## Build Commands

### Development Build
```bash
# Build for current platform only
make build

# Build with specific version
make build VERSION=v1.0.0

# Test version injection
make test-version
```

### Release Build
```bash
# Build all platforms (auto-detects version from git tag)
make release

# Build with specific version
make release VERSION=v1.0.0

# Show current version info
make version
```

### Version Management Commands
```bash
# Show current version and git info
make version

# Test that version injection works
make test-version

# Build specific platform with version
make macos VERSION=v1.0.0
make linux VERSION=v1.0.0
make windows VERSION=v1.0.0
```

## Automatic Update Management

### Safe Update Process
The updater now includes comprehensive process management to ensure safe updates:

#### **macOS (launchd) Updates**
1. **Stop launchd service** before applying update
2. **Kill all old processes** running previous versions
3. **Replace binary** with new version
4. **Restart launchd service** with updated binary
5. **Fallback to direct execution** if service management fails

#### **Linux/Windows Updates**
1. **Identify old processes** by PID and version
2. **Graceful termination** (SIGTERM) first
3. **Force kill** (SIGKILL) if processes don't stop
4. **Replace binary** and restart

#### **Process Detection Features**
- **Cross-platform process discovery** (ps, tasklist)
- **Version extraction** from command line arguments
- **Current process protection** (won't kill itself)
- **Multi-stage termination** (graceful + force)

### Update Flow
```bash
# Update process (automatic when update is available)
1. Check for new version
2. Stop all old SentinelGo processes
3. Download new binary
4. Replace current binary
5. Restart with new version
6. Update configuration
```

### Update Safety Features
- **Process isolation**: Only affects SentinelGo processes
- **Version tracking**: Identifies which version each process is running
- **Graceful shutdown**: Attempts clean termination first
- **Service continuity**: Automatically restarts after update
- **Error recovery**: Fallback options if service management fails

### Manual Update Control
```bash
# Check for updates manually
./sentinelgo -version

# Stop all processes before manual update
./sentinelgo -stop

# Install new version
sudo ./sentinelgo -install
```

## Release Assets
The build process creates these versioned assets:
- `sentinelgo-windows-amd64.exe` (~8MB)
- `sentinelgo-linux-amd64` (~6MB)
- `sentinelgo-linux-arm64` (~6MB)
- `sentinelgo-darwin-amd64` (~6MB)
- `sentinelgo-darwin-arm64` (~6MB)

Each binary includes embedded version information accessible via `-version` flag.

### Version Sources (in order of priority)
1. `VERSION` environment variable
2. Git tag (auto-detected)
3. Falls back to "dev"

### Version Injection
Versions are injected at build time via ldflags:
```bash
go build -ldflags "-X sentinelgo/internal/config.Version=$VERSION"
```

### Semantic Versioning
Use semantic versioning for releases:
- `v1.0.0` - Major release
- `v1.0.1` - Patch release
- `v1.1.0` - Minor release

## Environment Variables

Users must configure these environment variables:
```bash
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-supabase-anon-key
API_TOKEN=your-api-token
```

## GitHub Actions

### CI Workflow (.github/workflows/ci.yml)
- Runs on push to main/develop branches
- Runs tests on pull requests
- Builds all platforms for testing

### Release Workflow (.github/workflows/release.yml)
- Triggers on git tags (v*)
- Runs full test suite
- Builds all platforms
- Creates GitHub release with assets

## Security Considerations

- No secrets embedded in binaries
- Environment variables loaded at runtime
- GitHub releases are public by default
- Ensure Supabase credentials are properly secured

## Troubleshooting

### Build Issues
```bash
# Clean build artifacts
make clean

# Rebuild dependencies
make deps

# Check Go version (requires 1.22+)
go version
```

### Release Issues
```bash
# Check GitHub CLI installation
gh --version

# Verify authentication
gh auth status

# Manual release creation
gh release create v1.0.0 build/*
```

### Environment Issues
```bash
# Check .env file exists
ls -la .env

# Verify environment variables
cat .env
```

## Migration from Old Build System

The old build system embedded Supabase credentials at build time. The new system:

1. **Removes embedded secrets** - Better security
2. **Uses environment variables** - Runtime configuration
3. **Injects version only** - Simpler build process
4. **Automates releases** - GitHub Actions integration

No changes needed for existing installations - they'll continue to work with the new binary format.
