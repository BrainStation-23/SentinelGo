# SentinelGo Makefile
# Build for release with environment variable configuration

# Version can be set via:
# - VERSION env var (takes precedence)
# - git tag (automatically detected)
# - defaults to "dev"
#
# NOTE: kept shell-agnostic on purpose. Avoid `2>/dev/null` / `|| echo` here —
# those are Unix-only and break when GNU Make runs $(shell ...) through cmd.exe
# on Windows (path errors + a literally-quoted version). git describe writes to
# stdout on success; if git is missing or this isn't a repo, $(shell) yields an
# empty string and we fall back to "dev".
VERSION ?= $(shell git describe --tags --always --dirty)
ifeq ($(strip $(VERSION)),)
VERSION := dev
endif

# Build flags for version injection.
# NOTE: the cmd/sentinelgo Version lives in `package main`, so the linker symbol
# is `main.Version` — the full import path form (sentinelgo/cmd/sentinelgo.Version)
# is silently ignored. config.Version uses its real import path.
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X sentinelgo/internal/config.Version=$(VERSION)"

# Dev build output name. On Windows the binary needs a .exe extension to be
# runnable (PowerShell/cmd won't execute an extension-less file).
ifeq ($(OS),Windows_NT)
DEV_BIN := bin/sentinelgo.exe
else
DEV_BIN := bin/sentinelgo
endif

# Export CGO_ENABLED for every recipe via Make's `export` directive instead of an
# inline `CGO_ENABLED=0 <cmd>` prefix. The inline prefix is Unix-shell syntax and
# fails when Make runs recipes through cmd.exe on Windows ("'CGO_ENABLED' is not
# recognized"). Exporting works regardless of the recipe shell.
export CGO_ENABLED=0

# Targets
.PHONY: build clean clean-all all windows linux macos release sign version test-version deps test coverage coverage-html pre-release quality-check format-check setup packages check-no-cgo verify-cross

all: windows linux macos

windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o build/windows/sentinelgo-windows-amd64.exe ./cmd/sentinelgo

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o build/linux/sentinelgo-linux-amd64 ./cmd/sentinelgo
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o build/linux/sentinelgo-linux-arm64 ./cmd/sentinelgo

macos:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o build/darwin/sentinelgo-darwin-amd64 ./cmd/sentinelgo
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o build/darwin/sentinelgo-darwin-arm64 ./cmd/sentinelgo

# Build all platforms for release, then sign and generate SHA256SUMS.
# Requires SENTINELGO_SIGNING_KEY env var (base64-encoded ed25519 private key).
# In CI this is injected from GitHub Actions secrets; locally set it before running.
release: pre-release clean all
	@echo "Release built with version $(VERSION)"
	@echo "Assets created in build/ directory:"
	@find build -type f -name "*sentinelgo*" -exec ls -lh {} \;
	@echo "\nCreating release packages..."
	@mkdir -p release
	@cp installation-doc/INSTALLATION.md release/
	@cp installation-doc/install.bat release/
	@cp installation-doc/install.sh release/
	@cp build/windows/sentinelgo-windows-amd64.exe release/
	@cp build/linux/sentinelgo-linux-amd64 release/
	@cp build/linux/sentinelgo-linux-arm64 release/
	@cp build/darwin/sentinelgo-darwin-amd64 release/
	@cp build/darwin/sentinelgo-darwin-arm64 release/
	@$(MAKE) sign
	@echo "\nRelease packages ready in release/ directory:"
	@ls -la release/
	@echo "\nCleaning build folder files and subdirectories..."
	@rm -rf build/* || true

# Sign release binaries and generate SHA256SUMS.
# Reads SENTINELGO_SIGNING_KEY from the environment (base64 ed25519 private key).
# Run `go run ./scripts/keygen` once to generate the keypair if needed.
sign:
	@echo "Signing release binaries..."
	@go run ./scripts/sign \
	  release/sentinelgo-linux-amd64 \
	  release/sentinelgo-linux-arm64 \
	  release/sentinelgo-darwin-amd64 \
	  release/sentinelgo-darwin-arm64 \
	  release/sentinelgo-windows-amd64.exe
	@echo "Signatures and SHA256SUMS written to release/"

clean:
	rm -rf build/

# Development build (current platform only)
build:
	go build $(LDFLAGS) -o $(DEV_BIN) ./cmd/sentinelgo
	@echo "Built $(DEV_BIN) (version $(VERSION))"

# Show version information
version:
	@echo "Current version: $(VERSION)"
	@echo "Git commit: $(shell git rev-parse --short HEAD || echo unknown)"

# Test version injection
test-version: build
	@echo "Testing version injection..."
	@./$(DEV_BIN) -version

# Install dependencies
deps:
	go mod download
	go mod tidy

# Run tests (no coverage)
test:
	go test ./...

# Run tests with coverage and show per-function report
coverage:
	go test -coverprofile=coverage.out -coverpkg=./... ./...
	go tool cover -func=coverage.out

# Generate browsable HTML coverage report (run `make coverage` first)
coverage-html:
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report written to coverage.html"

# Pre-release quality checks
pre-release: 
	@echo "🚀 Running pre-release quality checks..."
	@./scripts/pre-release-check.sh

# Guard against cgo. This project builds with CGO_ENABLED=0 to ship static,
# cross-compilable binaries. A file using `import "C"` would be SILENTLY excluded
# under CGO_ENABLED=0 (its build constraint becomes false), turning a misconfig
# into missing functionality rather than a loud build error. See CLAUDE.md.
check-no-cgo:
	@if grep -rln 'import "C"' --include='*.go' . ; then \
		echo "❌ cgo usage found (import \"C\"). This project builds with CGO_ENABLED=0;"; \
		echo "   use a pure-Go implementation or a subprocess instead."; \
		exit 1; \
	fi
	@echo "✅ no cgo usage detected"

# Compile every release target with CGO_ENABLED=0 so platform-specific files
# (e.g. the audit log collectors) are type-checked on every run, not just the
# host platform's. Catches a broken Linux/macOS/Windows file from any dev machine.
# Uses explicit per-target recipes instead of a shell loop to stay shell-agnostic.
verify-cross:
	@echo "Type-checking linux/amd64..."
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build ./...
	@echo "Type-checking linux/arm64..."
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build ./...
	@echo "Type-checking darwin/amd64..."
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build ./...
	@echo "Type-checking darwin/arm64..."
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build ./...
	@echo "Type-checking windows/amd64..."
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build ./...
	@echo "✅ all release targets compile with CGO_ENABLED=0"

# Code quality checks
quality-check:
	@echo "🔍 Running quality checks..."
	@go vet ./...
	@command -v golangci-lint >/dev/null 2>&1 || (echo "📦 Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	@export PATH=$$PATH:$$(go env GOPATH)/bin && golangci-lint run

# Code format check
format-check:
	@echo "📝 Checking code formatting..."
	@if [ -n "$$(gofmt -s -l .)" ]; then \
		echo "❌ Code formatting issues found:"; \
		gofmt -s -l .; \
		echo "🔧 To fix: gofmt -s -w ."; \
		exit 1; \
	fi
	@echo "✅ Code formatting check passed"

# Create release assets directory structure
setup:
	mkdir -p build/windows build/linux build/darwin

# Create distribution packages
packages: release
	@echo "Creating distribution packages..."
	@cd release && \
		tar -czf sentinelgo-$(VERSION)-windows.tar.gz sentinelgo-windows-amd64.exe INSTALLATION.md install.bat && \
		tar -czf sentinelgo-$(VERSION)-linux-amd64.tar.gz sentinelgo-linux-amd64 INSTALLATION.md install.sh && \
		tar -czf sentinelgo-$(VERSION)-linux-arm64.tar.gz sentinelgo-linux-arm64 INSTALLATION.md install.sh && \
		tar -czf sentinelgo-$(VERSION)-darwin-amd64.tar.gz sentinelgo-darwin-amd64 INSTALLATION.md install.sh && \
		tar -czf sentinelgo-$(VERSION)-darwin-arm64.tar.gz sentinelgo-darwin-arm64 INSTALLATION.md install.sh
	@echo "Packages created:"
	@ls -la release/*.tar.gz

# make release VERSION=v1.0.0
# make release (uses git tag or "dev")
# make build (development build for current platform)
# make version (show current version)
# make test-version (test version injection)
