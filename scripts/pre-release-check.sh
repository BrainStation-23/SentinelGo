#!/bin/bash

# Pre-release gate. All checks must pass; any failure exits non-zero.

set -e

echo "Pre-release checks"
echo "=================="

# 1. Format
echo ""
echo "1. Format"
UNFORMATTED=$(gofmt -s -l .)
if [ -n "$UNFORMATTED" ]; then
    echo "FAIL: unformatted files (run: gofmt -s -w .):"
    echo "$UNFORMATTED"
    exit 1
fi
echo "ok"

# 2. Vet
echo ""
echo "2. Vet"
CGO_ENABLED=0 go vet ./...
echo "ok"

# 3. Lint
echo ""
echo "3. Lint"
if ! command -v golangci-lint >/dev/null 2>&1; then
    # Not on PATH; try GOPATH/bin before giving up
    GOPATH_LINT="$(go env GOPATH)/bin/golangci-lint"
    if [ -x "$GOPATH_LINT" ]; then
        export PATH=$PATH:$(go env GOPATH)/bin
    else
        echo "FAIL: golangci-lint not found. Install it: https://golangci-lint.run/usage/install/"
        exit 1
    fi
fi
golangci-lint run
echo "ok"

# 4. No cgo
echo ""
echo "4. No cgo"
if grep -rln 'import "C"' --include='*.go' .; then
    echo "FAIL: cgo found. Use pure-Go or a subprocess instead. See CLAUDE.md."
    exit 1
fi
echo "ok"

# 5. Cross-platform build
echo ""
echo "5. Cross-platform build (CGO_ENABLED=0)"
for target in "linux amd64" "linux arm64" "darwin amd64" "darwin arm64" "windows amd64"; do
    set -- $target
    printf "  %s/%s ... " "$1" "$2"
    CGO_ENABLED=0 GOOS=$1 GOARCH=$2 go build ./...
    echo "ok"
done

# 6. Tests
echo ""
echo "6. Tests"
CGO_ENABLED=0 go test -short -timeout 5m ./...
echo "ok"

echo ""
echo "All checks passed."
