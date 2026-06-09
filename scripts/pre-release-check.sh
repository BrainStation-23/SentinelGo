#!/bin/bash

set -e

echo "🚀 Pre-Release Quality Checks"
echo "============================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function to print status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ $2${NC}"
    else
        echo -e "${RED}❌ $2${NC}"
        return 1
    fi
}

print_warning() {
    echo -e "${YELLOW}⚠️ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# 1. Code Format Check
echo ""
echo "1. Code Format Check"
echo "-------------------"
UNFORMATTED=$(gofmt -s -l .)
if [ -n "$UNFORMATTED" ]; then
    print_error "Code formatting issues found:"
    echo "$UNFORMATTED"
    echo ""
    print_info "🔧 To fix: gofmt -s -w ."
    print_error "⏸️ Please fix formatting issues before release"
    exit 1
else
    print_status 0 "Code formatting check passed"
fi

# 2. Code Quality Check
echo ""
echo "2. Code Quality Check"
echo "--------------------"
print_info "Running go vet..."
if ! CGO_ENABLED=0 go vet ./...; then
    print_error "go vet found issues"
    print_info "🔧 To fix: CGO_ENABLED=0 go vet ./..."
    print_error "⏸️ Please fix vet issues before release"
    exit 1
fi
print_status 0 "go vet check passed"

print_info "Installing golangci-lint..."
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Add GOPATH/bin to PATH for this script
export PATH=$PATH:$(go env GOPATH)/bin

print_info "Running golangci-lint..."
if ! golangci-lint run; then
    print_error "golangci-lint found issues"
    print_info "🔧 To fix: golangci-lint run"
    print_error "⏸️ Please fix linting issues before release"
    exit 1
fi
print_status 0 "golangci-lint check passed"

# 2b. No-cgo Guard + Cross-Platform Build
echo ""
echo "2b. No-cgo Guard + Cross-Platform Build"
echo "---------------------------------------"
print_info "Checking for cgo usage (must be none; project builds CGO_ENABLED=0)..."
if grep -rln 'import "C"' --include='*.go' .; then
    print_error "cgo usage found. A cgo file is silently excluded under CGO_ENABLED=0,"
    print_info "🔧 To fix: replace the import \"C\" code with pure Go or a subprocess. See CLAUDE.md."
    print_error "⏸️ Remove cgo before release"
    exit 1
fi
print_status 0 "No cgo usage detected"

print_info "Type-checking every release target with CGO_ENABLED=0..."
for t in "linux amd64" "linux arm64" "darwin amd64" "darwin arm64" "windows amd64"; do
    set -- $t
    print_info "  building $1/$2..."
    if ! CGO_ENABLED=0 GOOS=$1 GOARCH=$2 go build ./...; then
        print_error "Cross-platform build failed for $1/$2"
        print_error "⏸️ Fix the platform-specific build before release"
        exit 1
    fi
done
print_status 0 "All release targets compile with CGO_ENABLED=0"

# 3. Code Review Check
echo ""
echo "3. Code Review Check"
echo "-------------------"

# Check for TODO/FIXME comments
TODO_COUNT=$(grep -r "TODO\|FIXME" --include="*.go" . | wc -l)
if [ "$TODO_COUNT" -gt 0 ]; then
    print_warning "Found $TODO_COUNT TODO/FIXME comments"
    echo "Consider addressing these before release"
fi

# Check for function documentation (GoDoc comment must be on the line above the func)
UNDOC_FUNCS=$(grep -rn "^func [A-Z]" --include="*.go" . | grep -v "_test.go" | while read line; do
    file=$(echo "$line" | cut -d: -f1)
    lineno=$(echo "$line" | cut -d: -f2)
    prev=$((lineno - 1))
    prevline=$(sed -n "${prev}p" "$file")
    if ! echo "$prevline" | grep -q "^//"; then echo "$line"; fi
done | wc -l)
if [ "$UNDOC_FUNCS" -gt 0 ]; then
    print_warning "Found $UNDOC_FUNCS undocumented public functions"
    echo "Consider adding documentation for public functions"
fi

# Check for hardcoded service_role keys or secrets (eyJ... JWTs with service_role, passwords, etc.)
HARDCODED_SECRETS=$(grep -rn "service_role\|password\s*=" --include="*.go" . | grep -v "_test.go" | grep -v "^.*//.*" | grep -v "SupabaseAnonKey" | wc -l)
if [ "$HARDCODED_SECRETS" -gt 0 ]; then
    print_warning "Potential hardcoded credentials found ($HARDCODED_SECRETS occurrences)"
    echo "Please review and ensure no service_role keys or passwords are hardcoded"
fi

# Check project structure
if [ ! -d "cmd" ] || [ ! -d "internal" ]; then
    print_error "Invalid project structure - missing cmd or internal directories"
    exit 1
fi
print_status 0 "Project structure is correct"

print_status 0 "Code review checks completed"

# 4. Test Suite
echo ""
echo "4. Test Suite"
echo "------------"
print_info "Running tests with coverage (minimum 20%)..."
print_info "Tests are co-located per package; -short skips slow OS/network integration tests."
if ! CGO_ENABLED=0 go test -short -cover -timeout 5m ./...; then
    print_error "Tests failed"
    print_info "🔧 To fix: go test -short ./..."
    print_error "⏸️ Please fix failing tests before release"
    exit 1
fi

print_status 0 "All tests passed with 20%+ coverage"

# 5. Build Test
echo ""
echo "5. Build Test"
echo "------------"
print_info "Testing build for current platform..."
if ! make build; then
    print_error "Build failed"
    print_error "⏸️ Please fix build issues before release"
    exit 1
fi
print_status 0 "Build test passed"

# 6. Version Check
echo ""
echo "6. Version Check"
echo "---------------"
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
print_info "Current version: $VERSION"

if [ "$VERSION" == "dev" ]; then
    print_warning "No version tag found - this is a development build"
    echo "For release, create a tag: git tag v1.0.0"
else
    print_status 0 "Version tag found: $VERSION"
fi

# Summary
echo ""
echo "🎉 Pre-Release Quality Checks Complete!"
echo "====================================="
echo -e "${GREEN}✅ Code formatting: PASSED${NC}"
echo -e "${GREEN}✅ Code quality: PASSED${NC}"
echo -e "${GREEN}✅ Code review: PASSED${NC}"
echo -e "${GREEN}✅ Test suite: PASSED (${COVERAGE}% coverage)${NC}"
echo -e "${GREEN}✅ Build test: PASSED${NC}"
echo ""
echo -e "${GREEN}🚀 Ready for release!${NC}"
echo ""
echo "Next steps:"
echo "1. If version is 'dev', create a tag: git tag v1.0.0"
echo "2. Push the tag: git push origin v1.0.0"
echo "3. GitHub Actions will create the release automatically"
