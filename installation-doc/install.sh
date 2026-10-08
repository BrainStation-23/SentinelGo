#!/bin/bash

# SentinelGo Universal Installation Script
# Usage: ./install.sh [COMMAND] (will auto-request sudo if needed)
# Works on Ubuntu/Debian, CentOS/RHEL, macOS, and Windows (via Git Bash)
#
# To run:
#   - Double-click (if file manager supports .sh execution)
#   - Right-click and select "Execute" or "Run in terminal"
#   - From terminal: ./install.sh

set -e

# Change to script directory (fixes execution from any location)
cd "$(dirname "$0")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SERVICE_NAME="sentinelgo"
BINARY_NAME="sentinelgo"
INSTALL_DIR="/opt/sentinelgo"
CONFIG_DIR="${INSTALL_DIR}/.sentinelgo"
SERVICE_USER="sentinelgo"
readonly OS_WINDOWS="windows"
readonly LAUNCHD_PLIST_PATH="/Library/LaunchDaemons/com.sentinelgo.agent.plist"

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            echo "ubuntu"
        elif command -v yum >/dev/null 2>&1; then
            echo "centos"
        elif command -v dnf >/dev/null 2>&1; then
            echo "fedora"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        echo "$OS_WINDOWS"
    else
        echo "unknown"
    fi
}

# Detect the CPU architecture in release-asset form (amd64 / arm64).
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "amd64" ;;
        arm64|aarch64) echo "arm64" ;;
        *) uname -m ;;
    esac
}

# select_binary prints the path of the binary to install from the current
# directory: a plain ./sentinelgo if present, otherwise the release asset that
# matches this machine's OS and CPU (sentinelgo-<os>-<arch>). Prints nothing if
# there is none. Choosing by OS/arch matters: a full release download contains
# every platform's binary, and installing the wrong one breaks the service.
select_binary() {
    if [[ -f "./$BINARY_NAME" ]]; then
        echo "./$BINARY_NAME"
        return
    fi
    local goos
    case "$(detect_os)" in
        ubuntu|centos|fedora|linux) goos="linux" ;;
        macos) goos="darwin" ;;
        "$OS_WINDOWS") goos="windows" ;;
        *) return ;;
    esac
    local candidate="./sentinelgo-${goos}-$(detect_arch)"
    [[ "$goos" == "windows" ]] && candidate="${candidate}.exe"
    if [[ -f "$candidate" ]]; then
        echo "$candidate"
    fi
}

# sha256_of prints the SHA-256 of a file using whichever tool the OS has.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        return 1
    fi
}

# verify_binary checks a binary against the SHA256SUMS published with the
# release before it is installed as root. A missing SHA256SUMS, a mismatch, or
# a binary that is not listed aborts the install: nothing unverified is run as
# root.
verify_binary() {
    local file="$1"
    local sums="./SHA256SUMS"
    if [[ ! -f "$sums" ]]; then
        print_error "SHA256SUMS not found next to the installer; refusing to install an unverified binary"
        print_error "Download SHA256SUMS from https://github.com/BrainStation-23/SentinelGo/releases and place it next to this script"
        exit 1
    fi

    local actual
    if ! actual=$(sha256_of "$file"); then
        print_error "No sha256sum or shasum available; cannot verify $(basename "$file")"
        exit 1
    fi

    local name expected
    name=$(basename "$file")
    expected=$(awk -v n="$name" '$2 == n || $2 == "*" n {print $1; exit}' "$sums")
    if [[ -n "$expected" ]]; then
        if [[ "$actual" != "$expected" ]]; then
            print_error "Checksum mismatch for $name"
            print_error "  expected: $expected"
            print_error "  actual:   $actual"
            print_error "The file is corrupted or has been tampered with. Download it again from the official release."
            exit 1
        fi
    elif ! awk '{print $1}' "$sums" | grep -qx "$actual"; then
        # A renamed binary (e.g. ./sentinelgo) is accepted if its hash is a
        # published release asset.
        print_error "$name is not a published release asset (its SHA-256 is not in SHA256SUMS)"
        exit 1
    fi
    print_success "Verified $name against SHA256SUMS"
}

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check if running with appropriate permissions and auto-elevate
check_permissions() {
    local os=$(detect_os)
    
    if [[ "$os" == "$OS_WINDOWS" ]]; then
        # Windows: Check if running as administrator
        if ! net session >/dev/null 2>&1; then
            print_error "Please run this script as Administrator on Windows"
            exit 1
        fi
    else
        # Unix-like: Check if running as root, auto-elevate if not
        if [[ $EUID -ne 0 ]]; then
            print_status "Administrator privileges required"
            print_status "Attempting to auto-elevate using sudo..."
            
            # Re-run script with sudo, passing all arguments
            exec sudo "$0" "$@"
            
            # If exec fails, fall back to error
            print_error "Failed to auto-elevate. Please run with sudo:"
            print_error "  sudo $0 $*"
            exit 1
        fi
    fi
}

# Create service user
create_service_user() {
    local os=$(detect_os)
    
    if [[ "$os" == "$OS_WINDOWS" ]]; then
        # Windows doesn't need a special user for this
        return 0
    fi
    
    if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
        print_status "Creating service user: $SERVICE_USER"
        if [[ "$os" == "macos" ]]; then
            # macOS: Create user with proper group
            sysadminctl -addUser "$SERVICE_USER" 2>/dev/null || dscl . -create /Users/"$SERVICE_USER"
            # Create group if it doesn't exist
            if ! dscl . -list /Groups | grep -q "^$SERVICE_USER$"; then
                dscl . -create /Groups/"$SERVICE_USER"
            fi
            dscl . -append /Groups/"$SERVICE_USER" GroupMembership "$SERVICE_USER"
        else
            # Linux: Create user and group
            useradd -r -s /bin/false "$SERVICE_USER" 2>/dev/null || true
        fi
        print_success "Service user created"
    else
        print_status "Service user already exists"
    fi
}

# Install directories and permissions
setup_directories() {
    print_status "Setting up directories and permissions"
    
    # Create install directory
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    
    # Check for config.json in current directory and move it
    if [[ -f "./config.json" ]]; then
        print_status "Found config.json in current directory, moving to config location"
        cp "./config.json" "$CONFIG_DIR/config.json"
        print_success "config.json moved to $CONFIG_DIR/config.json"
        print_status "Original config.json preserved in current directory"
    else
        print_status "No config.json found in current directory"
    fi
    
    # Pick the binary for this OS/CPU and verify it before installing as root.
    local src
    src=$(select_binary)
    if [[ -z "$src" ]]; then
        print_error "No SentinelGo binary for $(detect_os)/$(detect_arch) found in the current directory"
        print_error "Download the binary for your OS and CPU from https://github.com/BrainStation-23/SentinelGo/releases and place it next to this script"
        exit 1
    fi
    verify_binary "$src"
    print_status "Installing $(basename "$src")"
    if [[ "$src" == *.exe ]]; then
        cp "$src" "$INSTALL_DIR/$BINARY_NAME.exe"
    else
        cp "$src" "$INSTALL_DIR/$BINARY_NAME"
    fi
    
    # Set permissions
    chmod +x "$INSTALL_DIR/$BINARY_NAME"

    local os=$(detect_os)

    # Harden install directory and binary ownership/permissions.
    #
    # Security model: root owns the install directory and binary so that the
    # service account ($SERVICE_USER) cannot replace its own executable and
    # escalate to root. chmod 750 on the directory prevents unprivileged users
    # from listing or traversing it; chmod 750 on the binary allows root to
    # execute it while denying write access to everyone else. The service user
    # is added to the sentinelgo group (created below) so it can read the
    # binary — no world-read or world-write bits are set.
    if [[ "$os" == "macos" ]]; then
        # macOS: root owns install dir and binary; group wheel can read.
        chown -R root:wheel "$INSTALL_DIR" 2>/dev/null || true
        chmod 750 "$INSTALL_DIR" 2>/dev/null || true
        chmod 750 "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || true
        # Config dir is owned by root but accessible to the service group only.
        chmod 750 "$CONFIG_DIR" 2>/dev/null || true
        # Remove download quarantine flag and register with Gatekeeper so macOS
        # does not block the daemon with "cannot be verified for malware" on
        # first run.
        xattr -d com.apple.quarantine "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || true
        codesign --force --sign - "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || true
        spctl --add "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || true
    elif [[ "$os" == "$OS_WINDOWS" ]]; then
        # Windows: Skip ownership change (handled by install.bat via icacls).
        echo "[INFO] Skipping ownership change on Windows"
    else
        # Linux: root owns install dir and binary so the service user cannot
        # replace them. Create a dedicated group for the service account so it
        # can execute the binary without world-execute permissions.
        groupadd -f "$SERVICE_USER" 2>/dev/null || true
        if id "$SERVICE_USER" &>/dev/null; then
            usermod -aG "$SERVICE_USER" "$SERVICE_USER" 2>/dev/null || true
        fi
        chown -R root:"$SERVICE_USER" "$INSTALL_DIR" 2>/dev/null || true
        # 750: root rwx, service group r-x, others ---
        chmod 750 "$INSTALL_DIR" 2>/dev/null || true
        chmod 750 "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || true
        # Config dir: root owns it, group readable (agent writes via root
        # service context; 750 prevents unprivileged reads of secrets).
        chown -R root:"$SERVICE_USER" "$CONFIG_DIR" 2>/dev/null || true
        chmod 750 "$CONFIG_DIR" 2>/dev/null || true
    fi
    
    print_success "Directories and permissions set"
}

# Install systemd service (Linux)
install_systemd_service() {
    print_status "Installing systemd service"
    
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=SentinelGo Agent
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$BINARY_NAME -run --config $CONFIG_DIR/config.json
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sentinelgo
Environment=HOME=$INSTALL_DIR
Environment=XDG_CONFIG_HOME=$CONFIG_DIR

[Install]
WantedBy=multi-user.target
EOF
    
    chmod 644 "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    
    # Forcefully start service with verification
    print_status "Forcefully starting service..."
    systemctl start "$SERVICE_NAME"
    sleep 3
    
    # Verify service is running
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "Systemd service installed and started successfully"
        print_status "Service is running"
    else
        print_warning "Service may not be running, attempting force start..."
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        sleep 2
        systemctl start "$SERVICE_NAME"
        sleep 3
        
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            print_success "Service started successfully on retry"
        else
            print_error "Service failed to start after retry"
            print_status "Checking logs for errors:"
            journalctl -u "$SERVICE_NAME" -n 10 --no-pager
            print_status "Try manual start: systemctl start $SERVICE_NAME"
        fi
    fi
}

# Install launchd service (macOS)
install_launchd_service() {
    print_status "Installing launchd service"
    
    local current_user=$(whoami)
    
    cat > "$LAUNCHD_PLIST_PATH" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sentinelgo.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/$BINARY_NAME</string>
        <string>-run</string>
        <string>--config</string>
        <string>$CONFIG_DIR/config.json</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/sentinelgo.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/sentinelgo.log</string>
    <key>UserName</key>
    <string>$current_user</string>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
</dict>
</plist>
EOF
    
    # Set permissions for macOS
    chown root:wheel "$LAUNCHD_PLIST_PATH"
    chmod 644 "$LAUNCHD_PLIST_PATH"
    
    # First, try to unload any existing service
    print_status "Checking for existing service..."
    if launchctl print system/com.sentinelgo.agent >/dev/null 2>&1; then
        print_status "Unloading existing service..."
        launchctl bootout system "$LAUNCHD_PLIST_PATH" 2>/dev/null || true
        sleep 2
    fi
    
    # Try bootstrap first (newer macOS versions)
    print_status "Starting service..."
    if launchctl bootstrap system "$LAUNCHD_PLIST_PATH" 2>/dev/null; then
        launchctl kickstart -k system/com.sentinelgo.agent
        sleep 3
    else
        # Fallback to load for older macOS versions
        print_warning "Bootstrap failed, trying load command..."
        launchctl load -w "$LAUNCHD_PLIST_PATH" 2>/dev/null || true
        sleep 3
    fi
    
    # Verify service is running
    if launchctl print system/com.sentinelgo.agent >/dev/null 2>&1; then
        print_success "Launchd service installed and started successfully"
        print_status "Service is running"
    else
        print_warning "Service may not be running, attempting force start..."
        launchctl bootout system "$LAUNCHD_PLIST_PATH" 2>/dev/null || true
        sleep 2
        launchctl bootstrap system "$LAUNCHD_PLIST_PATH" 2>/dev/null || launchctl load -w "$LAUNCHD_PLIST_PATH" 2>/dev/null || true
        sleep 2
        launchctl kickstart -k system/com.sentinelgo.agent
        sleep 3
        
        if launchctl print system/com.sentinelgo.agent >/dev/null 2>&1; then
            print_success "Service started successfully on retry"
        else
            print_error "Service failed to start after retry"
            print_status "Check logs: tail -f /var/log/sentinelgo.log"
            print_status "Try manual start: launchctl kickstart -k system/com.sentinelgo.agent"
        fi
    fi
}


# Show service status
show_status() {
    print_status "Service Status:"
    
    local os=$(detect_os)
    
    case "$os" in
        ubuntu|centos|fedora|linux)
            systemctl status "$SERVICE_NAME" --no-pager
            print_status "Logs: journalctl -u $SERVICE_NAME -f"
            ;;
        macos)
            launchctl print system/com.sentinelgo.agent 2>/dev/null || echo "Service not loaded"
            print_status "Logs: tail -f /var/log/sentinelgo.log"
            ;;
        *)
            print_warning "Status check not implemented for OS: $os"
            ;;
    esac
}

# Uninstall function
uninstall_service() {
    print_status "Uninstalling SentinelGo..."
    
    check_permissions
    
    local os=$(detect_os)
    
    case "$os" in
        ubuntu|centos|fedora|linux)
            systemctl stop "$SERVICE_NAME" 2>/dev/null || true
            systemctl disable "$SERVICE_NAME"
            rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
            systemctl daemon-reload
            ;;
        macos)
            launchctl bootout system "$LAUNCHD_PLIST_PATH" 2>/dev/null || true
            rm -f "$LAUNCHD_PLIST_PATH"
            ;;
        *)
            print_warning "Uninstall of the OS service is not implemented for OS: $os"
            ;;
    esac
    
    # Remove directories and user
    read -p "Remove all SentinelGo data and user? (y/N): " -n 1 -r response
    if [[ $response =~ ^[Yy]$ ]]; then
        rm -rf "$INSTALL_DIR"
        if [[ "$os" != "$OS_WINDOWS" ]]; then
            userdel -r "$SERVICE_USER" 2>/dev/null || true
        fi
    fi
    
    print_success "SentinelGo service uninstalled successfully"
}

# Update function
update_service() {
    print_status "Updating SentinelGo..."
    
    check_permissions
    
    # Stop any running SentinelGo processes first
    print_status "Stopping any running SentinelGo processes..."
    local os=$(detect_os)
    case "$os" in
        ubuntu|centos|fedora|linux)
            systemctl stop sentinelgo 2>/dev/null || true
            ;;
        macos)
            launchctl kill system/com.sentinelgo.agent 2>/dev/null || true
            ;;
        *)
            print_warning "Stopping the running process is not implemented for OS: $os"
            ;;
    esac

    # Kill any remaining processes
    pkill -f sentinelgo 2>/dev/null || true
    # Force kill any remaining processes to prevent "Text file busy" error
    pkill -9 -f sentinelgo 2>/dev/null || true
    sleep 3

    setup_directories

    case "$os" in
        ubuntu|centos|fedora|linux)
            systemctl start sentinelgo
            ;;
        macos)
            launchctl start com.sentinelgo.agent
            ;;
        *)
            print_warning "Starting the service is not implemented for OS: $os"
            ;;
    esac

    print_success "SentinelGo updated successfully!"
}

# Fix service startup issues
fix_service() {
    print_status "Fixing SentinelGo service issues..."
    
    check_permissions
    
    # Stop service first
    print_status "Stopping service..."
    local os=$(detect_os)
    case "$os" in
        ubuntu|centos|fedora|linux)
            systemctl stop sentinelgo 2>/dev/null || true
            systemctl disable sentinelgo 2>/dev/null || true
            ;;
        macos)
            launchctl kill system/com.sentinelgo.agent 2>/dev/null || true
            ;;
        *)
            print_warning "Stopping the service is not implemented for OS: $os"
            ;;
    esac

    # Wait for complete stop
    sleep 3
    
    # Kill any remaining processes
    print_status "Killing remaining processes..."
    pkill -f sentinelgo 2>/dev/null || true
    sleep 2
    
    # Check and fix permissions
    print_status "Fixing permissions..."
    if [[ "$os" != "$OS_WINDOWS" ]]; then
        # Re-assert root ownership and restrictive permissions on the install
        # directory and binary (mirrors the hardening applied during install).
        if [[ "$os" == "macos" ]]; then
            chown -R root:wheel "$INSTALL_DIR" 2>/dev/null || true
            chmod 750 "$INSTALL_DIR" 2>/dev/null || true
            chmod 750 "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || true
        else
            chown -R root:"$SERVICE_USER" "$INSTALL_DIR" 2>/dev/null || true
            chmod 750 "$INSTALL_DIR" 2>/dev/null || true
            chmod 750 "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || true
        fi
    fi
    
    # Check config
    print_status "Checking config..."
    if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
        print_status "Creating default config..."
        mkdir -p "$CONFIG_DIR"
        echo '{"heartbeat_interval":"5m0s","auto_update":false}' > "$CONFIG_DIR/config.json"
        if [[ "$os" == "macos" ]]; then
            chown -R "$(whoami)" "$CONFIG_DIR"
        elif [[ "$os" != "$OS_WINDOWS" ]]; then
            chown -R "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR"
        fi
        print_success "Default config created at $CONFIG_DIR/config.json"
    else
        print_status "Config file already exists at $CONFIG_DIR/config.json"
        print_status "Using existing configuration"
    fi
    
    # Test binary
    print_status "Testing binary..."
    if [[ "$os" != "$OS_WINDOWS" ]]; then
        # Simple test - check if binary exists and is executable
        if [[ -x "$INSTALL_DIR/$BINARY_NAME" ]]; then
            print_status "Binary exists and is executable"
            
            # Restart service
            print_status "Restarting service..."
            case "$os" in
                ubuntu|centos|fedora|linux)
                    systemctl daemon-reload
                    systemctl enable "$SERVICE_NAME"
                    systemctl start "$SERVICE_NAME"
                    ;;
                macos)
                    launchctl bootstrap system "$LAUNCHD_PLIST_PATH"
                    launchctl kickstart -k system/com.sentinelgo.agent
                    ;;
                *)
                    print_warning "Restarting the service is not implemented for OS: $os"
                    ;;
            esac

            # Check status
            sleep 3
            case "$os" in
                ubuntu|centos|fedora|linux)
                    if systemctl is-active --quiet "$SERVICE_NAME"; then
                        print_success "Service started successfully!"
                        print_status "Current status:"
                        systemctl status "$SERVICE_NAME" --no-pager -l
                    else
                        print_error "Service failed to start - checking logs"
                        print_status "Recent logs:"
                        journalctl -u "$SERVICE_NAME" -n 10 --no-pager
                    fi
                    ;;
                *)
                    print_warning "Status check after restart is not implemented for OS: $os"
                    ;;
            esac
        else
            print_error "Binary not found or not executable"
            print_status "Installing binary first..."
            # Copy the binary for this OS/CPU if available (verified first).
            local repair_src
            repair_src=$(select_binary)
            if [[ -n "$repair_src" ]]; then
                verify_binary "$repair_src"
                cp "$repair_src" "$INSTALL_DIR/$BINARY_NAME"
                chmod 750 "$INSTALL_DIR/$BINARY_NAME"
                chown root:"$SERVICE_USER" "$INSTALL_DIR/$BINARY_NAME"
                print_status "Binary installed, trying again..."
            elif [[ -f "./build/linux/sentinelgo-linux-amd64" ]]; then
                cp "./build/linux/sentinelgo-linux-amd64" "$INSTALL_DIR/$BINARY_NAME"
                chmod 750 "$INSTALL_DIR/$BINARY_NAME"
                chown root:"$SERVICE_USER" "$INSTALL_DIR/$BINARY_NAME"
                print_status "Binary installed from build/, trying again..."
            else
                print_error "No binary found to install"
                print_status "Please build the binary first: make"
                return
            fi
            
            # Try to start service again
            case "$os" in
                ubuntu|centos|fedora|linux)
                    systemctl start "$SERVICE_NAME"
                    ;;
                macos)
                    launchctl kickstart -k system/com.sentinelgo.agent
                    ;;
                *)
                    print_warning "Starting the service is not implemented for OS: $os"
                    ;;
            esac

            sleep 3
            if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
                print_success "Service started successfully!"
            else
                print_error "Service still failed - manual intervention needed"
                print_status "Check logs: journalctl -u $SERVICE_NAME -f"
            fi
        fi
    fi
    
    print_success "Service fix completed!"
}

# Show help
show_help() {
    printf '%s\n' 'SentinelGo Universal Installation Script'
    printf '%s\n' ''
    printf '%s\n' 'Usage: ./install.sh [COMMAND] (auto-elevates with sudo if needed)'
    printf '%s\n' ''
    printf '%s\n' 'Commands:'
    printf '%s\n' '  install     Install SentinelGo as a service (default)'
    printf '%s\n' '  uninstall   Remove SentinelGo service and data'
    printf '%s\n' '  update      Update SentinelGo binary'
    printf '%s\n' '  status      Show service status'
    printf '%s\n' '  fix-service Fix service startup issues'
    printf '%s\n' '  help        Show this help message'
    printf '%s\n' ''
    printf '%s\n' 'Running the script:'
    printf '%s\n' '  - Double-click (if file manager supports .sh execution)'
    printf '%s\n' '  - Right-click and select "Execute" or "Run in terminal"'
    printf '%s\n' '  - From terminal: ./install.sh [command]'
    printf '%s\n' '  - Script will auto-request sudo if not running as root'
    printf '%s\n' ''
    printf '%s\n' 'Configuration Handling:'
    printf '%s\n' '  - If config.json exists in current directory, it will be copied to:'
    printf '%s\n' '    /opt/sentinelgo/.sentinelgo/config.json'
    printf '%s\n' '  - Original config.json is preserved in current directory'
    printf '%s\n' '  - If no config.json found, default config will be created'
    printf '%s\n' ''
    printf '%s\n' 'Examples:'
    printf '%s\n' '  ./install.sh install'
    printf '%s\n' '  ./install.sh uninstall'
    printf '%s\n' '  ./install.sh status'
    printf '%s\n' '  ./install.sh fix-service'
    printf '%s\n' ''
    printf '%s\n' 'Platform Support:'
    printf '%s\n' '  - Linux (systemd): Ubuntu, Debian, CentOS, RHEL, Fedora'
    printf '%s\n' '  - macOS (launchd): Intel and Apple Silicon'
    printf '%s\n' '  - Windows (Service): Via Git Bash or WSL'
}

# Install service
install_service() {
    print_status "Installing SentinelGo..."
    
    check_permissions
    
    # Stop any running SentinelGo processes first
    print_status "Stopping any running SentinelGo processes..."
    local os=$(detect_os)
    case "$os" in
        ubuntu|centos|fedora|linux)
            systemctl stop sentinelgo 2>/dev/null || true
            ;;
        macos)
            launchctl kill system/com.sentinelgo.agent 2>/dev/null || true
            ;;
        *)
            print_warning "Stopping the running process is not implemented for OS: $os"
            ;;
    esac

    # Kill any remaining processes
    pkill -f sentinelgo 2>/dev/null || true
    # Force kill any remaining processes to prevent "Text file busy" error
    pkill -9 -f sentinelgo 2>/dev/null || true
    sleep 3

    create_service_user
    setup_directories

    case "$os" in
        ubuntu|centos|fedora|linux)
            install_systemd_service
            ;;
        macos)
            install_launchd_service
            ;;
        *)
            print_warning "Service installation is not implemented for OS: $os"
            ;;
    esac
    
    print_success "SentinelGo installed successfully!"
    print_status "Use './install.sh status' to check service status"
    
    # Automatically enable auto-updates
    print_status "Enabling automatic updates..."
    local os=$(detect_os)
    case "$os" in
        ubuntu|centos|fedora|linux)
            if [[ -f "$INSTALL_DIR/$BINARY_NAME" ]]; then
                sudo "$INSTALL_DIR/$BINARY_NAME" -enable-auto-update
                print_success "Automatic updates enabled!"
            else
                print_warning "Binary not found, please enable auto-updates manually:"
                print_status "sudo $INSTALL_DIR/$BINARY_NAME -enable-auto-update"
            fi
            ;;
        macos)
            if [[ -f "$INSTALL_DIR/$BINARY_NAME" ]]; then
                "$INSTALL_DIR/$BINARY_NAME" -enable-auto-update
                print_success "Automatic updates enabled!"
            else
                print_warning "Binary not found, please enable auto-updates manually:"
                print_status "$INSTALL_DIR/$BINARY_NAME -enable-auto-update"
            fi
            ;;
        *)
            print_warning "Enabling automatic updates is not implemented for OS: $os"
            ;;
    esac
}

# Main script logic
main() {
    local command="${1:-install}"
    
    case "$command" in
        install)
            install_service
            ;;
        uninstall)
            uninstall_service
            ;;
        update)
            update_service
            ;;
        status)
            show_status
            ;;
        fix-service)
            fix_service
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Call main function with all arguments
main "$@"
