# SentinelGo Installation Guide

## Overview
SentinelGo is a cross-platform monitoring agent that runs as a system service. This guide provides multiple installation methods for Linux, macOS, and Windows.

## Quick Start

### Choose Your Platform:
- **[Linux](#linux)** - Ubuntu, Debian, CentOS, RHEL, etc.
- **[macOS](#macos)** - Intel and Apple Silicon
- **[Windows](#windows)** - Windows 10/11

### Installation Methods:
1. **Automated Scripts** - Recommended for most users
2. **Manual Installation** - For advanced users and custom setups

## 🚀 Quick Installation (One Command)

After downloading the release from GitHub, simply run:

```bash
# For Linux/macOS
sudo ./install.sh

# For Windows (run as Administrator)
./install.bat

```

That's it! SentinelGo will be installed and configured to start automatically on system boot.

### 📝 Configuration Handling

All installation scripts support automatic configuration handling:

- **If config.json exists** in the same directory as the installation script, it will be automatically copied to the proper config location
- **Original config.json** is preserved in the current directory  
- **If no config.json found**, a default configuration will be created

#### Config Locations by Platform:
- **Linux**: `/opt/sentinelgo/.sentinelgo/config.json`
- **macOS**: `/opt/sentinelgo/.sentinelgo/config.json`
- **Windows**: `C:\SentinelGo\.sentinelgo\config.json`

---


## 🛠️ Installation Commands

The `install.sh` script supports multiple commands:

### Install (Default)
```bash
sudo ./install.sh install
```
- Installs SentinelGo as a system service
- Creates necessary directories and permissions
- Sets up auto-start on boot
- Starts the service immediately

### Update
```bash
sudo ./install.sh update
```
- Updates the binary while keeping configuration
- Restarts the service with new version

### Status Check
```bash
sudo ./install.sh status
```
- Shows current service status
- Displays log locations

### Uninstall
```bash
sudo ./install.sh uninstall
```
- Removes the service
- Optionally removes all data and user

### Help
```bash
./install.sh help
```
- Shows all available commands

---

## 🖥️ Platform-Specific Details

### Ubuntu/Debian/CentOS
- Uses **systemd** for service management
- Binary location: `/opt/sentinelgo/sentinelgo`
- Config location: `/opt/sentinelgo/.sentinelgo/`
- Service name: `sentinelgo`
- Runs as **root** user for full system access

#### Service Management:
```bash
sudo systemctl start sentinelgo      # Start
sudo systemctl stop sentinelgo       # Stop
sudo systemctl restart sentinelgo    # Restart
sudo systemctl status sentinelgo     # Status
sudo systemctl enable sentinelgo     # Enable on boot
sudo systemctl disable sentinelgo    # Disable on boot
journalctl -u sentinelgo -f         # View logs
```

### macOS
- Uses **launchd** for service management
- Binary location: `/opt/sentinelgo/sentinelgo`
- Config location: `/opt/sentinelgo/.sentinelgo/`
- Service name: `com.sentinelgo.agent`
- Runs as **current user** for better compatibility

#### Service Management:
```bash
sudo launchctl load /Library/LaunchDaemons/com.sentinelgo.agent.plist    # Load
sudo launchctl unload /Library/LaunchDaemons/com.sentinelgo.agent.plist  # Unload
sudo launchctl start com.sentinelgo.agent                               # Start
sudo launchctl stop com.sentinelgo.agent                                # Stop
launchctl list | grep sentinelgo                                        # Status
tail -f /var/log/sentinelgo.log                                         # Logs
tail -f /var/log/sentinelgo.error.log                                   # Error logs
```

#### macOS Script Commands:
```bash
install-macos.sh install        # Install service
install-macos.sh uninstall      # Remove service
install-macos.sh help           # Show help
```

#### macOS Security Alert:
If you see "sentinelgo was blocked because it is not from an identified developer":
1. Open **System Settings → Privacy & Security**
2. Scroll down and click **"Allow Anyway"** next to sentinelgo
3. Run the installation script again

## 🐧 Linux

### Prerequisites
- Linux (systemd-based distro: Ubuntu 18.04+, Debian 10+, CentOS 8+, RHEL 8+, etc.)
- `sudo` or root access

### Option 1: Using Installation Script (Recommended)
```bash
# Download Linux binary from GitHub Releases
# https://github.com/habib45/SentinelGo/releases/latest

# Run as root
sudo ./install.sh install
```

### Option 2: Manual Installation

#### 1. Download the Binary
Download the latest Linux binary from GitHub Releases:
```
https://github.com/habib45/SentinelGo/releases/latest
```
Choose file named `sentinelgo-linux-amd64` (or `-arm64` for ARM).

#### 2. Create Directory and Copy Binary
```bash
sudo mkdir -p /opt/sentinelgo
sudo cp sentinelgo-linux-amd64 /opt/sentinelgo/sentinelgo
sudo chmod +x /opt/sentinelgo/sentinelgo
```

#### 3. Create Configuration
```bash
sudo mkdir -p /opt/sentinelgo/.sentinelgo
# Optional: Copy your custom config.json if you have one
# sudo cp ./config.json /opt/sentinelgo/.sentinelgo/config.json

# Or create default config
echo '{"heartbeat_interval":"5m0s","auto_update":false}' | sudo tee /opt/sentinelgo/.sentinelgo/config.json
```

#### 4. Create systemd Service
```bash
sudo tee /etc/systemd/system/sentinelgo.service > /dev/null <<'EOF'
[Unit]
Description=SentinelGo Agent
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/sentinelgo
ExecStart=/opt/sentinelgo/sentinelgo -run -config .sentinelgo/config.json
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sentinelgo
Environment=HOME=/opt/sentinelgo
Environment=XDG_CONFIG_HOME=/opt/sentinelgo/.sentinelgo

[Install]
WantedBy=multi-user.target
EOF
```

#### 5. Enable and Start Service
```bash
sudo systemctl daemon-reload
sudo systemctl enable sentinelgo
sudo systemctl start sentinelgo
```

#### 6. Verify Installation
```bash
sudo systemctl status sentinelgo
```
Should show `active (running)`.


### Service Management:
```bash
sudo systemctl start sentinelgo         # Start
sudo systemctl stop sentinelgo          # Stop
sudo systemctl restart sentinelgo       # Restart
sudo systemctl status sentinelgo        # Status
sudo systemctl enable sentinelgo        # Enable on boot
sudo systemctl disable sentinelgo       # Disable on boot
sudo journalctl -u sentinelgo -f       # View logs
```

### Uninstall (if needed)
```bash
sudo systemctl stop sentinelgo
sudo systemctl disable sentinelgo
sudo rm -f /etc/systemd/system/sentinelgo.service
sudo systemctl daemon-reload
sudo rm -rf /opt/sentinelgo
```

### Troubleshooting

#### Service Not Starting
```bash
# Check service status
sudo systemctl status sentinelgo

# Check for errors
sudo journalctl -u sentinelgo -n 20

# Check binary permissions
ls -la /opt/sentinelgo/sentinelgo
```

#### Permission Issues
```bash
# Fix ownership (runs as root)
sudo chown -R root:root /opt/sentinelgo

# Fix permissions
sudo chmod +x /opt/sentinelgo/sentinelgo
```

### Windows

#### Option 1: Using Installation Script (Recommended)
```cmd
# Download the Windows binary from GitHub Releases
# https://github.com/habib45/SentinelGo/releases/latest

# Run as Administrator
install.bat install
```

#### Windows Script Commands:
```cmd
install.bat install        # Install service
install.bat uninstall      # Remove service
install.bat update         # Update binary
install.bat status          # Show service status
install.bat help            # Show help
```


#### Option 2: Manual Windows Installation
```cmd
# 1. Create directory
mkdir C:\opt\sentinelgo

# 2. Copy binary (choose your architecture)
copy sentinelgo-windows-amd64.exe C:\opt\sentinelgo\sentinelgo.exe

# 3. Create config directory
mkdir C:\opt\sentinelgo\.sentinelgo

# 4. Create config file (optional: copy your custom config.json)
# copy config.json C:\opt\sentinelgo\.sentinelgo\config.json

# Or create default config
echo {"heartbeat_interval":"5m0s","auto_update":false} > C:\opt\sentinelgo\.sentinelgo\config.json

# 5. Install as service (Run as Administrator)
sc.exe create sentinelgo binPath= "C:\opt\sentinelgo\sentinelgo.exe -run" start= auto
sc.exe description sentinelgo "SentinelGo Agent - Cross-platform monitoring service"
sc.exe start sentinelgo
```

**Windows Service Management:**
- Uses **Windows Service** for service management
- Binary location: `C:\opt\sentinelgo\sentinelgo.exe`
- Config location: `C:\opt\sentinelgo\.sentinelgo\`
- Service name: `sentinelgo`

#### Service Management (Run as Administrator):
```cmd
sc.exe start sentinelgo          # Start
sc.exe stop sentinelgo           # Stop
sc.exe query sentinelgo          # Status
sc.exe delete sentinelgo         # Delete service
```

#### Windows Script Commands:
```cmd
install.bat install        # Install service
install.bat uninstall      # Remove service
install.bat update         # Update binary
install.bat status         # Show status
install.bat help           # Show help
```

---

## 🔧 Troubleshooting

### Service Not Starting
1. Check permissions: Ensure running as root/administrator
2. Check logs: Use platform-specific log commands above
3. Verify binary: Ensure correct binary for your OS

### Permission Errors
- **Linux/macOS**: Always use `sudo`
- **Windows**: Right-click and "Run as Administrator"

### Binary Not Found
- Ensure the binary is in the same directory as the installation script
- Verify you downloaded the correct binary for your OS and architecture
- Check file permissions: binary should be executable

### Port Conflicts
- SentinelGo uses HTTPS (port 443) for backend communication
- Check if another service is blocking network access
- Verify firewall settings allow outbound connections

---

## 📁 File Locations After Installation

### Linux/macOS
```
/opt/sentinelgo/
├── sentinelgo              # Main binary
└── .sentinelgo/
    └── config.json         # Configuration file
```

### Windows
```
C:\SentinelGo\
├── sentinelgo.exe          # Main binary
└── .sentinelgo\
    └── config.json         # Configuration file
```
## 🗑️ Complete Removal

To completely remove SentinelGo:

```bash
# Linux/macOS
sudo ./install.sh uninstall
# Answer 'y' when asked to remove all data

# Windows
./install.bat uninstall
# Run as Administrator
```

This removes:
- Service configuration
- Binary files
- Configuration files
- Service user account (Linux only)
- Log files
- Auto-start settings

---
