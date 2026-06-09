#!/bin/bash

# macOS SentinelGo Diagnostic Script
# Helps troubleshoot launchd service and update issues

echo "=== SentinelGo macOS Diagnostic ==="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "Note: Some commands may require sudo. Run with sudo for full diagnostics."
   echo ""
fi

# 1. Check if SentinelGo binary exists
echo "1. Checking SentinelGo binary..."
if [ -f "/opt/sentinelgo/sentinelgo" ]; then
    echo "✅ Binary found at /opt/sentinelgo/sentinelgo"
    echo "   Version: $(/opt/sentinelgo/sentinelgo -version 2>/dev/null || echo 'Unknown')"
    echo "   Permissions: $(ls -la /opt/sentinelgo/sentinelgo)"
else
    echo "❌ Binary not found at /opt/sentinelgo/sentinelgo"
    echo "   Expected location: /opt/sentinelgo/sentinelgo"
fi
echo ""

# 2. Check launchd plist file
echo "2. Checking launchd plist..."
if [ -f "/Library/LaunchDaemons/com.sentinelgo.agent.plist" ]; then
    echo "✅ Plist file found"
    echo "   Contents:"
    cat /Library/LaunchDaemons/com.sentinelgo.agent.plist | grep -A 5 -B 5 "ProgramArguments"
else
    echo "❌ Plist file not found"
    echo "   Expected: /Library/LaunchDaemons/com.sentinelgo.agent.plist"
fi
echo ""

# 3. Check launchd service status
echo "3. Checking launchd service status..."
if launchctl list | grep -q "com.sentinelgo.agent"; then
    echo "✅ Service found in launchctl list"
    launchctl list | grep "com.sentinelgo.agent"
else
    echo "❌ Service not found in launchctl list"
fi
echo ""

# 4. Check running processes
echo "4. Checking running SentinelGo processes..."
if pgrep -f "sentinelgo" > /dev/null; then
    echo "✅ SentinelGo processes found:"
    ps aux | grep sentinelgo | grep -v grep
    echo ""
    echo "Process details:"
    pgrep -f "sentinelgo" | while read pid; do
        echo "  PID $pid: $(ps -p $pid -o command=)"
        echo "    Version: $(/opt/sentinelgo/sentinelgo -version 2>/dev/null || echo 'Unknown')"
    done
else
    echo "❌ No SentinelGo processes found"
fi
echo ""

# 5. Check logs
echo "5. Checking logs..."
if [ -f "/var/log/sentinelgo.log" ]; then
    echo "✅ Application log found (last 10 lines):"
    tail -10 /var/log/sentinelgo.log
else
    echo "❌ Application log not found at /var/log/sentinelgo.log"
fi
echo ""

if [ -f "/var/log/sentinelgo.err" ]; then
    echo "✅ Error log found (last 10 lines):"
    tail -10 /var/log/sentinelgo.err
else
    echo "❌ Error log not found at /var/log/sentinelgo.err"
fi
echo ""

# 6. Test binary execution
echo "6. Testing binary execution..."
if [ -f "/opt/sentinelgo/sentinelgo" ]; then
    echo "Testing version command:"
    timeout 5s /opt/sentinelgo/sentinelgo -version || echo "❌ Version command failed"
    echo ""
    echo "Testing status command:"
    timeout 5s /opt/sentinelgo/sentinelgo -status || echo "❌ Status command failed"
else
    echo "❌ Cannot test - binary not found"
fi
echo ""

echo "=== Diagnostic Complete ==="
echo ""
echo "Common fixes:"
echo "1. If plist missing: sudo ./sentinelgo -install"
echo "2. If service not running: sudo launchctl load -w /Library/LaunchDaemons/com.sentinelgo.agent.plist"
echo "3. If processes stuck: ./sentinelgo -stop"
echo "4. If binary missing: sudo cp sentinelgo /opt/sentinelgo/sentinelgo && sudo chmod +x /opt/sentinelgo/sentinelgo"
