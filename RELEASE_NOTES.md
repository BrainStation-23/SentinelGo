# SentinelGo v2.1.11 Release Notes

## What's New

### Display Serial Number Fix (Linux)
- **Enhanced Serial Detection**: Fixed issue where display serial numbers were stored as "Unknown" on Linux systems
- **Multiple Fallback Methods**: Implemented cascading fallback approach for serial number detection:
  - Standard EDID parsing
  - edid-decode tool
  - xrandr --props output parsing
  - DMI system serial for internal displays
  - EDID hash generation as final fallback
- **Unique Identifiers**: Generated hash-based identifiers from EDID data when no serial is available
- **Improved Reliability**: Serial numbers are now guaranteed to be populated with actual values or unique identifiers

## Bug Fixes
- **Display Serial Number**: Resolved issue where Linux display serial numbers were always "Unknown"
- **File Permissions**: Fixed audit-config-sample.json permissions for test execution
- **Code Quality**: Resolved golangci-lint warnings with appropriate suppressions

## Technical Details
- **EDID Hash Generation**: Creates unique hex-based identifiers from manufacturer ID, model, and EDID bytes
- **Cross-Platform Serial Detection**: Enhanced detection methods specific to Linux systems
- **xrandr Integration**: Parses xrandr --props output to extract EDID hex data
- **DMI Fallback**: Uses system serial from /sys/class/dmi/id for internal displays

---
