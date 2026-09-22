@echo off
REM SentinelGo Windows Agent Installation Script
REM Enhanced version with better error handling and auto-start configuration
REM Usage: install.bat [install|uninstall|update|status|help|enable-autostart|disable-autostart]
REM 
REM To run as administrator:
REM   - Right-click install.bat and select "Run as administrator"
REM   - Or simply double-click (will auto-elevate if possible)

setlocal enabledelayedexpansion

REM Force working directory to script location (fixes Run as Administrator)
cd /d "%~dp0"

REM Configuration
set SERVICE_NAME=SentinelGo
set BINARY_NAME=sentinelgo.exe
set INSTALL_DIR=C:\SentinelGo
set CONFIG_DIR=%INSTALL_DIR%\.sentinelgo
set REQUIRED_BINARY=sentinelgo-windows-amd64.exe

REM Check administrator privileges and auto-elevate if needed
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [INFO] Administrator privileges required
    echo [INFO] Attempting to auto-elevate...
    
    REM Try to auto-elevate using VBScript (works from CMD)
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~f0", "install", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs" >nul 2>&1
    exit /b 0
)

REM Get command from parameters
set COMMAND=%1
if "%COMMAND%"=="" set COMMAND=install

REM Command routing
if "%COMMAND%"=="install" goto install
if "%COMMAND%"=="uninstall" goto uninstall
if "%COMMAND%"=="update" goto update
if "%COMMAND%"=="status" goto status
if "%COMMAND%"=="help" goto help
if "%COMMAND%"=="enable-autostart" goto enable-autostart
if "%COMMAND%"=="disable-autostart" goto disable-autostart
goto unknown

:install
echo ========================================
echo SentinelGo Windows Agent Installation
echo ========================================
echo.

REM Step 1: Locate Installation Artifacts
echo [STEP 1] Locating installation artifacts...
if not exist "%REQUIRED_BINARY%" (
    echo [ERROR] Required binary not found: %REQUIRED_BINARY%
    echo [INFO] Ensure sentinelgo-windows-amd64.exe is in the same directory as install.bat
    echo [INFO] Download from: https://github.com/habib45/SentinelGo/releases
    pause
    exit /b 1
)
echo [SUCCESS] Found %REQUIRED_BINARY%
echo.

REM Step 2: Uninstall existing installation (if present)
echo [STEP 2] Checking for existing installation...
set EXISTING_CONFIG_BACKUP=%TEMP%\sentinelgo_config_backup.json
sc query "%SERVICE_NAME%" >nul 2>&1
if %errorLevel% equ 0 (
    echo [INFO] Existing installation detected - performing clean uninstall first...

    REM Preserve config to TEMP before wiping install directory
    if exist "%CONFIG_DIR%\config.json" (
        copy "%CONFIG_DIR%\config.json" "%EXISTING_CONFIG_BACKUP%" /Y >nul 2>&1
        if !errorLevel! equ 0 (
            echo [SUCCESS] Preserved existing config to %EXISTING_CONFIG_BACKUP%
        ) else (
            echo [WARNING] Failed to preserve existing config - agent identity may be lost
        )
    )

    echo [INFO] Stopping existing service...
    sc stop "%SERVICE_NAME%" >nul 2>&1
    timeout /t 3 /nobreak >nul

    echo [INFO] Deleting existing service...
    sc delete "%SERVICE_NAME%" >nul 2>&1
    timeout /t 2 /nobreak >nul

    echo [INFO] Removing installation directory...
    if exist "%INSTALL_DIR%" (
        rmdir /S /Q "%INSTALL_DIR%" >nul 2>&1
        if !errorLevel! equ 0 (
            echo [SUCCESS] Installation directory removed
        ) else (
            echo [WARNING] Failed to fully remove installation directory
        )
    )

    echo [SUCCESS] Existing installation removed
) else (
    echo [INFO] No existing installation found - clean install
    if exist "%EXISTING_CONFIG_BACKUP%" del "%EXISTING_CONFIG_BACKUP%" >nul 2>&1
)
echo.

REM Step 3: Prepare Installation Directory
echo [STEP 3] Preparing installation directory...
if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
    echo [SUCCESS] Created %INSTALL_DIR%
)
if not exist "%CONFIG_DIR%" (
    mkdir "%CONFIG_DIR%"
    echo [SUCCESS] Created %CONFIG_DIR%
)

REM Harden directory permissions: remove inherited ACEs, grant SYSTEM and
REM Administrators full control only. This prevents low-privilege users from
REM replacing sentinelgo.exe (binary planting / local privilege escalation).
echo [INFO] Hardening directory permissions...
icacls "%INSTALL_DIR%" /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /grant:r "BUILTIN\Administrators:(OI)(CI)F" >nul 2>&1
if %errorLevel% equ 0 (
    echo [SUCCESS] Directory permissions hardened - standard users cannot modify %INSTALL_DIR%
) else (
    echo [WARNING] Failed to harden directory permissions - installation may be vulnerable to binary replacement
    echo [INFO] Manually run: icacls "%INSTALL_DIR%" /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /grant:r "BUILTIN\Administrators:(OI)(CI)F"
)
echo.

REM Step 4: Deploy Configuration File
echo [STEP 4] Deploying configuration file...
if exist "%EXISTING_CONFIG_BACKUP%" (
    REM Restore preserved config from previous installation (keeps agent identity)
    copy "%EXISTING_CONFIG_BACKUP%" "%CONFIG_DIR%\config.json" /Y >nul 2>&1
    if !errorLevel! equ 0 (
        echo [SUCCESS] Restored existing agent configuration (identity preserved)
        del "%EXISTING_CONFIG_BACKUP%" >nul 2>&1
    ) else (
        echo [WARNING] Failed to restore existing config - falling back to bundled config
        goto deploy_bundled_config
    )
) else (
    :deploy_bundled_config
    if exist "config.json" (
        copy "config.json" "%CONFIG_DIR%\config.json" /Y >nul 2>&1
        if !errorLevel! equ 0 (
            echo [SUCCESS] Configuration deployed to %CONFIG_DIR%\config.json
        ) else (
            echo [ERROR] Failed to deploy configuration
            pause
            exit /b 1
        )
    ) else (
        echo [WARNING] No config.json found in current directory
        echo [INFO] Creating default configuration...
        (
            echo {
            echo   "heartbeat_interval": "5m0s",
            echo   "github_owner": "habib45",
            echo   "github_repo": "SentinelGo",
            echo   "current_version": "v2.1.4",
            echo   "auto_update": true,
            echo   "supabase_url": "https://tvoszjyryzlfdampkozd.supabase.co",
            echo   "device_id": "",
            echo   "agent_uuid": "",
            echo   "agent_secret": "",
            echo   "agent_id": "",
            echo   "access_token": "",
            echo   "refresh_token": ""
            echo }
        ) > "%CONFIG_DIR%\config.json"
        echo [SUCCESS] Default configuration created
    )
)
echo.

REM Step 5: Deploy Agent Binary
echo [STEP 5] Deploying agent binary...
copy "%REQUIRED_BINARY%" "%INSTALL_DIR%\%BINARY_NAME%" /Y >nul 2>&1
if %errorLevel% equ 0 (
    echo [SUCCESS] Binary deployed and renamed to %BINARY_NAME%
) else (
    echo [ERROR] Failed to deploy binary
    pause
    exit /b 1
)

REM Explicitly lock the binary itself in case it was written before the
REM directory ACL was applied (e.g. re-install over an existing directory
REM whose permissions had drifted).
icacls "%INSTALL_DIR%\%BINARY_NAME%" /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:F" /grant:r "BUILTIN\Administrators:F" >nul 2>&1
if %errorLevel% equ 0 (
    echo [SUCCESS] Binary permissions hardened
) else (
    echo [WARNING] Failed to harden binary permissions
)
echo.

REM Step 6: Install New Service with Auto-Start and Recovery
echo [STEP 6] Installing Windows service with auto-start...
sc create "%SERVICE_NAME%" binPath= "%INSTALL_DIR%\%BINARY_NAME%" start= auto DisplayName= "SentinelGo Agent" >nul 2>&1
if %errorLevel% equ 0 (
    echo [SUCCESS] Service created with auto-start enabled
) else (
    echo [ERROR] Failed to create service (error code: %errorLevel%)
    echo [INFO] Continuing with installation - you can create the service manually later
    echo [INFO] Manual service creation: sc create "%SERVICE_NAME%" binPath= "%INSTALL_DIR%\%BINARY_NAME%" start= auto DisplayName= "SentinelGo Agent"
)

echo [INFO] Configuring service recovery (restart on failure)...
sc failure "%SERVICE_NAME%" reset= 86400 actions= restart/5000/restart/10000/restart/30000 >nul 2>&1
if %errorLevel% equ 0 (
    echo [SUCCESS] Service recovery configured (restart on failure)
) else (
    echo [WARNING] Failed to configure service recovery
)

echo [INFO] Setting service to restart on system reboot...
sc config "%SERVICE_NAME%" start= auto >nul 2>&1
if %errorLevel% equ 0 (
    echo [SUCCESS] Auto-start on boot enabled
) else (
    echo [WARNING] Failed to enable auto-start
)

echo [INFO] Forcefully starting service...
sc start "%SERVICE_NAME%" >nul 2>&1
timeout /t 3 /nobreak >nul

REM Verify service is running
sc query "%SERVICE_NAME%" | find "RUNNING" >nul 2>&1
if %errorLevel% equ 0 (
    echo [SUCCESS] Service is running
) else (
    echo [WARNING] Service may not be running, attempting force start...
    sc start "%SERVICE_NAME%" >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc query "%SERVICE_NAME%" | find "RUNNING" >nul 2>&1
    if %errorLevel% equ 0 (
        echo [SUCCESS] Service started successfully on retry
    ) else (
        echo [ERROR] Service failed to start
        echo [INFO] Check service status with: sc query %SERVICE_NAME%
        echo [INFO] Start manually with: sc start %SERVICE_NAME%
    )
)
echo.

REM Step 7: Runtime Update Check Info
echo [STEP 7] Runtime update configuration...
echo [INFO] Agent configured with auto-update capability
echo [INFO] Update endpoint: GitHub Releases API

REM Read current version from config.json
set CURRENT_VERSION=
if exist "%CONFIG_DIR%\config.json" (
    for /f "usebackq tokens=*" %%a in ("%CONFIG_DIR%\config.json") do (
        set line=%%a
        echo !line! | find "current_version" >nul
        if !errorLevel! equ 0 (
            set CURRENT_VERSION=!line:*"current_version": "=!
            set CURRENT_VERSION=!CURRENT_VERSION:",=!
            set CURRENT_VERSION=!CURRENT_VERSION: =!
        )
    )
)
if "%CURRENT_VERSION%"=="" (
    set CURRENT_VERSION=Unknown
)
echo [INFO] Current version: %CURRENT_VERSION%
echo [INFO] Auto-update enabled in config.json
echo.

echo ========================================
echo Installation Complete!
echo ========================================
echo.
echo Service Name: %SERVICE_NAME%
echo Install Path: %INSTALL_DIR%
echo Config Path:  %CONFIG_DIR%\config.json
echo.
echo Useful commands:
echo   install.bat status              - Check service status
echo   install.bat uninstall           - Remove service
echo   install.bat update              - Update to latest version
echo   install.bat enable-autostart    - Enable auto-start on boot
echo   install.bat disable-autostart   - Disable auto-start
echo.
echo The agent will automatically check for updates on startup.
echo.

REM Restart prompt
echo Your computer needs a restart to properly work this application.
echo.
set /p RESTART_CHOICE="Do you want to restart? (y/yes n/no): "
if /i "%RESTART_CHOICE%"=="y" goto restart_computer
if /i "%RESTART_CHOICE%"=="yes" goto restart_computer
echo Restart canceled. Please restart later to ensure proper operation.
echo.
goto end

:restart_computer
echo [INFO] Restarting computer in 10 seconds...
shutdown /r /f /t 10
goto end

:uninstall
echo ========================================
echo SentinelGo Uninstall
echo ========================================
echo.

echo [INFO] Stopping service...
sc stop "%SERVICE_NAME%" >nul 2>&1
timeout /t 2 /nobreak >nul

echo [INFO] Deleting service...
sc delete "%SERVICE_NAME%" >nul 2>&1
if %errorLevel% equ 0 (
    echo [SUCCESS] Service removed
) else (
    echo [WARNING] Service not found or already removed
)

echo [INFO] Removing files...
if exist "%INSTALL_DIR%" (
    rmdir /S /Q "%INSTALL_DIR%" >nul 2>&1
    if %errorLevel% equ 0 (
        echo [SUCCESS] Installation directory removed
    ) else (
        echo [WARNING] Failed to remove installation directory
        echo [INFO] You may need to manually delete: %INSTALL_DIR%
    )
) else (
    echo [INFO] Installation directory not found
)

echo.
echo [SUCCESS] Uninstall complete!
goto end

:update
echo ========================================
echo SentinelGo Update
echo ========================================
echo.

REM Check if binary exists
if not exist "%REQUIRED_BINARY%" (
    echo [ERROR] Update binary not found: %REQUIRED_BINARY%
    echo [INFO] Download latest version from: https://github.com/habib45/SentinelGo/releases
    pause
    exit /b 1
)

echo [INFO] Stopping service...
sc stop "%SERVICE_NAME%" >nul 2>&1
timeout /t 3 /nobreak >nul

echo [INFO] Updating binary...
copy "%REQUIRED_BINARY%" "%INSTALL_DIR%\%BINARY_NAME%" /Y >nul 2>&1
if %errorLevel% equ 0 (
    echo [SUCCESS] Binary updated
) else (
    echo [ERROR] Failed to update binary
    pause
    exit /b 1
)

REM Re-apply hardened permissions after binary replacement.
icacls "%INSTALL_DIR%\%BINARY_NAME%" /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:F" /grant:r "BUILTIN\Administrators:F" >nul 2>&1
if %errorLevel% equ 0 (
    echo [SUCCESS] Binary permissions hardened
) else (
    echo [WARNING] Failed to harden binary permissions after update
)

echo [INFO] Starting service...
sc start "%SERVICE_NAME%" >nul 2>&1
if %errorLevel% equ 0 (
    echo [SUCCESS] Service restarted
) else (
    echo [WARNING] Service start may have failed
)

echo.
echo [SUCCESS] Update complete!
goto end

:status
echo ========================================
echo SentinelGo Status
echo ========================================
echo.

echo [INFO] Service Status:
sc query "%SERVICE_NAME%"
echo.

echo [INFO] Service Configuration:
sc qc "%SERVICE_NAME%" | find "START_TYPE"
echo.

echo [INFO] Installation Details:
if exist "%INSTALL_DIR%\%BINARY_NAME%" (
    echo Binary: [INSTALLED] %INSTALL_DIR%\%BINARY_NAME%
) else (
    echo Binary: [MISSING] %INSTALL_DIR%\%BINARY_NAME%
)

if exist "%CONFIG_DIR%\config.json" (
    echo Config: [EXISTS] %CONFIG_DIR%\config.json
) else (
    echo Config: [MISSING] %CONFIG_DIR%\config.json
)
echo.
goto end

:enable-autostart
echo ========================================
echo Enable Auto-Start
echo ========================================
echo.

echo [INFO] Enabling auto-start for SentinelGo service...
sc config "%SERVICE_NAME%" start= auto >nul 2>&1
if %errorLevel% equ 0 (
    echo [SUCCESS] Service configured to start automatically on boot
    echo [INFO] The service will now start automatically when Windows starts
) else (
    echo [ERROR] Failed to enable auto-start (error code: %errorLevel%)
    echo [INFO] Verify service exists with: install.bat status
    pause
    exit /b 1
)
echo.
goto end

:disable-autostart
echo ========================================
echo Disable Auto-Start
echo ========================================
echo.

echo [INFO] Disabling auto-start for SentinelGo service...
sc config "%SERVICE_NAME%" start= demand >nul 2>&1
if %errorLevel% equ 0 (
    echo [SUCCESS] Service configured for manual start
    echo [INFO] The service will no longer start automatically on boot
    echo [INFO] Start manually with: sc start %SERVICE_NAME%
) else (
    echo [ERROR] Failed to disable auto-start (error code: %errorLevel%)
    echo [INFO] Verify service exists with: install.bat status
    pause
    exit /b 1
)
echo.
goto end

:help
echo ========================================
echo SentinelGo Installation Script Help
echo ========================================
echo.
echo Usage: install.bat [command]
echo.
echo Commands:
echo   install              Install SentinelGo service (default)
echo   uninstall            Remove SentinelGo service completely
echo   update               Update to new binary version
echo   status               Check service and installation status
echo   enable-autostart     Configure service to start on boot
echo   disable-autostart    Configure service for manual start
echo   help                 Show this help message
echo.
echo Installation Requirements:
echo   - Administrator privileges
echo   - sentinelgo-windows-amd64.exe in current directory
echo   - config.json (optional, will create default)
echo.
echo Examples:
echo   install.bat                    # Install service
echo   install.bat install            # Install service (explicit)
echo   install.bat uninstall          # Remove completely
echo   install.bat status             # Check status
echo   install.bat update             # Update binary
echo   install.bat enable-autostart   # Start on boot
echo   install.bat disable-autostart  # Manual start only
echo.
echo Paths:
echo   Installation: %INSTALL_DIR%
echo   Configuration: %CONFIG_DIR%\config.json
echo   Service Name: %SERVICE_NAME%
echo.
echo Auto-Start Configuration:
echo   - enable-autostart: Service starts automatically on Windows boot
echo   - disable-autostart: Service must be started manually
echo   - Default on install: Manual start (use enable-autostart to change)
echo.
goto end

:unknown
echo [ERROR] Unknown command: %COMMAND%
echo [INFO] Run 'install.bat help' for usage information
pause
exit /b 1

:end
pause