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
REM
REM The binary lives under %ProgramFiles% and mutable state under %ProgramData%.
REM The agent used to install into C:\SentinelGo, and a directory created directly
REM under the drive root inherits C:\'s "Authenticated Users:(OI)(CI)(IO)(M)" ACE
REM -- an inherit-only Modify grant that propagates to every child. That made
REM sentinelgo.exe writable by any standard user while the service ran it as
REM LocalSystem (CyberStation PT-2026-001 finding #1). %ProgramFiles% denies
REM non-administrator writes by default; %ProgramData% does not, which is why both
REM are given an explicit protected ACL below.
set SERVICE_NAME=SentinelGo
set BINARY_NAME=sentinelgo.exe
set INSTALL_DIR=%ProgramFiles%\SentinelGo
set CONFIG_DIR=%ProgramData%\SentinelGo
REM The pre-relocation install directory. It is removed, never reused: agents are
REM provisioned by clean install against a freshly built backend, so anything left
REM there belongs to a decommissioned deployment -- including a config.json holding
REM credentials for a backend that no longer exists.
set LEGACY_DIR=C:\SentinelGo
set REQUIRED_BINARY=sentinelgo-windows-amd64.exe

REM Check administrator privileges
REM
REM This used to write a VBScript into %TEMP% and execute it to trigger UAC.
REM Dropping an executable script into a world-writable directory and then running
REM it is a poor pattern in an installer that goes on to create a LocalSystem
REM service, and it reliably trips antivirus and application allowlisting. Ask the
REM operator to elevate instead.
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Administrator privileges are required.
    echo [INFO] Right-click install.bat and choose "Run as administrator", or run
    echo [INFO] it from an elevated Command Prompt.
    pause
    exit /b 1
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
REM
REM The config is no longer shuffled through %TEMP%. It lives in %ProgramData%,
REM which this step does not touch, so the agent's identity survives a reinstall
REM without its credentials ever being copied to a temporary location.
echo [STEP 2] Checking for existing installation...
sc query "%SERVICE_NAME%" >nul 2>&1
if %errorLevel% equ 0 (
    echo [INFO] Existing installation detected - removing the service first...

    echo [INFO] Stopping existing service...
    sc stop "%SERVICE_NAME%" >nul 2>&1
    timeout /t 3 /nobreak >nul

    echo [INFO] Deleting existing service...
    sc delete "%SERVICE_NAME%" >nul 2>&1
    timeout /t 2 /nobreak >nul

    echo [SUCCESS] Existing service removed
) else (
    echo [INFO] No existing installation found - clean install
)

REM Remove only the binary directory, never the state directory.
if exist "%INSTALL_DIR%\%BINARY_NAME%" (
    del /F /Q "%INSTALL_DIR%\%BINARY_NAME%" >nul 2>&1
)

REM Remove the pre-relocation tree outright. It is the directory whose inherited
REM ACL caused the privilege escalation, and it holds a cleartext config for a
REM decommissioned backend. Hardening it would leave those credentials on disk;
REM deleting it is both simpler and strictly safer.
if exist "%LEGACY_DIR%" (
    echo [INFO] Removing the previous installation at %LEGACY_DIR%...
    rmdir /S /Q "%LEGACY_DIR%" >nul 2>&1
    if exist "%LEGACY_DIR%" (
        echo [WARNING] Could not fully remove %LEGACY_DIR%. It may contain credentials
        echo [WARNING] for the previous deployment - delete it manually.
    ) else (
        echo [SUCCESS] Previous installation removed
    )
)
echo.

REM Step 3: Prepare and harden the installation directories
echo [STEP 3] Preparing installation directories...

REM Refuse to install into a junction or symlink. A standard user can create a
REM directory under %ProgramData% before the installer runs, and a reparse point
REM there would silently redirect the agent's credentials somewhere of their
REM choosing.
dir /AL "%ProgramData%" 2>nul | find /I " SentinelGo" >nul && goto fail_reparse
dir /AL "%ProgramFiles%" 2>nul | find /I " SentinelGo" >nul && goto fail_reparse

if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
    echo [SUCCESS] Created %INSTALL_DIR%
)
if not exist "%CONFIG_DIR%" (
    mkdir "%CONFIG_DIR%"
    echo [SUCCESS] Created %CONFIG_DIR%
)

REM Apply an explicit, protected ACL to both directories BEFORE anything is
REM copied into them, so every file inherits the correct permissions rather than
REM being created permissively and fixed afterwards.
REM
REM SIDs are used literally because group names are localised: "Administrators"
REM is "Administratoren" on a German system and the command would silently fail.
REM   S-1-5-18     = NT AUTHORITY\SYSTEM
REM   S-1-5-32-544 = BUILTIN\Administrators
REM
REM /inheritance:r is the essential part -- it severs inheritance from the parent.
REM Note there is deliberately no grant for BUILTIN\Users: %CONFIG_DIR% holds
REM agent_secret and both tokens in cleartext, so read access is precisely what is
REM being denied.
call :harden_dir "%INSTALL_DIR%" || goto fail_hardening
call :harden_dir "%CONFIG_DIR%"  || goto fail_hardening

echo [SUCCESS] Installation directories hardened (SYSTEM and Administrators only)
echo.

REM Step 4: Deploy Configuration File
echo [STEP 4] Deploying configuration file...
REM The per-agent config.json ships in the same zip as this installer. It is the
REM only source of the agent's identity, so there is no fabricated fallback: a
REM generated default would name a backend this deployment does not use and carry
REM no credentials, producing an agent that starts, fails to authenticate, and
REM looks installed while reporting nothing.
if exist "config.json" (
    copy "config.json" "%CONFIG_DIR%\config.json" /Y >nul 2>&1
    if !errorLevel! equ 0 (
        echo [SUCCESS] Configuration deployed to %CONFIG_DIR%\config.json
    ) else (
        echo [ERROR] Failed to deploy configuration
        pause
        exit /b 1
    )
) else if exist "%CONFIG_DIR%\config.json" (
    REM Reinstalling over an existing agent: keep its identity.
    echo [INFO] Keeping the existing configuration at %CONFIG_DIR%\config.json
) else (
    echo [ERROR] No config.json found next to this installer, and none already
    echo [ERROR] installed at %CONFIG_DIR%.
    echo [INFO] config.json is generated per agent and ships in the same zip as
    echo [INFO] this installer. Extract the whole zip and run install.bat from
    echo [INFO] inside it.
    pause
    exit /b 1
)

REM Lock the credentials down immediately. The directory ACL already covers this,
REM but the file is the thing that matters and an explicit grant is cheap.
icacls "%CONFIG_DIR%\config.json" /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" /Q >nul 2>&1
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
echo.

REM Step 6: Install New Service with Auto-Start and Recovery
echo [STEP 6] Installing Windows service with auto-start...
REM The binary path MUST be quoted: %ProgramFiles% contains a space, and an
REM unquoted service path is the textbook escalation -- the SCM would try
REM C:\Program.exe first. obj= is stated explicitly rather than relying on the
REM LocalSystem default.
sc create "%SERVICE_NAME%" binPath= "\"%INSTALL_DIR%\%BINARY_NAME%\" -config \"%CONFIG_DIR%\config.json\"" start= auto obj= "LocalSystem" DisplayName= "SentinelGo Agent" >nul 2>&1
if %errorLevel% equ 0 (
    echo [SUCCESS] Service created with auto-start enabled
) else (
    echo [ERROR] Failed to create service (error code: %errorLevel%)
    echo [INFO] Continuing with installation - you can create the service manually later
    echo [INFO] Manual service creation (note the quoting - the path contains a space):
    echo [INFO]   sc create "%SERVICE_NAME%" binPath= "\"%INSTALL_DIR%\%BINARY_NAME%\" -config \"%CONFIG_DIR%\config.json\"" start= auto obj= "LocalSystem" DisplayName= "SentinelGo Agent"
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

:harden_dir
REM Apply the protected ACL to the directory named by %~1.
REM Returns a non-zero exit code on failure so the caller can abort.
REM
REM %~1 strips the caller's quotes so the path can be re-quoted safely; using %1
REM directly would produce "C:\Program Files\SentinelGo"\* for the wildcard below.
set "_HD_DIR=%~1"

REM Take ownership first. An owner holds implicit WRITE_DAC regardless of the
REM DACL, so if a standard user pre-created the directory, a restrictive ACL
REM alone would not stop them from simply rewriting it.
icacls "%_HD_DIR%" /setowner "*S-1-5-32-544" /T /C /Q >nul 2>&1

icacls "%_HD_DIR%" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" /Q >nul 2>&1
if %errorLevel% neq 0 (
    set "_HD_DIR="
    exit /b 1
)

REM Force any pre-existing children to drop explicit ACEs and inherit the above.
REM The wildcard matters: /reset on the directory itself would re-enable
REM inheritance from its parent and pull the vulnerable ACE straight back in.
icacls "%_HD_DIR%\*" /reset /T /C /Q >nul 2>&1

set "_HD_DIR="
exit /b 0

:fail_reparse
echo [ERROR] An existing SentinelGo directory is a junction or symbolic link.
echo [ERROR] Refusing to install: the agent's files could be redirected elsewhere.
echo [INFO] Remove the link and run the installer again.
pause
exit /b 1

:fail_hardening
echo [ERROR] Failed to apply directory permissions.
echo [ERROR] Refusing to install: the agent runs as LocalSystem, and installing it
echo [ERROR] into a directory writable by standard users is a privilege escalation.
pause
exit /b 1

:unknown
echo [ERROR] Unknown command: %COMMAND%
echo [INFO] Run 'install.bat help' for usage information
pause
exit /b 1

:end
pause