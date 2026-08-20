@echo off
REM SentinelGo Windows Agent Installation Script
REM Enhanced version with better error handling and auto-start configuration
REM Usage: install.bat [install|clean-install|uninstall|update|status|help|enable-autostart|disable-autostart]
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

REM Resolve the requested operation before elevation so UAC relaunches the
REM same command instead of silently changing clean-install/uninstall to install.
set COMMAND=%~1
if "%COMMAND%"=="" set COMMAND=install

REM Check administrator privileges and auto-elevate if needed
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [INFO] Administrator privileges required
    echo [INFO] Attempting to auto-elevate...
    
    REM Try to auto-elevate using VBScript (works from CMD)
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~f0", "%COMMAND%", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs" >nul 2>&1
    exit /b 0
)

REM Command routing
if /I "%COMMAND%"=="install" goto install
if /I "%COMMAND%"=="clean-install" goto clean-install
if /I "%COMMAND%"=="uninstall" goto uninstall
if /I "%COMMAND%"=="update" goto update
if /I "%COMMAND%"=="status" goto status
if /I "%COMMAND%"=="help" goto help
if /I "%COMMAND%"=="enable-autostart" goto enable-autostart
if /I "%COMMAND%"=="disable-autostart" goto disable-autostart
goto unknown

:clean-install
set CLEAN_INSTALL=1
goto install

:install
if not defined CLEAN_INSTALL set CLEAN_INSTALL=0
echo ========================================
echo SentinelGo Windows Agent Installation
if "%CLEAN_INSTALL%"=="1" echo Mode: CLEAN INSTALL ^(old identity/config will be removed^)
if "%CLEAN_INSTALL%"=="0" echo Mode: UPGRADE ^(old identity/config will be preserved^)
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

REM Step 2: Remove every previous service/file installation. Detection is
REM independent: a manually deleted directory can leave an SCM service behind,
REM while a failed install can leave files without a registered service.
echo [STEP 2] Checking for existing installation...
set EXISTING_CONFIG_BACKUP=%TEMP%\sentinelgo_config_backup_%RANDOM%_%RANDOM%.json
set EXISTING_BINARY_BACKUP=%TEMP%\sentinelgo_binary_backup_%RANDOM%_%RANDOM%.exe
set EXISTING_TELEMETRY_STATE_BACKUP=%TEMP%\sentinelgo_telemetry_state_%RANDOM%_%RANDOM%.db
set EXISTING_TELEMETRY_QUEUE_BACKUP=%TEMP%\sentinelgo_telemetry_queue_%RANDOM%_%RANDOM%.db
set EXISTING_SERVICE=0
set EXISTING_FILES=0
sc query "%SERVICE_NAME%" >nul 2>&1
if %errorLevel% equ 0 set EXISTING_SERVICE=1
if exist "%INSTALL_DIR%" set EXISTING_FILES=1

if "%CLEAN_INSTALL%"=="0" if exist "%CONFIG_DIR%\config.json" (
    copy "%CONFIG_DIR%\config.json" "%EXISTING_CONFIG_BACKUP%" /Y >nul 2>&1
    if !errorLevel! neq 0 (
        echo [ERROR] Failed to preserve the existing config; aborting to protect agent identity
        exit /b 1
    )
    echo [SUCCESS] Preserved existing agent configuration
)
if "%CLEAN_INSTALL%"=="0" if exist "%INSTALL_DIR%\%BINARY_NAME%" (
    copy "%INSTALL_DIR%\%BINARY_NAME%" "%EXISTING_BINARY_BACKUP%" /Y >nul 2>&1
    if !errorLevel! neq 0 (
        echo [ERROR] Failed to preserve the existing executable; aborting upgrade
        if exist "%EXISTING_CONFIG_BACKUP%" del "%EXISTING_CONFIG_BACKUP%" >nul 2>&1
        exit /b 1
    )
    echo [SUCCESS] Preserved previous working executable for rollback
)

if "%EXISTING_SERVICE%"=="1" (
    echo [INFO] Stopping existing service...
    sc stop "%SERVICE_NAME%" >nul 2>&1
    timeout /t 2 /nobreak >nul
)

REM The monotonic telemetry generation and durable outbound queue are part of
REM protocol correctness. Copy them only after the service has stopped so the
REM SQLite files are consistent across an installer upgrade.
if "%CLEAN_INSTALL%"=="0" if exist "%CONFIG_DIR%\sentinelgo_telemetry.db" (
    copy "%CONFIG_DIR%\sentinelgo_telemetry.db" "%EXISTING_TELEMETRY_STATE_BACKUP%" /Y >nul 2>&1
    if !errorLevel! neq 0 (
        echo [ERROR] Failed to preserve telemetry ordering state; restarting previous service and aborting
        if "%EXISTING_SERVICE%"=="1" sc start "%SERVICE_NAME%" >nul 2>&1
        exit /b 1
    )
)
if "%CLEAN_INSTALL%"=="0" if exist "%CONFIG_DIR%\sentinelgo_telemetry_queue.db" (
    copy "%CONFIG_DIR%\sentinelgo_telemetry_queue.db" "%EXISTING_TELEMETRY_QUEUE_BACKUP%" /Y >nul 2>&1
    if !errorLevel! neq 0 (
        echo [ERROR] Failed to preserve queued telemetry; restarting previous service and aborting
        if "%EXISTING_SERVICE%"=="1" sc start "%SERVICE_NAME%" >nul 2>&1
        exit /b 1
    )
)

if "%EXISTING_SERVICE%"=="1" (
    echo [INFO] Deleting existing service...
    sc delete "%SERVICE_NAME%" >nul 2>&1
    if !errorLevel! neq 0 (
        echo [ERROR] Windows refused to delete the existing service
        if exist "%EXISTING_CONFIG_BACKUP%" echo [INFO] Preserved config backup: %EXISTING_CONFIG_BACKUP%
        exit /b 1
    )
)

set SERVICE_DELETE_WAIT=0
:wait_for_service_delete
sc query "%SERVICE_NAME%" >nul 2>&1
if %errorLevel% neq 0 goto service_deleted
set /a SERVICE_DELETE_WAIT+=1
if %SERVICE_DELETE_WAIT% geq 15 (
    echo [ERROR] Existing service is still registered after 30 seconds
    echo [INFO] Close Services.msc and any process holding the service, then retry
    if exist "%EXISTING_CONFIG_BACKUP%" echo [INFO] Preserved config backup: %EXISTING_CONFIG_BACKUP%
    exit /b 1
)
timeout /t 2 /nobreak >nul
goto wait_for_service_delete

:service_deleted
if exist "%INSTALL_DIR%" (
    echo [INFO] Removing previous installation directory...
    rmdir /S /Q "%INSTALL_DIR%" >nul 2>&1
    if exist "%INSTALL_DIR%" (
        echo [ERROR] Failed to remove %INSTALL_DIR%; installation stopped
        if exist "%EXISTING_CONFIG_BACKUP%" echo [INFO] Preserved config backup: %EXISTING_CONFIG_BACKUP%
        exit /b 1
    )
)
if "%EXISTING_SERVICE%"=="0" if "%EXISTING_FILES%"=="0" echo [INFO] No existing installation found
if "%EXISTING_SERVICE%"=="1" echo [SUCCESS] Existing Windows service removed
if "%EXISTING_FILES%"=="1" echo [SUCCESS] Existing installation files removed
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
echo.

REM Step 4: Deploy Configuration File
echo [STEP 4] Deploying configuration file...
if exist "%EXISTING_CONFIG_BACKUP%" (
    REM Restore preserved config from previous installation (keeps agent identity)
    copy "%EXISTING_CONFIG_BACKUP%" "%CONFIG_DIR%\config.json" /Y >nul 2>&1
    if !errorLevel! equ 0 (
        echo [SUCCESS] Restored existing agent configuration (identity preserved)
    ) else (
        echo [ERROR] Failed to restore existing config; refusing to replace device identity
        goto install_failed
    )
) else goto deploy_bundled_config
goto config_deployed

:deploy_bundled_config
if exist "config.json" (
    copy "config.json" "%CONFIG_DIR%\config.json" /Y >nul 2>&1
    if !errorLevel! equ 0 (
        echo [SUCCESS] Configuration deployed to %CONFIG_DIR%\config.json
    ) else (
        echo [ERROR] Failed to deploy configuration
        goto install_failed
    )
) else (
    echo [ERROR] Bundled config.json was not found; refusing to install an unconfigured service
    goto install_failed
)
:config_deployed
if exist "%EXISTING_TELEMETRY_STATE_BACKUP%" (
    copy "%EXISTING_TELEMETRY_STATE_BACKUP%" "%CONFIG_DIR%\sentinelgo_telemetry.db" /Y >nul 2>&1
    if errorLevel 1 goto install_failed
)
if exist "%EXISTING_TELEMETRY_QUEUE_BACKUP%" (
    copy "%EXISTING_TELEMETRY_QUEUE_BACKUP%" "%CONFIG_DIR%\sentinelgo_telemetry_queue.db" /Y >nul 2>&1
    if errorLevel 1 goto install_failed
)
echo.

REM Step 5: Deploy Agent Binary
echo [STEP 5] Deploying agent binary...
copy "%REQUIRED_BINARY%" "%INSTALL_DIR%\%BINARY_NAME%" /Y >nul 2>&1
if %errorLevel% equ 0 (
    echo [SUCCESS] Binary deployed and renamed to %BINARY_NAME%
) else (
    echo [ERROR] Failed to deploy binary
    goto install_failed
)
echo.

REM Step 6: Install New Service with Auto-Start and Recovery
echo [STEP 6] Installing Windows service with auto-start...
sc create "%SERVICE_NAME%" binPath= "%INSTALL_DIR%\%BINARY_NAME%" start= auto DisplayName= "SentinelGo Agent" >nul 2>&1
if %errorLevel% equ 0 (
    echo [SUCCESS] Service created with auto-start enabled
) else (
    echo [ERROR] Failed to create service (error code: %errorLevel%)
    echo [INFO] Installation stopped; no partially configured service will be reported as successful
    goto install_failed
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
call :verify_service_stable
if %errorLevel% equ 0 (
    echo [SUCCESS] Service is stable and running
) else (
    echo [WARNING] Service may not be running, attempting force start...
    sc start "%SERVICE_NAME%" >nul 2>&1
    call :verify_service_stable
    if %errorLevel% equ 0 (
        echo [SUCCESS] Service started successfully on retry
    ) else (
        echo [ERROR] Service failed to start
        goto install_failed
    )
)
if exist "%EXISTING_CONFIG_BACKUP%" del "%EXISTING_CONFIG_BACKUP%" >nul 2>&1
if exist "%EXISTING_BINARY_BACKUP%" del "%EXISTING_BINARY_BACKUP%" >nul 2>&1
if exist "%EXISTING_TELEMETRY_STATE_BACKUP%" del "%EXISTING_TELEMETRY_STATE_BACKUP%" >nul 2>&1
if exist "%EXISTING_TELEMETRY_QUEUE_BACKUP%" del "%EXISTING_TELEMETRY_QUEUE_BACKUP%" >nul 2>&1
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

:install_failed
if "%CLEAN_INSTALL%"=="1" (
    echo [ERROR] Clean installation failed; no previous version was retained by design
    exit /b 1
)
if not exist "%EXISTING_BINARY_BACKUP%" (
    echo [ERROR] Upgrade failed and no previous executable was available to restore
    if exist "%EXISTING_CONFIG_BACKUP%" echo [INFO] Preserved config backup: %EXISTING_CONFIG_BACKUP%
    exit /b 1
)
echo [WARNING] Upgrade failed; restoring the previous SentinelGo version...
sc stop "%SERVICE_NAME%" >nul 2>&1
sc delete "%SERVICE_NAME%" >nul 2>&1
call :wait_service_absent
if errorLevel 1 goto install_rollback_failed
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%"
copy "%EXISTING_BINARY_BACKUP%" "%INSTALL_DIR%\%BINARY_NAME%" /Y >nul 2>&1
if errorLevel 1 goto install_rollback_failed
if exist "%EXISTING_CONFIG_BACKUP%" copy "%EXISTING_CONFIG_BACKUP%" "%CONFIG_DIR%\config.json" /Y >nul 2>&1
if exist "%EXISTING_TELEMETRY_STATE_BACKUP%" copy "%EXISTING_TELEMETRY_STATE_BACKUP%" "%CONFIG_DIR%\sentinelgo_telemetry.db" /Y >nul 2>&1
if exist "%EXISTING_TELEMETRY_QUEUE_BACKUP%" copy "%EXISTING_TELEMETRY_QUEUE_BACKUP%" "%CONFIG_DIR%\sentinelgo_telemetry_queue.db" /Y >nul 2>&1
sc create "%SERVICE_NAME%" binPath= "%INSTALL_DIR%\%BINARY_NAME%" start= auto DisplayName= "SentinelGo Agent" >nul 2>&1
if errorLevel 1 goto install_rollback_failed
sc failure "%SERVICE_NAME%" reset= 86400 actions= restart/5000/restart/10000/restart/30000 >nul 2>&1
sc start "%SERVICE_NAME%" >nul 2>&1
call :verify_service_stable
if errorLevel 1 goto install_rollback_failed
echo update_failed_rolled_back>"%INSTALL_DIR%\sentinelgo_update_failure.txt"
del "%EXISTING_BINARY_BACKUP%" >nul 2>&1
if exist "%EXISTING_CONFIG_BACKUP%" del "%EXISTING_CONFIG_BACKUP%" >nul 2>&1
if exist "%EXISTING_TELEMETRY_STATE_BACKUP%" del "%EXISTING_TELEMETRY_STATE_BACKUP%" >nul 2>&1
if exist "%EXISTING_TELEMETRY_QUEUE_BACKUP%" del "%EXISTING_TELEMETRY_QUEUE_BACKUP%" >nul 2>&1
echo [SUCCESS] Previous SentinelGo version restored and running
exit /b 1

:install_rollback_failed
echo update_failed_rollback_failed>"%INSTALL_DIR%\sentinelgo_update_failure.txt"
echo [ERROR] Automatic rollback failed; previous executable remains at %EXISTING_BINARY_BACKUP%
if exist "%EXISTING_CONFIG_BACKUP%" echo [INFO] Previous config remains at %EXISTING_CONFIG_BACKUP%
exit /b 2

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
set UPDATE_BINARY_BACKUP=%TEMP%\sentinelgo_update_backup_%RANDOM%_%RANDOM%.exe
copy "%INSTALL_DIR%\%BINARY_NAME%" "%UPDATE_BINARY_BACKUP%" /Y >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Could not preserve the running executable; update aborted
    exit /b 1
)
sc stop "%SERVICE_NAME%" >nul 2>&1
timeout /t 3 /nobreak >nul

echo [INFO] Updating binary...
copy "%REQUIRED_BINARY%" "%INSTALL_DIR%\%BINARY_NAME%" /Y >nul 2>&1
if %errorLevel% equ 0 (
    echo [SUCCESS] Binary updated
) else (
    echo [ERROR] Failed to update binary
    goto update_rollback
)

echo [INFO] Starting service...
sc start "%SERVICE_NAME%" >nul 2>&1
call :verify_service_stable
if %errorLevel% neq 0 goto update_rollback
echo [SUCCESS] Service restarted and is running
del "%UPDATE_BINARY_BACKUP%" >nul 2>&1

echo.
echo [SUCCESS] Update complete!
goto end

:update_rollback
echo [WARNING] Update failed; restoring previous executable...
sc stop "%SERVICE_NAME%" >nul 2>&1
timeout /t 2 /nobreak >nul
copy "%UPDATE_BINARY_BACKUP%" "%INSTALL_DIR%\%BINARY_NAME%" /Y >nul 2>&1
if %errorLevel% neq 0 (
    echo update_failed_rollback_failed>"%INSTALL_DIR%\sentinelgo_update_failure.txt"
    echo [ERROR] Rollback copy failed; backup retained at %UPDATE_BINARY_BACKUP%
    exit /b 2
)
sc start "%SERVICE_NAME%" >nul 2>&1
call :verify_service_stable
if %errorLevel% neq 0 (
    echo update_failed_rollback_failed>"%INSTALL_DIR%\sentinelgo_update_failure.txt"
    echo [ERROR] Previous service failed to restart; backup retained at %UPDATE_BINARY_BACKUP%
    exit /b 2
)
echo update_failed_rolled_back>"%INSTALL_DIR%\sentinelgo_update_failure.txt"
del "%UPDATE_BINARY_BACKUP%" >nul 2>&1
echo [SUCCESS] Previous version restored and running
exit /b 1

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
echo   install              Upgrade/reinstall and preserve the existing device identity (default)
echo   clean-install        Remove old service, files, config and device identity before installing
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
echo   - bundled config.json in the current directory
echo.
echo Examples:
echo   install.bat                    # Install service
echo   install.bat install            # Upgrade/reinstall and preserve agent identity
echo   install.bat clean-install      # Completely replace service, files and config
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
echo   - Default on install: Automatic start
echo.
goto end

:unknown
echo [ERROR] Unknown command: %COMMAND%
echo [INFO] Run 'install.bat help' for usage information
pause
exit /b 1

:end
pause
goto :eof

:verify_service_stable
set VERIFY_ATTEMPTS=0
set VERIFY_HEALTHY=0
:verify_service_stable_loop
timeout /t 2 /nobreak >nul
sc query "%SERVICE_NAME%" | find "RUNNING" >nul 2>&1
if errorLevel 1 (set VERIFY_HEALTHY=0) else (set /a VERIFY_HEALTHY+=1)
if !VERIFY_HEALTHY! geq 5 exit /b 0
set /a VERIFY_ATTEMPTS+=1
if !VERIFY_ATTEMPTS! geq 30 exit /b 1
goto verify_service_stable_loop

:wait_service_absent
set DELETE_ATTEMPTS=0
:wait_service_absent_loop
sc query "%SERVICE_NAME%" >nul 2>&1
if errorLevel 1 exit /b 0
set /a DELETE_ATTEMPTS+=1
if !DELETE_ATTEMPTS! geq 15 exit /b 1
timeout /t 2 /nobreak >nul
goto wait_service_absent_loop
