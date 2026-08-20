package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsInstallerReplacementContract(t *testing.T) {
	path := filepath.Join("..", "..", "..", "installation-doc", "install.bat")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read install.bat: %v", err)
	}
	script := string(raw)

	required := []string{
		`if /I "%COMMAND%"=="clean-install" goto clean-install`,
		`echo UAC.ShellExecute "%~f0", "%COMMAND%", "", "runas", 1`,
		`if exist "%INSTALL_DIR%" set EXISTING_FILES=1`,
		`if "%CLEAN_INSTALL%"=="0" if exist "%CONFIG_DIR%\config.json"`,
		`sc delete "%SERVICE_NAME%"`,
		`:wait_for_service_delete`,
		`rmdir /S /Q "%INSTALL_DIR%"`,
		`[ERROR] Failed to create service`,
		`set EXISTING_BINARY_BACKUP=`,
		`:install_failed`,
		`:install_rollback_failed`,
		`update_failed_rolled_back`,
		`sc query "%SERVICE_NAME%" | find "RUNNING"`,
		`:update_rollback`,
		`:verify_service_stable`,
		`if !VERIFY_HEALTHY! geq 5 exit /b 0`,
		`sentinelgo_telemetry.db`,
		`sentinelgo_telemetry_queue.db`,
	}
	for _, fragment := range required {
		if !strings.Contains(script, fragment) {
			t.Errorf("install.bat is missing contract fragment %q", fragment)
		}
	}

	commandIndex := strings.Index(script, "set COMMAND=%~1")
	elevationIndex := strings.Index(script, "net session")
	if commandIndex < 0 || elevationIndex < 0 || commandIndex > elevationIndex {
		t.Error("installer must preserve the requested command across UAC elevation")
	}
}
