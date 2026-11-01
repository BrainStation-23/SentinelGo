//go:build windows

package notify

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// sentinelGoAUMID is the App User Model ID registered for SentinelGo. Using
// our own ID means notifications are attributed to SentinelGo in the
// notification center and are not affected by the user's PowerShell
// notification settings.
const sentinelGoAUMID = "SentinelOps.SentinelGo"

// aumidRegKey is where Windows looks up display name and icon for an AUMID
// that belongs to a desktop (non-packaged) app.
const aumidRegKey = `Software\Classes\AppUserModelId\` + sentinelGoAUMID

// toastScript sends a ToastGeneric notification under our own AUMID.
// Title, body and level arrive via environment variables so they are never
// parsed as script. A warning or critical level plays the reminder sound;
// critical also requests the "urgent" scenario (Windows 11 Do Not Disturb
// bypass; older versions ignore it).
const toastScript = `[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$xml = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]::new()
$body = $env:SG_NOTIFY_BODY
$title = $env:SG_NOTIFY_TITLE
$level = $env:SG_NOTIFY_LEVEL
$audio = ''
$scenario = ''
if ($level -eq 'warning' -or $level -eq 'critical') {
  $audio = '<audio src="ms-winsoundevent:Notification.Reminder"/>'
}
if ($level -eq 'critical') { $scenario = ' scenario="urgent"' }
$escaped_title = [System.Security.SecurityElement]::Escape($title)
$escaped_body  = [System.Security.SecurityElement]::Escape($body)
$toastXml = "<toast$scenario><visual><binding template='ToastGeneric'><text>$escaped_title</text><text>$escaped_body</text></binding></visual>$audio</toast>"
$xml.LoadXml($toastXml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($env:SG_NOTIFY_AUMID).Show([Windows.UI.Notifications.ToastNotification]::new($xml))`

const createNoWindow = 0x08000000

// powershellPath is Windows PowerShell in the system directory, not looked
// up through PATH.
func powershellPath() string {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		dir = `C:\Windows\System32`
	}
	return filepath.Join(dir, `WindowsPowerShell\v1.0\powershell.exe`)
}

// aumidOnce ensures we only attempt AUMID registration once per process.
var aumidOnce sync.Once

// ensureAUMID registers the SentinelGo AUMID in the current user's registry
// so Windows can attribute toasts to us. It is idempotent and best-effort:
// a failure is logged but never prevents a notification attempt.
func ensureAUMID() {
	aumidOnce.Do(func() {
		if err := registerAUMID(); err != nil {
			log.Printf("notify: could not register AUMID (notifications may show as Windows PowerShell): %v", err)
		}
	})
}

// installIconPath is where install.bat places the branded PNG. Windows Action
// Center can render a PNG from IconUri directly (no shell extension needed).
const installIconPath = `C:\sentinelgo\sentinelgo.png`

// registerAUMID writes the minimal registry entry Windows needs to attribute
// toasts to a desktop app without a packaged identity. DisplayName is required.
// IconUri prefers the dedicated branded PNG at the install directory; it falls
// back to the running executable (which carries an embedded .ico resource when
// built via `make windows`).
func registerAUMID() error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, aumidRegKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry key: %w", err)
	}
	defer k.Close()

	if err := k.SetStringValue("DisplayName", "SentinelGo"); err != nil {
		return fmt.Errorf("set DisplayName: %w", err)
	}

	// Prefer the standalone PNG: Windows renders it at full colour in the
	// Action Center without needing a shell extension to extract it.
	// Fall back to the exe so the AUMID always has an icon.
	if _, err := os.Stat(installIconPath); err == nil {
		_ = k.SetStringValue("IconUri", installIconPath)
	} else if exe, err := os.Executable(); err == nil {
		_ = k.SetStringValue("IconUri", exe)
	}
	return nil
}

func command(ctx context.Context, title, body, level string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, powershellPath(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", toastScript) // #nosec G204 -- fixed script; text arrives via environment
	cmd.Env = append(os.Environ(),
		"SG_NOTIFY_TITLE="+title,
		"SG_NOTIFY_BODY="+body,
		"SG_NOTIFY_LEVEL="+level,
		"SG_NOTIFY_AUMID="+sentinelGoAUMID,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd
}

func platformSend(title, body, level string) error {
	ensureAUMID()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return command(ctx, title, body, level).Run()
}
