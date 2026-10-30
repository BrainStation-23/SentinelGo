//go:build windows

package notify

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// toastScript shows a toast through WinRT from Windows PowerShell, under
// PowerShell's own app id (registered on every Windows 10/11). Title, body and
// level come from the environment, so they are never parsed as script. A
// warning or critical level plays the reminder sound; critical also asks for
// the "urgent" scenario, which Windows 11 shows through Do Not Disturb (older
// versions ignore it).
const toastScript = `[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$x = $t.GetElementsByTagName('text')
$x.Item(0).AppendChild($t.CreateTextNode($env:SG_NOTIFY_TITLE)) > $null
$x.Item(1).AppendChild($t.CreateTextNode($env:SG_NOTIFY_BODY)) > $null
if ($env:SG_NOTIFY_LEVEL -eq 'warning' -or $env:SG_NOTIFY_LEVEL -eq 'critical') {
  $a = $t.CreateElement('audio'); $a.SetAttribute('src', 'ms-winsoundevent:Notification.Reminder'); $t.DocumentElement.AppendChild($a) > $null
}
if ($env:SG_NOTIFY_LEVEL -eq 'critical') { $t.DocumentElement.SetAttribute('scenario', 'urgent') }
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe').Show([Windows.UI.Notifications.ToastNotification]::new($t))`

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

func command(ctx context.Context, title, body, level string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, powershellPath(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", toastScript) // #nosec G204 -- fixed script; text arrives via environment
	cmd.Env = append(os.Environ(), "SG_NOTIFY_TITLE="+title, "SG_NOTIFY_BODY="+body, "SG_NOTIFY_LEVEL="+level)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd
}

func platformSend(title, body, level string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return command(ctx, title, body, level).Run()
}
