//go:build windows

package notify

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// toastScript shows a toast through WinRT from Windows PowerShell, under
// PowerShell's own app id (registered on every Windows 10/11). Title and body
// come from the environment, so they are never parsed as script.
const toastScript = `[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$x = $t.GetElementsByTagName('text')
$x.Item(0).AppendChild($t.CreateTextNode($env:SG_NOTIFY_TITLE)) > $null
$x.Item(1).AppendChild($t.CreateTextNode($env:SG_NOTIFY_BODY)) > $null
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe').Show([Windows.UI.Notifications.ToastNotification]::new($t))`

const createNoWindow = 0x08000000

func command(ctx context.Context, title, body string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", toastScript) // #nosec G204 -- fixed script; text arrives via environment
	cmd.Env = append(os.Environ(), "SG_NOTIFY_TITLE="+title, "SG_NOTIFY_BODY="+body)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd
}

func platformSend(title, body string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return command(ctx, title, body).Run()
}
