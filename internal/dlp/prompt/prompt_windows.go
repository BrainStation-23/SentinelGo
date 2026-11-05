//go:build windows

package prompt

import (
	"context"
	"os/exec"
	"syscall"

	"sentinelgo/internal/binpath"
)

// winScript shows a small WinForms dialog and prints {"choice","reason"} as
// one JSON line. All text comes from environment variables.
const winScript = `$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$nl = [Environment]::NewLine
$f = New-Object System.Windows.Forms.Form
$f.Text = $env:SG_TITLE
$f.TopMost = $true
$f.StartPosition = 'CenterScreen'
$f.FormBorderStyle = 'FixedDialog'
$f.MaximizeBox = $false
$f.MinimizeBox = $false
$f.ClientSize = New-Object System.Drawing.Size(480, 270)
$f.Tag = 'cancel'
$l = New-Object System.Windows.Forms.Label
$l.Text = $env:SG_MSG + $nl + $nl + $env:SG_PROMPT
$l.SetBounds(12, 12, 456, 90)
$f.Controls.Add($l)
$t = New-Object System.Windows.Forms.TextBox
$t.Multiline = $true
$t.MaxLength = 1000
$t.SetBounds(12, 106, 456, 100)
$f.Controls.Add($t)
$x = 12
function Add-Choice([string]$text, [string]$choice) {
  $b = New-Object System.Windows.Forms.Button
  $b.Text = $text
  $b.Tag = $choice
  $b.SetBounds($script:x, 222, 148, 32)
  $b.Add_Click({ param($s, $e) $f.Tag = $s.Tag; $f.Close() })
  $f.Controls.Add($b)
  $script:x += 154
}
if ($env:SG_CAN_OVERRIDE -eq '1') { Add-Choice 'Continue with a reason' 'override' }
if ($env:SG_CAN_REQUEST -eq '1') { Add-Choice 'Request an exception' 'request' }
Add-Choice 'Cancel' 'cancel'
[void]$f.ShowDialog()
@{ choice = [string]$f.Tag; reason = [string]$t.Text } | ConvertTo-Json -Compress`

func flag(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// Show asks with a WinForms dialog in the helper's (the user's) session.
func Show(ctx context.Context, a Ask) (Answer, error) {
	if !a.CanOverride && !a.CanRequest {
		return Answer{Choice: ChoiceCancel}, nil
	}
	ps, ok := binpath.Lookup("powershell")
	if !ok {
		return Answer{}, ErrUnavailable
	}
	cmd := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-STA", "-ExecutionPolicy", "Bypass", "-Command", winScript) // #nosec G204 -- fixed script; text arrives via environment
	cmd.Env = append(cmd.Environ(), "SG_TITLE="+a.Title, "SG_MSG="+a.Message, "SG_PROMPT="+reasonPrompt,
		"SG_CAN_OVERRIDE="+flag(a.CanOverride), "SG_CAN_REQUEST="+flag(a.CanRequest))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // no console window; the form still shows
	out, err := cmd.Output()
	if err != nil {
		return Answer{}, err
	}
	return parseWindows(string(out)), nil
}
