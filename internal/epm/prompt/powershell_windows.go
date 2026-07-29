//go:build windows

package prompt

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// dialogTimeout bounds how long the PowerShell dialog subprocess may block
// waiting for user input — see WindowsPrompter's doc comment.
const dialogTimeout = 5 * time.Minute

// inputBoxScript is a minimal WinForms text-input dialog. Prefixing the
// final output with "OK:" or "CANCEL:" is what lets Go tell "the user
// typed nothing and clicked OK" apart from "the user clicked Cancel" —
// VB.Interaction.InputBox (the simpler one-line alternative) cannot make
// that distinction at all, since it returns an empty string for both,
// which is why this uses the more verbose Form/DialogResult approach
// instead.
const inputBoxScript = `
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$form = New-Object System.Windows.Forms.Form
$form.Text = '%s'
$form.Size = New-Object System.Drawing.Size(420,160)
$form.StartPosition = 'CenterScreen'
$form.Topmost = $true
$form.FormBorderStyle = 'FixedDialog'
$form.MinimizeBox = $false
$form.MaximizeBox = $false
$label = New-Object System.Windows.Forms.Label
$label.Text = '%s'
$label.AutoSize = $false
$label.Size = New-Object System.Drawing.Size(380,40)
$label.Location = New-Object System.Drawing.Point(10,10)
$form.Controls.Add($label)
$textbox = New-Object System.Windows.Forms.TextBox
$textbox.Location = New-Object System.Drawing.Point(10,55)
$textbox.Size = New-Object System.Drawing.Size(380,20)
$form.Controls.Add($textbox)
$okButton = New-Object System.Windows.Forms.Button
$okButton.Text = 'OK'
$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$okButton.Location = New-Object System.Drawing.Point(225,90)
$form.Controls.Add($okButton)
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = 'Cancel'
$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$cancelButton.Location = New-Object System.Drawing.Point(310,90)
$form.Controls.Add($cancelButton)
$form.AcceptButton = $okButton
$form.CancelButton = $cancelButton
$form.Add_Shown({ $form.Activate(); $textbox.Focus() })
$result = $form.ShowDialog()
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    Write-Output ("OK:" + $textbox.Text)
} else {
    Write-Output "CANCEL:"
}
`

// powershellInputBox renders inputBoxScript and parses its "OK:"/"CANCEL:"
// prefixed stdout — see parseInputBoxOutput.
func powershellInputBox(title, message string) (string, bool, error) {
	script := fmt.Sprintf(inputBoxScript, escapePowerShellSingleQuoted(title), escapePowerShellSingleQuoted(message))

	ctx, cancel := context.WithTimeout(context.Background(), dialogTimeout)
	defer cancel()

	// #nosec G204 - the script body is a fixed template; only title/message
	// (escaped for PowerShell single-quoted strings above) are caller-supplied.
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
	out, err := cmd.Output()
	if err != nil {
		return "", false, fmt.Errorf("prompt: powershell input box: %w", err)
	}
	return parseInputBoxOutput(string(out))
}

// parseInputBoxOutput parses inputBoxScript's final Write-Output line. Split
// out from powershellInputBox for testability without a live PowerShell.
func parseInputBoxOutput(stdout string) (string, bool, error) {
	line := strings.TrimSpace(stdout)
	if text, ok := strings.CutPrefix(line, "OK:"); ok {
		return text, true, nil
	}
	if strings.HasPrefix(line, "CANCEL:") {
		return "", false, nil
	}
	return "", false, fmt.Errorf("prompt: unexpected input box output %q", stdout)
}
