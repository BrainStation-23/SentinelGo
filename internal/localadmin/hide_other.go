//go:build !windows

package localadmin

import "os/exec"

func hideWindow(*exec.Cmd) {}
