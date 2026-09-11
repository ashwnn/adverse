//go:build !windows

package integration

import (
	"os/exec"
	"syscall"
)

// setSysProcAttr puts the child in its own process group so we can kill the
// whole group (including grandchildren) on cleanup.
func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcess sends SIGKILL to the process group.
func killProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	// Negative PID => kill the whole process group.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	_ = cmd.Process.Kill()
}
