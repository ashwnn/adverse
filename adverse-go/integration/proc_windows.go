//go:build windows

package integration

import (
	"os/exec"
	"syscall"
)

// setSysProcAttr puts the child in its own process group (CREATE_NEW_PROCESS_GROUP)
// so it can be terminated cleanly without affecting the parent. HideWindow prevents
// spawned child processes from flashing a console window during integration tests.
func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
}

func killProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
