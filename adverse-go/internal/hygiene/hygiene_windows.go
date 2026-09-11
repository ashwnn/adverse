//go:build windows

package hygiene

import (
	"sync"

	"golang.org/x/sys/windows"
)

// errorMode suppresses the three blocking error dialogs a non-interactive
// agent must never show.
const errorMode = windows.SEM_FAILCRITICALERRORS |
	windows.SEM_NOGPFAULTERRORBOX |
	windows.SEM_NOOPENFILEERRORBOX

// kernel32/user32 procedures not exposed by x/sys/windows. GetConsoleWindow is
// exported by kernel32; ShowWindow by user32. Lazy system DLLs are resolved
// from System32 only.
var (
	user32               = windows.NewLazySystemDLL("user32.dll")
	procGetConsoleWindow = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleWindow")
	procShowWindow       = user32.NewProc("ShowWindow")
)

var once sync.Once

// Apply suppresses error dialogs and hides an attached console window. It is
// idempotent and best-effort: any failure is swallowed so the agent continues.
func Apply() {
	once.Do(func() {
		defer func() { _ = recover() }()

		_ = windows.SetErrorMode(errorMode)

		hwnd, _, _ := procGetConsoleWindow.Call()
		if hwnd == 0 {
			return
		}
		procShowWindow.Call(hwnd, uintptr(windows.SW_HIDE))
	})
}
