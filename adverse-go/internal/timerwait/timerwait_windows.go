//go:build windows

package timerwait

import (
	"context"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Manual kernel32 bindings: x/sys/windows does not export the waitable-timer
// API family, so the few procedures needed are declared here.
var (
	kernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procCreateWaitableTimer = kernel32.NewProc("CreateWaitableTimerExW")
	procSetWaitableTimer    = kernel32.NewProc("SetWaitableTimer")
	procCreateEvent         = kernel32.NewProc("CreateEventW")
	procSetEvent            = kernel32.NewProc("SetEvent")
	procCloseHandle         = kernel32.NewProc("CloseHandle")
)

const (
	createWaitableTimerHighResolution = 0x00000002
	timerAllAccess                    = 0x001F0003 // TIMER_ALL_ACCESS
	waitObject0                       = 0
	waitFailed                        = 0xFFFFFFFF
)

// sleepPlatform waits on a high-resolution waitable timer plus a cancel event.
// Returns false when the context is cancelled.
func sleepPlatform(ctx context.Context, d time.Duration) bool {
	hTimer, _, err := procCreateWaitableTimer.Call(
		0, 0, createWaitableTimerHighResolution, timerAllAccess)
	if hTimer == 0 || err != syscall.Errno(0) {
		return fallbackSleep(ctx, d)
	}
	defer closeHandle(hTimer)

	// Relative due time in 100ns units (negative = relative).
	due := -int64(d / 100)
	r, _, err := procSetWaitableTimer.Call(hTimer, uintptr(unsafe.Pointer(&due)), 0, 0, 0, 0)
	if r == 0 || err != syscall.Errno(0) {
		return fallbackSleep(ctx, d)
	}

	// Manual-reset event, initially non-signaled.
	hEvent, _, err := procCreateEvent.Call(0, 1, 0, 0)
	if hEvent == 0 || err != syscall.Errno(0) {
		return fallbackSleep(ctx, d)
	}
	defer closeHandle(hEvent)

	// Wake the event when the context is cancelled.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			procSetEvent.Call(hEvent)
		case <-done:
		}
	}()

	// Wait for either the timer (index 0) or the cancel event (index 1).
	wait, err := windows.WaitForMultipleObjects(
		[]windows.Handle{windows.Handle(hTimer), windows.Handle(hEvent)},
		false, // waitAll = FALSE
		windows.INFINITE,
	)
	if err != nil && wait != waitObject0 && wait != waitObject0+1 {
		return fallbackSleep(ctx, d)
	}
	return wait == waitObject0 // timer fired; cancel event -> false
}

func closeHandle(h uintptr) {
	procCloseHandle.Call(h)
}
