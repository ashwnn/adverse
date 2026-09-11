// Package timerwait provides a Windows waitable-timer sleep that never touches
// NtDelayExecution, plus a plain context-aware fallback on other platforms.
//
// Rationale: the canonical AV "sleep" tell is the Sleep/SleepEx/
// NtDelayExecution pattern. A waitable timer (CreateWaitableTimer +
// SetWaitableTimer + WaitForMultipleObjects) blocks the thread on a kernel
// timer object instead. Note: the Go runtime's own time.Sleep already uses its
// timer machinery rather than NtDelayExecution; this package is for agents that
// want the beacon/chunk pacing driven by an explicit kernel timer object.
package timerwait

import (
	"context"
	"time"
)

// Sleep blocks for d, returning false if ctx is cancelled first.
func Sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	return sleepPlatform(ctx, d)
}

// fallbackSleep is the context-aware timer used on non-Windows platforms and
// whenever the kernel waitable timer cannot be created.
func fallbackSleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
