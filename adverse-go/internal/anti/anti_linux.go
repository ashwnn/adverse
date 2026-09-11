//go:build linux

package anti

import (
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// linuxTracerCheck inspects /proc/self/status TracerPid (non-zero => ptrace).
func linuxTracerCheck() CheckResult {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return CheckResult{Name: "tracer_pid", Triggered: false, Detail: "procfs unavailable"}
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[1] != "0" {
				return CheckResult{Name: "tracer_pid", Triggered: true, Detail: line}
			}
			return CheckResult{Name: "tracer_pid", Triggered: false, Detail: line}
		}
	}
	return CheckResult{Name: "tracer_pid", Triggered: false, Detail: "no TracerPid line"}
}

// secondClockMS returns milliseconds since boot via CLOCK_BOOTTIME, using a
// raw syscall (unix.ClockGettime is not exported in x/sys v0.28.0 on Linux).
func secondClockMS() (int64, bool) {
	var ts unix.Timespec
	_, _, errno := unix.Syscall(unix.SYS_CLOCK_GETTIME, uintptr(unix.CLOCK_BOOTTIME), uintptr(unsafe.Pointer(&ts)), 0)
	if errno != 0 {
		return 0, false
	}
	return ts.Sec*1000 + ts.Nsec/1e6, true
}
