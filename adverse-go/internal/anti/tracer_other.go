//go:build !linux

package anti

// linuxTracerCheck on non-Linux hosts has no procfs to consult. It reports an
// explicit non-triggered result so PlatformChecks keeps the same signal shape
// across GOOS targets without pretending a check ran.
func linuxTracerCheck() CheckResult {
	return CheckResult{Name: "tracer_pid", Triggered: false, Detail: "procfs unavailable"}
}
