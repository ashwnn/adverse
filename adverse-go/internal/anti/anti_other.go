//go:build !windows

package anti

import "os"

// PlatformChecks for non-Windows hosts (Linux CI). Real anti-debug PEB checks
// are Windows-only; on other platforms we report sandbox signals that still
// work (procfs, env).
func PlatformChecks() []CheckResult {
	var out []CheckResult
	// Linux tracer check
	out = append(out, linuxTracerCheck())
	out = append(out, envSandboxCheck())
	out = append(out, cpuidHypervisorCheck())
	out = append(out, cpuidVendorCheck())
	return out
}

// envSandboxCheck looks for known sandbox env markers (common in VT sandboxes).
// It is defined here for every non-Windows GOOS (Linux, darwin, BSD) so the
// symbol exists exactly once per target; anti_windows.go provides the Windows
// variant with additional filesystem/hostname probes.
func envSandboxCheck() CheckResult {
	markers := []string{"SANDBOX", "VIRUSTOTAL", "CAPE_SANDBOX", "JOEBOX"}
	for _, m := range markers {
		if os.Getenv(m) != "" {
			return CheckResult{Name: "env_sandbox", Triggered: true, Detail: m + "=present"}
		}
	}
	return CheckResult{Name: "env_sandbox", Triggered: false, Detail: "clean"}
}

// cpuidHypervisorCheck is a no-op on non-Windows. CPUID execution requires
// platform-specific assembly that is only provided for Windows amd64.
func cpuidHypervisorCheck() CheckResult {
	return CheckResult{Name: "vm_cpuid_hypervisor", Triggered: false, Detail: "non-windows: cpuid not evaluated"}
}

// cpuidVendorCheck is a no-op on non-Windows.
func cpuidVendorCheck() CheckResult {
	return CheckResult{Name: "vm_cpuid_vendor", Triggered: false, Detail: "non-windows: cpuid not evaluated"}
}

// CPUIDHypervisorPresent is a no-op on non-Windows. CPUID execution requires
// platform-specific assembly that is only provided for Windows amd64.
func CPUIDHypervisorPresent() (bool, string) {
	return false, "non-windows: cpuid not evaluated"
}
