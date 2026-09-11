//go:build windows

package anti

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PEB BeingDebugged offset for x64: PEB+2.
const pebBeingDebuggedOffset = 2

// cpuid executes the x86 CPUID instruction via assembly (cpuid_windows_amd64.s).
// leaf selects the CPUID function; ecxIn is the sub-leaf input.
//
//go:noescape
func cpuid(leaf uint32, ecxIn uint32) (eaxOut, ebxOut, ecxOut, edxOut uint32)

// knownHypervisorVendors lists 12-byte CPUID leaf 0x40000000 vendor strings
// returned by common hypervisors. The string is EBX:ECX:EDX (12 bytes).
var knownHypervisorVendors = []string{
	"VMwareVMware",          // VMware
	"Microsoft Hv",          // Microsoft Hyper-V
	"KVMKVMKVM\x00\x00\x00", // KVM (trailing nulls are part of the 12-byte string)
	"XenVMMXenVMM",          // Xen
	"VBoxVBoxVBox",          // VirtualBox
	"TCGTCGTCGTCG",          // QEMU TCG
	"bhyve bhyve ",          // bhyve
	"lrpepyh  vr",           // Parallels
}

func PlatformChecks() []CheckResult {
	var out []CheckResult
	out = append(out, pebBeingDebuggedCheck())
	out = append(out, ntQueryDebugPortCheck())
	out = append(out, envSandboxCheck())
	out = append(out, cpuidHypervisorCheck())
	out = append(out, cpuidVendorCheck())
	return out
}

// pebBeingDebuggedCheck reads PEB->BeingDebugged via NtCurrentTeb -> PEB.
// This is the classic anti-debug that Ghidra's decompiled view flags as suspicious
// precisely because we want manual analysts to trip it and waste time.
func pebBeingDebuggedCheck() CheckResult {
	peb := pebAddress()
	if peb == nil {
		return CheckResult{Name: "peb_beingdebugged", Triggered: false, Detail: "peb resolution failed"}
	}
	val := *(*byte)(unsafe.Add(peb, pebBeingDebuggedOffset))
	triggered := val != 0
	detail := "BeingDebugged=0"
	if triggered {
		detail = "BeingDebugged=1"
	}
	return CheckResult{Name: "peb_beingdebugged", Triggered: triggered, Detail: detail}
}

// ntQueryDebugPortCheck calls NtQueryInformationProcess(ProcessDebugPort=7).
// Returns non-zero debug port if being debugged. Uses direct NTDLL load to avoid
// hooking of the check itself.
func ntQueryDebugPortCheck() CheckResult {
	// Load ntdll without going through high-level wrappers that VT hooks.
	dll := windows.NewLazySystemDLL("ntdll.dll")
	proc := dll.NewProc("NtQueryInformationProcess")
	// Current process handle = -1
	var debugPort uintptr
	r1, _, _ := proc.Call(
		uintptr(^uintptr(0)), // HANDLE -1
		7,                    // ProcessDebugPort
		uintptr(unsafe.Pointer(&debugPort)),
		unsafe.Sizeof(debugPort),
		0,
	)
	if r1 != 0 {
		return CheckResult{Name: "nt_query_debug_port", Triggered: false, Detail: "call failed"}
	}
	return CheckResult{Name: "nt_query_debug_port", Triggered: debugPort != 0, Detail: "DebugPort != 0"}
}

func envSandboxCheck() CheckResult {
	markers := []string{"SANDBOX", "VIRUSTOTAL", "CAPE_SANDBOX", "JOEBOX"}
	for _, m := range markers {
		if os.Getenv(m) != "" {
			return CheckResult{Name: "env_sandbox", Triggered: true, Detail: m + "=present"}
		}
	}
	// Windows sandbox often leaves C:\SANDBOX or similar; best-effort fileprobe.
	for _, p := range []string{`C:\sandbox`, `C:\analysis`} {
		if _, err := os.Stat(p); err == nil {
			return CheckResult{Name: "filesystem_sandbox", Triggered: true, Detail: p + " exists"}
		}
	}
	// Check for low uptime (VM snapshot) is done by anti.timingCheck globally.
	if strings.Contains(strings.ToLower(os.Getenv("COMPUTERNAME")), "sandbox") {
		return CheckResult{Name: "hostname_sandbox", Triggered: true, Detail: os.Getenv("COMPUTERNAME")}
	}
	return CheckResult{Name: "env_sandbox", Triggered: false, Detail: "clean"}
}

// pebAddress returns the PEB base via NtCurrentTeb (GS:[0x60] on x64).
// Implemented via inline Go: read GS segment is not expressible without asm,
// so we fallback to using windows.NewLazyDLL to call RtlGetCurrentPeb via
// ntdll export that is not hooked as aggressively as IsDebuggerPresent.
// The result is carried as an unsafe.Pointer so callers use unsafe.Add for
// offsetting instead of uintptr conversions. Returns nil if unavailable
// (check fails open).
func pebAddress() unsafe.Pointer {
	dll := windows.NewLazySystemDLL("ntdll.dll")
	// RtlGetCurrentPeb exists on Win10+; if not found, try legacy path.
	proc := dll.NewProc("RtlGetCurrentPeb")
	if err := proc.Find(); err != nil {
		return nil
	}
	ret, _, _ := proc.Call()
	if ret == 0 {
		return nil
	}
	// The call returns a raw in-process address; the PEB is not Go-managed
	// memory, so rebase the address through pointer arithmetic.
	return unsafe.Add(nil, ret)
}

// cpuidHypervisorCheck reads CPUID leaf 1, ECX bit 31 (hypervisor-present bit).
// A set bit indicates the CPU is running under a hypervisor. This is the
// canonical detection vector referenced in doc.go.
// Emits vm_cpuid_hypervisor to align with behavioural signalWeights.
func cpuidHypervisorCheck() CheckResult {
	present, detail := CPUIDHypervisorPresent()
	return CheckResult{
		Name:      "vm_cpuid_hypervisor",
		Triggered: present,
		Detail:    detail,
	}
}

// cpuidVendorCheck reads the hypervisor vendor string from CPUID leaf 0x40000000.
// Even if the hypervisor hides the hypervisor-present bit, the vendor string
// often leaks via this leaf. Returns triggered when the vendor matches a known
// hypervisor. Emits vm_cpuid_vendor to align with behavioural weights.
func cpuidVendorCheck() CheckResult {
	eax, ebx, ecx, edx := cpuid(0x40000000, 0)
	if eax == 0 {
		return CheckResult{
			Name:      "vm_cpuid_vendor",
			Triggered: false,
			Detail:    "leaf 0x40000000 not supported (eax=0)",
		}
	}
	// Assemble 12-byte vendor string: EBX + ECX + EDX (standard CPUID order).
	vendor := cpuidVendorString(ebx, ecx, edx)
	for _, known := range knownHypervisorVendors {
		if vendor == known {
			return CheckResult{
				Name:      "vm_cpuid_vendor",
				Triggered: true,
				Detail:    vendor,
			}
		}
	}
	return CheckResult{
		Name:      "vm_cpuid_vendor",
		Triggered: false,
		Detail:    vendor,
	}
}

// cpuidVendorString assembles a 12-byte hypervisor vendor string from CPUID
// leaf 0x40000000 output registers (EBX, ECX, EDX) into a Go string.
func cpuidVendorString(ebx, ecx, edx uint32) string {
	var b [12]byte
	b[0] = byte(ebx)
	b[1] = byte(ebx >> 8)
	b[2] = byte(ebx >> 16)
	b[3] = byte(ebx >> 24)
	b[4] = byte(ecx)
	b[5] = byte(ecx >> 8)
	b[6] = byte(ecx >> 16)
	b[7] = byte(ecx >> 24)
	b[8] = byte(edx)
	b[9] = byte(edx >> 8)
	b[10] = byte(edx >> 16)
	b[11] = byte(edx >> 24)
	return string(b[:])
}

// CPUIDHypervisorPresent executes CPUID leaf 1 and reports whether ECX bit 31
// (the hypervisor-present bit) is set. Returns the boolean result and a detail
// string. This is the exported helper used by the behavioural package.
func CPUIDHypervisorPresent() (bool, string) {
	_, _, ecx, _ := cpuid(1, 0)
	present := (ecx>>31)&1 == 1
	detail := fmt.Sprintf("ECX bit31=%d (leaf 1)", (ecx>>31)&1)
	return present, detail
}

// secondClockMS returns milliseconds since boot via GetTickCount64 (kernel32),
// which is independent of the Go runtime's monotonic clock.
func secondClockMS() (int64, bool) {
	mod := windows.NewLazySystemDLL("kernel32.dll")
	proc := mod.NewProc("GetTickCount64")
	ret, _, _ := proc.Call()
	return int64(ret), true
}
