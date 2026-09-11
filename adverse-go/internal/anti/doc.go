// Package anti provides anti-analysis primitives that complement
// obfuscate's static hardening with dynamic execution guards.
//
// Coverage:
//
//   - Anti-debug: PEB BeingDebugged / NtQueryInformationProcess(ProcessDebugPort),
//     timing delta, tracer-pid check on Linux.
//   - Anti-VM/Sandbox: cpuid hypervisor bit, known sandbox artifacts, uptime
//     checks that fail under emulation.
//   - Anti-disassembly: execution-path validation that Ghidra's decompiler or a
//     bytecode VM would mispredict (opaque predicates + jump targets resolved
//     via obfuscate dispatch).
//   - Anti-emulation: stalling loops with side-effects invisible to emulators,
//     API hammering detection.
//
// All checks are best-effort. A failure does NOT abort the agent; the caller
// logs the signal and may alter behavior (e.g., delay exfiltration), denying
// free analysis to automated sandboxes.
//
// Lab use: checks are no-ops on non-Windows/non-Linux test hosts and are
// gated behind the anti build tag when maximal stealth is required. They do
// not perform host modification.
//
// Environment: pure Go with minimal x/sys usage. Windows syscalls reuse the
// stealth resolver; Linux uses standard syscalls. No cgo.
package anti
