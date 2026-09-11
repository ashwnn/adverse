package syscalls

import (
	"sync"
	"unsafe"
)

// Persistent trampoline pool.
//
// The pool replaces the legacy per-call pattern (VirtualAlloc RW per syscall,
// write stub, VirtualProtect RX, execute, VirtualFree) with a single, fixed
// set of stubs built once:
//
//   - CODE region: one allocation holding all trampoline code, written once,
//     then flipped RW -> RX exactly once. On Windows the preferred placement is
//     inside a loaded image's tail slack (see trampoline_pool_windows.go), so
//     VirtualQuery reports MEM_IMAGE rather than private executable memory.
//   - ARGS region: one private RW allocation holding per-stub argument blocks.
//     Argument loads in the code use absolute RIP-relative displacements
//     (generateTrampolineExternal), so writing args never requires a
//     protection flip.
//
// Properties vs. the legacy path:
//   - Zero per-call VirtualAlloc / VirtualProtect / VirtualFree churn.
//   - No repeating RX->RW->RX protection-flip pattern on a private region
//     (the temporal signal ETW-TI consumers and sleep-obfuscation detectors
//     key on).
//   - No private executable allocation when image-slack placement succeeds.
//
// Honest limits (documented, not solved):
//   - The stub bytes are plaintext at rest in the code region. The legacy
//     VEH per-call decryption (behavioural.ArmEncryptedTrampoline) is retired
//     from the hot path; per-call freshness is traded for a stable image-backed
//     code region. Section-backing memory scanners (e.g. Moneta) can still flag
//     unbacked executable slack inside an image.
//   - Kernel telemetry (ETW-TI, Sysmon callbacks, MDE) observes the syscalls
//     themselves regardless of how the stub is stored.
//   - The pool allocates and never frees: it is intended for the process
//     lifetime of the agent.
//
// Windows placement, fallback, and invocation live in
// trampoline_pool_windows.go; non-Windows builds return a nil pool from
// getTrampolinePool (the simulated executeSyscall path is unchanged).

// poolAlignment is the slot alignment for code and args regions.
const poolAlignment = 8

// poolEntry describes one trampoline slot inside the shared pool.
type poolEntry struct {
	// number is the reference syscall number (SysNtOpenKey etc.), used as the
	// stable map key from syscallStub.number.
	number uint16
	// argc is the number of syscall arguments this stub expects.
	argc int
	// ssn is the syscall number resolved at pool build time (fallback to the
	// reference constant when dynamic resolution fails).
	ssn uint16
	// codeOff / codeLen locate the code within the pool's code region.
	codeOff uintptr
	codeLen uintptr
	// argsOff locates the args block within the pool's args region.
	argsOff uintptr
}

// trampolinePool is the persistent stub pool. Fields are immutable after
// build; invoke() serializes on mu because the args region is shared mutable
// state.
type trampolinePool struct {
	mu sync.Mutex

	// codeBase/argsBase are raw OS allocations (VirtualAlloc), carried as
	// unsafe.Pointer so slot offsets use unsafe.Add. Windows API calls take
	// uintptr(codeBase)/uintptr(argsBase).
	codeBase unsafe.Pointer
	codeSize uintptr
	argsBase unsafe.Pointer
	argsSize uintptr

	// module is the name of the loaded image whose slack hosts the code
	// region; empty when the code region is a private allocation.
	module string

	entries map[uint16]*poolEntry
	ready   bool
}

// align8 rounds v up to the next multiple of 8.
func align8(v uintptr) uintptr {
	return (v + poolAlignment - 1) &^ (poolAlignment - 1)
}

// poolLayout assigns non-overlapping, 8-byte-aligned code and args slots to
// entries, mutating codeOff/codeLen/argsOff, and returns the total code and
// args region sizes. codeLens must have one entry per entry.
func poolLayout(entries []poolEntry, codeLens []uintptr) (codeSize uintptr, argsSize uintptr) {
	if len(entries) != len(codeLens) {
		panic("syscalls: poolLayout: entries and codeLens length mismatch")
	}
	for i := range entries {
		cl := align8(codeLens[i])
		entries[i].codeOff = codeSize
		entries[i].codeLen = cl
		codeSize += cl

		entries[i].argsOff = argsSize
		argsSize += align8(uintptr(entries[i].argc) * 8)
	}
	return codeSize, argsSize
}

// entryFor maps a syscallStub (reference number) to its pool slot.
func (p *trampolinePool) entryFor(stub *syscallStub) (*poolEntry, bool) {
	e, ok := p.entries[stub.number]
	return e, ok
}
