//go:build !amd64

package obfuscate

// JunkIsland for non-amd64 targets is provided by the portable pure-Go
// implementation in junk_island.go (no build tag). This file is retained only
// to document that the historical amd64-specific asm variant was removed in
// favor of portability and runtime safety.
