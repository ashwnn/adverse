// Disabled: the real JunkIsland implementation is the portable pure-Go
// opaque-predicate version in junk_island.go. A hand-written amd64
// "jump-over-data-byte" trampoline was considered but rejected: a
// mis-encoded displacement would crash the agent at runtime, and the
// runtime mis-decode behavior cannot be verified in this build environment.
// This file is retained only as a marker so it is not mistaken for missing;
// it defines no symbols.
