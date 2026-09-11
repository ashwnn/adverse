//go:build !linux && !windows

package audit

// lockBytes is a no-op on platforms that lack mlock/VirtualLock
// (e.g., darwin, freebsd). Linux uses syscall.Mlock; Windows uses
// VirtualLock in secure_windows.go.
func lockBytes(b []byte) {}

// unlockBytes is the matching no-op for unlockBytes.
func unlockBytes(b []byte) {}
