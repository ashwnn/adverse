//go:build windows

package audit

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// lockBytes pins the given pages in physical memory via VirtualLock so they
// cannot be paged to the swap file. This protects sensitive hive plaintext
// from forensic disk analysis. Falls back silently on error (e.g., if the
// process lacks SeLockMemoryPrivilege).
func lockBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	_ = windows.VirtualLock(
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
	)
}

// unlockBytes releases previously locked pages via VirtualUnlock.
func unlockBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	_ = windows.VirtualUnlock(
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
	)
}
