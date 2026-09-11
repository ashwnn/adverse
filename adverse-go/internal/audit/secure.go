// Package audit provides anti-forensic memory hygiene: locked buffers,
// secure-zero semantics, and synthetic registry hive generation for lab use.
//
// On Linux, SecureBuffer approximates VirtualLock via mlock(2) where available.
// On Windows, VirtualLock is used directly (build-tagged). secureZero uses
// unsafe volatile stores that cannot be optimized away by the compiler.
//
// Scope: locking/zeroization applies only to memory held inside a
// SecureBuffer. Plain []byte values produced by convenience APIs (such as the
// plaintext returned by GenerateSyntheticHive) are ordinary heap allocations
// and are not locked or automatically zeroed.
//
// Residual risk: kernel telemetry (ETW-TI, Sysmon, MDE) still observes all
// memory operations regardless of user-mode zeroing.
package audit

import (
	"crypto/rand"
	"runtime"
	"sync"
	"unsafe"
)

// SecureBuffer is a locked, zero-on-free buffer for hive plaintext.
type SecureBuffer struct {
	mu     sync.Mutex
	data   []byte
	locked bool
}

// NewSecureBuffer allocates a locked buffer of n bytes (simulated VirtualLock).
func NewSecureBuffer(n int) (*SecureBuffer, error) {
	if n <= 0 {
		return nil, nil
	}
	b := make([]byte, n)
	// Attempt mlock on Linux if available; fall back to runtime KeepAlive.
	lockBytes(b)
	runtime.KeepAlive(b)
	return &SecureBuffer{data: b, locked: true}, nil
}

// Bytes returns the underlying slice (caller must not retain after Free).
func (s *SecureBuffer) Bytes() []byte {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

// Write copies p into the buffer (reallocates if needed).
func (s *SecureBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(p) > len(s.data) {
		// Zero and unlock old buffer before replacing.
		SecureZeroBytes(s.data)
		unlockBytes(s.data)
		nb := make([]byte, len(p))
		lockBytes(nb)
		runtime.KeepAlive(nb)
		s.data = nb
		s.locked = true
	}
	copy(s.data, p)
	return len(p), nil
}

// SecureZero overwrites the buffer with zeros using a non-optimized path.
func (s *SecureBuffer) SecureZero() {
	s.mu.Lock()
	defer s.mu.Unlock()
	SecureZeroBytes(s.data)
}

// Free zeros and releases the buffer (simulated VirtualUnlock + VirtualFree).
func (s *SecureBuffer) Free() {
	s.mu.Lock()
	defer s.mu.Unlock()
	SecureZeroBytes(s.data)
	unlockBytes(s.data)
	s.data = nil
	s.locked = false
}

// SecureZeroBytes zeros a byte slice via volatile pointer (prevents optimization).
func SecureZeroBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	p := unsafe.Pointer(&b[0])
	for i := range b {
		*(*byte)(unsafe.Pointer(uintptr(p) + uintptr(i))) = 0
	}
	runtime.KeepAlive(b)
}

// GenerateSyntheticHive builds a synthetic regf hive with canary markers.
//
// Ownership/zeroization contract — it returns TWO INDEPENDENT copies:
//
//   - the []byte is an ordinary, unlocked heap allocation. It is the synthetic
//     exfil payload handed to the caller; this package never locks or zeroes
//     it. Callers that want it erased must call SecureZeroBytes themselves once
//     serialization is complete.
//   - the *SecureBuffer is a separate locked copy. SecureZero/Free zero only
//     that locked copy; they never mutate the returned slice.
//
// The "plaintext lives in locked buffers" property therefore applies only to
// the SecureBuffer copy, not to the returned slice.
func GenerateSyntheticHive(hive string, size int, canary string) ([]byte, *SecureBuffer, error) {
	if size < 100 {
		size = 1024
	}
	sb, err := NewSecureBuffer(size)
	if err != nil {
		return nil, nil, err
	}
	plain := make([]byte, size)
	copy(plain[:4], []byte("regf"))
	copy(plain[4:8], []byte{0x01, 0x00, 0x00, 0x00}) // version

	// Embed canary at fixed offset
	can := []byte(canary)
	if len(can) > 0 && size > 100 {
		copy(plain[50:50+len(can)], can)
	}

	// Hive-specific synthetic markers at offset 80
	switch hive {
	case "SYSTEM":
		copy(plain[80:88], []byte("BootKey:"))
	case "SAM":
		copy(plain[80:89], []byte("UserNames"))
	case "SECURITY":
		copy(plain[80:87], []byte("Policy:"))
	}

	// Fill rest with pseudo-random (non-sensitive)
	if size > 100 {
		rand.Read(plain[100:])
	}

	// Copy into secure buffer
	copy(sb.Bytes(), plain)
	return plain, sb, nil
}

// VerifyZeroed checks that a byte slice is all zeros (for forensic test).
func VerifyZeroed(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
