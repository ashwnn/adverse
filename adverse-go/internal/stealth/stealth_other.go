//go:build !windows

package stealth

import (
	"fmt"
)

// resolveViaExport simulates export RVA sort on non-Windows platforms.
// Returns a deterministic fixture map matching syscalls package constants.
func resolveViaExport(name string, seed byte) (uint16, error) {
	fixture := map[string]uint16{
		"NtOpenKey":                0x0019,
		"NtClose":                  0x000F,
		"NtAllocateVirtualMemory":  0x0018,
		"NtFreeVirtualMemory":      0x001D,
		"NtProtectVirtualMemory":   0x0050,
		"NtSaveKey":                0x0100,
		"NtCreateFile":             0x0052,
		"NtQuerySystemInformation": 0x0036,
		// Real extraction stubs (fixture values for Linux CI)
		"NtOpenProcessToken":      0x00F9,
		"NtAdjustPrivilegesToken": 0x0128,
		"NtReadFile":              0x0006,
	}
	if v, ok := fixture[name]; ok {
		_ = seed
		return v, nil
	}
	return 0, fmt.Errorf("unknown Nt export: %s", name)
}
