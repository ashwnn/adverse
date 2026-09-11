package antiforensic

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
)

// Config controls a scrub. Enabled is the explicit opt-in: when false, or when
// the binary runs on a non-Windows host, Scrub is a no-op. ExePath must be the
// absolute path of the running agent; only traces that reference its basename
// or path are removed. Args are used for matching command-line-derived traces
// where relevant. Logger is optional and receives the same actions that are
// accumulated in the Report.
type Config struct {
	Enabled bool
	ExePath string
	Args    []string
	Logger  *log.Logger
}

// Report records what a scrub did. Removed lists successful deletions, Skipped
// lists expected refusals (missing admin rights, missing key, locked or
// in-use artifact), and Errors lists unexpected failures. All three are
// best-effort and never abort the scrub.
type Report struct {
	Removed []string
	Skipped []string
	Errors  []string
}

// Scrub performs the best-effort cleanup described in the package
// documentation. It never returns an error and never fails hard: all failures
// are recorded in the Report (or, as a last resort, in Errors after a panic is
// recovered). If !Enabled or the host is not Windows, it is a no-op that
// returns an empty Report.
func Scrub(cfg Config) (rep Report) {
	defer func() {
		if r := recover(); r != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("antiforensic: recovered panic: %v", r))
		}
	}()
	return scrub(cfg)
}

func (r *Report) addRemoved(format string, args ...any) {
	r.Removed = append(r.Removed, fmt.Sprintf(format, args...))
}

func (r *Report) addSkipped(format string, args ...any) {
	r.Skipped = append(r.Skipped, fmt.Sprintf(format, args...))
}

func (r *Report) addError(format string, args ...any) {
	r.Errors = append(r.Errors, fmt.Sprintf(format, args...))
}

// minDistinctiveArgLen is the shortest argument that may participate in
// command-line matching. Short flags such as "-v" are ignored so unrelated MRU
// entries are never deleted just because the agent shares a common flag.
const minDistinctiveArgLen = 8

// rot13 applies the ROT13 substitution used by UserAssist value names. It is an
// involution, so the same function both encodes and decodes.
func rot13(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(b)
}

// baseName returns the last element of a path using either separator style, so
// Windows paths can be reasoned about on any host. A trailing separator is
// ignored: baseName(`C:\Tools\`) is "Tools".
func baseName(p string) string {
	p = strings.TrimRight(p, `\/`)
	if p == "" {
		return ""
	}
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// normalizeForMatch folds case and unifies separators for path comparison.
func normalizeForMatch(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), "/", `\`)
}

// normalizedAbs returns a cleaned, absolute, case-folded path for identity
// comparisons. If the path cannot be made absolute it is still cleaned.
func normalizedAbs(p string) string {
	if p == "" {
		return ""
	}
	if a, err := filepath.Abs(p); err == nil {
		p = a
	}
	return normalizeForMatch(filepath.Clean(p))
}

// samePathFold reports whether two paths refer to the same filesystem object by
// case-insensitive, separator-insensitive comparison of their cleaned absolute
// forms.
func samePathFold(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return normalizedAbs(a) == normalizedAbs(b)
}

// isIdentByte reports whether b is part of a file-name token. It exists so a
// basename match cannot bleed into a longer name: "agent.exe" must not match
// "myagent.exe" or "agent.exe.bak".
func isIdentByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '.', b == '_', b == '-':
		return true
	}
	return false
}

// containsExeName reports whether candidate contains name as a case-insensitive
// token delimited by non-identifier characters (or string boundaries).
func containsExeName(candidate, name string) bool {
	if candidate == "" || name == "" {
		return false
	}
	hay := strings.ToLower(candidate)
	needle := strings.ToLower(name)
	for from := 0; from <= len(hay)-len(needle); {
		i := strings.Index(hay[from:], needle)
		if i < 0 {
			return false
		}
		i += from
		end := i + len(needle)
		beforeOK := i == 0 || !isIdentByte(hay[i-1])
		afterOK := end == len(hay) || !isIdentByte(hay[end])
		if beforeOK && afterOK {
			return true
		}
		from = i + 1
	}
	return false
}

// referencesExe reports whether a registry string value or decoded name
// references the agent, either by full path or by basename.
func referencesExe(candidate, exePath string) bool {
	if candidate == "" || exePath == "" {
		return false
	}
	c := normalizeForMatch(candidate)
	if containsExeName(c, normalizeForMatch(exePath)) {
		return true
	}
	if base := baseName(exePath); base != "" {
		return containsExeName(c, strings.ToLower(base))
	}
	return false
}

// distinctiveArg reports whether an argument is specific enough to be used as a
// deletion signal: long enough and resembling a path, URL, or key=value pair.
func distinctiveArg(arg string) bool {
	arg = strings.TrimSpace(arg)
	if len(arg) < minDistinctiveArgLen {
		return false
	}
	return strings.ContainsAny(arg, `\/:=`)
}

// argMatches reports whether a registry string value contains one of the
// configured distinctive arguments.
func argMatches(value string, args []string) bool {
	if value == "" {
		return false
	}
	v := normalizeForMatch(value)
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if !distinctiveArg(arg) {
			continue
		}
		if strings.Contains(v, normalizeForMatch(arg)) {
			return true
		}
	}
	return false
}

func asciiLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func asciiFoldEqual(a, b byte) bool {
	return asciiLower(a) == asciiLower(b)
}

// containsFoldASCII searches raw bytes for an ASCII needle, case-insensitively.
func containsFoldASCII(data []byte, needle string) bool {
	if needle == "" || len(data) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(data); i++ {
		ok := true
		for j := 0; j < len(needle); j++ {
			if !asciiFoldEqual(data[i+j], needle[j]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// containsUTF16LEFold searches raw bytes for an ASCII needle encoded as
// UTF-16LE with a zero high byte, case-insensitively. This is how shell item
// (PIDL) data and REG_SZ values store file names.
func containsUTF16LEFold(data []byte, needle string) bool {
	if needle == "" || len(data) < 2*len(needle) {
		return false
	}
	for i := 0; i+2*len(needle) <= len(data); i++ {
		ok := true
		for j := 0; j < len(needle); j++ {
			if data[i+2*j+1] != 0 || !asciiFoldEqual(data[i+2*j], needle[j]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// matchesNeedle searches a registry value's raw bytes for needle in ASCII and
// UTF-16LE form, trying both path separator styles.
func matchesNeedle(data []byte, needle string) bool {
	if len(data) == 0 || needle == "" {
		return false
	}
	variants := [3]string{
		needle,
		strings.ReplaceAll(needle, "/", `\`),
		strings.ReplaceAll(needle, `\`, "/"),
	}
	for _, v := range variants {
		if v == "" {
			continue
		}
		if containsFoldASCII(data, v) || containsUTF16LEFold(data, v) {
			return true
		}
	}
	return false
}

// binaryReferencesExe reports whether a binary registry value references the
// agent by full path or basename.
func binaryReferencesExe(data []byte, exePath string) bool {
	if exePath == "" {
		return false
	}
	if matchesNeedle(data, exePath) {
		return true
	}
	if base := baseName(exePath); base != "" {
		return matchesNeedle(data, base)
	}
	return false
}

// binaryArgMatches reports whether a binary registry value references one of
// the configured distinctive arguments (e.g. a URL stored as UTF-16 in a PIDL).
func binaryArgMatches(data []byte, args []string) bool {
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if distinctiveArg(arg) && matchesNeedle(data, arg) {
			return true
		}
	}
	return false
}
