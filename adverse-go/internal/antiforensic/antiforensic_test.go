package antiforensic

import (
	"io"
	"log"
	"testing"
)

func TestRot13(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Hello, World!", "Uryyb, Jbeyq!"},
		{"n", "a"},
		{"N", "A"},
		{"C:\\Users\\ash\\agent.exe", "P:\\Hfref\\nfu\\ntrag.rkr"},
		{"123 _-", "123 _-"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := rot13(tc.in); got != tc.want {
			t.Errorf("rot13(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if got := rot13(rot13(tc.in)); got != tc.in {
			t.Errorf("rot13 round-trip of %q = %q", tc.in, got)
		}
	}
}

func TestBaseName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"agent.exe", "agent.exe"},
		{`C:\Tools\Agent.EXE`, "Agent.EXE"},
		{"C:/tools/agent.exe", "agent.exe"},
		{"/usr/local/bin/agent", "agent"},
		{`C:\Tools\`, "Tools"},
		{"agent", "agent"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := baseName(tc.in); got != tc.want {
			t.Errorf("baseName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestContainsExeNameBoundaries(t *testing.T) {
	cases := []struct {
		candidate, name string
		want            bool
	}{
		{`C:\tools\agent.exe`, "agent.exe", true},
		{`/opt/Agent.EXE`, "agent.exe", true},
		{"agent.exe", "agent.exe", true},
		{`UEME_RUNPATH:C:\tools\agent.exe`, "agent.exe", true},
		{`UEME_RUNPATH:C:\tools\agent.exe --profile=lab`, "agent.exe", true},
		{`C:\tools\myagent.exe`, "agent.exe", false},
		{`C:\tools\agent.exe.bak`, "agent.exe", false},
		{`C:\tools\agent.exe-1234`, "agent.exe", false},
		{"", "agent.exe", false},
		{"agent.exe", "", false},
	}
	for _, tc := range cases {
		if got := containsExeName(tc.candidate, tc.name); got != tc.want {
			t.Errorf("containsExeName(%q, %q) = %v, want %v", tc.candidate, tc.name, got, tc.want)
		}
	}
}

func TestReferencesExe(t *testing.T) {
	exe := `C:\Tools\Agent.EXE`
	cases := []struct {
		candidate string
		want      bool
	}{
		{`c:\tools\agent.exe`, true},
		{`C:/tools/agent.exe`, true},
		{`UEME_RUNPATH:C:\tools\agent.exe`, true},
		{`UEME_RUNPATH:C:\tools\agent.exe --profile=lab`, true},
		{`\Device\HarddiskVolume3\Users\lab\agent.exe`, true},
		{`C:\tools\otheragent.exe`, false},
		{`C:\tools\agent.exe.bak`, false},
		{`C:\tools\unrelated.exe`, false},
		{"", false},
	}
	for _, tc := range cases {
		if got := referencesExe(tc.candidate, exe); got != tc.want {
			t.Errorf("referencesExe(%q) = %v, want %v", tc.candidate, got, tc.want)
		}
	}
	if referencesExe(`C:\tools\agent.exe`, "") {
		t.Error("referencesExe with empty exe path should be false")
	}
}

func TestSamePathFold(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{`C:\Temp\Agent.EXE`, `c:\temp\agent.exe`, true},
		{`C:/Temp/agent.exe`, `C:\Temp\agent.exe`, true},
		{`C:\Temp\agent.exe`, `C:\Temp\other.exe`, false},
		{"", `C:\Temp\agent.exe`, false},
	}
	for _, tc := range cases {
		if got := samePathFold(tc.a, tc.b); got != tc.want {
			t.Errorf("samePathFold(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestArgMatches(t *testing.T) {
	cases := []struct {
		value string
		args  []string
		want  bool
	}{
		{"cmd /c agent.exe --profile=lab", []string{"--profile=lab"}, true},
		{`run C:\payloads\stage2.bin`, []string{`C:\payloads\stage2.bin`}, true},
		{"x --profile=lab", []string{"  --profile=lab  "}, true},
		{"whatever -v", []string{"-v"}, false},
		{"noise lognoise", []string{"lognoise"}, false},
		{"x", nil, false},
		{"", []string{"--profile=lab"}, false},
	}
	for _, tc := range cases {
		if got := argMatches(tc.value, tc.args); got != tc.want {
			t.Errorf("argMatches(%q, %v) = %v, want %v", tc.value, tc.args, got, tc.want)
		}
	}
}

func utf16le(s string) []byte {
	out := make([]byte, 0, 2*len(s))
	for i := 0; i < len(s); i++ {
		out = append(out, s[i], 0)
	}
	return out
}

func TestContainsFoldASCII(t *testing.T) {
	data := []byte("session LOGGING Agent.EXE pid=42")
	if !containsFoldASCII(data, "agent.exe") {
		t.Error("expected case-insensitive ASCII match")
	}
	if containsFoldASCII(data, "other.exe") {
		t.Error("unexpected match for other.exe")
	}
	if containsFoldASCII(data, "") {
		t.Error("empty needle must not match")
	}
	if containsFoldASCII([]byte("agent"), "agent.exe") {
		t.Error("needle longer than data must not match")
	}
}

func TestContainsUTF16LEFold(t *testing.T) {
	data := utf16le(`C:\Tools\AGENT.EXE`)
	if !containsUTF16LEFold(data, "agent.exe") {
		t.Error("expected UTF-16LE case-insensitive match")
	}
	if !containsUTF16LEFold(data, "tools") {
		t.Error("expected UTF-16LE match for path element")
	}
	if containsUTF16LEFold(data, "other.exe") {
		t.Error("unexpected UTF-16LE match for other.exe")
	}
	if containsUTF16LEFold(data, "") {
		t.Error("empty needle must not match")
	}
	if containsUTF16LEFold(data[:4], "agent.exe") {
		t.Error("needle longer than data must not match")
	}
}

func TestBinaryReferencesExe(t *testing.T) {
	exe := `C:\Users\lab\agent.exe`
	utf16Data := utf16le(`\Device\HarddiskVolume3\Users\lab\agent.exe`)
	if !binaryReferencesExe(utf16Data, exe) {
		t.Error("expected UTF-16LE device-path reference")
	}
	asciiData := []byte(`junk C:/Tools/Agent.EXE junk`)
	if !binaryReferencesExe(asciiData, `C:\Tools\agent.exe`) {
		t.Error("expected ASCII forward-slash reference")
	}
	if binaryReferencesExe([]byte("nothing to see"), exe) {
		t.Error("unexpected match")
	}
	if binaryReferencesExe(utf16Data, "") {
		t.Error("empty exe path must not match")
	}
}

func TestBinaryArgMatches(t *testing.T) {
	data := utf16le(`cmd.exe /k https://lab.example/stage2`)
	if !binaryArgMatches(data, []string{"https://lab.example/stage2"}) {
		t.Error("expected UTF-16LE argument match")
	}
	if binaryArgMatches(data, []string{"-x"}) {
		t.Error("short argument must be ignored")
	}
	if binaryArgMatches([]byte("nope"), []string{"--profile=lab"}) {
		t.Error("unexpected argument match")
	}
}

func TestReportAccumulation(t *testing.T) {
	var r Report
	r.addRemoved("removed %d", 3)
	r.addSkipped("skipped %s", "denied")
	r.addError("error %d", 7)
	if len(r.Removed) != 1 || r.Removed[0] != "removed 3" {
		t.Errorf("Removed = %v", r.Removed)
	}
	if len(r.Skipped) != 1 || r.Skipped[0] != "skipped denied" {
		t.Errorf("Skipped = %v", r.Skipped)
	}
	if len(r.Errors) != 1 || r.Errors[0] != "error 7" {
		t.Errorf("Errors = %v", r.Errors)
	}
}

func assertEmptyReport(t *testing.T, r Report) {
	t.Helper()
	if len(r.Removed) != 0 || len(r.Skipped) != 0 || len(r.Errors) != 0 {
		t.Fatalf("expected empty report, got removed=%v skipped=%v errors=%v", r.Removed, r.Skipped, r.Errors)
	}
}

func TestScrubDisabledNoop(t *testing.T) {
	r := Scrub(Config{
		Enabled: false,
		ExePath: `C:\Tools\agent.exe`,
		Args:    []string{"--profile=lab"},
		Logger:  log.New(io.Discard, "", 0),
	})
	assertEmptyReport(t, r)
}
