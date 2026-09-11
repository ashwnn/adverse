package opsec

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCoverage_DirectSyscall(t *testing.T) {
	cfg := &Config{SyntheticOnly: true, DirectSyscalls: true}
	rows := Coverage(cfg)

	for _, r := range rows {
		if r.Stage == StageDirectSyscall {
			switch r.Category {
			case "User-mode hooks":
				if r.Status != StatusAvoided {
					t.Errorf("user-mode hook row expected Avoided, got %v", r.Status)
				}
			case "Sysmon", "ETW-TI", "MDE/EDR":
				if r.Status != StatusUnaffected {
					t.Errorf("kernel sensor %q expected Unaffected, got %v", r.Sensor, r.Status)
				}
			}
		}
	}
}

func TestCoverage_DirectSyscall_Disabled(t *testing.T) {
	cfg := &Config{SyntheticOnly: true, DirectSyscalls: false}
	rows := Coverage(cfg)

	for _, r := range rows {
		if r.Stage == StageDirectSyscall {
			if r.Status != StatusNotApplicable {
				t.Errorf("expected NotApplicable when disabled, got %v", r.Status)
			}
		}
	}
}

func TestCoverage_SyntheticOnly(t *testing.T) {
	cfg := &Config{SyntheticOnly: true, DirectSyscalls: true}
	rows := Coverage(cfg)

	for _, r := range rows {
		if r.Stage == StageHiveExtraction {
			if r.Technique == "Synthetic regf generation" {
				if r.Status != StatusAvoided {
					t.Errorf("synthetic row expected Avoided, got %v", r.Status)
				}
			}
		}
	}
}

func TestCoverage_Transport(t *testing.T) {
	cfg := &Config{SyntheticOnly: true, DirectSyscalls: true}
	rows := Coverage(cfg)

	found := false
	for _, r := range rows {
		if r.Stage == StageTransport {
			found = true
			if r.Status != StatusDegraded {
				t.Errorf("HTTPS transport expected Degraded, got %v", r.Status)
			}
		}
	}
	if !found {
		t.Error("no transport rows found")
	}
}

func TestRender(t *testing.T) {
	cfg := &Config{SyntheticOnly: true, DirectSyscalls: true}
	rows := Coverage(cfg)
	rendered := rows.Render()
	if len(rendered) == 0 {
		t.Fatal("Render produced empty output")
	}
	if !strings.Contains(rendered, "Avoided") {
		t.Error("Render output should contain 'Avoided'")
	}
}

func TestRenderEmpty(t *testing.T) {
	var sl SensorList
	rendered := sl.Render()
	if rendered != "(no coverage data)" {
		t.Errorf("expected empty message, got %q", rendered)
	}
}

func TestToRows_JSON(t *testing.T) {
	cfg := &Config{SyntheticOnly: true, DirectSyscalls: true}
	rows := Coverage(cfg)
	coverageRows := rows.ToRows()

	data, err := json.Marshal(coverageRows)
	if err != nil {
		t.Fatalf("JSON marshal: %v", err)
	}

	var parsed []CoverageRow
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("JSON unmarshal: %v", err)
	}

	foundAvoided := false
	for _, r := range parsed {
		if r.Status == "Avoided" {
			foundAvoided = true
			break
		}
	}
	if !foundAvoided {
		t.Error("expected at least one Avoided row")
	}
}

func TestSensorStatus_String(t *testing.T) {
	tests := []struct {
		status   SensorStatus
		expected string
	}{
		{StatusAvoided, "Avoided"},
		{StatusDegraded, "Degraded"},
		{StatusUnaffected, "Unaffected"},
		{StatusNotApplicable, "NotApplicable"},
		{SensorStatus(99), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.status.String(); got != tt.expected {
			t.Errorf("SensorStatus(%d) = %q, want %q", int(tt.status), got, tt.expected)
		}
	}
}

func TestNoKernelProviderAsPatchTarget(t *testing.T) {
	cfg := &Config{SyntheticOnly: true, DirectSyscalls: true}
	rows := Coverage(cfg)
	for _, r := range rows {
		if r.Stage == StageDirectSyscall {
			if r.Category == "Sysmon" || r.Category == "ETW-TI" || r.Category == "MDE/EDR" {
				if r.Status == StatusAvoided {
					t.Errorf("kernel provider %q must never be Avoided", r.Sensor)
				}
			}
		}
	}
}
