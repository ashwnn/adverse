// Package opsec models per-sensor detection coverage for the ADVERSE client pipeline.
//
// The sensor-coverage matrix marks which sensors are affected or unaffected
// by the agent's techniques (direct syscalls, synthetic extraction, HTTPS transport).
// Kernel sensors (ETW-TI, Sysmon callbacks, MDE) are always marked Unaffected.
//
// This package is read-only — it does not perform any evasion or collection.
package opsec

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SensorStatus describes the effect of a technique on a specific sensor.
type SensorStatus int

const (
	StatusAvoided       SensorStatus = iota // technique avoids this sensor
	StatusDegraded                          // degrades confidence but sensor still fires
	StatusUnaffected                        // no effect; sensor observes normally
	StatusNotApplicable                     // sensor not relevant
)

func (s SensorStatus) String() string {
	switch s {
	case StatusAvoided:
		return "Avoided"
	case StatusDegraded:
		return "Degraded"
	case StatusUnaffected:
		return "Unaffected"
	case StatusNotApplicable:
		return "NotApplicable"
	default:
		return "Unknown"
	}
}

// Stage identifies the pipeline stage.
type Stage string

const (
	StageDirectSyscall  Stage = "direct_syscall"
	StageHiveExtraction Stage = "hive_extraction"
	StageTransport      Stage = "transport"
)

// Sensor describes one technique × sensor observation.
type Sensor struct {
	Stage     Stage        `json:"stage"`
	Technique string       `json:"technique"`
	Sensor    string       `json:"sensor"`
	Category  string       `json:"category"`
	Status    SensorStatus `json:"status"`
	Rationale string       `json:"rationale"`
}

// SensorList is a named slice with rendering methods.
type SensorList []Sensor

// CoverageRow is the flattened output type for JSON.
type CoverageRow struct {
	Stage     string `json:"stage"`
	Technique string `json:"technique"`
	Sensor    string `json:"sensor"`
	Category  string `json:"category"`
	Status    string `json:"status"`
	Rationale string `json:"rationale"`
}

// Config controls which techniques are active for coverage computation.
type Config struct {
	SyntheticOnly  bool `json:"synthetic_only"`
	DirectSyscalls bool `json:"direct_syscalls"`
}

// Coverage returns the full sensor-coverage matrix for the given config.
func Coverage(cfg *Config) SensorList {
	var rows []Sensor
	rows = append(rows, coverageDirectSyscall(cfg)...)
	rows = append(rows, coverageHiveExtraction(cfg)...)
	rows = append(rows, coverageTransport(cfg)...)
	return rows
}

func coverageDirectSyscall(cfg *Config) []Sensor {
	na := StatusNotApplicable
	if !cfg.DirectSyscalls {
		return []Sensor{
			{Stage: StageDirectSyscall, Technique: "NtOpenKey direct syscall", Sensor: "ntdll user-mode hooks", Category: "User-mode hooks", Status: na, Rationale: "Direct syscalls not enabled"},
		}
	}
	return []Sensor{
		{
			Stage: StageDirectSyscall, Technique: "NtOpenKey direct syscall",
			Sensor: "ntdll!NtOpenKey user-mode hooks", Category: "User-mode hooks",
			Status: StatusAvoided, Rationale: "SYSCALL instruction bypasses ntdll user-mode hooks",
		},
		{
			Stage: StageDirectSyscall, Technique: "Persistent trampoline pool (image slack)",
			Sensor: "Memory scanners — private executable region heuristics (Moneta, pe-sieve)", Category: "Memory scanners",
			Status: StatusDegraded, Rationale: "Stub code is committed once inside a loaded image's tail slack, so VirtualQuery reports MEM_IMAGE rather than private RX; section-backing scanners can still flag unbacked image slack",
		},
		{
			Stage: StageDirectSyscall, Technique: "Trampoline pool (private fallback)",
			Sensor: "Memory scanners — private executable region heuristics (Moneta, pe-sieve)", Category: "Memory scanners",
			Status: StatusDegraded, Rationale: "If image-slack placement fails, one persistent private RX region remains (no per-call VirtualAlloc/VirtualProtect churn)",
		},
		{
			Stage: StageDirectSyscall, Technique: "NtOpenKey direct syscall",
			Sensor: "Sysmon 12/13/14 (kernel callbacks)", Category: "Sysmon",
			Status: StatusUnaffected, Rationale: "Kernel CmRegisterCallbackEx fires regardless of call origin",
		},
		{
			Stage: StageDirectSyscall, Technique: "NtOpenKey direct syscall",
			Sensor: "ETW-TI (kernel provider)", Category: "ETW-TI",
			Status: StatusUnaffected, Rationale: "Kernel provider; cannot be patched from user-mode",
		},
		{
			Stage: StageDirectSyscall, Technique: "NtOpenKey direct syscall",
			Sensor: "MDE EDR correlation", Category: "MDE/EDR",
			Status: StatusUnaffected, Rationale: "MDE correlates kernel telemetry",
		},
	}
}

func coverageHiveExtraction(cfg *Config) []Sensor {
	na := StatusNotApplicable
	if cfg.SyntheticOnly {
		return []Sensor{
			{Stage: StageHiveExtraction, Technique: "Synthetic regf generation", Sensor: "Filesystem sensors (Sysmon 11, MFT)", Category: "Sysmon", Status: StatusAvoided, Rationale: "No file operations; in-memory synthetic data only"},
			{Stage: StageHiveExtraction, Technique: "NtSaveKey", Sensor: "Kernel registry telemetry", Category: "Sysmon", Status: na, Rationale: "Not used in synthetic mode"},
		}
	}
	return []Sensor{
		{Stage: StageHiveExtraction, Technique: "NtSaveKey", Sensor: "Sysmon 12 + file creation", Category: "Sysmon", Status: StatusUnaffected, Rationale: "Kernel telemetry observes NtSaveKey"},
		{Stage: StageHiveExtraction, Technique: "NtSaveKey", Sensor: "MDE behavior monitoring", Category: "MDE/EDR", Status: StatusUnaffected, Rationale: "Kernel-mode monitoring active"},
	}
}

func coverageTransport(cfg *Config) []Sensor {
	return []Sensor{
		{
			Stage: StageTransport, Technique: "HTTPS POST", Sensor: "TLS inspection / proxy logs",
			Category: "Network", Status: StatusDegraded,
			Rationale: "Standard HTTPS traffic; jitter degrades timing analysis",
		},
	}
}

// Render produces a human-readable table for verbose/dry-run CLI output.
func (s SensorList) Render() string {
	if len(s) == 0 {
		return "(no coverage data)"
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%-4s %-25s %-40s %-30s %-15s %s\n",
		"#", "Stage", "Technique", "Sensor", "Status", "Rationale"))
	b.WriteString(strings.Repeat("-", 140) + "\n")
	for i, row := range s {
		b.WriteString(fmt.Sprintf("%-4d %-25s %-40s %-30s %-15s %s\n",
			i+1, string(row.Stage), row.Technique, row.Sensor, row.Status.String(), row.Rationale))
	}
	return b.String()
}

// ToRows converts SensorList to []CoverageRow for JSON marshalling.
func (s SensorList) ToRows() []CoverageRow {
	rows := make([]CoverageRow, len(s))
	for i, sensor := range s {
		rows[i] = CoverageRow{
			Stage:     string(sensor.Stage),
			Technique: sensor.Technique,
			Sensor:    sensor.Sensor,
			Category:  sensor.Category,
			Status:    sensor.Status.String(),
			Rationale: sensor.Rationale,
		}
	}
	return rows
}

// MarshalJSON implements json.Marshaler for CoverageRow.
func (cr CoverageRow) MarshalJSON() ([]byte, error) {
	type Alias CoverageRow
	return json.Marshal(struct {
		Alias
	}{Alias(cr)})
}
