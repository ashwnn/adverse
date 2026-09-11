package message

import (
	"strings"
	"testing"
)

func TestValidateValid(t *testing.T) {
	valid := []map[string]any{
		Make("hello", "agent-1", "task-1", "", 1.0),
		Make("beacon", "agent-1", "task-1", "ok", 2.5),
		Make("task", "agent-1", "task-1", "run-cmd", 3),
		Make("result", "agent-1", "task-1", "whoami output", 4.2),
		Make("kill", "agent-1", "task-1", "kill", 5.0),
	}
	for i, m := range valid {
		if err := Validate(m); err != nil {
			t.Errorf("case %d: %v", i, err)
		}
	}
}

func TestValidateKillFields(t *testing.T) {
	m := Make("kill", "agent-1", "task-1", "kill", 5.0)
	m["epoch"] = float64(42)
	m["sig"] = "sig-b64"
	if err := Validate(m); err != nil {
		t.Errorf("valid kill fields rejected: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	base := func() map[string]any { return Make("beacon", "agent-1", "task-1", "p", 1.0) }
	tests := []struct {
		name   string
		mutate func(m map[string]any)
		want   string
	}{
		{"missing type", func(m map[string]any) { delete(m, "type") }, "type"},
		{"non-string type", func(m map[string]any) { m["type"] = 7 }, "type"},
		{"unknown type", func(m map[string]any) { m["type"] = "explode" }, "unknown type"},
		{"missing agent_id", func(m map[string]any) { delete(m, "agent_id") }, "agent_id"},
		{"empty agent_id", func(m map[string]any) { m["agent_id"] = "" }, "agent_id"},
		{"missing task_id", func(m map[string]any) { delete(m, "task_id") }, "task_id"},
		{"missing ts", func(m map[string]any) { delete(m, "ts") }, "ts"},
		{"string ts", func(m map[string]any) { m["ts"] = "now" }, "ts"},
		{"oversized payload", func(m map[string]any) { m["payload"] = strings.Repeat("a", MaxPayload+1) }, "1MB"},
		{"int payload", func(m map[string]any) { m["payload"] = 123 }, "payload"},
		{"bad epoch type", func(m map[string]any) { m["epoch"] = "seven" }, "epoch"},
		{"fractional epoch", func(m map[string]any) { m["epoch"] = 1.5 }, "epoch"},
		{"negative epoch", func(m map[string]any) { m["epoch"] = float64(-1) }, "epoch"},
		{"epoch at 2^64", func(m map[string]any) { m["epoch"] = 18446744073709551616.0 }, "epoch"},
		{"non-string sig", func(m map[string]any) { m["sig"] = 9 }, "sig"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := base()
			tc.mutate(m)
			err := Validate(m)
			if err == nil {
				t.Fatalf("accepted invalid message")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestValidatePayloadCoercion(t *testing.T) {
	// Python coerces dict/list payloads to their repr for validation.
	for _, p := range []any{
		map[string]any{"a": 1},
		[]any{1, 2, 3},
	} {
		m := Make("result", "agent-1", "task-1", "", 1.0)
		m["payload"] = p
		if err := Validate(m); err != nil {
			t.Errorf("payload %v rejected: %v", p, err)
		}
	}
}

func TestMakeRoundTrip(t *testing.T) {
	m := Make("task", "a", "t", "cmd", 9.5)
	if m["type"] != "task" || m["agent_id"] != "a" || m["task_id"] != "t" || m["payload"] != "cmd" || m["ts"] != 9.5 {
		t.Fatalf("Make shape wrong: %#v", m)
	}
	if err := Validate(m); err != nil {
		t.Fatalf("Make output invalid: %v", err)
	}
}
