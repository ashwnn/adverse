// Package message is a Go port of the ADVERSE control-protocol message schema
// (Python reference: c2/core/message.py in the repository root).
//
// Messages are JSON dicts with the fixed shape:
//
//	{"type", "agent_id", "task_id", "payload", "ts"}
//
// Supported types: hello, beacon, task, ack, result, kill.
package message

import (
	"fmt"
	"math"
)

// ValidTypes is the set of supported message types.
var ValidTypes = map[string]struct{}{
	"hello":  {},
	"beacon": {},
	"task":   {},
	"ack":    {},
	"result": {},
	"kill":   {},
}

// MaxPayload caps payload size at 1MB (results / uploads).
const MaxPayload = 1 << 20

// Make constructs a canonical message dict.
func Make(msgType, agentID, taskID, payload string, ts float64) map[string]any {
	return map[string]any{
		"type":     msgType,
		"agent_id": agentID,
		"task_id":  taskID,
		"payload":  payload,
		"ts":       ts,
	}
}

// Validate returns an error string if d is not a valid message, else nil.
// It mirrors the Python reference field-for-field, including the payload
// coercion rules and the optional epoch/sig kill fields.
func Validate(d map[string]any) error {
	t, ok := d["type"].(string)
	if !ok {
		return fmt.Errorf("missing/invalid 'type'")
	}
	if _, ok := ValidTypes[t]; !ok {
		return fmt.Errorf("unknown type %q", t)
	}
	if agentID, ok := d["agent_id"].(string); !ok || agentID == "" {
		return fmt.Errorf("missing/invalid 'agent_id'")
	}
	if taskID, ok := d["task_id"].(string); !ok || taskID == "" {
		return fmt.Errorf("missing/invalid 'task_id'")
	}
	if _, ok := d["ts"].(float64); !ok {
		return fmt.Errorf("missing/invalid 'ts'")
	}
	payload := ""
	switch p := d["payload"].(type) {
	case nil:
	case string:
		payload = p
	case map[string]any, []any:
		payload = fmt.Sprintf("%v", p)
	default:
		return fmt.Errorf("invalid 'payload' type")
	}
	if len([]byte(payload)) > MaxPayload {
		return fmt.Errorf("payload exceeds 1MB cap")
	}
	if e, ok := d["epoch"]; ok {
		f, ok := e.(float64)
		// Float64 cannot precisely represent 2^64; 18446744073709551616 is 2^64.
		// Use >= 2^64 to reject overflow (MaxUint64=2^64-1 rounds to 2^64 in float64,
		// so this is off by one for that exact value, but epoch is small in practice).
		if !ok || f != math.Trunc(f) || f < 0 || f >= 18446744073709551616 {
			return fmt.Errorf("invalid 'epoch' (must be an int in 0..2**64-1)")
		}
	}
	if s, ok := d["sig"]; ok {
		if _, ok := s.(string); !ok {
			return fmt.Errorf("invalid 'sig' type (must be str)")
		}
	}
	return nil
}
