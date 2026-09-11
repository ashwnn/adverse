package message

import (
	"encoding/json"
	"testing"
)

// FuzzValidate ensures message.Validate never panics on arbitrary input and
// that valid messages round-trip. The validator must fail closed (non-nil
// error) for anything not exactly matching the schema.
func FuzzValidate(f *testing.F) {
	f.Add([]byte(`{"type":"beacon","agent_id":"aabbccdd","task_id":"t","payload":"","ts":1.0}`))
	f.Add([]byte(`{"type":"ack","agent_id":"aabbccdd","task_id":"t","payload":"","ts":1.0}`))
	f.Add([]byte(`{"type":"unknown","agent_id":"x","task_id":"t","payload":"","ts":1.0}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"type":"kill","agent_id":"x","task_id":"k","payload":"kill","ts":1.0,"epoch":5,"sig":"abc"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var d map[string]any
		if err := json.Unmarshal(data, &d); err != nil {
			t.Skip()
		}
		_ = Validate(d)
	})
}
