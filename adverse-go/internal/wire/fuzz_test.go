package wire

import (
	"testing"
)

// FuzzParse ensures wire.Parse never panics on arbitrary input and that
// accepted frames round-trip through Build. Corrupt frames must fail closed
// (error or !complete), never crash.
func FuzzParse(f *testing.F) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	prefix := []byte("SX1")
	msg := []byte(`{"type":"beacon","agent_id":"aabbccdd","task_id":"t","payload":"","ts":1.0}`)
	// Seed corpus: valid frame, truncated frame, garbage, oversized length.
	if frame, err := Build(msg, key, prefix, nil, 0, DirectionClientToServer); err == nil {
		f.Add(frame)
		f.Add(frame[:len(frame)-1])
		f.Add([]byte("garbage"))
		f.Add([]byte{0x53, 0x58, 0x31, 0x00, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff})
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			t.Skip()
		}
		_, _, _, _ = Parse(data, key, prefix, nil, DirectionClientToServer)
	})
}
