package registrywin

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// SyntheticHeaderValid validates a regf synthetic header before exfil: the
// data must start with the regf magic and carry at least one synthetic marker.
func SyntheticHeaderValid(data []byte) error {
	if len(data) < 4 || string(data[:4]) != "regf" {
		return fmt.Errorf("synthetic validation failed: missing regf magic")
	}
	if !strings.Contains(string(data), "CANARY") &&
		!strings.Contains(string(data), "BootKey") &&
		!strings.Contains(string(data), "UserNames") &&
		!strings.Contains(string(data), "Policy:") {
		return fmt.Errorf("synthetic validation failed: no canary/synthetic marker")
	}
	return nil
}

// GenerateCanary returns a random CANARY token for this session.
func GenerateCanary() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "CANARY-" + hex.EncodeToString(b)
}
