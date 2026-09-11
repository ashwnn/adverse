package registrywin

import "testing"

func TestSyntheticHeaderValid(t *testing.T) {
	if err := SyntheticHeaderValid([]byte("regf\x00\x01CANARY-abc")); err != nil {
		t.Errorf("expected valid: %v", err)
	}
	if err := SyntheticHeaderValid([]byte("regf\x00\x01BootKey:data")); err != nil {
		t.Errorf("expected valid with BootKey: %v", err)
	}
	if err := SyntheticHeaderValid([]byte("regf\x00\x01UserNames")); err != nil {
		t.Errorf("expected valid with UserNames: %v", err)
	}
	if err := SyntheticHeaderValid([]byte("regf\x00\x01Policy:abc")); err != nil {
		t.Errorf("expected valid with Policy:: %v", err)
	}
	if err := SyntheticHeaderValid([]byte("bad!")); err == nil {
		t.Error("expected invalid header error")
	}
	if err := SyntheticHeaderValid([]byte("regf\x00\x00nope")); err == nil {
		t.Error("expected canary missing error")
	}
}

func TestGenerateCanary(t *testing.T) {
	c1 := GenerateCanary()
	c2 := GenerateCanary()
	if c1 == c2 {
		t.Error("canaries should differ")
	}
	if len(c1) < 8 {
		t.Error("canary too short")
	}
}
