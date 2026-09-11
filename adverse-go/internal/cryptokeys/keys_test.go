package cryptokeys

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// katFile is the known-answer vector set loaded from testdata/kat.json.
// There is no external generator script; the forward-secret vectors can be
// reprinted with:
//
//	GEN_KAT_FS=1 go test ./internal/cryptokeys -run TestGenKATFS -v
//
// (see gen_kat_fs_test.go). The remaining vectors are maintained by hand.
type katFile struct {
	Secret        string `json:"secret"`
	Secret32      string `json:"secret32"`
	BootstrapKey  string `json:"bootstrap_key"`
	ServerStatic  string `json:"server_static_pub"`
	KillSignPub   string `json:"kill_sign_pub"`
	AgentEphPriv  string `json:"agent_eph_priv"`
	AgentEphPub   string `json:"agent_eph_pub"`
	ServerEphPriv string `json:"server_eph_priv"`
	ServerEphPub  string `json:"server_eph_pub"`
	Salt          string `json:"salt"`
	AgentID       string `json:"agent_id"`
	HandshakeKey  string `json:"handshake_key"`
	SessionKeyFS  string `json:"session_key_fs"`
	FramePrefix   string `json:"frame_prefix"`
	FramePrefixFS string `json:"frame_prefix_fs"`
	Kill          struct {
		Epoch   uint64 `json:"epoch"`
		AgentID string `json:"agent_id"`
		Payload string `json:"payload"`
		Sig     string `json:"sig"`
	} `json:"kill"`
}

func loadKAT(t *testing.T) katFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "kat.json"))
	if err != nil {
		t.Fatalf("read kat.json: %v", err)
	}
	var k katFile
	if err := json.Unmarshal(raw, &k); err != nil {
		t.Fatalf("parse kat.json: %v", err)
	}
	return k
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

func bytes32(t *testing.T, b []byte) [32]byte {
	t.Helper()
	if len(b) != 32 {
		t.Fatalf("want 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func bytes16(t *testing.T, b []byte) [16]byte {
	t.Helper()
	if len(b) != 16 {
		t.Fatalf("want 16 bytes, got %d", len(b))
	}
	var out [16]byte
	copy(out[:], b)
	return out
}

func bytes3(t *testing.T, b []byte) [3]byte {
	t.Helper()
	if len(b) != 3 {
		t.Fatalf("want 3 bytes, got %d", len(b))
	}
	var out [3]byte
	copy(out[:], b)
	return out
}

// TestKatVectors verifies the Go key schedule reproduces the Python v2
// reference values for every derivation step.
func TestKatVectors(t *testing.T) {
	k := loadKAT(t)

	secret32 := bytes32(t, mustHex(t, k.Secret32))
	got32, err := Secret32(k.Secret)
	if err != nil {
		t.Fatalf("Secret32: %v", err)
	}
	if got32 != secret32 {
		t.Errorf("Secret32 mismatch: got %x want %x", got32, secret32)
	}

	boot, err := BootstrapKey(secret32)
	if err != nil {
		t.Fatalf("BootstrapKey: %v", err)
	}
	if want := mustHex(t, k.BootstrapKey); hex.EncodeToString(boot[:]) != k.BootstrapKey {
		t.Errorf("BootstrapKey mismatch: got %x want %x", boot, want)
	}

	serverPriv, err := DeriveServerKey(secret32)
	if err != nil {
		t.Fatalf("DeriveServerKey: %v", err)
	}
	serverPub, err := ServerPublicBytes(serverPriv)
	if err != nil {
		t.Fatalf("ServerPublicBytes: %v", err)
	}
	if want := mustHex(t, k.ServerStatic); hex.EncodeToString(serverPub[:]) != k.ServerStatic {
		t.Errorf("server static pub mismatch: got %x want %x", serverPub, want)
	}

	signPriv, err := DeriveSignKey(secret32)
	if err != nil {
		t.Fatalf("DeriveSignKey: %v", err)
	}
	signPub := signPriv.Public().(ed25519.PublicKey)
	if want := mustHex(t, k.KillSignPub); hex.EncodeToString(signPub) != k.KillSignPub {
		t.Errorf("kill sign pub mismatch: got %x want %x", signPub, want)
	}

	ephPub := bytes32(t, mustHex(t, k.AgentEphPub))
	salt := bytes16(t, mustHex(t, k.Salt))
	handshake, err := HandshakeKey(serverPriv, ephPub, salt, k.AgentID)
	if err != nil {
		t.Fatalf("HandshakeKey: %v", err)
	}
	if want := mustHex(t, k.HandshakeKey); hex.EncodeToString(handshake[:]) != k.HandshakeKey {
		t.Errorf("handshake key mismatch: got %x want %x", handshake, want)
	}

	// Agent-side derivation must agree: ECDH(agent_eph, server_pub) gives the
	// same shared secret, proving both peers derive the identical handshake key.
	ephPriv, err := ecdh.X25519().NewPrivateKey(mustHex(t, k.AgentEphPriv))
	if err != nil {
		t.Fatalf("agent eph: %v", err)
	}
	agentHandshake, err := HandshakeKey(ephPriv, serverPub, salt, k.AgentID)
	if err != nil {
		t.Fatalf("HandshakeKey (agent side): %v", err)
	}
	if agentHandshake != handshake {
		t.Errorf("agent-side handshake key mismatch: got %x want %x", agentHandshake, handshake)
	}

	prefix, err := FramePrefix(handshake, "v2")
	if err != nil {
		t.Fatalf("FramePrefix: %v", err)
	}
	if want := mustHex(t, k.FramePrefix); hex.EncodeToString(prefix[:]) != k.FramePrefix {
		t.Errorf("frame prefix mismatch: got %x want %x", prefix, want)
	}

	if !KillVerify(signPub, k.Kill.Epoch, k.Kill.AgentID, k.Kill.Payload, mustHex(t, k.Kill.Sig)) {
		t.Error("KillVerify rejected the Python-signed kill vector")
	}
	if KillVerify(signPub, k.Kill.Epoch+1, k.Kill.AgentID, k.Kill.Payload, mustHex(t, k.Kill.Sig)) {
		t.Error("KillVerify accepted a kill with a wrong epoch")
	}

	// Forward-secret session key: ECDH(server_eph, agent_eph) on both sides.
	serverEphPriv, err := ecdh.X25519().NewPrivateKey(mustHex(t, k.ServerEphPriv))
	if err != nil {
		t.Fatalf("server eph: %v", err)
	}
	fsKey, err := SessionKey(serverEphPriv, ephPub, salt, k.AgentID)
	if err != nil {
		t.Fatalf("SessionKey (FS): %v", err)
	}
	if want := mustHex(t, k.SessionKeyFS); hex.EncodeToString(fsKey[:]) != k.SessionKeyFS {
		t.Errorf("FS session key mismatch: got %x want %x", fsKey, want)
	}
	// Agent side must derive the same FS key from its eph + server_eph_pub.
	serverEphPub := bytes32(t, mustHex(t, k.ServerEphPub))
	agentFSKey, err := SessionKey(ephPriv, serverEphPub, salt, k.AgentID)
	if err != nil {
		t.Fatalf("SessionKey (agent FS): %v", err)
	}
	if agentFSKey != fsKey {
		t.Errorf("agent-side FS session key mismatch: got %x want %x", agentFSKey, fsKey)
	}
	fsPrefix, err := FramePrefix(fsKey, "v2")
	if err != nil {
		t.Fatalf("FramePrefix (FS): %v", err)
	}
	if want := mustHex(t, k.FramePrefixFS); hex.EncodeToString(fsPrefix[:]) != k.FramePrefixFS {
		t.Errorf("FS frame prefix mismatch: got %x want %x", fsPrefix, want)
	}
}

// TestKillSignVerifyRoundTrip exercises sign/verify locally, including all
// tamper and binding failures.
func TestKillSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sig, err := KillSign(priv, 7, "agent-7", "kill")
	if err != nil {
		t.Fatalf("KillSign: %v", err)
	}
	if !KillVerify(pub, 7, "agent-7", "kill", sig) {
		t.Error("valid signature rejected")
	}
	for name, bad := range map[string]bool{
		"tampered sig":  KillVerify(pub, 7, "agent-7", "kill", append(append([]byte{}, sig[:len(sig)-1]...), sig[len(sig)-1]^0xFF)),
		"wrong epoch":   KillVerify(pub, 8, "agent-7", "kill", sig),
		"wrong agent":   KillVerify(pub, 7, "agent-8", "kill", sig),
		"wrong payload": KillVerify(pub, 7, "agent-7", "killx", sig),
		"short sig":     KillVerify(pub, 7, "agent-7", "kill", sig[:16]),
		"nil pub":       KillVerify(nil, 7, "agent-7", "kill", sig),
	} {
		if bad {
			t.Errorf("%s: forged signature accepted", name)
		}
	}
}

// TestErrorCases pins the validation failure modes.
func TestErrorCases(t *testing.T) {
	if _, err := Secret32(""); err == nil {
		t.Error("Secret32 accepted an empty secret")
	}
	var secret [32]byte
	serverPriv, err := DeriveServerKey(secret)
	if err != nil {
		t.Fatalf("DeriveServerKey: %v", err)
	}
	// All-zero X25519 public keys are rejected by crypto/ecdh.
	if _, err := SessionKey(serverPriv, [32]byte{}, [16]byte{1}, "agent"); err == nil {
		t.Error("SessionKey accepted an all-zero peer public key")
	}
	if _, err := SessionKey(serverPriv, [32]byte{9}, [16]byte{1}, ""); err != ErrEmptyAgentID {
		t.Errorf("SessionKey with empty agent_id: got %v, want ErrEmptyAgentID", err)
	}
	if _, err := FramePrefix([32]byte{1}, ""); err == nil {
		t.Error("FramePrefix accepted an empty label")
	}
}

// TestDeterminism verifies derivations are stable across calls.
func TestDeterminism(t *testing.T) {
	var secret [32]byte
	copy(secret[:], []byte("determinism-check"))
	a, err := DeriveServerKey(secret)
	if err != nil {
		t.Fatalf("DeriveServerKey: %v", err)
	}
	b, err := DeriveServerKey(secret)
	if err != nil {
		t.Fatalf("DeriveServerKey: %v", err)
	}
	if !a.Equal(b) {
		t.Error("DeriveServerKey is non-deterministic")
	}
}

// TestKeygenFormat verifies Keygen output shape and freshness.
func TestKeygenFormat(t *testing.T) {
	k1, err := Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}
	k2, err := Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}
	if len(k1) != 64 || len(k2) != 64 {
		t.Errorf("Keygen length: got %d and %d, want 64 hex chars", len(k1), len(k2))
	}
	if _, err := hex.DecodeString(k1); err != nil {
		t.Errorf("Keygen output is not hex: %v", err)
	}
	if k1 == k2 {
		t.Error("Keygen produced identical secrets")
	}
}
