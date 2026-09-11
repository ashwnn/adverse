package cryptokeys

import (
	"crypto/ecdh"
	"encoding/hex"
	"os"
	"testing"
)

// TestGenKATFS is a one-shot generator (not an assertion test) that prints the
// deterministic forward-secret KAT values for baking into testdata/kat.json.
// It uses a fixed server ephemeral private key so the vectors are reproducible.
func TestGenKATFS(t *testing.T) {
	if os.Getenv("GEN_KAT_FS") == "" {
		t.Skip("set GEN_KAT_FS=1 to (re)generate forward-secret KAT vectors")
	}
	serverEphPrivHex := "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	agentEphPubHex := "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"
	saltHex := "000102030405060708090a0b0c0d0e0f"
	agentID := "agent-kat-1"

	ephPrivBytes, _ := hex.DecodeString(serverEphPrivHex)
	serverEphPriv, err := ecdh.X25519().NewPrivateKey(ephPrivBytes)
	if err != nil {
		t.Fatal(err)
	}
	serverEphPub := serverEphPriv.PublicKey().Bytes()

	var agentEphPub [32]byte
	ab, _ := hex.DecodeString(agentEphPubHex)
	copy(agentEphPub[:], ab)

	var salt [16]byte
	sb, _ := hex.DecodeString(saltHex)
	copy(salt[:], sb)

	sk, err := SessionKey(serverEphPriv, agentEphPub, salt, agentID)
	if err != nil {
		t.Fatal(err)
	}

	fsPrefix, err := FramePrefix(sk, "v2")
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("server_eph_priv = %s", serverEphPrivHex)
	t.Logf("server_eph_pub = %s", hex.EncodeToString(serverEphPub))
	t.Logf("session_key_fs = %s", hex.EncodeToString(sk[:]))
	t.Logf("frame_prefix_fs = %s", hex.EncodeToString(fsPrefix[:]))
}
