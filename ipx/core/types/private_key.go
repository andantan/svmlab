package types

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/andantan/svmlab/core/codec"
)

const (
	PrivateKeyLength       = ed25519.PrivateKeySize
	PrivateKeySeedLength   = ed25519.SeedSize
	PrivateKeyBase58Length = 88
)

// PrivateKey is an expanded ed25519 secret key, laid out as
// [seed 32 || public key 32].
//
// Only the seed is secret. The trailing half is the public key, cached in
// place so that signing never has to derive it. A secp256k1 key is a bare
// 32-byte scalar with no public half stored beside it, which is why a Solana
// secret is twice the size of an EVM one.
type PrivateKey struct {
	Key ed25519.PrivateKey

	bytes  []byte
	base58 string
}

func NewPrivateKey(k ed25519.PrivateKey) *PrivateKey {
	return &PrivateKey{
		Key: k,
	}
}

// NewPrivateKeyFromBytes builds a secret key from its raw 64 bytes.
//
// The trailing public key is checked against one derived from the seed. A
// mismatch means the key is corrupt or forged, and accepting it would yield
// signatures that fail to verify against the address the caller believes
// they are signing for.
func NewPrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != PrivateKeyLength {
		return nil, fmt.Errorf("private key must be %d bytes but got: %d", PrivateKeyLength, len(b))
	}

	derived := ed25519.NewKeyFromSeed(b[:PrivateKeySeedLength])
	if !bytes.Equal(derived[PrivateKeySeedLength:], b[PrivateKeySeedLength:]) {
		return nil, fmt.Errorf("private key is inconsistent: trailing public key does not match the seed")
	}

	cp := make([]byte, PrivateKeyLength)
	copy(cp, b)

	return &PrivateKey{
		Key:   cp,
		bytes: cp,
	}, nil
}

// NewPrivateKeyFromBase58 parses the base58 form of an expanded secret key,
// which is what wallets such as Phantom import and export.
func NewPrivateKeyFromBase58(s string) (*PrivateKey, error) {
	b, err := codec.Base58.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base58 private key: %w", err)
	}

	k, err := NewPrivateKeyFromBytes(b)
	if err != nil {
		return nil, err
	}
	k.base58 = s

	return k, nil
}

// NewPrivateKeyFromJSON parses the byte-array form written by solana-keygen
// into ~/.config/solana/id.json.
//
// The file holds all 64 bytes as a JSON array of numbers, for example
// [148,230,241,...]. Wallets use the base58 form instead, so both encodings
// have to be accepted to work with the CLI and a wallet at the same time.
func NewPrivateKeyFromJSON(data []byte) (*PrivateKey, error) {
	// Unmarshalling straight into []byte would fail: encoding/json expects a
	// base64 string for that type, not an array of numbers.
	var nums []int
	if err := json.Unmarshal(data, &nums); err != nil {
		return nil, fmt.Errorf("invalid private key json: %w", err)
	}

	b := make([]byte, len(nums))
	for i, n := range nums {
		if n < 0 || n > 0xff {
			return nil, fmt.Errorf("private key json: value %d at index %d is not a byte", n, i)
		}
		b[i] = byte(n)
	}

	return NewPrivateKeyFromBytes(b)
}

// NewPrivateKeyFromSeed expands the 32 secret bytes into a full key.
func NewPrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	if len(seed) != PrivateKeySeedLength {
		return nil, fmt.Errorf("seed must be %d bytes but got: %d", PrivateKeySeedLength, len(seed))
	}

	return NewPrivateKey(ed25519.NewKeyFromSeed(seed)), nil
}

func (k *PrivateKey) IsNil() bool {
	if k == nil || k.Key == nil {
		return true
	}

	return false
}

func (k *PrivateKey) Bytes() []byte {
	if k.bytes == nil {
		k.bytes = k.Key
	}

	return k.bytes
}

// Seed returns the 32 secret bytes the key pair is derived from.
func (k *PrivateKey) Seed() []byte {
	return k.Bytes()[:PrivateKeySeedLength]
}

// Base58 returns the secret in plain text. It is deliberately not String, so
// that the key cannot leak into a log through %v.
func (k *PrivateKey) Base58() string {
	if k.base58 == "" {
		k.base58 = codec.Base58.Encode(k.Bytes())
	}

	return k.base58
}

// String returns a redacted description naming only the address the key
// controls. Call Base58 to obtain the secret itself.
func (k *PrivateKey) String() string {
	return fmt.Sprintf("PrivateKey(%s)", k.PublicKey())
}

// Equal reports whether two secret keys are identical.
//
// The comparison is not constant time. It is meant for checking config and
// fixtures, not for guarding a secret against a timing attack.
func (k *PrivateKey) Equal(o *PrivateKey) bool {
	return bytes.Equal(k.Bytes(), o.Bytes())
}

// PublicKey returns the account address.
//
// Unlike the secp256k1 equivalent this does no curve arithmetic: the public
// key already sits in the trailing half of the secret.
func (k *PrivateKey) PublicKey() *PublicKey {
	return NewPublicKey(ed25519.PublicKey(k.Bytes()[PrivateKeySeedLength:]))
}
