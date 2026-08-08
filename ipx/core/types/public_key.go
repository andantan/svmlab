package types

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/andantan/svmlab/core/codec"
)

const (
	PublicKeyLength       = ed25519.PublicKeySize
	PublicKeyBase58Length = 44

	// MaxSeedLength is the longest seed CreateWithSeed may use.
	MaxSeedLength = 32
)

// PublicKey is an ed25519 public key.
//
// On Solana this one value fills three roles that are distinct on an EVM
// chain: it is the public key, it is the account address, and for an
// executable account it is the program id. Nothing hashes the key the way
// keccak256 reduces a secp256k1 key to a 20-byte address, so the 32 bytes
// here are the address.
type PublicKey struct {
	Key ed25519.PublicKey

	bytes  []byte
	base58 string
}

func NewPublicKey(k ed25519.PublicKey) *PublicKey {
	return &PublicKey{
		Key: k,
	}
}

func NewPublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != PublicKeyLength {
		return nil, fmt.Errorf("public key must be %d bytes but got: %d", PublicKeyLength, len(b))
	}

	cp := make([]byte, PublicKeyLength)
	copy(cp, b)

	return &PublicKey{
		Key:   cp,
		bytes: cp,
	}, nil
}

// NewPublicKeyFromBase58 parses an address in the form it appears in
// explorers, RPC payloads, and wallets.
func NewPublicKeyFromBase58(s string) (*PublicKey, error) {
	b, err := codec.Base58.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base58 public key: %w", err)
	}

	k, err := NewPublicKeyFromBytes(b)
	if err != nil {
		return nil, err
	}
	k.base58 = s

	return k, nil
}

// CreateWithSeed derives an address from a base key, a seed, and an owner.
//
//	address = SHA256(base || seed || owner)
//
// This is not a program derived address. There is no curve check and no bump:
// the result may well land on the curve, and nothing cares, because a PDA is
// unsignable by construction while this address is merely never signed for.
// Authority here is the base key, so whoever can sign for base controls every
// address derived from it, and the derived account never signs for itself.
//
// Deriving an address is separate from using one. Only the System Program's
// with-seed instructions accept such an address, and building those is what
// core's System builders do with the result.
func CreateWithSeed(base *PublicKey, seed string, owner *PublicKey) (*PublicKey, error) {
	if base.IsNil() {
		return nil, fmt.Errorf("create with seed: base is required")
	}
	if owner.IsNil() {
		return nil, fmt.Errorf("create with seed: owner is required")
	}
	if len(seed) > MaxSeedLength {
		return nil, fmt.Errorf("create with seed: seed is %d bytes but the limit is %d", len(seed), MaxSeedLength)
	}

	ownerBytes := owner.Bytes()
	if len(ownerBytes) >= len(pdaMarker) &&
		string(ownerBytes[len(ownerBytes)-len(pdaMarker):]) == pdaMarker {
		return nil, fmt.Errorf("create with seed: owner ends with %q, which is reserved for program derived addresses", pdaMarker)
	}

	h := sha256.New()
	h.Write(base.Bytes())
	h.Write([]byte(seed))
	h.Write(ownerBytes)

	return NewPublicKeyFromBytes(h.Sum(nil))
}

func (k *PublicKey) IsNil() bool {
	if k == nil || k.Key == nil {
		return true
	}

	return false
}

func (k *PublicKey) Bytes() []byte {
	if k.bytes == nil {
		k.bytes = k.Key
	}

	return k.bytes
}

// Base58 returns the address string. Unlike an EVM hex address there is no
// checksum in the encoding, so a typo cannot be detected from the string
// alone.
func (k *PublicKey) Base58() string {
	if k.base58 == "" {
		k.base58 = codec.Base58.Encode(k.Bytes())
	}

	return k.base58
}

func (k *PublicKey) String() string {
	return k.Base58()
}

func (k *PublicKey) Equal(o *PublicKey) bool {
	return bytes.Equal(k.Bytes(), o.Bytes())
}

// IsZero reports whether every byte is zero.
//
// The zero value is not a sentinel for "unset": it is the System Program id,
// a real and frequently referenced account key.
func (k *PublicKey) IsZero() bool {
	for _, b := range k.Bytes() {
		if b != 0 {
			return false
		}
	}

	return true
}
