package types

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	"github.com/andantan/svmlab/core/codec"
)

const (
	PublicKeyLength       = ed25519.PublicKeySize
	PublicKeyBase58Length = 44
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
