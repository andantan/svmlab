package types

import (
	"bytes"
	"fmt"

	"github.com/andantan/svmlab/core/codec"
)

// SignatureLength 32 bytes R point + 32 bytes S scalar
const (
	SignatureLength       = 64
	SignatureBase58Length = 88
)

// Signature is an ed25519 signature, laid out as [R 32 || S 32].
//
// It is one byte shorter than its EVM counterpart, and the missing byte is
// the recovery id. secp256k1 lets a verifier recover the signer's public key
// from the signature alone, which is what ecrecover does and what makes the
// EIP-155 V byte necessary. ed25519 has no such recovery: the public key must
// be supplied to verify, so a transaction lists its signers explicitly in the
// message and matches them to signatures by position.
//
// The base58 form of the first signature in a transaction is that
// transaction's id, which is the value explorers index and getSignatureStatuses
// takes. A transaction therefore has no id until it has been signed.
// R and S are held as raw bytes rather than the big.Int an EVM signature
// uses. R is a compressed Edwards point, not an integer at all, and S is a
// little-endian scalar, so reading either as a big-endian integer produces a
// meaningless value.
type Signature struct {
	bytes  []byte
	r      []byte
	s      []byte
	base58 string
}

func NewSignature(b []byte) (*Signature, error) {
	if len(b) != SignatureLength {
		return nil, fmt.Errorf("signature must be %d bytes but got: %d", SignatureLength, len(b))
	}

	cp := make([]byte, SignatureLength)
	copy(cp, b)

	return &Signature{
		bytes: cp,
		r:     cp[:32],
		s:     cp[32:],
	}, nil
}

// NewSignatureFromBase58 parses a signature in the form the RPC layer and
// explorers use, which for the first signature of a transaction is also its
// transaction id.
func NewSignatureFromBase58(s string) (*Signature, error) {
	b, err := codec.Base58.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base58 signature: %w", err)
	}

	sig, err := NewSignature(b)
	if err != nil {
		return nil, err
	}
	sig.base58 = s

	return sig, nil
}

// NewEmptySignature returns the all-zero placeholder a transaction carries in
// a slot whose signer has not signed yet.
//
// The signature array is fixed to the number of required signers before any
// signing happens, because its length is part of the serialized transaction
// and every signer signs the same message bytes. Empty slots are how a
// partially signed transaction is passed between co-signers.
func NewEmptySignature() *Signature {
	cp := make([]byte, SignatureLength)

	return &Signature{
		bytes: cp,
		r:     cp[:32],
		s:     cp[32:],
	}
}

func (s *Signature) IsNil() bool {
	if s == nil || s.bytes == nil {
		return true
	}

	if s.r == nil || s.s == nil {
		return true
	}

	return false
}

func (s *Signature) Bytes() []byte {
	return s.bytes
}

func (s *Signature) Base58() string {
	if s.base58 == "" {
		s.base58 = codec.Base58.Encode(s.bytes)
	}

	return s.base58
}

func (s *Signature) String() string {
	return s.Base58()
}

func (s *Signature) Equal(o *Signature) bool {
	return bytes.Equal(s.bytes, o.bytes)
}

// IsZero reports whether the signature is the all-zero placeholder, meaning
// the corresponding signer has not signed yet.
func (s *Signature) IsZero() bool {
	for _, b := range s.bytes {
		if b != 0 {
			return false
		}
	}

	return true
}

// R returns the first half, the compressed Edwards point.
func (s *Signature) R() []byte {
	if s.r == nil {
		s.r = s.bytes[:32]
	}

	return s.r
}

// S returns the second half, the little-endian scalar.
func (s *Signature) S() []byte {
	if s.s == nil {
		s.s = s.bytes[32:]
	}

	return s.s
}
