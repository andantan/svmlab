package core

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
)

type signer struct{}

var Signer = new(signer)

// Sign signs the given message bytes with the provided private key and returns
// a 64-byte ed25519 signature in [R || S] format.
//
// The input is the message itself, not a digest of it. This is the opposite of
// the EVM convention, where the caller computes a Keccak-256 hash and signs
// those 32 bytes. ed25519 as specified in RFC 8032 is PureEdDSA: signing hashes
// the message internally with SHA-512, twice, and the nonce derivation depends
// on the full message. Pre-hashing would sign the digest as if it were the
// message, producing a signature that no verifier holding the real message can
// check.
//
// There is also no recovery id to return. secp256k1 lets a verifier recover the
// signing key from a signature, which is what ecrecover does and why an EVM
// signature carries a V byte. ed25519 requires the public key as an input to
// verification, so the signer must be known in advance.
func (s *signer) Sign(message []byte, priv *types.PrivateKey) (*types.Signature, error) {
	if priv.IsNil() {
		return nil, fmt.Errorf("signer: private key is nil")
	}

	sig, err := types.NewSignature(ed25519.Sign(priv.Key, message))
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// Verify reports whether the signature is valid for the message under the
// given public key.
//
// The public key is an argument rather than something derived from the
// signature, which is the practical consequence of ed25519 offering no
// recovery: nothing here can answer "who signed this".
func (s *signer) Verify(message []byte, sig *types.Signature, pub *types.PublicKey) bool {
	if sig.IsNil() || pub.IsNil() {
		return false
	}

	return ed25519.Verify(pub.Key, message, sig.Bytes())
}

// SignMessage signs a compiled message.
//
// Every signer of a transaction signs these same bytes. The account list, its
// ordering, and the recent blockhash are all inside them, so a signature
// commits to the exact set of accounts and privileges the transaction will
// execute with.
func (s *signer) SignMessage(message *types.Message, priv *types.PrivateKey) (*types.Signature, error) {
	raw, err := message.Serialize()
	if err != nil {
		return nil, fmt.Errorf("signer: serialize message: %w", err)
	}

	return s.Sign(raw, priv)
}

// SignTransaction signs a transaction with the given keys, placing each
// signature in the slot belonging to its signer.
//
// The message is serialized once and reused, both to avoid repeating the work
// and to guarantee every key signs byte-identical input. A key that is not a
// required signer is an error rather than a no-op: silently ignoring it would
// leave the transaction short a signature and fail only once the cluster
// rejected it.
//
// Keys may be supplied in any order and across several calls, so a transaction
// can be passed between co-signers and completed incrementally.
func (s *signer) SignTransaction(tx *types.Transaction, privs ...*types.PrivateKey) error {
	if tx.IsNil() {
		return fmt.Errorf("signer: transaction is nil")
	}
	if len(privs) == 0 {
		return fmt.Errorf("signer: at least one private key is required")
	}

	raw, err := tx.Message.Serialize()
	if err != nil {
		return fmt.Errorf("signer: serialize message: %w", err)
	}

	for i, priv := range privs {
		if priv.IsNil() {
			return fmt.Errorf("signer: private key[%d] is nil", i)
		}

		sig, err := s.Sign(raw, priv)
		if err != nil {
			return fmt.Errorf("signer: sign with key[%d]: %w", i, err)
		}
		if err = tx.SetSignature(priv.PublicKey(), sig); err != nil {
			return fmt.Errorf("signer: %w", err)
		}
	}

	return nil
}

// VerifyTransaction checks every signature against the account key occupying
// the same position.
//
// This is the check a validator performs before executing, and running it
// locally turns a rejected broadcast into an error raised before the request
// is made.
func (s *signer) VerifyTransaction(tx *types.Transaction) error {
	if tx.IsNil() {
		return fmt.Errorf("signer: transaction is nil")
	}

	signers := tx.Message.Signers()
	if len(tx.Signatures) != len(signers) {
		return fmt.Errorf("signer: %d signatures but the message requires %d", len(tx.Signatures), len(signers))
	}

	raw, err := tx.Message.Serialize()
	if err != nil {
		return fmt.Errorf("signer: serialize message: %w", err)
	}

	for i, sig := range tx.Signatures {
		if sig.IsNil() || sig.IsZero() {
			return fmt.Errorf("signer: signature[%d] for %s is missing", i, signers[i])
		}
		if !s.Verify(raw, sig, signers[i]) {
			return fmt.Errorf("signer: signature[%d] is not valid for %s", i, signers[i])
		}
	}

	return nil
}

// SignRawTransaction signs a serialized transaction without parsing its
// message into a *types.Message, and returns the transaction with the
// signature written into its slot.
//
// This is what an externally built transaction needs — a swap or bridge
// payload, typically a v0 message with address lookup tables this project
// does not model yet. Placing a signature turns out not to need that model at
// all. A signer must be a static key, since a lookup table address can never
// be one: verifying a signature has to work without resolving the table, so
// the runtime forbids exactly the case that would require it. The slots are
// therefore the message's leading account keys whether the message is legacy
// or versioned, and reading them costs three header bytes and a short-vec
// count, not the instructions or the lookup tables that follow.
//
// The bytes signed are everything after the signature array, unchanged and
// unreordered, which is what the same rule guarantees a validator will
// reproduce when it verifies. That is also why this function knows nothing
// about what the transaction does: reading that far is not a security check
// here, it is out of scope, and a caller signing a transaction it cannot
// otherwise account for is trusting whatever produced it.
func (s *signer) SignRawTransaction(raw []byte, priv *types.PrivateKey) ([]byte, error) {
	if priv.IsNil() {
		return nil, fmt.Errorf("signer: private key is nil")
	}

	versioned, err := types.IsVersionedTransaction(raw)
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}

	n, sigPrefixSize, err := codec.Binary.ReadShortVecLen(raw)
	if err != nil {
		return nil, fmt.Errorf("signer: signature count: %w", err)
	}

	sigSectionEnd := sigPrefixSize + n*types.SignatureLength
	message := raw[sigSectionEnd:]

	offset := 0
	if versioned {
		// The version byte precedes the header in a versioned message and has
		// no counterpart in a legacy one.
		offset = 1
	}
	if len(message) < offset+types.MessageHeaderLength {
		return nil, fmt.Errorf("signer: message is too short for a header")
	}
	numRequiredSignatures := int(message[offset])

	keyCount, keyCountSize, err := codec.Binary.ReadShortVecLen(message[offset+types.MessageHeaderLength:])
	if err != nil {
		return nil, fmt.Errorf("signer: account key count: %w", err)
	}
	if numRequiredSignatures > keyCount {
		return nil, fmt.Errorf("signer: %d required signatures exceeds %d account keys", numRequiredSignatures, keyCount)
	}

	keysStart := offset + types.MessageHeaderLength + keyCountSize
	keysEnd := keysStart + numRequiredSignatures*types.PublicKeyLength
	if len(message) < keysEnd {
		return nil, fmt.Errorf("signer: message is too short for %d signer keys", numRequiredSignatures)
	}

	pub := priv.PublicKey().Bytes()
	slot := -1
	for i := range numRequiredSignatures {
		start := keysStart + i*types.PublicKeyLength
		if bytes.Equal(message[start:start+types.PublicKeyLength], pub) {
			slot = i
			break
		}
	}
	if slot < 0 {
		return nil, fmt.Errorf("signer: %s is not a required signer", priv.PublicKey())
	}

	sig := ed25519.Sign(priv.Key, message)

	out := make([]byte, len(raw))
	copy(out, raw)
	copy(out[sigPrefixSize+slot*types.SignatureLength:], sig)

	return out, nil
}
