package core

import (
	"bytes"
	"crypto/rand"
	"crypto/sha3"
	"encoding/binary"
	"fmt"

	"github.com/secure-io/siv-go"
)

// AeKeyLen is the byte length of an AeKey -- the symmetric key
// Token-2022's ConfidentialTransfer family uses to encrypt an account's
// own decryptable balance under AES-128-GCM-SIV, separately from the
// ElGamal encryption everyone else (the auditor, the mint) can also read.
//
// Confirmed against solana-zk-sdk's AeKey::from_seed: the first 16 bytes
// of a SHA3-512 digest, matching AES-128's key size.
const AeKeyLen = 16

// AeKeySeedMessage builds the exact message upstream's
// AeKey::seed_from_signer signs to derive an account's AeKey
// deterministically: the fixed prefix b"AeKey" followed by a public
// seed. tool/sign is this package's own signer -- this function exists
// so the caller never has to construct the message by hand, only sign
// what it returns and hand the signature to DeriveAeKeyFromSignature.
//
// tokenAccount is the public seed: confirmed against
// solana-foundation's own Confidential-Balances-Sample
// (AeKey::new_from_signer(authority, &token_account.to_bytes())) rather
// than assumed -- upstream's own doc comment leaves public_seed
// unspecified, since AeKey::new_from_signer accepts any bytes there, and
// the token account's own address is the convention real tooling
// settled on so two accounts under the same owner never share a key.
func AeKeySeedMessage(tokenAccount []byte) ([]byte, error) {
	if len(tokenAccount) != 32 {
		return nil, fmt.Errorf("ae key seed message: token account is %d bytes, expected 32", len(tokenAccount))
	}

	return append([]byte("AeKey"), tokenAccount...), nil
}

// DeriveAeKeyFromSignature reproduces AeKey::new_from_signer's second
// half: given the Ed25519 signature over AeKeySeedMessage's own output,
// it returns the AeKey that signature determines.
//
// Confirmed against solana-zk-sdk's auth_encryption.rs: this is two
// rounds of SHA3-512, not one -- seed_from_signer hashes the raw
// signature into a 64-byte seed, and from_seed hashes that seed again
// and keeps only the first 16 bytes. Skipping the first round and
// hashing the signature only once would produce a key no real wallet
// derives the same way, since both crates run both rounds.
//
// A signature of all zero bytes is rejected, the same check upstream
// runs (some Signer implementations return the default signature rather
// than erroring, which is not suitable key material) -- confirmed
// against a real 64-byte Ed25519 signature never legitimately being all
// zero, since that would require an all-zero R component, negligible
// probability for a real signing key.
func DeriveAeKeyFromSignature(signature []byte) ([]byte, error) {
	if len(signature) != 64 {
		return nil, fmt.Errorf("derive ae key: signature is %d bytes, expected 64", len(signature))
	}
	if bytes.Equal(signature, make([]byte, 64)) {
		return nil, fmt.Errorf("derive ae key: signature is all zero, not suitable key material")
	}

	seed := sha3.Sum512(signature)
	key := sha3.Sum512(seed[:])

	return key[:AeKeyLen], nil
}

// AeCiphertextLen is the wire length of an AeCiphertext: a 12-byte nonce
// followed by AES-128-GCM-SIV's ciphertext-plus-tag for an 8-byte
// plaintext (8 + 16 = 24 bytes), confirmed against solana-zk-sdk's own
// AeCiphertext layout.
const AeCiphertextLen = 36

// EncryptAeAmount AES-128-GCM-SIV-encrypts amount (little-endian, the
// same encoding every other u64 field in this API uses on the wire) under
// key, with a fresh random 12-byte nonce prepended to the output --
// solana-zk-sdk's own AeKey::encrypt, given a key derived elsewhere
// rather than one this function derives itself.
//
// This exists for decryptable_zero_balance on
// extensions/confidential-transfer-account/configure-account, which
// always encrypts zero -- a freshly configured account has no balance
// yet -- but takes amount generally rather than hardcoding it, since
// nothing about the encryption itself is specific to zero.
func EncryptAeAmount(key []byte, amount uint64) ([]byte, error) {
	if len(key) != AeKeyLen {
		return nil, fmt.Errorf("encrypt ae amount: key is %d bytes, expected %d", len(key), AeKeyLen)
	}

	aead, err := siv.NewGCM(key)
	if err != nil {
		return nil, fmt.Errorf("encrypt ae amount: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("encrypt ae amount: %w", err)
	}

	plaintext := make([]byte, 8)
	binary.LittleEndian.PutUint64(plaintext, amount)

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 0, AeCiphertextLen)
	out = append(out, nonce...)
	out = append(out, ciphertext...)

	return out, nil
}

// DecryptAeAmount reverses EncryptAeAmount, returning the u64 amount ct
// encrypts under key. This exists for this package's own round-trip
// verification of EncryptAeAmount's output, not for anything a Token-2022
// instruction needs -- decryption is a wallet's job against balances it
// reads off chain, never something this server does against a value it
// only just encrypted itself for a transaction that has not landed yet.
func DecryptAeAmount(key, ct []byte) (uint64, error) {
	if len(key) != AeKeyLen {
		return 0, fmt.Errorf("decrypt ae amount: key is %d bytes, expected %d", len(key), AeKeyLen)
	}
	if len(ct) != AeCiphertextLen {
		return 0, fmt.Errorf("decrypt ae amount: ciphertext is %d bytes, expected %d", len(ct), AeCiphertextLen)
	}

	aead, err := siv.NewGCM(key)
	if err != nil {
		return 0, fmt.Errorf("decrypt ae amount: %w", err)
	}

	nonce := ct[:aead.NonceSize()]
	sealed := ct[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return 0, fmt.Errorf("decrypt ae amount: %w", err)
	}
	if len(plaintext) != 8 {
		return 0, fmt.Errorf("decrypt ae amount: plaintext is %d bytes, expected 8", len(plaintext))
	}

	return binary.LittleEndian.Uint64(plaintext), nil
}
