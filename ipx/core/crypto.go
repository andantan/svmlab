package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/andantan/svmlab/core/types"
	"github.com/gtank/ristretto255"
	"github.com/secure-io/siv-go"
)

// SVMEd25519Key bundles a key pair.
//
// Its EVM counterpart carries a third member, the address, because keccak256
// reduces a secp256k1 key to twenty bytes that cannot be read back out of it.
// Nothing reduces an ed25519 key: the account address is the public key, byte
// for byte, so storing it separately would duplicate the same value and give
// the verification below nothing to compare against. Account exists as an
// accessor instead, so the vocabulary survives without the duplication.
type SVMEd25519Key struct {
	PrivateKey *types.PrivateKey
	PublicKey  *types.PublicKey
}

// GenerateKey generates a new ed25519 key pair.
func GenerateKey() (*SVMEd25519Key, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	k, err := types.NewPrivateKeyFromBytes(priv)
	if err != nil {
		return nil, err
	}

	return &SVMEd25519Key{
		PrivateKey: k,
		PublicKey:  k.PublicKey(),
	}, nil
}

// DeriveKeyFromPrivBase58 reconstructs a key pair from the base58 secret alone.
//
// No public key is needed, since the expanded secret already carries one in its
// trailing half.
func DeriveKeyFromPrivBase58(privBase58 string) (*SVMEd25519Key, error) {
	priv, err := types.NewPrivateKeyFromBase58(privBase58)
	if err != nil {
		return nil, err
	}

	return &SVMEd25519Key{
		PrivateKey: priv,
		PublicKey:  priv.PublicKey(),
	}, nil
}

// DeriveKeyFromJSON reconstructs a key pair from the byte-array form
// solana-keygen writes.
func DeriveKeyFromJSON(data []byte) (*SVMEd25519Key, error) {
	priv, err := types.NewPrivateKeyFromJSON(data)
	if err != nil {
		return nil, err
	}

	return &SVMEd25519Key{
		PrivateKey: priv,
		PublicKey:  priv.PublicKey(),
	}, nil
}

// DeriveKeyFromBase58 reconstructs a key pair and verifies that the stored
// public key is the one the secret belongs to.
//
// Parsing already rejects a secret whose trailing half disagrees with its seed.
// This adds the check that matters for a config file: that the entry names the
// account the caller thinks it does. A pair that drifted apart would otherwise
// sign without complaint and spend from the wrong account.
func DeriveKeyFromBase58(privBase58, pubBase58 string) (*SVMEd25519Key, error) {
	key, err := DeriveKeyFromPrivBase58(privBase58)
	if err != nil {
		return nil, err
	}

	declared, err := types.NewPublicKeyFromBase58(pubBase58)
	if err != nil {
		return nil, errors.New("stored public key: " + err.Error())
	}

	if !key.PublicKey.Equal(declared) {
		return nil, errors.New("stored public key does not match private key")
	}

	return key, nil
}

// Account returns the address the key controls, which on Solana is the public
// key itself.
func (k *SVMEd25519Key) Account() *types.PublicKey {
	return k.PublicKey
}

func (k *SVMEd25519Key) VerifyKeyPair() error {
	if k == nil || k.PrivateKey.IsNil() || k.PublicKey.IsNil() {
		return errors.New("invalid key pair")
	}

	if !bytes.Equal(k.PrivateKey.PublicKey().Bytes(), k.PublicKey.Bytes()) {
		return errors.New("private key and public key do not match")
	}

	return nil
}

// SVMElGamalKey bundles an ElGamal key pair over the ristretto255 group,
// the scheme Token-2022's ConfidentialTransfer family uses to encrypt
// balances and transfer amounts.
//
// This is a different key entirely from SVMEd25519Key: SecretKey is a
// ristretto255 scalar, not an ed25519 seed, and PublicKey is a compressed
// ristretto255 group element (also 32 bytes, the same wire length as a
// Solana address, but not one -- it can never sign a transaction or hold
// lamports). Both are returned as raw bytes rather than *types.PublicKey,
// since wrapping a group element in a type named for ed25519 addresses
// would misstate what it is.
type SVMElGamalKey struct {
	SecretKey []byte // 32-byte ristretto255 scalar
	PublicKey []byte // 32-byte compressed ristretto255 element
}

// elgamalH is the second, independent generator Solana's twisted ElGamal
// scheme derives its public keys from -- not the group's own base point G
// (what ScalarBaseMult multiplies against), a distinct point entirely.
//
// Computed as SHA3-512 of G's compressed encoding, mapped into the group
// via Ristretto's uniform-bytes hash-to-group construction (RFC 9496,
// the same algorithm ristretto255.Element.SetUniformBytes implements).
// Confirmed byte-for-byte against solana-zk-sdk's own pedersen.rs:
//
//	pub static ref H: RistrettoPoint =
//	    RistrettoPoint::hash_from_bytes::<Sha3_512>(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
//
// This is computed once at package init rather than per call: it is a
// fixed public constant, not a secret, the same as G itself.
var elgamalH *ristretto255.Element

func init() {
	digest := sha3.Sum512(ristretto255.NewGeneratorElement().Bytes())

	h, err := ristretto255.NewIdentityElement().SetUniformBytes(digest[:])
	if err != nil {
		// digest is always exactly 64 bytes (sha3.Sum512's return type),
		// the one length SetUniformBytes ever accepts, so this can only
		// fail if the ristretto255 package itself changed shape.
		panic("elgamal: failed to derive H generator: " + err.Error())
	}

	elgamalH = h
}

// GenerateElGamalKey generates a new ElGamal key pair: a uniformly random
// scalar as the secret key, and public_key = secret_key^-1 * H -- H, not
// the group's own base point, and the secret's inverse, not the secret
// itself. Both departures from the textbook construction are deliberate
// choices of Solana's "twisted ElGamal" variant, confirmed against
// solana-zk-sdk's own ElGamalPubkey::new rather than assumed from a
// standard ElGamal keypair -- this is the exact relationship
// PubkeyValidityProof exists to prove knowledge of, so getting it backwards
// here would make every proof built against a key from this function
// invalid against the deployed verifier while still looking like a
// plausible key pair locally.
//
// SetUniformBytes reduces 64 uniformly random bytes modulo the group's
// order l = 2^252 + 27742317777372353535851937790883648493, rather than
// generating a scalar directly, so the result is uniform over the field
// rather than biased toward small values the way interpreting 32 random
// bytes as a scalar without reduction would be.
func GenerateElGamalKey() (*SVMElGamalKey, error) {
	var seed [64]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("elgamal: %w", err)
	}

	secret, err := ristretto255.NewScalar().SetUniformBytes(seed[:])
	if err != nil {
		return nil, fmt.Errorf("elgamal: %w", err)
	}

	public, err := DeriveElGamalPublicKey(secret.Bytes())
	if err != nil {
		return nil, fmt.Errorf("elgamal: %w", err)
	}

	return &SVMElGamalKey{
		SecretKey: secret.Bytes(),
		PublicKey: public,
	}, nil
}

// DeriveElGamalPublicKey computes the public key secretKey determines:
// secret_key^-1 * H, the exact relationship GenerateElGamalKey establishes
// and ProvePubkeyValidity/VerifyPubkeyValidity check. This exists
// separately from GenerateElGamalKey for the case where only the secret
// half is on hand -- a proof endpoint asked to build a
// PubkeyValidityProof from secret_key alone has to know the public key
// the proof is about before it can build the transcript, the same public
// key the caller could otherwise have kept from generate/elgamal-keypair
// but should not have to resend.
func DeriveElGamalPublicKey(secretKey []byte) ([]byte, error) {
	if len(secretKey) != 32 {
		return nil, fmt.Errorf("derive elgamal public key: secret key is %d bytes, expected 32", len(secretKey))
	}

	s, err := ristretto255.NewScalar().SetCanonicalBytes(secretKey)
	if err != nil {
		return nil, fmt.Errorf("derive elgamal public key: %w", err)
	}

	sInv := ristretto255.NewScalar().Invert(s)
	public := ristretto255.NewIdentityElement().ScalarMult(sInv, elgamalH)

	return public.Bytes(), nil
}

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
