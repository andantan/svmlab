package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha3"
	"errors"
	"fmt"

	"github.com/andantan/svmlab/core/types"
	"github.com/gtank/ristretto255"
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
