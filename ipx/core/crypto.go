package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"

	"github.com/andantan/svmlab/core/types"
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
