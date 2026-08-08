package misc

import (
	"github.com/andantan/svmlab/core"
)

// GenerateKeypairResponse carries a freshly generated key pair.
//
// PrivateKey is the base58 form of the expanded secret, which is exactly what
// the private_key field in config.yaml expects, so the value pastes straight
// into a keys entry. PublicKey is redundant to it, since the secret carries
// the public half in its trailing 32 bytes, and is returned only so the
// address is readable without decoding anything.
//
// The secret is returned in plain text. That is the point of a local lab
// keypair, and matches config.yaml already holding secrets unencrypted.
type GenerateKeypairResponse struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

func NewGenerateKeypairResponse(k *core.SVMEd25519Key) *GenerateKeypairResponse {
	return &GenerateKeypairResponse{
		PublicKey:  k.PublicKey.Base58(),
		PrivateKey: k.PrivateKey.Base58(),
	}
}
