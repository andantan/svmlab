package misc

import (
	"errors"
	"strings"

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

// ConvertBase58To64Request carries an arbitrary base58 string to re-encode
// as base64.
//
// This does not care whether the value is a public key, a signature, a
// hash, or something else — it decodes base58 to bytes and re-encodes those
// bytes as base64, nothing more.
type ConvertBase58To64Request struct {
	Value string `json:"value"`

	value string
}

func (r *ConvertBase58To64Request) ValidateRequest() error {
	r.value = strings.TrimSpace(r.Value)
	if r.value == "" {
		return errors.New("value: must not be empty")
	}

	return nil
}

func (r *ConvertBase58To64Request) ToValue() string {
	return r.value
}

type ConvertBase58To64Response struct {
	Base64 string `json:"base64"`
}

func NewConvertBase58To64Response(base64 string) *ConvertBase58To64Response {
	return &ConvertBase58To64Response{
		Base64: base64,
	}
}

// ConvertBase64To58Request carries an arbitrary base64 string to re-encode
// as base58.
type ConvertBase64To58Request struct {
	Value string `json:"value"`

	value string
}

func (r *ConvertBase64To58Request) ValidateRequest() error {
	r.value = strings.TrimSpace(r.Value)
	if r.value == "" {
		return errors.New("value: must not be empty")
	}

	return nil
}

func (r *ConvertBase64To58Request) ToValue() string {
	return r.value
}

type ConvertBase64To58Response struct {
	Base58 string `json:"base58"`
}

func NewConvertBase64To58Response(base58 string) *ConvertBase64To58Response {
	return &ConvertBase64To58Response{
		Base58: base58,
	}
}
