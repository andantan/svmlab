package misc

import (
	"errors"
	"strings"

	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
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

// GenerateElGamalKeypairResponse carries a freshly generated ristretto255
// ElGamal key pair, for Token-2022's ConfidentialTransfer family --
// auditor_elgamal_pubkey on
// extensions/confidential-transfer-mint/initialize, and the account-side
// ElGamal pubkey configure-account (not yet built) will need.
//
// Neither field is a Solana address: both are base58-encoded raw 32-byte
// ristretto255 values (a scalar and a group element), not ed25519 keys,
// and cannot sign a transaction or hold lamports the way
// GenerateKeypairResponse's pair can. The secret is returned in plain
// text, the same as GenerateKeypairResponse -- this is a local lab tool,
// not a wallet.
type GenerateElGamalKeypairResponse struct {
	PublicKey string `json:"public_key"`
	SecretKey string `json:"secret_key"`
}

func NewGenerateElGamalKeypairResponse(k *core.SVMElGamalKey) *GenerateElGamalKeypairResponse {
	return &GenerateElGamalKeypairResponse{
		PublicKey: codec.Base58.Encode(k.PublicKey),
		SecretKey: codec.Base58.Encode(k.SecretKey),
	}
}

// ProvePubkeyValidityRequest carries the secret half of an ElGamal key
// pair (see generate/elgamal-keypair) to build a PubkeyValidityProof
// against -- the sigma-protocol proof
// extensions/confidential-transfer-account/configure-account requires
// alongside the public key it names, since nothing else lets the deployed
// program tell a real ElGamal public key from 32 arbitrary bytes.
//
// This never sends SecretKey anywhere but back here: the proof itself is
// zero-knowledge, so PublicKey and Proof in the response reveal nothing
// about SecretKey beyond what configure-account already needs to see.
type ProvePubkeyValidityRequest struct {
	// SecretKey is the ElGamal secret key, base58-encoded, exactly what
	// generate/elgamal-keypair's secret_key returns.
	SecretKey string `json:"secret_key" example:""`

	secretKey []byte
}

func (r *ProvePubkeyValidityRequest) ValidateRequest() error {
	secretKey, err := codec.Base58.DecodeFixed(strings.TrimSpace(r.SecretKey), 32)
	if err != nil {
		return errors.New("secret_key: " + err.Error())
	}
	r.secretKey = secretKey

	return nil
}

func (r *ProvePubkeyValidityRequest) ToSecretKey() []byte { return r.secretKey }

// ProvePubkeyValidityResponse carries the public key SecretKey derives
// (public_key = secret_key^-1 * H, GenerateElGamalKey's own construction)
// alongside a proof that whoever holds SecretKey knows it.
type ProvePubkeyValidityResponse struct {
	PublicKey string `json:"public_key"`
	Proof     string `json:"proof"`
}

func NewProvePubkeyValidityResponse(publicKey, proof []byte) *ProvePubkeyValidityResponse {
	return &ProvePubkeyValidityResponse{
		PublicKey: codec.Base58.Encode(publicKey),
		Proof:     codec.Base58.Encode(proof),
	}
}

// AeKeySeedMessageRequest names the token account an AeKey will be
// derived for.
//
// This does not build the AeKey itself: it only returns the exact bytes
// to sign, which the caller then passes to sign/ (with the account
// owner's own key) and hands the resulting signature to derive/ae-key.
// Splitting it this way keeps the actual signature -- the one thing that
// has to come from the owner's real wallet key -- out of this server's
// hands entirely, the same reason every other secret in this API is
// supplied by the caller rather than generated from one held here.
type AeKeySeedMessageRequest struct {
	// TokenAccount is the account an AeKey will encrypt the confidential
	// balance for (see extensions/confidential-transfer-account/configure-account).
	TokenAccount string `json:"token_account" example:""`

	tokenAccount *types.PublicKey
}

func (r *AeKeySeedMessageRequest) ValidateRequest() error {
	tokenAccount, err := types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount))
	if err != nil {
		return errors.New("token_account: " + err.Error())
	}
	r.tokenAccount = tokenAccount

	return nil
}

func (r *AeKeySeedMessageRequest) TokenAccountKey() *types.PublicKey { return r.tokenAccount }

// AeKeySeedMessageResponse carries the message to sign, base64 -- the
// same encoding sign/'s own message field expects, so the response
// pastes directly into that call.
type AeKeySeedMessageResponse struct {
	Message string `json:"message"`
}

func NewAeKeySeedMessageResponse(message []byte) *AeKeySeedMessageResponse {
	return &AeKeySeedMessageResponse{
		Message: codec.Base64.Encode(message),
	}
}

// DeriveAeKeyRequest carries the signature sign/ produced over
// ae-key-seed-message's own output.
type DeriveAeKeyRequest struct {
	// Signature is base58, the same encoding sign/'s own response uses.
	Signature string `json:"signature" example:""`

	signature []byte
}

func (r *DeriveAeKeyRequest) ValidateRequest() error {
	signature, err := codec.Base58.DecodeFixed(strings.TrimSpace(r.Signature), 64)
	if err != nil {
		return errors.New("signature: " + err.Error())
	}
	r.signature = signature

	return nil
}

func (r *DeriveAeKeyRequest) ToSignature() []byte { return r.signature }

// DeriveAeKeyResponse carries the AeKey the given signature determines,
// base58-encoded.
type DeriveAeKeyResponse struct {
	AeKey string `json:"ae_key"`
}

func NewDeriveAeKeyResponse(aeKey []byte) *DeriveAeKeyResponse {
	return &DeriveAeKeyResponse{
		AeKey: codec.Base58.Encode(aeKey),
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
