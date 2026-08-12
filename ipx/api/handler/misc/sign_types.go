package misc

import (
	"errors"
	"fmt"
	"strings"

	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
)

// SignTransactionRequest names the signers for a serialized transaction.
//
// Signers come from either side and may be mixed in one call. PublicKeys are
// resolved against config.yaml, so no secret travels in the body and the
// server signs only for accounts it was configured with. PrivateKeys carry the
// secret directly, which is what an account created in the same flow needs:
// its key authorizes its own creation once and is not worth registering.
//
// Neither list is positional. A slot is found from the key itself, since the
// serialized message lists its signers in slot order, so order here is free
// and keys may be named across several calls as a transaction moves between
// co-signers.
//
// A versioned message is accepted without being parsed into a *types.Message
// at all. A signer must be one of the message's leading static keys, since an
// address lookup table entry can never sign — verifying a signature has to
// work without resolving the table, so the runtime forbids exactly the case
// that would require it. Locating a slot therefore costs a header and a
// short-vec count, not the address table lookups this project does not model.
// The cost is a thinner response: nothing here reads what the transaction
// does, so it cannot be shown back, and a caller signing one it cannot
// otherwise account for is trusting whatever produced it.
type SignTransactionRequest struct {
	Transaction string `json:"transaction"`

	// Encoding is required rather than defaulted or detected, since base64
	// and base58 partly overlap in their alphabets and a wrong guess would
	// decode to different bytes than the caller sent rather than failing
	// outright.
	Encoding    string   `json:"encoding" example:"base64"`
	PublicKeys  []string `json:"public_keys" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	PrivateKeys []string `json:"private_keys"`

	tx          *types.Transaction
	raw         []byte
	versioned   bool
	privateKeys []*types.PrivateKey
}

func (r *SignTransactionRequest) ValidateRequest() error {
	raw, err := codec.DecodeByName(r.Encoding, r.Transaction)
	if err != nil {
		return errors.New("transaction: " + err.Error())
	}

	if r.versioned, err = types.IsVersionedTransaction(raw); err != nil {
		return errors.New(err.Error())
	}
	r.raw = raw

	if !r.versioned {
		if r.tx, err = types.DeserializeTransaction(raw); err != nil {
			return errors.New("transaction: " + err.Error())
		}
	}

	if len(r.PublicKeys) == 0 && len(r.PrivateKeys) == 0 {
		return errors.New("public_keys or private_keys: at least one key is required")
	}

	for i := range r.PublicKeys {
		r.PublicKeys[i] = strings.TrimSpace(r.PublicKeys[i])
		if r.PublicKeys[i] == "" {
			return fmt.Errorf("public_keys[%d]: must not be empty", i)
		}
	}

	r.privateKeys = make([]*types.PrivateKey, len(r.PrivateKeys))
	for i := range r.PrivateKeys {
		if r.privateKeys[i], err = types.NewPrivateKeyFromBase58(strings.TrimSpace(r.PrivateKeys[i])); err != nil {
			return fmt.Errorf("private_keys[%d]: %s", i, err)
		}
	}

	return nil
}

func (r *SignTransactionRequest) ToTransaction() *types.Transaction {
	return r.tx
}

func (r *SignTransactionRequest) ToRaw() []byte {
	return r.raw
}

func (r *SignTransactionRequest) IsVersioned() bool {
	return r.versioned
}

func (r *SignTransactionRequest) ToPrivateKeys() []*types.PrivateKey {
	return r.privateKeys
}

// SignTransactionResponse reports the signed bytes and which slots are filled.
//
// TransactionID is empty until every slot is filled, because the id is the fee
// payer's signature and a partially signed transaction has none to stand
// behind it.
type SignTransactionResponse struct {
	Transaction   string   `json:"transaction"`
	TransactionID string   `json:"transaction_id"`
	Signatures    []string `json:"signatures"`
	FullySigned   bool     `json:"fully_signed"`
}

func NewSignTransactionResponse(tx *types.Transaction, raw []byte) *SignTransactionResponse {
	signatures := make([]string, len(tx.Signatures))
	for i, sig := range tx.Signatures {
		if sig.IsZero() {
			continue
		}
		signatures[i] = sig.Base58()
	}

	var id string
	if tx.IsFullySigned() {
		if sig, err := tx.ID(); err == nil {
			id = sig.Base58()
		}
	}

	return &SignTransactionResponse{
		Transaction:   codec.Base64.Encode(raw),
		TransactionID: id,
		Signatures:    signatures,
		FullySigned:   tx.IsFullySigned(),
	}
}

// NewSignVersionedTransactionResponse builds the same shape from raw bytes
// alone, reading only the signature array. That array's layout does not
// depend on the message being legacy or versioned, so the same four fields
// are answerable without the richer parse the legacy path has.
func NewSignVersionedTransactionResponse(raw []byte) (*SignTransactionResponse, error) {
	n, prefix, err := codec.Binary.ReadShortVecLen(raw)
	if err != nil {
		return nil, fmt.Errorf("signature count: %w", err)
	}
	if len(raw) < prefix+n*types.SignatureLength {
		return nil, fmt.Errorf("%d bytes is too short for %d signatures", len(raw), n)
	}

	signatures := make([]string, n)
	fullySigned := true
	for i := range n {
		start := prefix + i*types.SignatureLength
		b := raw[start : start+types.SignatureLength]

		zero := true
		for _, c := range b {
			if c != 0 {
				zero = false
				break
			}
		}
		if zero {
			fullySigned = false
			continue
		}
		signatures[i] = codec.Base58.Encode(b)
	}

	var id string
	if fullySigned && n > 0 {
		id = signatures[0]
	}

	return &SignTransactionResponse{
		Transaction:   codec.Base64.Encode(raw),
		TransactionID: id,
		Signatures:    signatures,
		FullySigned:   fullySigned,
	}, nil
}

// SignRequest signs arbitrary bytes.
//
// Message is base64 rather than a digest. ed25519 as specified in RFC 8032 is
// PureEdDSA and hashes internally, so signing a digest would produce a
// signature that no verifier holding the real message can check. Pass the
// message itself, such as the message field returned by a build.
type SignRequest struct {
	PublicKey string `json:"public_key" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Message   string `json:"message"`

	message []byte
}

func (r *SignRequest) ValidateRequest() error {
	r.PublicKey = strings.TrimSpace(r.PublicKey)
	if r.PublicKey == "" {
		return errors.New("public_key is required")
	}

	b, err := codec.Base64.Decode(strings.TrimSpace(r.Message))
	if err != nil {
		return errors.New("message: invalid base64: " + err.Error())
	}
	if len(b) == 0 {
		return errors.New("message: must not be empty")
	}
	r.message = b

	return nil
}

func (r *SignRequest) ToMessage() []byte {
	return r.message
}

// SignResponse is the bare signature, with nothing assembled around it.
type SignResponse struct {
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

func NewSignResponse(pub *types.PublicKey, sig *types.Signature) *SignResponse {
	return &SignResponse{
		PublicKey: pub.Base58(),
		Signature: sig.Base58(),
	}
}

// VerifyRequest checks a signature against a message and a public key.
//
// The public key is required, and no endpoint can recover it from the
// signature: ed25519 offers no recovery, which is what ecrecover provides on
// an EVM chain. Any key may be given here, not only one from config.
type VerifyRequest struct {
	PublicKey string `json:"public_key" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Message   string `json:"message"`
	Signature string `json:"signature"`

	publicKey *types.PublicKey
	message   []byte
	signature *types.Signature
}

func (r *VerifyRequest) ValidateRequest() error {
	var err error
	if r.publicKey, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.PublicKey)); err != nil {
		return errors.New("public_key: " + err.Error())
	}

	if r.message, err = codec.Base64.Decode(strings.TrimSpace(r.Message)); err != nil {
		return errors.New("message: invalid base64: " + err.Error())
	}
	if len(r.message) == 0 {
		return errors.New("message: must not be empty")
	}

	if r.signature, err = types.NewSignatureFromBase58(strings.TrimSpace(r.Signature)); err != nil {
		return errors.New("signature: " + err.Error())
	}

	return nil
}

func (r *VerifyRequest) ToPublicKey() *types.PublicKey {
	return r.publicKey
}

func (r *VerifyRequest) ToMessage() []byte {
	return r.message
}

func (r *VerifyRequest) ToSignature() *types.Signature {
	return r.signature
}

type VerifyResponse struct {
	Valid bool `json:"valid"`
}

func NewVerifyResponse(valid bool) *VerifyResponse {
	return &VerifyResponse{Valid: valid}
}
