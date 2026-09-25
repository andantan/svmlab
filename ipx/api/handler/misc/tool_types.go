package misc

import (
	"errors"
	"fmt"
	"strconv"
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

// ProveConfidentialTransferRequest names everything the three proofs one
// ConfidentialTransfer needs are built from. The three come out of one
// request rather than three because they share their inputs: the same
// fresh Pedersen openings and the same ciphertexts feed all of them, so
// proofs built in separate calls would each draw different randomness and
// no longer describe the same transfer.
type ProveConfidentialTransferRequest struct {
	// SourceElgamalSecretKey is the source account's own ElGamal secret
	// key, base58-encoded. The public key is derived from it here.
	SourceElgamalSecretKey string `json:"source_elgamal_secret_key" example:""`

	// DestinationElgamalPubkey is the destination account's ElGamal public
	// key, base58-encoded.
	DestinationElgamalPubkey string `json:"destination_elgamal_pubkey" example:""`

	// AuditorElgamalPubkey may be left empty for a mint with no auditor.
	// Given, it must be the exact value that mint's
	// ConfidentialTransferMint.auditor_elgamal_pubkey holds.
	AuditorElgamalPubkey string `json:"auditor_elgamal_pubkey" example:""`

	// CurrentAvailableBalanceCiphertext is the source's current available
	// balance, base58-encoded raw 64-byte ElGamal ciphertext.
	CurrentAvailableBalanceCiphertext string `json:"current_available_balance_ciphertext" example:""`

	// CurrentDecryptableAvailableBalance is the source's current available
	// balance, base58-encoded raw 36-byte AE ciphertext.
	CurrentDecryptableAvailableBalance string `json:"current_decryptable_available_balance" example:""`

	// AeKey decrypts CurrentDecryptableAvailableBalance and encrypts the
	// new one, base58-encoded raw 16-byte key.
	AeKey string `json:"ae_key" example:""`

	// Amount is the raw base-unit count to move. It cannot exceed 2^48 - 1
	// nor the source's current available balance.
	Amount string `json:"amount" example:"250"`

	sourceSecretKey                    []byte
	destinationElgamalPubkey           []byte
	auditorElgamalPubkey               []byte
	currentAvailableBalanceCiphertext  []byte
	currentDecryptableAvailableBalance []byte
	aeKey                              []byte
	amount                             uint64
}

func (r *ProveConfidentialTransferRequest) ValidateRequest() error {
	var err error

	if r.sourceSecretKey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.SourceElgamalSecretKey), 32); err != nil {
		return errors.New("source_elgamal_secret_key: " + err.Error())
	}
	if r.destinationElgamalPubkey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.DestinationElgamalPubkey), 32); err != nil {
		return errors.New("destination_elgamal_pubkey: " + err.Error())
	}
	if a := strings.TrimSpace(r.AuditorElgamalPubkey); a != "" {
		if r.auditorElgamalPubkey, err = codec.Base58.DecodeFixed(a, 32); err != nil {
			return errors.New("auditor_elgamal_pubkey: " + err.Error())
		}
	}
	if r.currentAvailableBalanceCiphertext, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.CurrentAvailableBalanceCiphertext), 64); err != nil {
		return errors.New("current_available_balance_ciphertext: " + err.Error())
	}
	if r.currentDecryptableAvailableBalance, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.CurrentDecryptableAvailableBalance), core.AeCiphertextLen); err != nil {
		return errors.New("current_decryptable_available_balance: " + err.Error())
	}
	if r.aeKey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.AeKey), core.AeKeyLen); err != nil {
		return errors.New("ae_key: " + err.Error())
	}

	amount := strings.TrimSpace(r.Amount)
	if amount == "" {
		return errors.New("amount is required")
	}
	if r.amount, err = strconv.ParseUint(amount, 10, 64); err != nil {
		return errors.New("amount: " + err.Error())
	}
	if r.amount == 0 {
		return errors.New("amount must be greater than zero")
	}

	return nil
}

func (r *ProveConfidentialTransferRequest) ToSourceSecretKey() []byte { return r.sourceSecretKey }
func (r *ProveConfidentialTransferRequest) ToDestinationElgamalPubkey() []byte {
	return r.destinationElgamalPubkey
}
func (r *ProveConfidentialTransferRequest) ToAuditorElgamalPubkey() []byte {
	return r.auditorElgamalPubkey
}
func (r *ProveConfidentialTransferRequest) ToCurrentAvailableBalanceCiphertext() []byte {
	return r.currentAvailableBalanceCiphertext
}
func (r *ProveConfidentialTransferRequest) ToCurrentDecryptableAvailableBalance() []byte {
	return r.currentDecryptableAvailableBalance
}
func (r *ProveConfidentialTransferRequest) ToAeKey() []byte  { return r.aeKey }
func (r *ProveConfidentialTransferRequest) ToAmount() uint64 { return r.amount }

// ProveConfidentialTransferResponse carries the three proof-data blobs
// (each the proof_data of its matching zk-elgamal-proof/context-state/
// verify endpoint) and the three values ConfidentialTransfer's own
// instruction data needs. Nothing here can be rebuilt later: a second call
// draws new openings and produces proofs that no longer match any context
// state account already verified from this response.
type ProveConfidentialTransferResponse struct {
	EqualityProofData string `json:"equality_proof_data"`
	ValidityProofData string `json:"validity_proof_data"`
	RangeProofData    string `json:"range_proof_data"`

	AuditorCiphertextLo                  string `json:"auditor_ciphertext_lo"`
	AuditorCiphertextHi                  string `json:"auditor_ciphertext_hi"`
	NewSourceDecryptableAvailableBalance string `json:"new_source_decryptable_available_balance"`

	SourceElgamalPubkey string `json:"source_elgamal_pubkey"`
}

func NewProveConfidentialTransferResponse(p *core.TransferProofs, sourcePublicKey []byte) *ProveConfidentialTransferResponse {
	return &ProveConfidentialTransferResponse{
		EqualityProofData:                    codec.Base58.Encode(p.EqualityProof),
		ValidityProofData:                    codec.Base58.Encode(p.ValidityProof),
		RangeProofData:                       codec.Base58.Encode(p.RangeProof),
		AuditorCiphertextLo:                  codec.Base58.Encode(p.AuditorCiphertextLo),
		AuditorCiphertextHi:                  codec.Base58.Encode(p.AuditorCiphertextHi),
		NewSourceDecryptableAvailableBalance: codec.Base58.Encode(p.NewSourceDecryptableAvailableBalance),
		SourceElgamalPubkey:                  codec.Base58.Encode(sourcePublicKey),
	}
}

// ProveConfidentialWithdrawRequest names everything the two proofs one
// confidential Withdraw needs are built from. Both come out of one request
// because they share their inputs: the same fresh Pedersen opening and the
// same remaining-balance ciphertext feed both, so proofs built in separate
// calls would each draw different randomness and no longer describe the
// same withdrawal.
type ProveConfidentialWithdrawRequest struct {
	// ElgamalSecretKey is the account's own ElGamal secret key,
	// base58-encoded. The public key is derived from it here.
	ElgamalSecretKey string `json:"elgamal_secret_key" example:""`

	// CurrentAvailableBalanceCiphertext is the account's current available
	// balance, base58-encoded raw 64-byte ElGamal ciphertext.
	CurrentAvailableBalanceCiphertext string `json:"current_available_balance_ciphertext" example:""`

	// CurrentDecryptableAvailableBalance is the account's current available
	// balance, base58-encoded raw 36-byte AE ciphertext.
	CurrentDecryptableAvailableBalance string `json:"current_decryptable_available_balance" example:""`

	// AeKey decrypts CurrentDecryptableAvailableBalance and encrypts the
	// new one, base58-encoded raw 16-byte key.
	AeKey string `json:"ae_key" example:""`

	// Amount is the raw base-unit count to withdraw. It cannot exceed the
	// account's current available balance.
	Amount string `json:"amount" example:"5"`

	secretKey                          []byte
	currentAvailableBalanceCiphertext  []byte
	currentDecryptableAvailableBalance []byte
	aeKey                              []byte
	amount                             uint64
}

func (r *ProveConfidentialWithdrawRequest) ValidateRequest() error {
	var err error

	if r.secretKey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.ElgamalSecretKey), 32); err != nil {
		return errors.New("elgamal_secret_key: " + err.Error())
	}
	if r.currentAvailableBalanceCiphertext, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.CurrentAvailableBalanceCiphertext), 64); err != nil {
		return errors.New("current_available_balance_ciphertext: " + err.Error())
	}
	if r.currentDecryptableAvailableBalance, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.CurrentDecryptableAvailableBalance), core.AeCiphertextLen); err != nil {
		return errors.New("current_decryptable_available_balance: " + err.Error())
	}
	if r.aeKey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.AeKey), core.AeKeyLen); err != nil {
		return errors.New("ae_key: " + err.Error())
	}

	amount := strings.TrimSpace(r.Amount)
	if amount == "" {
		return errors.New("amount is required")
	}
	if r.amount, err = strconv.ParseUint(amount, 10, 64); err != nil {
		return errors.New("amount: " + err.Error())
	}
	if r.amount == 0 {
		return errors.New("amount must be greater than zero")
	}

	return nil
}

func (r *ProveConfidentialWithdrawRequest) ToElgamalSecretKey() []byte { return r.secretKey }
func (r *ProveConfidentialWithdrawRequest) ToCurrentAvailableBalanceCiphertext() []byte {
	return r.currentAvailableBalanceCiphertext
}
func (r *ProveConfidentialWithdrawRequest) ToCurrentDecryptableAvailableBalance() []byte {
	return r.currentDecryptableAvailableBalance
}
func (r *ProveConfidentialWithdrawRequest) ToAeKey() []byte  { return r.aeKey }
func (r *ProveConfidentialWithdrawRequest) ToAmount() uint64 { return r.amount }

// ProveConfidentialWithdrawResponse carries the two proof-data blobs (each
// the proof_data of its matching zk-elgamal-proof/context-state/verify
// endpoint) and the one value Withdraw's own instruction data needs.
// Nothing here can be rebuilt later: a second call draws new openings and
// produces proofs that no longer match any context-state account already
// verified from this response.
type ProveConfidentialWithdrawResponse struct {
	EqualityProofData string `json:"equality_proof_data"`
	RangeProofData    string `json:"range_proof_data"`

	NewDecryptableAvailableBalance string `json:"new_decryptable_available_balance"`

	ElgamalPubkey string `json:"elgamal_pubkey"`
}

func NewProveConfidentialWithdrawResponse(p *core.WithdrawProofs, publicKey []byte) *ProveConfidentialWithdrawResponse {
	return &ProveConfidentialWithdrawResponse{
		EqualityProofData:              codec.Base58.Encode(p.EqualityProof),
		RangeProofData:                 codec.Base58.Encode(p.RangeProof),
		NewDecryptableAvailableBalance: codec.Base58.Encode(p.NewDecryptableAvailableBalance),
		ElgamalPubkey:                  codec.Base58.Encode(publicKey),
	}
}

// ProveConfidentialEmptyAccountRequest names what the single proof one
// confidential EmptyAccount needs is built from: the account's ElGamal
// secret key and its current available balance ciphertext, which must
// encrypt zero.
type ProveConfidentialEmptyAccountRequest struct {
	// ElgamalSecretKey is the account's own ElGamal secret key,
	// base58-encoded. The public key is derived from it here.
	ElgamalSecretKey string `json:"elgamal_secret_key" example:""`

	// AvailableBalanceCiphertext is the account's current available
	// balance, base58-encoded raw 64-byte ElGamal ciphertext, read off
	// chain. It must already encrypt zero (see
	// extensions/confidential-transfer-account/withdraw) or the proof
	// will not verify.
	AvailableBalanceCiphertext string `json:"available_balance_ciphertext" example:""`

	secretKey  []byte
	ciphertext []byte
}

func (r *ProveConfidentialEmptyAccountRequest) ValidateRequest() error {
	var err error

	if r.secretKey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.ElgamalSecretKey), 32); err != nil {
		return errors.New("elgamal_secret_key: " + err.Error())
	}
	if r.ciphertext, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.AvailableBalanceCiphertext), 64); err != nil {
		return errors.New("available_balance_ciphertext: " + err.Error())
	}

	return nil
}

func (r *ProveConfidentialEmptyAccountRequest) ToElgamalSecretKey() []byte { return r.secretKey }
func (r *ProveConfidentialEmptyAccountRequest) ToAvailableBalanceCiphertext() []byte {
	return r.ciphertext
}

// ProveConfidentialEmptyAccountResponse carries the proof-data blob (the
// proof_data of zk-elgamal-proof/context-state/verify/zero-ciphertext).
// It is only valid while the account's available balance ciphertext is
// the one it was built from.
type ProveConfidentialEmptyAccountResponse struct {
	ZeroCiphertextProofData string `json:"zero_ciphertext_proof_data"`
	ElgamalPubkey           string `json:"elgamal_pubkey"`
}

func NewProveConfidentialEmptyAccountResponse(proof, publicKey []byte) *ProveConfidentialEmptyAccountResponse {
	return &ProveConfidentialEmptyAccountResponse{
		ZeroCiphertextProofData: codec.Base58.Encode(proof),
		ElgamalPubkey:           codec.Base58.Encode(publicKey),
	}
}

// ProveConfidentialTransferWithFeeRequest is ProveConfidentialTransferRequest
// for a mint that carries a transfer fee. The mint is named rather than its
// keys and fee parameters being passed in: the fee rate and cap in effect
// this epoch, the auditor key, and the withdraw withheld authority key are
// all read from the mint here, since the deployed program recomputes them
// from the same place and rejects proofs built for different values.
type ProveConfidentialTransferWithFeeRequest struct {
	// Mint must carry the TransferFeeConfig, ConfidentialTransferMint, and
	// ConfidentialTransferFeeConfig extensions.
	Mint string `json:"mint" example:""`

	// SourceElgamalSecretKey is the source account's own ElGamal secret
	// key, base58-encoded. The public key is derived from it here.
	SourceElgamalSecretKey string `json:"source_elgamal_secret_key" example:""`

	// DestinationElgamalPubkey is the destination account's ElGamal public
	// key, base58-encoded.
	DestinationElgamalPubkey string `json:"destination_elgamal_pubkey" example:""`

	// CurrentAvailableBalanceCiphertext is the source's current available
	// balance, base58-encoded raw 64-byte ElGamal ciphertext.
	CurrentAvailableBalanceCiphertext string `json:"current_available_balance_ciphertext" example:""`

	// CurrentDecryptableAvailableBalance is the source's current available
	// balance, base58-encoded raw 36-byte AE ciphertext.
	CurrentDecryptableAvailableBalance string `json:"current_decryptable_available_balance" example:""`

	// AeKey decrypts CurrentDecryptableAvailableBalance and encrypts the
	// new one, base58-encoded raw 16-byte key.
	AeKey string `json:"ae_key" example:""`

	// Amount is the raw base-unit count to move, before the fee. It cannot
	// exceed 2^48 - 1 nor the source's current available balance.
	Amount string `json:"amount" example:"1000"`

	mint                               *types.PublicKey
	sourceSecretKey                    []byte
	destinationElgamalPubkey           []byte
	currentAvailableBalanceCiphertext  []byte
	currentDecryptableAvailableBalance []byte
	aeKey                              []byte
	amount                             uint64
}

func (r *ProveConfidentialTransferWithFeeRequest) ValidateRequest() error {
	var err error

	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.sourceSecretKey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.SourceElgamalSecretKey), 32); err != nil {
		return errors.New("source_elgamal_secret_key: " + err.Error())
	}
	if r.destinationElgamalPubkey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.DestinationElgamalPubkey), 32); err != nil {
		return errors.New("destination_elgamal_pubkey: " + err.Error())
	}
	if r.currentAvailableBalanceCiphertext, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.CurrentAvailableBalanceCiphertext), 64); err != nil {
		return errors.New("current_available_balance_ciphertext: " + err.Error())
	}
	if r.currentDecryptableAvailableBalance, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.CurrentDecryptableAvailableBalance), core.AeCiphertextLen); err != nil {
		return errors.New("current_decryptable_available_balance: " + err.Error())
	}
	if r.aeKey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.AeKey), core.AeKeyLen); err != nil {
		return errors.New("ae_key: " + err.Error())
	}

	amount := strings.TrimSpace(r.Amount)
	if amount == "" {
		return errors.New("amount is required")
	}
	if r.amount, err = strconv.ParseUint(amount, 10, 64); err != nil {
		return errors.New("amount: " + err.Error())
	}
	if r.amount == 0 {
		return errors.New("amount must be greater than zero")
	}

	return nil
}

func (r *ProveConfidentialTransferWithFeeRequest) MintKey() *types.PublicKey { return r.mint }
func (r *ProveConfidentialTransferWithFeeRequest) ToSourceSecretKey() []byte {
	return r.sourceSecretKey
}
func (r *ProveConfidentialTransferWithFeeRequest) ToDestinationElgamalPubkey() []byte {
	return r.destinationElgamalPubkey
}
func (r *ProveConfidentialTransferWithFeeRequest) ToCurrentAvailableBalanceCiphertext() []byte {
	return r.currentAvailableBalanceCiphertext
}
func (r *ProveConfidentialTransferWithFeeRequest) ToCurrentDecryptableAvailableBalance() []byte {
	return r.currentDecryptableAvailableBalance
}
func (r *ProveConfidentialTransferWithFeeRequest) ToAeKey() []byte  { return r.aeKey }
func (r *ProveConfidentialTransferWithFeeRequest) ToAmount() uint64 { return r.amount }

// ProveConfidentialTransferWithFeeResponse carries the five proof-data
// blobs (each the proof_data of its matching zk-elgamal-proof/context-state/
// verify endpoint), the three values TransferWithFee's own instruction data
// needs, and the parameters everything was built against so the caller can
// see what the mint supplied. Nothing here can be rebuilt later: a second
// call draws new openings and produces proofs that no longer match any
// context-state account already verified from this response.
type ProveConfidentialTransferWithFeeResponse struct {
	EqualityProofData               string `json:"equality_proof_data"`
	TransferAmountValidityProofData string `json:"transfer_amount_validity_proof_data"`
	PercentageWithCapProofData      string `json:"percentage_with_cap_proof_data"`
	FeeValidityProofData            string `json:"fee_validity_proof_data"`
	RangeProofData                  string `json:"range_proof_data"`

	AuditorCiphertextLo                  string `json:"auditor_ciphertext_lo"`
	AuditorCiphertextHi                  string `json:"auditor_ciphertext_hi"`
	NewSourceDecryptableAvailableBalance string `json:"new_source_decryptable_available_balance"`

	Fee                    string `json:"fee"`
	FeeRateBasisPoints     uint16 `json:"fee_rate_basis_points"`
	MaximumFee             string `json:"maximum_fee"`
	Epoch                  uint64 `json:"epoch"`
	AuditorElgamalPubkey   string `json:"auditor_elgamal_pubkey,omitempty"`
	WithdrawWithheldPubkey string `json:"withdraw_withheld_authority_elgamal_pubkey"`
	SourceElgamalPubkey    string `json:"source_elgamal_pubkey"`
}

func NewProveConfidentialTransferWithFeeResponse(
	p *core.TransferWithFeeProofs, sourcePublicKey, auditorPublicKey, withdrawWithheldPublicKey []byte,
	feeRateBasisPoints uint16, maximumFee, epoch uint64,
) *ProveConfidentialTransferWithFeeResponse {
	res := &ProveConfidentialTransferWithFeeResponse{
		EqualityProofData:                    codec.Base58.Encode(p.EqualityProof),
		TransferAmountValidityProofData:      codec.Base58.Encode(p.TransferAmountValidityProof),
		PercentageWithCapProofData:           codec.Base58.Encode(p.PercentageWithCapProof),
		FeeValidityProofData:                 codec.Base58.Encode(p.FeeValidityProof),
		RangeProofData:                       codec.Base58.Encode(p.RangeProof),
		AuditorCiphertextLo:                  codec.Base58.Encode(p.AuditorCiphertextLo),
		AuditorCiphertextHi:                  codec.Base58.Encode(p.AuditorCiphertextHi),
		NewSourceDecryptableAvailableBalance: codec.Base58.Encode(p.NewSourceDecryptableAvailableBalance),
		Fee:                                  strconv.FormatUint(p.Fee, 10),
		FeeRateBasisPoints:                   feeRateBasisPoints,
		MaximumFee:                           strconv.FormatUint(maximumFee, 10),
		Epoch:                                epoch,
		WithdrawWithheldPubkey:               codec.Base58.Encode(withdrawWithheldPublicKey),
		SourceElgamalPubkey:                  codec.Base58.Encode(sourcePublicKey),
	}
	if len(auditorPublicKey) > 0 {
		res.AuditorElgamalPubkey = codec.Base58.Encode(auditorPublicKey)
	}

	return res
}

// DefaultRecordChunkSize is the chunk size split/record-chunks uses when none
// is given: small enough that one record/write transaction stays under the
// 1232-byte limit with or without a durable nonce (about 1015 bytes fit
// without one, about 909 with), so the same chunks work either way.
const DefaultRecordChunkSize = 900

// MaxRecordChunkSize is the most one record/write transaction can carry
// without a durable nonce -- slightly under the roughly 1015 that fit, so a
// chunk this large still has room for a slightly larger message.
const MaxRecordChunkSize = 1000

// SplitRecordChunksRequest names bytes to write into a record account.
type SplitRecordChunksRequest struct {
	// Data is the bytes to split, base58-encoded -- typically a proof_data
	// blob from one of the tool/prove endpoints.
	Data string `json:"data" example:""`

	// ChunkSize is how many bytes each record/write carries. Left empty or
	// zero it is 900, which fits a transaction with or without a durable
	// nonce. It cannot exceed 1000.
	ChunkSize uint64 `json:"chunk_size" example:"900"`

	data      []byte
	chunkSize int
}

func (r *SplitRecordChunksRequest) ValidateRequest() error {
	var err error

	if v := strings.TrimSpace(r.Data); v == "" {
		return errors.New("data is required")
	} else if r.data, err = codec.Base58.Decode(v); err != nil {
		return errors.New("data: " + err.Error())
	}
	if len(r.data) == 0 {
		return errors.New("data is empty")
	}

	size := r.ChunkSize
	if size == 0 {
		size = DefaultRecordChunkSize
	}
	if size > MaxRecordChunkSize {
		return fmt.Errorf("chunk_size: %d exceeds %d, the most one record/write transaction can carry", size, MaxRecordChunkSize)
	}
	r.chunkSize = int(size)

	return nil
}

// SplitRecordChunksResponse lists the writes that put the whole of Data into
// a record account, in order. Each Chunk is one record/write call: its
// Offset and Data go straight into that endpoint's offset and data fields.
type SplitRecordChunksResponse struct {
	// TotalLength is len(Data) in bytes -- the data_length to create the
	// record account with (record/create-account).
	TotalLength int `json:"total_length"`

	// ProofOffset is where the data starts within the record account:
	// 33, the record header's length. It is the proof_offset a
	// verify-from-account request needs when Data is a proof.
	ProofOffset int `json:"proof_offset"`

	Chunks []RecordChunk `json:"chunks"`
}

// RecordChunk is one record/write call.
type RecordChunk struct {
	// Offset is the record/write offset, as a string like every other
	// 64-bit value in this API.
	Offset string `json:"offset"`
	Length int    `json:"length"`
	// Data is the chunk, base58-encoded.
	Data string `json:"data"`
}

func NewSplitRecordChunksResponse(data []byte, chunkSize int) *SplitRecordChunksResponse {
	res := &SplitRecordChunksResponse{
		TotalLength: len(data),
		ProofOffset: core.RecordAccountHeaderLen,
	}
	for offset := 0; offset < len(data); offset += chunkSize {
		end := offset + chunkSize
		if end > len(data) {
			end = len(data)
		}
		res.Chunks = append(res.Chunks, RecordChunk{
			Offset: strconv.Itoa(offset),
			Length: end - offset,
			Data:   codec.Base58.Encode(data[offset:end]),
		})
	}

	return res
}

// ProveConfidentialWithdrawWithheldFromMintRequest names what the proof one
// confidential WithdrawWithheldTokensFromMint needs is built from. The mint
// and the destination account are named rather than their ciphertexts and
// keys being passed in: the mint's withheld amount, the withdraw
// authority's key, and the destination's ElGamal key and decryptable
// balance are read from chain, since the deployed program compares the
// proof against those very values.
type ProveConfidentialWithdrawWithheldFromMintRequest struct {
	// Mint must carry the ConfidentialTransferFeeConfig extension.
	Mint string `json:"mint" example:""`

	// Destination is the token account the fees are credited to, which must
	// hold Mint and carry the ConfidentialTransferAccount extension.
	Destination string `json:"destination" example:""`

	// WithdrawElgamalSecretKey is the secret key of the ElGamal public key
	// the mint encrypts withheld fees under, base58-encoded raw 32 bytes.
	WithdrawElgamalSecretKey string `json:"withdraw_elgamal_secret_key" example:""`

	// AeKey is the destination's own AE key, base58-encoded raw 16 bytes,
	// needed to work out its new decryptable balance.
	AeKey string `json:"ae_key" example:""`

	mint        *types.PublicKey
	destination *types.PublicKey
	secretKey   []byte
	aeKey       []byte
}

func (r *ProveConfidentialWithdrawWithheldFromMintRequest) ValidateRequest() error {
	var err error

	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.destination, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Destination)); err != nil {
		return errors.New("destination: " + err.Error())
	}
	if r.secretKey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.WithdrawElgamalSecretKey), 32); err != nil {
		return errors.New("withdraw_elgamal_secret_key: " + err.Error())
	}
	if r.aeKey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.AeKey), 16); err != nil {
		return errors.New("ae_key: " + err.Error())
	}

	return nil
}

func (r *ProveConfidentialWithdrawWithheldFromMintRequest) MintKey() *types.PublicKey { return r.mint }
func (r *ProveConfidentialWithdrawWithheldFromMintRequest) DestinationKey() *types.PublicKey {
	return r.destination
}
func (r *ProveConfidentialWithdrawWithheldFromMintRequest) ToWithdrawSecretKey() []byte {
	return r.secretKey
}
func (r *ProveConfidentialWithdrawWithheldFromMintRequest) ToAeKey() []byte { return r.aeKey }

// ProveConfidentialWithdrawWithheldFromMintResponse carries the proof-data
// blob (the proof_data of
// zk-elgamal-proof/context-state/verify/ciphertext-ciphertext-equality) and
// the new decryptable balance the withdraw instruction itself carries. The
// proof only matches the mint's withheld amount as it is right now, and a
// second call draws fresh randomness, so it must be used as returned.
type ProveConfidentialWithdrawWithheldFromMintResponse struct {
	CiphertextCiphertextEqualityProofData string `json:"ciphertext_ciphertext_equality_proof_data"`
	NewDecryptableAvailableBalance        string `json:"new_decryptable_available_balance"`
	WithheldAmount                        string `json:"withheld_amount"`
	WithdrawElgamalPubkey                 string `json:"withdraw_elgamal_pubkey"`
	DestinationElgamalPubkey              string `json:"destination_elgamal_pubkey"`
}

// ProveConfidentialWithdrawWithheldFromAccountsRequest names what the proof one
// confidential WithdrawWithheldTokensFromAccounts needs is built from. The mint,
// the source accounts and the destination are named rather than their
// ciphertexts and keys being passed in: the sources' withheld amounts, the withdraw
// authority's key, and the destination's ElGamal key and decryptable
// balance are read from chain, since the deployed program compares the
// proof against those very values.
type ProveConfidentialWithdrawWithheldFromAccountsRequest struct {
	// Mint must carry the ConfidentialTransferFeeConfig extension.
	Mint string `json:"mint" example:""`

	// SourceAccounts are the token accounts to withdraw from, each holding
	// Mint and carrying ConfidentialTransferFeeAmount. The same set has to
	// go to the withdraw endpoint.
	SourceAccounts []string `json:"source_accounts"`

	// Destination is the token account the fees are credited to, which must
	// hold Mint and carry the ConfidentialTransferAccount extension.
	Destination string `json:"destination" example:""`

	// WithdrawElgamalSecretKey is the secret key of the ElGamal public key
	// the mint encrypts withheld fees under, base58-encoded raw 32 bytes.
	WithdrawElgamalSecretKey string `json:"withdraw_elgamal_secret_key" example:""`

	// AeKey is the destination's own AE key, base58-encoded raw 16 bytes,
	// needed to work out its new decryptable balance.
	AeKey string `json:"ae_key" example:""`

	mint        *types.PublicKey
	sources     []*types.PublicKey
	destination *types.PublicKey
	secretKey   []byte
	aeKey       []byte
}

func (r *ProveConfidentialWithdrawWithheldFromAccountsRequest) ValidateRequest() error {
	var err error

	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if len(r.SourceAccounts) == 0 {
		return errors.New("source_accounts: at least one is required")
	}
	seen := make(map[string]bool, len(r.SourceAccounts))
	r.sources = make([]*types.PublicKey, len(r.SourceAccounts))
	for i, a := range r.SourceAccounts {
		if r.sources[i], err = types.NewPublicKeyFromBase58(strings.TrimSpace(a)); err != nil {
			return fmt.Errorf("source_accounts[%d]: %s", i, err)
		}
		if seen[r.sources[i].Base58()] {
			return fmt.Errorf("source_accounts[%d]: %s is listed twice", i, r.sources[i])
		}
		seen[r.sources[i].Base58()] = true
	}
	if r.destination, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Destination)); err != nil {
		return errors.New("destination: " + err.Error())
	}
	if r.secretKey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.WithdrawElgamalSecretKey), 32); err != nil {
		return errors.New("withdraw_elgamal_secret_key: " + err.Error())
	}
	if r.aeKey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.AeKey), 16); err != nil {
		return errors.New("ae_key: " + err.Error())
	}

	return nil
}

func (r *ProveConfidentialWithdrawWithheldFromAccountsRequest) MintKey() *types.PublicKey {
	return r.mint
}
func (r *ProveConfidentialWithdrawWithheldFromAccountsRequest) DestinationKey() *types.PublicKey {
	return r.destination
}
func (r *ProveConfidentialWithdrawWithheldFromAccountsRequest) ToWithdrawSecretKey() []byte {
	return r.secretKey
}
func (r *ProveConfidentialWithdrawWithheldFromAccountsRequest) SourceKeys() []*types.PublicKey {
	return r.sources
}
func (r *ProveConfidentialWithdrawWithheldFromAccountsRequest) ToAeKey() []byte { return r.aeKey }

// ProveConfidentialWithdrawWithheldFromAccountsResponse carries the proof-data
// blob (the proof_data of
// zk-elgamal-proof/context-state/verify/ciphertext-ciphertext-equality) and
// the new decryptable balance the withdraw instruction itself carries. The
// proof only matches the mint's withheld amount as it is right now, and a
// second call draws fresh randomness, so it must be used as returned.
type ProveConfidentialWithdrawWithheldFromAccountsResponse struct {
	CiphertextCiphertextEqualityProofData string `json:"ciphertext_ciphertext_equality_proof_data"`
	NewDecryptableAvailableBalance        string `json:"new_decryptable_available_balance"`
	WithheldAmount                        string `json:"withheld_amount"`
	WithdrawElgamalPubkey                 string `json:"withdraw_elgamal_pubkey"`
	DestinationElgamalPubkey              string `json:"destination_elgamal_pubkey"`
}
