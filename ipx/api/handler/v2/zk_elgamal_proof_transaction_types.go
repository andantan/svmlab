package v2

import (
	"errors"
	"strconv"
	"strings"

	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
	"github.com/andantan/svmlab/core/zkbridge"
)

// ContextStateCreatePubkeyValidityRequest funds a new account sized
// and owned for a PubkeyValidity proof's ProofContextState<T> layout --
// System CreateAccount only, not yet written to. It must land in the same
// transaction as (and strictly before) the matching
// context-state/verify-pubkey-validity instruction: nothing stops another
// party from claiming an uninitialized account in between otherwise.
type ContextStateCreatePubkeyValidityRequest struct {
	// ContextStateAccount is the account created. It signs alongside
	// RentPayer, since an address does not exist until whoever holds its
	// private key authorizes its creation. It must not already exist.
	ContextStateAccount string `json:"context_state_account" example:""`

	// RentPayer funds ContextStateAccount's creation for exactly the
	// rent-exemption minimum for a PubkeyValidity context (65 bytes).
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	csa *types.PublicKey
	rp  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *ContextStateCreatePubkeyValidityRequest) ValidateRequest() error {
	var err error

	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.rp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateCreatePubkeyValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreatePubkeyValidityRequest) RentPayerKey() *types.PublicKey { return r.rp }
func (r *ContextStateCreatePubkeyValidityRequest) FeePayerKey() *types.PublicKey  { return r.fp }
func (r *ContextStateCreatePubkeyValidityRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *ContextStateCreatePubkeyValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreatePubkeyValidityResponse reports the built
// transaction.
type ContextStateCreatePubkeyValidityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount string `json:"context_state_account"`
	Space               uint64 `json:"space"`
	RentExemptLamports  uint64 `json:"rent_exempt_lamports"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateCreatePubkeyValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreatePubkeyValidityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateCreatePubkeyValidityResponse{
		Transaction:         codec.Base64.Encode(raw),
		Message:             codec.Base64.Encode(message),
		RecentBlockhash:     tx.Message.RecentBlockhash.Base58(),
		AccountKeys:         keys,
		Signers:             signers,
		NonceAuthority:      nonceAuth,
		ContextStateAccount: contextStateAccount.Base58(),
		Space:               space,
		RentExemptLamports:  rentExemptLamports,
		Fee:                 newSystemPayer(feePayer, fee),
	}
}

// ContextStateCreateCiphertextCommitmentEqualityRequest funds a new
// account sized and owned for a CiphertextCommitmentEquality proof's
// ProofContextState<T> layout -- System CreateAccount only, not yet
// written to. It must land in the same transaction as (and strictly
// before) the matching
// context-state/verify-ciphertext-commitment-equality instruction:
// nothing stops another party from claiming an uninitialized account in
// between otherwise.
type ContextStateCreateCiphertextCommitmentEqualityRequest struct {
	// ContextStateAccount is the account created. It signs alongside
	// RentPayer, since an address does not exist until whoever holds its
	// private key authorizes its creation. It must not already exist.
	ContextStateAccount string `json:"context_state_account" example:""`

	// RentPayer funds ContextStateAccount's creation for exactly the
	// rent-exemption minimum for a CiphertextCommitmentEquality context
	// (161 bytes).
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	csa *types.PublicKey
	rp  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *ContextStateCreateCiphertextCommitmentEqualityRequest) ValidateRequest() error {
	var err error

	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.rp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateCreateCiphertextCommitmentEqualityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateCiphertextCommitmentEqualityRequest) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateCiphertextCommitmentEqualityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateCiphertextCommitmentEqualityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateCreateCiphertextCommitmentEqualityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateCiphertextCommitmentEqualityResponse reports
// the built transaction.
type ContextStateCreateCiphertextCommitmentEqualityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount string `json:"context_state_account"`
	Space               uint64 `json:"space"`
	RentExemptLamports  uint64 `json:"rent_exempt_lamports"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateCreateCiphertextCommitmentEqualityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateCiphertextCommitmentEqualityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateCreateCiphertextCommitmentEqualityResponse{
		Transaction:         codec.Base64.Encode(raw),
		Message:             codec.Base64.Encode(message),
		RecentBlockhash:     tx.Message.RecentBlockhash.Base58(),
		AccountKeys:         keys,
		Signers:             signers,
		NonceAuthority:      nonceAuth,
		ContextStateAccount: contextStateAccount.Base58(),
		Space:               space,
		RentExemptLamports:  rentExemptLamports,
		Fee:                 newSystemPayer(feePayer, fee),
	}
}

// ContextStateCreateBatchedGroupedCiphertext3HandlesValidityRequest
// funds a new account sized and owned for a
// BatchedGroupedCiphertext3HandlesValidity proof's ProofContextState<T>
// layout -- System CreateAccount only, not yet written to. It must land
// in the same transaction as (and strictly before) the matching
// context-state/verify-batched-grouped-ciphertext-3-handles-validity
// instruction: nothing stops another party from claiming an uninitialized
// account in between otherwise.
type ContextStateCreateBatchedGroupedCiphertext3HandlesValidityRequest struct {
	// ContextStateAccount is the account created. It signs alongside
	// RentPayer, since an address does not exist until whoever holds its
	// private key authorizes its creation. It must not already exist.
	ContextStateAccount string `json:"context_state_account" example:""`

	// RentPayer funds ContextStateAccount's creation for exactly the
	// rent-exemption minimum for a BatchedGroupedCiphertext3HandlesValidity
	// context (385 bytes).
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	csa *types.PublicKey
	rp  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *ContextStateCreateBatchedGroupedCiphertext3HandlesValidityRequest) ValidateRequest() error {
	var err error

	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.rp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateCreateBatchedGroupedCiphertext3HandlesValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateBatchedGroupedCiphertext3HandlesValidityRequest) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateBatchedGroupedCiphertext3HandlesValidityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateBatchedGroupedCiphertext3HandlesValidityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateCreateBatchedGroupedCiphertext3HandlesValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateBatchedGroupedCiphertext3HandlesValidityResponse
// reports the built transaction.
type ContextStateCreateBatchedGroupedCiphertext3HandlesValidityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount string `json:"context_state_account"`
	Space               uint64 `json:"space"`
	RentExemptLamports  uint64 `json:"rent_exempt_lamports"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateCreateBatchedGroupedCiphertext3HandlesValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateBatchedGroupedCiphertext3HandlesValidityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateCreateBatchedGroupedCiphertext3HandlesValidityResponse{
		Transaction:         codec.Base64.Encode(raw),
		Message:             codec.Base64.Encode(message),
		RecentBlockhash:     tx.Message.RecentBlockhash.Base58(),
		AccountKeys:         keys,
		Signers:             signers,
		NonceAuthority:      nonceAuth,
		ContextStateAccount: contextStateAccount.Base58(),
		Space:               space,
		RentExemptLamports:  rentExemptLamports,
		Fee:                 newSystemPayer(feePayer, fee),
	}
}

// ContextStateCreateBatchedRangeProofU128Request funds a new
// account sized and owned for a BatchedRangeProofU128 proof's
// ProofContextState<T> layout -- System CreateAccount only, not yet
// written to. It must land in the same transaction as (and strictly
// before) the matching context-state/verify-batched-range-proof-u128
// instruction: nothing stops another party from claiming an uninitialized
// account in between otherwise.
type ContextStateCreateBatchedRangeProofU128Request struct {
	// ContextStateAccount is the account created. It signs alongside
	// RentPayer, since an address does not exist until whoever holds its
	// private key authorizes its creation. It must not already exist.
	ContextStateAccount string `json:"context_state_account" example:""`

	// RentPayer funds ContextStateAccount's creation for exactly the
	// rent-exemption minimum for a BatchedRangeProofU128 context (297
	// bytes).
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	csa *types.PublicKey
	rp  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *ContextStateCreateBatchedRangeProofU128Request) ValidateRequest() error {
	var err error

	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.rp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateCreateBatchedRangeProofU128Request) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateBatchedRangeProofU128Request) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateBatchedRangeProofU128Request) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateBatchedRangeProofU128Request) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateCreateBatchedRangeProofU128Request) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateBatchedRangeProofU128Response reports the
// built transaction.
type ContextStateCreateBatchedRangeProofU128Response struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount string `json:"context_state_account"`
	Space               uint64 `json:"space"`
	RentExemptLamports  uint64 `json:"rent_exempt_lamports"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateCreateBatchedRangeProofU128Response(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateBatchedRangeProofU128Response {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateCreateBatchedRangeProofU128Response{
		Transaction:         codec.Base64.Encode(raw),
		Message:             codec.Base64.Encode(message),
		RecentBlockhash:     tx.Message.RecentBlockhash.Base58(),
		AccountKeys:         keys,
		Signers:             signers,
		NonceAuthority:      nonceAuth,
		ContextStateAccount: contextStateAccount.Base58(),
		Space:               space,
		RentExemptLamports:  rentExemptLamports,
		Fee:                 newSystemPayer(feePayer, fee),
	}
}

// ContextStateCreateZeroCiphertextRequest funds a new account sized and owned
// for a ZeroCiphertext proof's ProofContextState<T> layout -- System CreateAccount
// only, not yet written to. It must land in the same transaction as (and
// strictly before) the matching context-state/verify-zero-ciphertext
// instruction: nothing stops another party from claiming an
// uninitialized account in between otherwise.
type ContextStateCreateZeroCiphertextRequest struct {
	// ContextStateAccount is the account created. It signs alongside
	// RentPayer, since an address does not exist until whoever holds its
	// private key authorizes its creation. It must not already exist.
	ContextStateAccount string `json:"context_state_account" example:""`

	// RentPayer funds ContextStateAccount's creation for exactly the
	// rent-exemption minimum for a ZeroCiphertext context (129 bytes).
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	csa *types.PublicKey
	rp  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *ContextStateCreateZeroCiphertextRequest) ValidateRequest() error {
	var err error

	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.rp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateCreateZeroCiphertextRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateZeroCiphertextRequest) RentPayerKey() *types.PublicKey { return r.rp }
func (r *ContextStateCreateZeroCiphertextRequest) FeePayerKey() *types.PublicKey  { return r.fp }
func (r *ContextStateCreateZeroCiphertextRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *ContextStateCreateZeroCiphertextRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateZeroCiphertextResponse reports the built transaction.
type ContextStateCreateZeroCiphertextResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount string `json:"context_state_account"`
	Space               uint64 `json:"space"`
	RentExemptLamports  uint64 `json:"rent_exempt_lamports"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateCreateZeroCiphertextResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateZeroCiphertextResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateCreateZeroCiphertextResponse{
		Transaction:         codec.Base64.Encode(raw),
		Message:             codec.Base64.Encode(message),
		RecentBlockhash:     tx.Message.RecentBlockhash.Base58(),
		AccountKeys:         keys,
		Signers:             signers,
		NonceAuthority:      nonceAuth,
		ContextStateAccount: contextStateAccount.Base58(),
		Space:               space,
		RentExemptLamports:  rentExemptLamports,
		Fee:                 newSystemPayer(feePayer, fee),
	}
}

// ContextStateCreateCiphertextCiphertextEqualityRequest funds a new account sized and owned
// for a CiphertextCiphertextEquality proof's ProofContextState<T> layout -- System CreateAccount
// only, not yet written to. It must land in the same transaction as (and
// strictly before) the matching context-state/verify-ciphertext-ciphertext-equality
// instruction: nothing stops another party from claiming an
// uninitialized account in between otherwise.
type ContextStateCreateCiphertextCiphertextEqualityRequest struct {
	// ContextStateAccount is the account created. It signs alongside
	// RentPayer, since an address does not exist until whoever holds its
	// private key authorizes its creation. It must not already exist.
	ContextStateAccount string `json:"context_state_account" example:""`

	// RentPayer funds ContextStateAccount's creation for exactly the
	// rent-exemption minimum for a CiphertextCiphertextEquality context (225 bytes).
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	csa *types.PublicKey
	rp  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *ContextStateCreateCiphertextCiphertextEqualityRequest) ValidateRequest() error {
	var err error

	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.rp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateCreateCiphertextCiphertextEqualityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateCiphertextCiphertextEqualityRequest) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateCiphertextCiphertextEqualityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateCiphertextCiphertextEqualityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateCreateCiphertextCiphertextEqualityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateCiphertextCiphertextEqualityResponse reports the built transaction.
type ContextStateCreateCiphertextCiphertextEqualityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount string `json:"context_state_account"`
	Space               uint64 `json:"space"`
	RentExemptLamports  uint64 `json:"rent_exempt_lamports"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateCreateCiphertextCiphertextEqualityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateCiphertextCiphertextEqualityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateCreateCiphertextCiphertextEqualityResponse{
		Transaction:         codec.Base64.Encode(raw),
		Message:             codec.Base64.Encode(message),
		RecentBlockhash:     tx.Message.RecentBlockhash.Base58(),
		AccountKeys:         keys,
		Signers:             signers,
		NonceAuthority:      nonceAuth,
		ContextStateAccount: contextStateAccount.Base58(),
		Space:               space,
		RentExemptLamports:  rentExemptLamports,
		Fee:                 newSystemPayer(feePayer, fee),
	}
}

// ContextStateCreatePercentageWithCapRequest funds a new account sized and owned
// for a PercentageWithCap proof's ProofContextState<T> layout -- System CreateAccount
// only, not yet written to. It must land in the same transaction as (and
// strictly before) the matching context-state/verify-percentage-with-cap
// instruction: nothing stops another party from claiming an
// uninitialized account in between otherwise.
type ContextStateCreatePercentageWithCapRequest struct {
	// ContextStateAccount is the account created. It signs alongside
	// RentPayer, since an address does not exist until whoever holds its
	// private key authorizes its creation. It must not already exist.
	ContextStateAccount string `json:"context_state_account" example:""`

	// RentPayer funds ContextStateAccount's creation for exactly the
	// rent-exemption minimum for a PercentageWithCap context (137 bytes).
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	csa *types.PublicKey
	rp  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *ContextStateCreatePercentageWithCapRequest) ValidateRequest() error {
	var err error

	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.rp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateCreatePercentageWithCapRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreatePercentageWithCapRequest) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreatePercentageWithCapRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreatePercentageWithCapRequest) Blockhash() *types.Hash { return r.rbh }
func (r *ContextStateCreatePercentageWithCapRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreatePercentageWithCapResponse reports the built transaction.
type ContextStateCreatePercentageWithCapResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount string `json:"context_state_account"`
	Space               uint64 `json:"space"`
	RentExemptLamports  uint64 `json:"rent_exempt_lamports"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateCreatePercentageWithCapResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreatePercentageWithCapResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateCreatePercentageWithCapResponse{
		Transaction:         codec.Base64.Encode(raw),
		Message:             codec.Base64.Encode(message),
		RecentBlockhash:     tx.Message.RecentBlockhash.Base58(),
		AccountKeys:         keys,
		Signers:             signers,
		NonceAuthority:      nonceAuth,
		ContextStateAccount: contextStateAccount.Base58(),
		Space:               space,
		RentExemptLamports:  rentExemptLamports,
		Fee:                 newSystemPayer(feePayer, fee),
	}
}

// ContextStateCreateBatchedRangeProofU64Request funds a new account sized and owned
// for a BatchedRangeProofU64 proof's ProofContextState<T> layout -- System CreateAccount
// only, not yet written to. It must land in the same transaction as (and
// strictly before) the matching context-state/verify-batched-range-proof-u64
// instruction: nothing stops another party from claiming an
// uninitialized account in between otherwise.
type ContextStateCreateBatchedRangeProofU64Request struct {
	// ContextStateAccount is the account created. It signs alongside
	// RentPayer, since an address does not exist until whoever holds its
	// private key authorizes its creation. It must not already exist.
	ContextStateAccount string `json:"context_state_account" example:""`

	// RentPayer funds ContextStateAccount's creation for exactly the
	// rent-exemption minimum for a BatchedRangeProofU64 context (297 bytes).
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	csa *types.PublicKey
	rp  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *ContextStateCreateBatchedRangeProofU64Request) ValidateRequest() error {
	var err error

	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.rp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateCreateBatchedRangeProofU64Request) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateBatchedRangeProofU64Request) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateBatchedRangeProofU64Request) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateBatchedRangeProofU64Request) Blockhash() *types.Hash { return r.rbh }
func (r *ContextStateCreateBatchedRangeProofU64Request) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateBatchedRangeProofU64Response reports the built transaction.
type ContextStateCreateBatchedRangeProofU64Response struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount string `json:"context_state_account"`
	Space               uint64 `json:"space"`
	RentExemptLamports  uint64 `json:"rent_exempt_lamports"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateCreateBatchedRangeProofU64Response(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateBatchedRangeProofU64Response {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateCreateBatchedRangeProofU64Response{
		Transaction:         codec.Base64.Encode(raw),
		Message:             codec.Base64.Encode(message),
		RecentBlockhash:     tx.Message.RecentBlockhash.Base58(),
		AccountKeys:         keys,
		Signers:             signers,
		NonceAuthority:      nonceAuth,
		ContextStateAccount: contextStateAccount.Base58(),
		Space:               space,
		RentExemptLamports:  rentExemptLamports,
		Fee:                 newSystemPayer(feePayer, fee),
	}
}

// ContextStateCreateBatchedRangeProofU256Request funds a new account sized and owned
// for a BatchedRangeProofU256 proof's ProofContextState<T> layout -- System CreateAccount
// only, not yet written to. It must land in the same transaction as (and
// strictly before) the matching context-state/verify-batched-range-proof-u256
// instruction: nothing stops another party from claiming an
// uninitialized account in between otherwise.
type ContextStateCreateBatchedRangeProofU256Request struct {
	// ContextStateAccount is the account created. It signs alongside
	// RentPayer, since an address does not exist until whoever holds its
	// private key authorizes its creation. It must not already exist.
	ContextStateAccount string `json:"context_state_account" example:""`

	// RentPayer funds ContextStateAccount's creation for exactly the
	// rent-exemption minimum for a BatchedRangeProofU256 context (297 bytes).
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	csa *types.PublicKey
	rp  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *ContextStateCreateBatchedRangeProofU256Request) ValidateRequest() error {
	var err error

	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.rp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateCreateBatchedRangeProofU256Request) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateBatchedRangeProofU256Request) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateBatchedRangeProofU256Request) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateBatchedRangeProofU256Request) Blockhash() *types.Hash { return r.rbh }
func (r *ContextStateCreateBatchedRangeProofU256Request) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateBatchedRangeProofU256Response reports the built transaction.
type ContextStateCreateBatchedRangeProofU256Response struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount string `json:"context_state_account"`
	Space               uint64 `json:"space"`
	RentExemptLamports  uint64 `json:"rent_exempt_lamports"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateCreateBatchedRangeProofU256Response(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateBatchedRangeProofU256Response {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateCreateBatchedRangeProofU256Response{
		Transaction:         codec.Base64.Encode(raw),
		Message:             codec.Base64.Encode(message),
		RecentBlockhash:     tx.Message.RecentBlockhash.Base58(),
		AccountKeys:         keys,
		Signers:             signers,
		NonceAuthority:      nonceAuth,
		ContextStateAccount: contextStateAccount.Base58(),
		Space:               space,
		RentExemptLamports:  rentExemptLamports,
		Fee:                 newSystemPayer(feePayer, fee),
	}
}

// ContextStateCreateGroupedCiphertext2HandlesValidityRequest funds a new account sized and owned
// for a GroupedCiphertext2HandlesValidity proof's ProofContextState<T> layout -- System CreateAccount
// only, not yet written to. It must land in the same transaction as (and
// strictly before) the matching context-state/verify-grouped-ciphertext-2-handles-validity
// instruction: nothing stops another party from claiming an
// uninitialized account in between otherwise.
type ContextStateCreateGroupedCiphertext2HandlesValidityRequest struct {
	// ContextStateAccount is the account created. It signs alongside
	// RentPayer, since an address does not exist until whoever holds its
	// private key authorizes its creation. It must not already exist.
	ContextStateAccount string `json:"context_state_account" example:""`

	// RentPayer funds ContextStateAccount's creation for exactly the
	// rent-exemption minimum for a GroupedCiphertext2HandlesValidity context (193 bytes).
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	csa *types.PublicKey
	rp  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *ContextStateCreateGroupedCiphertext2HandlesValidityRequest) ValidateRequest() error {
	var err error

	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.rp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateCreateGroupedCiphertext2HandlesValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateGroupedCiphertext2HandlesValidityRequest) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateGroupedCiphertext2HandlesValidityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateGroupedCiphertext2HandlesValidityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateCreateGroupedCiphertext2HandlesValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateGroupedCiphertext2HandlesValidityResponse reports the built transaction.
type ContextStateCreateGroupedCiphertext2HandlesValidityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount string `json:"context_state_account"`
	Space               uint64 `json:"space"`
	RentExemptLamports  uint64 `json:"rent_exempt_lamports"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateCreateGroupedCiphertext2HandlesValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateGroupedCiphertext2HandlesValidityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateCreateGroupedCiphertext2HandlesValidityResponse{
		Transaction:         codec.Base64.Encode(raw),
		Message:             codec.Base64.Encode(message),
		RecentBlockhash:     tx.Message.RecentBlockhash.Base58(),
		AccountKeys:         keys,
		Signers:             signers,
		NonceAuthority:      nonceAuth,
		ContextStateAccount: contextStateAccount.Base58(),
		Space:               space,
		RentExemptLamports:  rentExemptLamports,
		Fee:                 newSystemPayer(feePayer, fee),
	}
}

// ContextStateCreateBatchedGroupedCiphertext2HandlesValidityRequest funds a new account sized and owned
// for a BatchedGroupedCiphertext2HandlesValidity proof's ProofContextState<T> layout -- System CreateAccount
// only, not yet written to. It must land in the same transaction as (and
// strictly before) the matching context-state/verify-batched-grouped-ciphertext-2-handles-validity
// instruction: nothing stops another party from claiming an
// uninitialized account in between otherwise.
type ContextStateCreateBatchedGroupedCiphertext2HandlesValidityRequest struct {
	// ContextStateAccount is the account created. It signs alongside
	// RentPayer, since an address does not exist until whoever holds its
	// private key authorizes its creation. It must not already exist.
	ContextStateAccount string `json:"context_state_account" example:""`

	// RentPayer funds ContextStateAccount's creation for exactly the
	// rent-exemption minimum for a BatchedGroupedCiphertext2HandlesValidity context (289 bytes).
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	csa *types.PublicKey
	rp  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *ContextStateCreateBatchedGroupedCiphertext2HandlesValidityRequest) ValidateRequest() error {
	var err error

	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.rp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateCreateBatchedGroupedCiphertext2HandlesValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateBatchedGroupedCiphertext2HandlesValidityRequest) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateBatchedGroupedCiphertext2HandlesValidityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateBatchedGroupedCiphertext2HandlesValidityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateCreateBatchedGroupedCiphertext2HandlesValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateBatchedGroupedCiphertext2HandlesValidityResponse reports the built transaction.
type ContextStateCreateBatchedGroupedCiphertext2HandlesValidityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount string `json:"context_state_account"`
	Space               uint64 `json:"space"`
	RentExemptLamports  uint64 `json:"rent_exempt_lamports"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateCreateBatchedGroupedCiphertext2HandlesValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateBatchedGroupedCiphertext2HandlesValidityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateCreateBatchedGroupedCiphertext2HandlesValidityResponse{
		Transaction:         codec.Base64.Encode(raw),
		Message:             codec.Base64.Encode(message),
		RecentBlockhash:     tx.Message.RecentBlockhash.Base58(),
		AccountKeys:         keys,
		Signers:             signers,
		NonceAuthority:      nonceAuth,
		ContextStateAccount: contextStateAccount.Base58(),
		Space:               space,
		RentExemptLamports:  rentExemptLamports,
		Fee:                 newSystemPayer(feePayer, fee),
	}
}

// ContextStateCreateGroupedCiphertext3HandlesValidityRequest funds a new account sized and owned
// for a GroupedCiphertext3HandlesValidity proof's ProofContextState<T> layout -- System CreateAccount
// only, not yet written to. It must land in the same transaction as (and
// strictly before) the matching context-state/verify-grouped-ciphertext-3-handles-validity
// instruction: nothing stops another party from claiming an
// uninitialized account in between otherwise.
type ContextStateCreateGroupedCiphertext3HandlesValidityRequest struct {
	// ContextStateAccount is the account created. It signs alongside
	// RentPayer, since an address does not exist until whoever holds its
	// private key authorizes its creation. It must not already exist.
	ContextStateAccount string `json:"context_state_account" example:""`

	// RentPayer funds ContextStateAccount's creation for exactly the
	// rent-exemption minimum for a GroupedCiphertext3HandlesValidity context (257 bytes).
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	csa *types.PublicKey
	rp  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *ContextStateCreateGroupedCiphertext3HandlesValidityRequest) ValidateRequest() error {
	var err error

	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.rp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateCreateGroupedCiphertext3HandlesValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateGroupedCiphertext3HandlesValidityRequest) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateGroupedCiphertext3HandlesValidityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateGroupedCiphertext3HandlesValidityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateCreateGroupedCiphertext3HandlesValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateGroupedCiphertext3HandlesValidityResponse reports the built transaction.
type ContextStateCreateGroupedCiphertext3HandlesValidityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount string `json:"context_state_account"`
	Space               uint64 `json:"space"`
	RentExemptLamports  uint64 `json:"rent_exempt_lamports"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateCreateGroupedCiphertext3HandlesValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateGroupedCiphertext3HandlesValidityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateCreateGroupedCiphertext3HandlesValidityResponse{
		Transaction:         codec.Base64.Encode(raw),
		Message:             codec.Base64.Encode(message),
		RecentBlockhash:     tx.Message.RecentBlockhash.Base58(),
		AccountKeys:         keys,
		Signers:             signers,
		NonceAuthority:      nonceAuth,
		ContextStateAccount: contextStateAccount.Base58(),
		Space:               space,
		RentExemptLamports:  rentExemptLamports,
		Fee:                 newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyPubkeyValidityRequest verifies a PubkeyValidity proof
// and persists its context (the ElGamal pubkey alone) into an existing
// context-state account -- ZkElgamalProof opcode VerifyPubkeyValidity,
// context-state form. contextStateAccount must already exist, sized and
// owned for this proof type (see context-state/create/pubkey-validity).
type ContextStateVerifyPubkeyValidityRequest struct {
	// ElgamalPubkey is the ElGamal public key the proof is about,
	// base58-encoded (see tool/generate/elgamal-keypair).
	ElgamalPubkey string `json:"elgamal_pubkey" example:""`

	// PubkeyProof proves whoever built this request knows the secret key
	// ElgamalPubkey was derived from, base58-encoded (see
	// tool/prove/pubkey-validity).
	PubkeyProof string `json:"pubkey_proof" example:""`

	// ContextStateAccount already exists, created via
	// context-state/create/pubkey-validity.
	ContextStateAccount string `json:"context_state_account" example:""`

	// ContextStateAccountOwner is recorded as the context's owner -- the
	// key context-state/close will later require a signature from to
	// reclaim this account's rent. It does not sign here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	elgamalPubkey []byte
	pubkeyProof   []byte
	csa           *types.PublicKey
	owner         *types.PublicKey
	fp            *types.PublicKey
	rbh           *types.Hash
	dna           *types.PublicKey
}

func (r *ContextStateVerifyPubkeyValidityRequest) ValidateRequest() error {
	var err error

	if r.elgamalPubkey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.ElgamalPubkey), 32); err != nil {
		return errors.New("elgamal_pubkey: " + err.Error())
	}
	if r.pubkeyProof, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.PubkeyProof), core.PubkeyValidityProofLen); err != nil {
		return errors.New("pubkey_proof: " + err.Error())
	}
	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyPubkeyValidityRequest) ToElgamalPubkey() []byte { return r.elgamalPubkey }
func (r *ContextStateVerifyPubkeyValidityRequest) ToPubkeyProof() []byte   { return r.pubkeyProof }
func (r *ContextStateVerifyPubkeyValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateVerifyPubkeyValidityRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.owner
}
func (r *ContextStateVerifyPubkeyValidityRequest) FeePayerKey() *types.PublicKey { return r.fp }
func (r *ContextStateVerifyPubkeyValidityRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *ContextStateVerifyPubkeyValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyPubkeyValidityResponse reports the built transaction.
type ContextStateVerifyPubkeyValidityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyPubkeyValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount, contextStateAccountOwner *types.PublicKey,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateVerifyPubkeyValidityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyPubkeyValidityResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyCiphertextCommitmentEqualityRequest verifies a CiphertextCommitmentEquality proof and persists its
// context into an existing context-state account -- ZkElgamalProof
// opcode VerifyCiphertextCommitmentEquality, context-state form. contextStateAccount must
// already exist, sized and owned for this proof type (see
// context-state/create/ciphertext-commitment-equality).
type ContextStateVerifyCiphertextCommitmentEqualityRequest struct {
	// ProofData is zkbridge.ProveCiphertextCommitmentEquality's own output (320 bytes),
	// base58-encoded -- context then proof, packed exactly as the
	// deployed program's VerifyCiphertextCommitmentEquality instruction expects.
	ProofData string `json:"proof_data" example:""`

	// ContextStateAccount already exists, created via
	// context-state/create/ciphertext-commitment-equality.
	ContextStateAccount string `json:"context_state_account" example:""`

	// ContextStateAccountOwner is recorded as the context's owner --
	// the key context-state/close will later require a signature from
	// to reclaim this account's rent. It does not sign here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofData []byte
	csa       *types.PublicKey
	owner     *types.PublicKey
	fp        *types.PublicKey
	rbh       *types.Hash
	dna       *types.PublicKey
}

func (r *ContextStateVerifyCiphertextCommitmentEqualityRequest) ValidateRequest() error {
	var err error

	if r.proofData, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.ProofData), zkbridge.CiphertextCommitmentEqualityProofDataLen); err != nil {
		return errors.New("proof_data: " + err.Error())
	}
	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyCiphertextCommitmentEqualityRequest) ToProofData() []byte {
	return r.proofData
}
func (r *ContextStateVerifyCiphertextCommitmentEqualityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateVerifyCiphertextCommitmentEqualityRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.owner
}
func (r *ContextStateVerifyCiphertextCommitmentEqualityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateVerifyCiphertextCommitmentEqualityRequest) Blockhash() *types.Hash { return r.rbh }
func (r *ContextStateVerifyCiphertextCommitmentEqualityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyCiphertextCommitmentEqualityResponse reports the built transaction.
type ContextStateVerifyCiphertextCommitmentEqualityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyCiphertextCommitmentEqualityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount, contextStateAccountOwner *types.PublicKey,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateVerifyCiphertextCommitmentEqualityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyCiphertextCommitmentEqualityResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyBatchedGroupedCiphertext3HandlesValidityRequest verifies a BatchedGroupedCiphertext3HandlesValidity proof and persists its
// context into an existing context-state account -- ZkElgamalProof
// opcode VerifyBatchedGroupedCiphertext3HandlesValidity, context-state form. contextStateAccount must
// already exist, sized and owned for this proof type (see
// context-state/create/batched-grouped-ciphertext-3-handles-validity).
type ContextStateVerifyBatchedGroupedCiphertext3HandlesValidityRequest struct {
	// ProofData is zkbridge.ProveBatchedGroupedCiphertext3HandlesValidity's own output (544 bytes),
	// base58-encoded -- context then proof, packed exactly as the
	// deployed program's VerifyBatchedGroupedCiphertext3HandlesValidity instruction expects.
	ProofData string `json:"proof_data" example:""`

	// ContextStateAccount already exists, created via
	// context-state/create/batched-grouped-ciphertext-3-handles-validity.
	ContextStateAccount string `json:"context_state_account" example:""`

	// ContextStateAccountOwner is recorded as the context's owner --
	// the key context-state/close will later require a signature from
	// to reclaim this account's rent. It does not sign here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofData []byte
	csa       *types.PublicKey
	owner     *types.PublicKey
	fp        *types.PublicKey
	rbh       *types.Hash
	dna       *types.PublicKey
}

func (r *ContextStateVerifyBatchedGroupedCiphertext3HandlesValidityRequest) ValidateRequest() error {
	var err error

	if r.proofData, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.ProofData), zkbridge.BatchedGroupedCiphertext3HandlesValidityProofDataLen); err != nil {
		return errors.New("proof_data: " + err.Error())
	}
	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyBatchedGroupedCiphertext3HandlesValidityRequest) ToProofData() []byte {
	return r.proofData
}
func (r *ContextStateVerifyBatchedGroupedCiphertext3HandlesValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateVerifyBatchedGroupedCiphertext3HandlesValidityRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.owner
}
func (r *ContextStateVerifyBatchedGroupedCiphertext3HandlesValidityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateVerifyBatchedGroupedCiphertext3HandlesValidityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateVerifyBatchedGroupedCiphertext3HandlesValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyBatchedGroupedCiphertext3HandlesValidityResponse reports the built transaction.
type ContextStateVerifyBatchedGroupedCiphertext3HandlesValidityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyBatchedGroupedCiphertext3HandlesValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount, contextStateAccountOwner *types.PublicKey,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateVerifyBatchedGroupedCiphertext3HandlesValidityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyBatchedGroupedCiphertext3HandlesValidityResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyBatchedRangeProofU128Request verifies a BatchedRangeProofU128 proof and persists its
// context into an existing context-state account -- ZkElgamalProof
// opcode VerifyBatchedRangeProofU128, context-state form. contextStateAccount must
// already exist, sized and owned for this proof type (see
// context-state/create/batched-range-proof-u128).
type ContextStateVerifyBatchedRangeProofU128Request struct {
	// ProofData is zkbridge.ProveBatchedRangeProofU128's own output (1000 bytes),
	// base58-encoded -- context then proof, packed exactly as the
	// deployed program's VerifyBatchedRangeProofU128 instruction expects.
	ProofData string `json:"proof_data" example:""`

	// ContextStateAccount already exists, created via
	// context-state/create/batched-range-proof-u128.
	ContextStateAccount string `json:"context_state_account" example:""`

	// ContextStateAccountOwner is recorded as the context's owner --
	// the key context-state/close will later require a signature from
	// to reclaim this account's rent. It does not sign here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofData []byte
	csa       *types.PublicKey
	owner     *types.PublicKey
	fp        *types.PublicKey
	rbh       *types.Hash
	dna       *types.PublicKey
}

func (r *ContextStateVerifyBatchedRangeProofU128Request) ValidateRequest() error {
	var err error

	if r.proofData, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.ProofData), zkbridge.BatchedRangeProofU128DataLen); err != nil {
		return errors.New("proof_data: " + err.Error())
	}
	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyBatchedRangeProofU128Request) ToProofData() []byte { return r.proofData }
func (r *ContextStateVerifyBatchedRangeProofU128Request) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateVerifyBatchedRangeProofU128Request) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.owner
}
func (r *ContextStateVerifyBatchedRangeProofU128Request) FeePayerKey() *types.PublicKey { return r.fp }
func (r *ContextStateVerifyBatchedRangeProofU128Request) Blockhash() *types.Hash        { return r.rbh }
func (r *ContextStateVerifyBatchedRangeProofU128Request) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyBatchedRangeProofU128Response reports the built transaction.
type ContextStateVerifyBatchedRangeProofU128Response struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyBatchedRangeProofU128Response(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount, contextStateAccountOwner *types.PublicKey,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateVerifyBatchedRangeProofU128Response {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyBatchedRangeProofU128Response{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyZeroCiphertextRequest verifies a ZeroCiphertext proof and persists its
// context into an existing context-state account -- ZkElgamalProof
// opcode VerifyZeroCiphertext, context-state form. contextStateAccount must
// already exist, sized and owned for this proof type (see
// context-state/create/zero-ciphertext).
type ContextStateVerifyZeroCiphertextRequest struct {
	// ProofData is the full ZeroCiphertextProofData wire bytes (context then
	// proof), base58-encoded, packed by the caller exactly as the
	// deployed program's VerifyZeroCiphertext instruction expects -- no from-scratch
	// prover exists in this codebase for this proof type yet.
	ProofData string `json:"proof_data" example:""`

	// ContextStateAccount already exists, created via
	// context-state/create/zero-ciphertext.
	ContextStateAccount string `json:"context_state_account" example:""`

	// ContextStateAccountOwner is recorded as the context's owner --
	// the key context-state/close will later require a signature from
	// to reclaim this account's rent. It does not sign here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofData []byte
	csa       *types.PublicKey
	owner     *types.PublicKey
	fp        *types.PublicKey
	rbh       *types.Hash
	dna       *types.PublicKey
}

func (r *ContextStateVerifyZeroCiphertextRequest) ValidateRequest() error {
	var err error

	if r.proofData, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.ProofData), core.ZeroCiphertextProofDataLen); err != nil {
		return errors.New("proof_data: " + err.Error())
	}
	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyZeroCiphertextRequest) ToProofData() []byte { return r.proofData }
func (r *ContextStateVerifyZeroCiphertextRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateVerifyZeroCiphertextRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.owner
}
func (r *ContextStateVerifyZeroCiphertextRequest) FeePayerKey() *types.PublicKey { return r.fp }
func (r *ContextStateVerifyZeroCiphertextRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *ContextStateVerifyZeroCiphertextRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyZeroCiphertextResponse reports the built transaction.
type ContextStateVerifyZeroCiphertextResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyZeroCiphertextResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount, contextStateAccountOwner *types.PublicKey,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateVerifyZeroCiphertextResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyZeroCiphertextResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyCiphertextCiphertextEqualityRequest verifies a CiphertextCiphertextEquality proof and persists its
// context into an existing context-state account -- ZkElgamalProof
// opcode VerifyCiphertextCiphertextEquality, context-state form. contextStateAccount must
// already exist, sized and owned for this proof type (see
// context-state/create/ciphertext-ciphertext-equality).
type ContextStateVerifyCiphertextCiphertextEqualityRequest struct {
	// ProofData is the full CiphertextCiphertextEqualityProofData wire bytes (context then
	// proof), base58-encoded, packed by the caller exactly as the
	// deployed program's VerifyCiphertextCiphertextEquality instruction expects -- no from-scratch
	// prover exists in this codebase for this proof type yet.
	ProofData string `json:"proof_data" example:""`

	// ContextStateAccount already exists, created via
	// context-state/create/ciphertext-ciphertext-equality.
	ContextStateAccount string `json:"context_state_account" example:""`

	// ContextStateAccountOwner is recorded as the context's owner --
	// the key context-state/close will later require a signature from
	// to reclaim this account's rent. It does not sign here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofData []byte
	csa       *types.PublicKey
	owner     *types.PublicKey
	fp        *types.PublicKey
	rbh       *types.Hash
	dna       *types.PublicKey
}

func (r *ContextStateVerifyCiphertextCiphertextEqualityRequest) ValidateRequest() error {
	var err error

	if r.proofData, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.ProofData), core.CiphertextCiphertextEqualityProofDataLen); err != nil {
		return errors.New("proof_data: " + err.Error())
	}
	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyCiphertextCiphertextEqualityRequest) ToProofData() []byte {
	return r.proofData
}
func (r *ContextStateVerifyCiphertextCiphertextEqualityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateVerifyCiphertextCiphertextEqualityRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.owner
}
func (r *ContextStateVerifyCiphertextCiphertextEqualityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateVerifyCiphertextCiphertextEqualityRequest) Blockhash() *types.Hash { return r.rbh }
func (r *ContextStateVerifyCiphertextCiphertextEqualityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyCiphertextCiphertextEqualityResponse reports the built transaction.
type ContextStateVerifyCiphertextCiphertextEqualityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyCiphertextCiphertextEqualityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount, contextStateAccountOwner *types.PublicKey,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateVerifyCiphertextCiphertextEqualityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyCiphertextCiphertextEqualityResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyPercentageWithCapRequest verifies a PercentageWithCap proof and persists its
// context into an existing context-state account -- ZkElgamalProof
// opcode VerifyPercentageWithCap, context-state form. contextStateAccount must
// already exist, sized and owned for this proof type (see
// context-state/create/percentage-with-cap).
type ContextStateVerifyPercentageWithCapRequest struct {
	// ProofData is the full PercentageWithCapProofData wire bytes (context then
	// proof), base58-encoded, packed by the caller exactly as the
	// deployed program's VerifyPercentageWithCap instruction expects -- no from-scratch
	// prover exists in this codebase for this proof type yet.
	ProofData string `json:"proof_data" example:""`

	// ContextStateAccount already exists, created via
	// context-state/create/percentage-with-cap.
	ContextStateAccount string `json:"context_state_account" example:""`

	// ContextStateAccountOwner is recorded as the context's owner --
	// the key context-state/close will later require a signature from
	// to reclaim this account's rent. It does not sign here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofData []byte
	csa       *types.PublicKey
	owner     *types.PublicKey
	fp        *types.PublicKey
	rbh       *types.Hash
	dna       *types.PublicKey
}

func (r *ContextStateVerifyPercentageWithCapRequest) ValidateRequest() error {
	var err error

	if r.proofData, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.ProofData), core.PercentageWithCapProofDataLen); err != nil {
		return errors.New("proof_data: " + err.Error())
	}
	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyPercentageWithCapRequest) ToProofData() []byte { return r.proofData }
func (r *ContextStateVerifyPercentageWithCapRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateVerifyPercentageWithCapRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.owner
}
func (r *ContextStateVerifyPercentageWithCapRequest) FeePayerKey() *types.PublicKey { return r.fp }
func (r *ContextStateVerifyPercentageWithCapRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *ContextStateVerifyPercentageWithCapRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyPercentageWithCapResponse reports the built transaction.
type ContextStateVerifyPercentageWithCapResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyPercentageWithCapResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount, contextStateAccountOwner *types.PublicKey,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateVerifyPercentageWithCapResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyPercentageWithCapResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyBatchedRangeProofU64Request verifies a BatchedRangeProofU64 proof and persists its
// context into an existing context-state account -- ZkElgamalProof
// opcode VerifyBatchedRangeProofU64, context-state form. contextStateAccount must
// already exist, sized and owned for this proof type (see
// context-state/create/batched-range-proof-u64).
type ContextStateVerifyBatchedRangeProofU64Request struct {
	// ProofData is the full BatchedRangeProofU64ProofData wire bytes (context then
	// proof), base58-encoded, packed by the caller exactly as the
	// deployed program's VerifyBatchedRangeProofU64 instruction expects -- no from-scratch
	// prover exists in this codebase for this proof type yet.
	ProofData string `json:"proof_data" example:""`

	// ContextStateAccount already exists, created via
	// context-state/create/batched-range-proof-u64.
	ContextStateAccount string `json:"context_state_account" example:""`

	// ContextStateAccountOwner is recorded as the context's owner --
	// the key context-state/close will later require a signature from
	// to reclaim this account's rent. It does not sign here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofData []byte
	csa       *types.PublicKey
	owner     *types.PublicKey
	fp        *types.PublicKey
	rbh       *types.Hash
	dna       *types.PublicKey
}

func (r *ContextStateVerifyBatchedRangeProofU64Request) ValidateRequest() error {
	var err error

	if r.proofData, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.ProofData), core.BatchedRangeProofU64ProofDataLen); err != nil {
		return errors.New("proof_data: " + err.Error())
	}
	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyBatchedRangeProofU64Request) ToProofData() []byte { return r.proofData }
func (r *ContextStateVerifyBatchedRangeProofU64Request) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateVerifyBatchedRangeProofU64Request) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.owner
}
func (r *ContextStateVerifyBatchedRangeProofU64Request) FeePayerKey() *types.PublicKey { return r.fp }
func (r *ContextStateVerifyBatchedRangeProofU64Request) Blockhash() *types.Hash        { return r.rbh }
func (r *ContextStateVerifyBatchedRangeProofU64Request) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyBatchedRangeProofU64Response reports the built transaction.
type ContextStateVerifyBatchedRangeProofU64Response struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyBatchedRangeProofU64Response(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount, contextStateAccountOwner *types.PublicKey,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateVerifyBatchedRangeProofU64Response {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyBatchedRangeProofU64Response{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyBatchedRangeProofU256Request verifies a BatchedRangeProofU256 proof and persists its
// context into an existing context-state account -- ZkElgamalProof
// opcode VerifyBatchedRangeProofU256, context-state form. contextStateAccount must
// already exist, sized and owned for this proof type (see
// context-state/create/batched-range-proof-u256).
type ContextStateVerifyBatchedRangeProofU256Request struct {
	// ProofData is the full BatchedRangeProofU256ProofData wire bytes (context then
	// proof), base58-encoded, packed by the caller exactly as the
	// deployed program's VerifyBatchedRangeProofU256 instruction expects -- no from-scratch
	// prover exists in this codebase for this proof type yet.
	ProofData string `json:"proof_data" example:""`

	// ContextStateAccount already exists, created via
	// context-state/create/batched-range-proof-u256.
	ContextStateAccount string `json:"context_state_account" example:""`

	// ContextStateAccountOwner is recorded as the context's owner --
	// the key context-state/close will later require a signature from
	// to reclaim this account's rent. It does not sign here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofData []byte
	csa       *types.PublicKey
	owner     *types.PublicKey
	fp        *types.PublicKey
	rbh       *types.Hash
	dna       *types.PublicKey
}

func (r *ContextStateVerifyBatchedRangeProofU256Request) ValidateRequest() error {
	var err error

	if r.proofData, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.ProofData), core.BatchedRangeProofU256ProofDataLen); err != nil {
		return errors.New("proof_data: " + err.Error())
	}
	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyBatchedRangeProofU256Request) ToProofData() []byte { return r.proofData }
func (r *ContextStateVerifyBatchedRangeProofU256Request) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateVerifyBatchedRangeProofU256Request) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.owner
}
func (r *ContextStateVerifyBatchedRangeProofU256Request) FeePayerKey() *types.PublicKey { return r.fp }
func (r *ContextStateVerifyBatchedRangeProofU256Request) Blockhash() *types.Hash        { return r.rbh }
func (r *ContextStateVerifyBatchedRangeProofU256Request) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyBatchedRangeProofU256Response reports the built transaction.
type ContextStateVerifyBatchedRangeProofU256Response struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyBatchedRangeProofU256Response(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount, contextStateAccountOwner *types.PublicKey,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateVerifyBatchedRangeProofU256Response {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyBatchedRangeProofU256Response{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyGroupedCiphertext2HandlesValidityRequest verifies a GroupedCiphertext2HandlesValidity proof and persists its
// context into an existing context-state account -- ZkElgamalProof
// opcode VerifyGroupedCiphertext2HandlesValidity, context-state form. contextStateAccount must
// already exist, sized and owned for this proof type (see
// context-state/create/grouped-ciphertext-2-handles-validity).
type ContextStateVerifyGroupedCiphertext2HandlesValidityRequest struct {
	// ProofData is the full GroupedCiphertext2HandlesValidityProofData wire bytes (context then
	// proof), base58-encoded, packed by the caller exactly as the
	// deployed program's VerifyGroupedCiphertext2HandlesValidity instruction expects -- no from-scratch
	// prover exists in this codebase for this proof type yet.
	ProofData string `json:"proof_data" example:""`

	// ContextStateAccount already exists, created via
	// context-state/create/grouped-ciphertext-2-handles-validity.
	ContextStateAccount string `json:"context_state_account" example:""`

	// ContextStateAccountOwner is recorded as the context's owner --
	// the key context-state/close will later require a signature from
	// to reclaim this account's rent. It does not sign here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofData []byte
	csa       *types.PublicKey
	owner     *types.PublicKey
	fp        *types.PublicKey
	rbh       *types.Hash
	dna       *types.PublicKey
}

func (r *ContextStateVerifyGroupedCiphertext2HandlesValidityRequest) ValidateRequest() error {
	var err error

	if r.proofData, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.ProofData), core.GroupedCiphertext2HandlesValidityProofDataLen); err != nil {
		return errors.New("proof_data: " + err.Error())
	}
	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyGroupedCiphertext2HandlesValidityRequest) ToProofData() []byte {
	return r.proofData
}
func (r *ContextStateVerifyGroupedCiphertext2HandlesValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateVerifyGroupedCiphertext2HandlesValidityRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.owner
}
func (r *ContextStateVerifyGroupedCiphertext2HandlesValidityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateVerifyGroupedCiphertext2HandlesValidityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateVerifyGroupedCiphertext2HandlesValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyGroupedCiphertext2HandlesValidityResponse reports the built transaction.
type ContextStateVerifyGroupedCiphertext2HandlesValidityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyGroupedCiphertext2HandlesValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount, contextStateAccountOwner *types.PublicKey,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateVerifyGroupedCiphertext2HandlesValidityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyGroupedCiphertext2HandlesValidityResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyBatchedGroupedCiphertext2HandlesValidityRequest verifies a BatchedGroupedCiphertext2HandlesValidity proof and persists its
// context into an existing context-state account -- ZkElgamalProof
// opcode VerifyBatchedGroupedCiphertext2HandlesValidity, context-state form. contextStateAccount must
// already exist, sized and owned for this proof type (see
// context-state/create/batched-grouped-ciphertext-2-handles-validity).
type ContextStateVerifyBatchedGroupedCiphertext2HandlesValidityRequest struct {
	// ProofData is the full BatchedGroupedCiphertext2HandlesValidityProofData wire bytes (context then
	// proof), base58-encoded, packed by the caller exactly as the
	// deployed program's VerifyBatchedGroupedCiphertext2HandlesValidity instruction expects -- no from-scratch
	// prover exists in this codebase for this proof type yet.
	ProofData string `json:"proof_data" example:""`

	// ContextStateAccount already exists, created via
	// context-state/create/batched-grouped-ciphertext-2-handles-validity.
	ContextStateAccount string `json:"context_state_account" example:""`

	// ContextStateAccountOwner is recorded as the context's owner --
	// the key context-state/close will later require a signature from
	// to reclaim this account's rent. It does not sign here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofData []byte
	csa       *types.PublicKey
	owner     *types.PublicKey
	fp        *types.PublicKey
	rbh       *types.Hash
	dna       *types.PublicKey
}

func (r *ContextStateVerifyBatchedGroupedCiphertext2HandlesValidityRequest) ValidateRequest() error {
	var err error

	if r.proofData, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.ProofData), core.BatchedGroupedCiphertext2HandlesValidityProofDataLen); err != nil {
		return errors.New("proof_data: " + err.Error())
	}
	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyBatchedGroupedCiphertext2HandlesValidityRequest) ToProofData() []byte {
	return r.proofData
}
func (r *ContextStateVerifyBatchedGroupedCiphertext2HandlesValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateVerifyBatchedGroupedCiphertext2HandlesValidityRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.owner
}
func (r *ContextStateVerifyBatchedGroupedCiphertext2HandlesValidityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateVerifyBatchedGroupedCiphertext2HandlesValidityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateVerifyBatchedGroupedCiphertext2HandlesValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyBatchedGroupedCiphertext2HandlesValidityResponse reports the built transaction.
type ContextStateVerifyBatchedGroupedCiphertext2HandlesValidityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyBatchedGroupedCiphertext2HandlesValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount, contextStateAccountOwner *types.PublicKey,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateVerifyBatchedGroupedCiphertext2HandlesValidityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyBatchedGroupedCiphertext2HandlesValidityResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyGroupedCiphertext3HandlesValidityRequest verifies a GroupedCiphertext3HandlesValidity proof and persists its
// context into an existing context-state account -- ZkElgamalProof
// opcode VerifyGroupedCiphertext3HandlesValidity, context-state form. contextStateAccount must
// already exist, sized and owned for this proof type (see
// context-state/create/grouped-ciphertext-3-handles-validity).
type ContextStateVerifyGroupedCiphertext3HandlesValidityRequest struct {
	// ProofData is the full GroupedCiphertext3HandlesValidityProofData wire bytes (context then
	// proof), base58-encoded, packed by the caller exactly as the
	// deployed program's VerifyGroupedCiphertext3HandlesValidity instruction expects -- no from-scratch
	// prover exists in this codebase for this proof type yet.
	ProofData string `json:"proof_data" example:""`

	// ContextStateAccount already exists, created via
	// context-state/create/grouped-ciphertext-3-handles-validity.
	ContextStateAccount string `json:"context_state_account" example:""`

	// ContextStateAccountOwner is recorded as the context's owner --
	// the key context-state/close will later require a signature from
	// to reclaim this account's rent. It does not sign here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofData []byte
	csa       *types.PublicKey
	owner     *types.PublicKey
	fp        *types.PublicKey
	rbh       *types.Hash
	dna       *types.PublicKey
}

func (r *ContextStateVerifyGroupedCiphertext3HandlesValidityRequest) ValidateRequest() error {
	var err error

	if r.proofData, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.ProofData), core.GroupedCiphertext3HandlesValidityProofDataLen); err != nil {
		return errors.New("proof_data: " + err.Error())
	}
	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyGroupedCiphertext3HandlesValidityRequest) ToProofData() []byte {
	return r.proofData
}
func (r *ContextStateVerifyGroupedCiphertext3HandlesValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateVerifyGroupedCiphertext3HandlesValidityRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.owner
}
func (r *ContextStateVerifyGroupedCiphertext3HandlesValidityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateVerifyGroupedCiphertext3HandlesValidityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateVerifyGroupedCiphertext3HandlesValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyGroupedCiphertext3HandlesValidityResponse reports the built transaction.
type ContextStateVerifyGroupedCiphertext3HandlesValidityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyGroupedCiphertext3HandlesValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount, contextStateAccountOwner *types.PublicKey,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateVerifyGroupedCiphertext3HandlesValidityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyGroupedCiphertext3HandlesValidityResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateCloseRequest closes a context-state account and reclaims its
// rent -- ZkElgamalProof CloseContextState. One endpoint serves every proof
// type: the instruction takes the same three accounts whatever proof the
// account holds.
type ContextStateCloseRequest struct {
	// ContextStateAccount is closed. It must be owned by the ZkElgamalProof
	// program and its recorded authority must be ContextStateAccountOwner.
	ContextStateAccount string `json:"context_state_account" example:""`

	// Destination receives the account's lamports.
	Destination string `json:"destination" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// ContextStateAccountOwner is the authority recorded when the account
	// was verified into (see context-state/verify). It signs.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	csa   *types.PublicKey
	dest  *types.PublicKey
	owner *types.PublicKey
	fp    *types.PublicKey
	rbh   *types.Hash
	dna   *types.PublicKey
}

func (r *ContextStateCloseRequest) ValidateRequest() error {
	var err error

	if r.csa, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.dest, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Destination)); err != nil {
		return errors.New("destination: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateCloseRequest) ContextStateAccountKey() *types.PublicKey { return r.csa }
func (r *ContextStateCloseRequest) DestinationKey() *types.PublicKey         { return r.dest }
func (r *ContextStateCloseRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.owner
}
func (r *ContextStateCloseRequest) FeePayerKey() *types.PublicKey { return r.fp }
func (r *ContextStateCloseRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *ContextStateCloseRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCloseResponse reports the built transaction.
type ContextStateCloseResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ContextStateAccount      string `json:"context_state_account"`
	Destination              string `json:"destination"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`
	ReclaimedLamports        uint64 `json:"reclaimed_lamports"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateCloseResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount, destination, contextStateAccountOwner, nonceAuthority *types.PublicKey,
	reclaimedLamports, fee uint64,
) *ContextStateCloseResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateCloseResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ContextStateAccount:      contextStateAccount.Base58(),
		Destination:              destination.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		ReclaimedLamports:        reclaimedLamports,
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyFromAccountPubkeyValidityRequest verifies a PubkeyValidity proof already written into an account, and persists its
// context into an existing context-state account -- the proof-in-account form of
// context-state/verify/pubkey-validity, for a proof too large to carry in one
// transaction. The instruction data is five bytes (a discriminator and a u32
// offset) however large the proof is.
type ContextStateVerifyFromAccountPubkeyValidityRequest struct {
	// ProofAccount holds the proof data, already written (for example with
	// record/write). Nothing checks who owns it -- the program only reads the
	// bytes -- but it has to be large enough to hold offset plus the proof.
	ProofAccount string `json:"proof_account" example:""`
	// ProofOffset is where the proof data starts within ProofAccount's data, up to
	// 4294967295. For a record account that is 33 plus wherever the proof was
	// written, so 33 for a proof written from offset 0.
	ProofOffset string `json:"proof_offset" example:""`
	// ContextStateAccount already exists, created via context-state/create.
	ContextStateAccount string `json:"context_state_account" example:""`
	// ContextStateAccountOwner is recorded as the context's owner -- the key
	// context-state/close will later require a signature from. It does not sign
	// here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// ComputeUnitLimit is the compute-unit limit the transaction is given, in
	// a ComputeBudget SetComputeUnitLimit instruction placed ahead of the
	// verify. The ZkElgamalProof program charges a fixed cost per proof
	// type before it verifies anything (range u128 costs the entire default
	// 200,000 and u256 costs 368,000), so without a raised limit the larger
	// proofs fail with ComputationalBudgetExceeded. Left empty or zero it is
	// this proof type's own cost plus a margin, rounded up to the next
	// thousand. It cannot exceed 1,400,000, the most a transaction may have.
	ComputeUnitLimit uint32 `json:"compute_unit_limit" example:"0"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofAccount             *types.PublicKey
	proofOffset              uint64
	contextStateAccount      *types.PublicKey
	contextStateAccountOwner *types.PublicKey
	fp                       *types.PublicKey
	rbh                      *types.Hash
	dna                      *types.PublicKey
}

func (r *ContextStateVerifyFromAccountPubkeyValidityRequest) ValidateRequest() error {
	var err error

	if r.proofAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ProofAccount)); err != nil {
		return errors.New("proof_account: " + err.Error())
	}
	if v := strings.TrimSpace(r.ProofOffset); v == "" {
		return errors.New("proof_offset is required")
	} else if r.proofOffset, err = strconv.ParseUint(v, 10, 64); err != nil {
		return errors.New("proof_offset: " + err.Error())
	}
	if r.contextStateAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.contextStateAccountOwner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.ComputeUnitLimit > 1_400_000 {
		return errors.New("compute_unit_limit: exceeds 1400000, the most a transaction may have")
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyFromAccountPubkeyValidityRequest) ProofAccountKey() *types.PublicKey {
	return r.proofAccount
}
func (r *ContextStateVerifyFromAccountPubkeyValidityRequest) ToProofOffset() uint64 {
	return r.proofOffset
}
func (r *ContextStateVerifyFromAccountPubkeyValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.contextStateAccount
}
func (r *ContextStateVerifyFromAccountPubkeyValidityRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.contextStateAccountOwner
}
func (r *ContextStateVerifyFromAccountPubkeyValidityRequest) ToComputeUnitLimit() uint32 {
	return r.ComputeUnitLimit
}
func (r *ContextStateVerifyFromAccountPubkeyValidityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateVerifyFromAccountPubkeyValidityRequest) Blockhash() *types.Hash { return r.rbh }
func (r *ContextStateVerifyFromAccountPubkeyValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyFromAccountPubkeyValidityResponse reports the built transaction.
type ContextStateVerifyFromAccountPubkeyValidityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ProofAccount             string `json:"proof_account"`
	ProofOffset              string `json:"proof_offset"`
	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyFromAccountPubkeyValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	proofAccount *types.PublicKey, proofOffset uint64, contextStateAccount *types.PublicKey, contextStateAccountOwner *types.PublicKey,
	fee uint64,
) *ContextStateVerifyFromAccountPubkeyValidityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyFromAccountPubkeyValidityResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ProofAccount:             proofAccount.Base58(),
		ProofOffset:              strconv.FormatUint(proofOffset, 10),
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyFromAccountCiphertextCommitmentEqualityRequest verifies a CiphertextCommitmentEquality proof already written into an account, and persists its
// context into an existing context-state account -- the proof-in-account form of
// context-state/verify/ciphertext-commitment-equality, for a proof too large to carry in one
// transaction. The instruction data is five bytes (a discriminator and a u32
// offset) however large the proof is.
type ContextStateVerifyFromAccountCiphertextCommitmentEqualityRequest struct {
	// ProofAccount holds the proof data, already written (for example with
	// record/write). Nothing checks who owns it -- the program only reads the
	// bytes -- but it has to be large enough to hold offset plus the proof.
	ProofAccount string `json:"proof_account" example:""`
	// ProofOffset is where the proof data starts within ProofAccount's data, up to
	// 4294967295. For a record account that is 33 plus wherever the proof was
	// written, so 33 for a proof written from offset 0.
	ProofOffset string `json:"proof_offset" example:""`
	// ContextStateAccount already exists, created via context-state/create.
	ContextStateAccount string `json:"context_state_account" example:""`
	// ContextStateAccountOwner is recorded as the context's owner -- the key
	// context-state/close will later require a signature from. It does not sign
	// here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// ComputeUnitLimit is the compute-unit limit the transaction is given, in
	// a ComputeBudget SetComputeUnitLimit instruction placed ahead of the
	// verify. The ZkElgamalProof program charges a fixed cost per proof
	// type before it verifies anything (range u128 costs the entire default
	// 200,000 and u256 costs 368,000), so without a raised limit the larger
	// proofs fail with ComputationalBudgetExceeded. Left empty or zero it is
	// this proof type's own cost plus a margin, rounded up to the next
	// thousand. It cannot exceed 1,400,000, the most a transaction may have.
	ComputeUnitLimit uint32 `json:"compute_unit_limit" example:"0"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofAccount             *types.PublicKey
	proofOffset              uint64
	contextStateAccount      *types.PublicKey
	contextStateAccountOwner *types.PublicKey
	fp                       *types.PublicKey
	rbh                      *types.Hash
	dna                      *types.PublicKey
}

func (r *ContextStateVerifyFromAccountCiphertextCommitmentEqualityRequest) ValidateRequest() error {
	var err error

	if r.proofAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ProofAccount)); err != nil {
		return errors.New("proof_account: " + err.Error())
	}
	if v := strings.TrimSpace(r.ProofOffset); v == "" {
		return errors.New("proof_offset is required")
	} else if r.proofOffset, err = strconv.ParseUint(v, 10, 64); err != nil {
		return errors.New("proof_offset: " + err.Error())
	}
	if r.contextStateAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.contextStateAccountOwner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.ComputeUnitLimit > 1_400_000 {
		return errors.New("compute_unit_limit: exceeds 1400000, the most a transaction may have")
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyFromAccountCiphertextCommitmentEqualityRequest) ProofAccountKey() *types.PublicKey {
	return r.proofAccount
}
func (r *ContextStateVerifyFromAccountCiphertextCommitmentEqualityRequest) ToProofOffset() uint64 {
	return r.proofOffset
}
func (r *ContextStateVerifyFromAccountCiphertextCommitmentEqualityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.contextStateAccount
}
func (r *ContextStateVerifyFromAccountCiphertextCommitmentEqualityRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.contextStateAccountOwner
}
func (r *ContextStateVerifyFromAccountCiphertextCommitmentEqualityRequest) ToComputeUnitLimit() uint32 {
	return r.ComputeUnitLimit
}
func (r *ContextStateVerifyFromAccountCiphertextCommitmentEqualityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateVerifyFromAccountCiphertextCommitmentEqualityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateVerifyFromAccountCiphertextCommitmentEqualityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyFromAccountCiphertextCommitmentEqualityResponse reports the built transaction.
type ContextStateVerifyFromAccountCiphertextCommitmentEqualityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ProofAccount             string `json:"proof_account"`
	ProofOffset              string `json:"proof_offset"`
	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyFromAccountCiphertextCommitmentEqualityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	proofAccount *types.PublicKey, proofOffset uint64, contextStateAccount *types.PublicKey, contextStateAccountOwner *types.PublicKey,
	fee uint64,
) *ContextStateVerifyFromAccountCiphertextCommitmentEqualityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyFromAccountCiphertextCommitmentEqualityResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ProofAccount:             proofAccount.Base58(),
		ProofOffset:              strconv.FormatUint(proofOffset, 10),
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyFromAccountBatchedGroupedCiphertext3HandlesValidityRequest verifies a BatchedGroupedCiphertext3HandlesValidity proof already written into an account, and persists its
// context into an existing context-state account -- the proof-in-account form of
// context-state/verify/batched-grouped-ciphertext-3-handles-validity, for a proof too large to carry in one
// transaction. The instruction data is five bytes (a discriminator and a u32
// offset) however large the proof is.
type ContextStateVerifyFromAccountBatchedGroupedCiphertext3HandlesValidityRequest struct {
	// ProofAccount holds the proof data, already written (for example with
	// record/write). Nothing checks who owns it -- the program only reads the
	// bytes -- but it has to be large enough to hold offset plus the proof.
	ProofAccount string `json:"proof_account" example:""`
	// ProofOffset is where the proof data starts within ProofAccount's data, up to
	// 4294967295. For a record account that is 33 plus wherever the proof was
	// written, so 33 for a proof written from offset 0.
	ProofOffset string `json:"proof_offset" example:""`
	// ContextStateAccount already exists, created via context-state/create.
	ContextStateAccount string `json:"context_state_account" example:""`
	// ContextStateAccountOwner is recorded as the context's owner -- the key
	// context-state/close will later require a signature from. It does not sign
	// here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// ComputeUnitLimit is the compute-unit limit the transaction is given, in
	// a ComputeBudget SetComputeUnitLimit instruction placed ahead of the
	// verify. The ZkElgamalProof program charges a fixed cost per proof
	// type before it verifies anything (range u128 costs the entire default
	// 200,000 and u256 costs 368,000), so without a raised limit the larger
	// proofs fail with ComputationalBudgetExceeded. Left empty or zero it is
	// this proof type's own cost plus a margin, rounded up to the next
	// thousand. It cannot exceed 1,400,000, the most a transaction may have.
	ComputeUnitLimit uint32 `json:"compute_unit_limit" example:"0"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofAccount             *types.PublicKey
	proofOffset              uint64
	contextStateAccount      *types.PublicKey
	contextStateAccountOwner *types.PublicKey
	fp                       *types.PublicKey
	rbh                      *types.Hash
	dna                      *types.PublicKey
}

func (r *ContextStateVerifyFromAccountBatchedGroupedCiphertext3HandlesValidityRequest) ValidateRequest() error {
	var err error

	if r.proofAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ProofAccount)); err != nil {
		return errors.New("proof_account: " + err.Error())
	}
	if v := strings.TrimSpace(r.ProofOffset); v == "" {
		return errors.New("proof_offset is required")
	} else if r.proofOffset, err = strconv.ParseUint(v, 10, 64); err != nil {
		return errors.New("proof_offset: " + err.Error())
	}
	if r.contextStateAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.contextStateAccountOwner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.ComputeUnitLimit > 1_400_000 {
		return errors.New("compute_unit_limit: exceeds 1400000, the most a transaction may have")
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyFromAccountBatchedGroupedCiphertext3HandlesValidityRequest) ProofAccountKey() *types.PublicKey {
	return r.proofAccount
}
func (r *ContextStateVerifyFromAccountBatchedGroupedCiphertext3HandlesValidityRequest) ToProofOffset() uint64 {
	return r.proofOffset
}
func (r *ContextStateVerifyFromAccountBatchedGroupedCiphertext3HandlesValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.contextStateAccount
}
func (r *ContextStateVerifyFromAccountBatchedGroupedCiphertext3HandlesValidityRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.contextStateAccountOwner
}
func (r *ContextStateVerifyFromAccountBatchedGroupedCiphertext3HandlesValidityRequest) ToComputeUnitLimit() uint32 {
	return r.ComputeUnitLimit
}
func (r *ContextStateVerifyFromAccountBatchedGroupedCiphertext3HandlesValidityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateVerifyFromAccountBatchedGroupedCiphertext3HandlesValidityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateVerifyFromAccountBatchedGroupedCiphertext3HandlesValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyFromAccountBatchedGroupedCiphertext3HandlesValidityResponse reports the built transaction.
type ContextStateVerifyFromAccountBatchedGroupedCiphertext3HandlesValidityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ProofAccount             string `json:"proof_account"`
	ProofOffset              string `json:"proof_offset"`
	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyFromAccountBatchedGroupedCiphertext3HandlesValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	proofAccount *types.PublicKey, proofOffset uint64, contextStateAccount *types.PublicKey, contextStateAccountOwner *types.PublicKey,
	fee uint64,
) *ContextStateVerifyFromAccountBatchedGroupedCiphertext3HandlesValidityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyFromAccountBatchedGroupedCiphertext3HandlesValidityResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ProofAccount:             proofAccount.Base58(),
		ProofOffset:              strconv.FormatUint(proofOffset, 10),
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyFromAccountBatchedRangeProofU128Request verifies a BatchedRangeProofU128 proof already written into an account, and persists its
// context into an existing context-state account -- the proof-in-account form of
// context-state/verify/batched-range-proof-u128, for a proof too large to carry in one
// transaction. The instruction data is five bytes (a discriminator and a u32
// offset) however large the proof is.
type ContextStateVerifyFromAccountBatchedRangeProofU128Request struct {
	// ProofAccount holds the proof data, already written (for example with
	// record/write). Nothing checks who owns it -- the program only reads the
	// bytes -- but it has to be large enough to hold offset plus the proof.
	ProofAccount string `json:"proof_account" example:""`
	// ProofOffset is where the proof data starts within ProofAccount's data, up to
	// 4294967295. For a record account that is 33 plus wherever the proof was
	// written, so 33 for a proof written from offset 0.
	ProofOffset string `json:"proof_offset" example:""`
	// ContextStateAccount already exists, created via context-state/create.
	ContextStateAccount string `json:"context_state_account" example:""`
	// ContextStateAccountOwner is recorded as the context's owner -- the key
	// context-state/close will later require a signature from. It does not sign
	// here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// ComputeUnitLimit is the compute-unit limit the transaction is given, in
	// a ComputeBudget SetComputeUnitLimit instruction placed ahead of the
	// verify. The ZkElgamalProof program charges a fixed cost per proof
	// type before it verifies anything (range u128 costs the entire default
	// 200,000 and u256 costs 368,000), so without a raised limit the larger
	// proofs fail with ComputationalBudgetExceeded. Left empty or zero it is
	// this proof type's own cost plus a margin, rounded up to the next
	// thousand. It cannot exceed 1,400,000, the most a transaction may have.
	ComputeUnitLimit uint32 `json:"compute_unit_limit" example:"0"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofAccount             *types.PublicKey
	proofOffset              uint64
	contextStateAccount      *types.PublicKey
	contextStateAccountOwner *types.PublicKey
	fp                       *types.PublicKey
	rbh                      *types.Hash
	dna                      *types.PublicKey
}

func (r *ContextStateVerifyFromAccountBatchedRangeProofU128Request) ValidateRequest() error {
	var err error

	if r.proofAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ProofAccount)); err != nil {
		return errors.New("proof_account: " + err.Error())
	}
	if v := strings.TrimSpace(r.ProofOffset); v == "" {
		return errors.New("proof_offset is required")
	} else if r.proofOffset, err = strconv.ParseUint(v, 10, 64); err != nil {
		return errors.New("proof_offset: " + err.Error())
	}
	if r.contextStateAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.contextStateAccountOwner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.ComputeUnitLimit > 1_400_000 {
		return errors.New("compute_unit_limit: exceeds 1400000, the most a transaction may have")
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyFromAccountBatchedRangeProofU128Request) ProofAccountKey() *types.PublicKey {
	return r.proofAccount
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU128Request) ToProofOffset() uint64 {
	return r.proofOffset
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU128Request) ContextStateAccountKey() *types.PublicKey {
	return r.contextStateAccount
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU128Request) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.contextStateAccountOwner
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU128Request) ToComputeUnitLimit() uint32 {
	return r.ComputeUnitLimit
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU128Request) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU128Request) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU128Request) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyFromAccountBatchedRangeProofU128Response reports the built transaction.
type ContextStateVerifyFromAccountBatchedRangeProofU128Response struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ProofAccount             string `json:"proof_account"`
	ProofOffset              string `json:"proof_offset"`
	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyFromAccountBatchedRangeProofU128Response(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	proofAccount *types.PublicKey, proofOffset uint64, contextStateAccount *types.PublicKey, contextStateAccountOwner *types.PublicKey,
	fee uint64,
) *ContextStateVerifyFromAccountBatchedRangeProofU128Response {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyFromAccountBatchedRangeProofU128Response{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ProofAccount:             proofAccount.Base58(),
		ProofOffset:              strconv.FormatUint(proofOffset, 10),
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyFromAccountZeroCiphertextRequest verifies a ZeroCiphertext proof already written into an account, and persists its
// context into an existing context-state account -- the proof-in-account form of
// context-state/verify/zero-ciphertext, for a proof too large to carry in one
// transaction. The instruction data is five bytes (a discriminator and a u32
// offset) however large the proof is.
type ContextStateVerifyFromAccountZeroCiphertextRequest struct {
	// ProofAccount holds the proof data, already written (for example with
	// record/write). Nothing checks who owns it -- the program only reads the
	// bytes -- but it has to be large enough to hold offset plus the proof.
	ProofAccount string `json:"proof_account" example:""`
	// ProofOffset is where the proof data starts within ProofAccount's data, up to
	// 4294967295. For a record account that is 33 plus wherever the proof was
	// written, so 33 for a proof written from offset 0.
	ProofOffset string `json:"proof_offset" example:""`
	// ContextStateAccount already exists, created via context-state/create.
	ContextStateAccount string `json:"context_state_account" example:""`
	// ContextStateAccountOwner is recorded as the context's owner -- the key
	// context-state/close will later require a signature from. It does not sign
	// here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// ComputeUnitLimit is the compute-unit limit the transaction is given, in
	// a ComputeBudget SetComputeUnitLimit instruction placed ahead of the
	// verify. The ZkElgamalProof program charges a fixed cost per proof
	// type before it verifies anything (range u128 costs the entire default
	// 200,000 and u256 costs 368,000), so without a raised limit the larger
	// proofs fail with ComputationalBudgetExceeded. Left empty or zero it is
	// this proof type's own cost plus a margin, rounded up to the next
	// thousand. It cannot exceed 1,400,000, the most a transaction may have.
	ComputeUnitLimit uint32 `json:"compute_unit_limit" example:"0"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofAccount             *types.PublicKey
	proofOffset              uint64
	contextStateAccount      *types.PublicKey
	contextStateAccountOwner *types.PublicKey
	fp                       *types.PublicKey
	rbh                      *types.Hash
	dna                      *types.PublicKey
}

func (r *ContextStateVerifyFromAccountZeroCiphertextRequest) ValidateRequest() error {
	var err error

	if r.proofAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ProofAccount)); err != nil {
		return errors.New("proof_account: " + err.Error())
	}
	if v := strings.TrimSpace(r.ProofOffset); v == "" {
		return errors.New("proof_offset is required")
	} else if r.proofOffset, err = strconv.ParseUint(v, 10, 64); err != nil {
		return errors.New("proof_offset: " + err.Error())
	}
	if r.contextStateAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.contextStateAccountOwner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.ComputeUnitLimit > 1_400_000 {
		return errors.New("compute_unit_limit: exceeds 1400000, the most a transaction may have")
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyFromAccountZeroCiphertextRequest) ProofAccountKey() *types.PublicKey {
	return r.proofAccount
}
func (r *ContextStateVerifyFromAccountZeroCiphertextRequest) ToProofOffset() uint64 {
	return r.proofOffset
}
func (r *ContextStateVerifyFromAccountZeroCiphertextRequest) ContextStateAccountKey() *types.PublicKey {
	return r.contextStateAccount
}
func (r *ContextStateVerifyFromAccountZeroCiphertextRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.contextStateAccountOwner
}
func (r *ContextStateVerifyFromAccountZeroCiphertextRequest) ToComputeUnitLimit() uint32 {
	return r.ComputeUnitLimit
}
func (r *ContextStateVerifyFromAccountZeroCiphertextRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateVerifyFromAccountZeroCiphertextRequest) Blockhash() *types.Hash { return r.rbh }
func (r *ContextStateVerifyFromAccountZeroCiphertextRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyFromAccountZeroCiphertextResponse reports the built transaction.
type ContextStateVerifyFromAccountZeroCiphertextResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ProofAccount             string `json:"proof_account"`
	ProofOffset              string `json:"proof_offset"`
	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyFromAccountZeroCiphertextResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	proofAccount *types.PublicKey, proofOffset uint64, contextStateAccount *types.PublicKey, contextStateAccountOwner *types.PublicKey,
	fee uint64,
) *ContextStateVerifyFromAccountZeroCiphertextResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyFromAccountZeroCiphertextResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ProofAccount:             proofAccount.Base58(),
		ProofOffset:              strconv.FormatUint(proofOffset, 10),
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyFromAccountCiphertextCiphertextEqualityRequest verifies a CiphertextCiphertextEquality proof already written into an account, and persists its
// context into an existing context-state account -- the proof-in-account form of
// context-state/verify/ciphertext-ciphertext-equality, for a proof too large to carry in one
// transaction. The instruction data is five bytes (a discriminator and a u32
// offset) however large the proof is.
type ContextStateVerifyFromAccountCiphertextCiphertextEqualityRequest struct {
	// ProofAccount holds the proof data, already written (for example with
	// record/write). Nothing checks who owns it -- the program only reads the
	// bytes -- but it has to be large enough to hold offset plus the proof.
	ProofAccount string `json:"proof_account" example:""`
	// ProofOffset is where the proof data starts within ProofAccount's data, up to
	// 4294967295. For a record account that is 33 plus wherever the proof was
	// written, so 33 for a proof written from offset 0.
	ProofOffset string `json:"proof_offset" example:""`
	// ContextStateAccount already exists, created via context-state/create.
	ContextStateAccount string `json:"context_state_account" example:""`
	// ContextStateAccountOwner is recorded as the context's owner -- the key
	// context-state/close will later require a signature from. It does not sign
	// here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// ComputeUnitLimit is the compute-unit limit the transaction is given, in
	// a ComputeBudget SetComputeUnitLimit instruction placed ahead of the
	// verify. The ZkElgamalProof program charges a fixed cost per proof
	// type before it verifies anything (range u128 costs the entire default
	// 200,000 and u256 costs 368,000), so without a raised limit the larger
	// proofs fail with ComputationalBudgetExceeded. Left empty or zero it is
	// this proof type's own cost plus a margin, rounded up to the next
	// thousand. It cannot exceed 1,400,000, the most a transaction may have.
	ComputeUnitLimit uint32 `json:"compute_unit_limit" example:"0"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofAccount             *types.PublicKey
	proofOffset              uint64
	contextStateAccount      *types.PublicKey
	contextStateAccountOwner *types.PublicKey
	fp                       *types.PublicKey
	rbh                      *types.Hash
	dna                      *types.PublicKey
}

func (r *ContextStateVerifyFromAccountCiphertextCiphertextEqualityRequest) ValidateRequest() error {
	var err error

	if r.proofAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ProofAccount)); err != nil {
		return errors.New("proof_account: " + err.Error())
	}
	if v := strings.TrimSpace(r.ProofOffset); v == "" {
		return errors.New("proof_offset is required")
	} else if r.proofOffset, err = strconv.ParseUint(v, 10, 64); err != nil {
		return errors.New("proof_offset: " + err.Error())
	}
	if r.contextStateAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.contextStateAccountOwner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.ComputeUnitLimit > 1_400_000 {
		return errors.New("compute_unit_limit: exceeds 1400000, the most a transaction may have")
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyFromAccountCiphertextCiphertextEqualityRequest) ProofAccountKey() *types.PublicKey {
	return r.proofAccount
}
func (r *ContextStateVerifyFromAccountCiphertextCiphertextEqualityRequest) ToProofOffset() uint64 {
	return r.proofOffset
}
func (r *ContextStateVerifyFromAccountCiphertextCiphertextEqualityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.contextStateAccount
}
func (r *ContextStateVerifyFromAccountCiphertextCiphertextEqualityRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.contextStateAccountOwner
}
func (r *ContextStateVerifyFromAccountCiphertextCiphertextEqualityRequest) ToComputeUnitLimit() uint32 {
	return r.ComputeUnitLimit
}
func (r *ContextStateVerifyFromAccountCiphertextCiphertextEqualityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateVerifyFromAccountCiphertextCiphertextEqualityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateVerifyFromAccountCiphertextCiphertextEqualityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyFromAccountCiphertextCiphertextEqualityResponse reports the built transaction.
type ContextStateVerifyFromAccountCiphertextCiphertextEqualityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ProofAccount             string `json:"proof_account"`
	ProofOffset              string `json:"proof_offset"`
	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyFromAccountCiphertextCiphertextEqualityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	proofAccount *types.PublicKey, proofOffset uint64, contextStateAccount *types.PublicKey, contextStateAccountOwner *types.PublicKey,
	fee uint64,
) *ContextStateVerifyFromAccountCiphertextCiphertextEqualityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyFromAccountCiphertextCiphertextEqualityResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ProofAccount:             proofAccount.Base58(),
		ProofOffset:              strconv.FormatUint(proofOffset, 10),
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyFromAccountPercentageWithCapRequest verifies a PercentageWithCap proof already written into an account, and persists its
// context into an existing context-state account -- the proof-in-account form of
// context-state/verify/percentage-with-cap, for a proof too large to carry in one
// transaction. The instruction data is five bytes (a discriminator and a u32
// offset) however large the proof is.
type ContextStateVerifyFromAccountPercentageWithCapRequest struct {
	// ProofAccount holds the proof data, already written (for example with
	// record/write). Nothing checks who owns it -- the program only reads the
	// bytes -- but it has to be large enough to hold offset plus the proof.
	ProofAccount string `json:"proof_account" example:""`
	// ProofOffset is where the proof data starts within ProofAccount's data, up to
	// 4294967295. For a record account that is 33 plus wherever the proof was
	// written, so 33 for a proof written from offset 0.
	ProofOffset string `json:"proof_offset" example:""`
	// ContextStateAccount already exists, created via context-state/create.
	ContextStateAccount string `json:"context_state_account" example:""`
	// ContextStateAccountOwner is recorded as the context's owner -- the key
	// context-state/close will later require a signature from. It does not sign
	// here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// ComputeUnitLimit is the compute-unit limit the transaction is given, in
	// a ComputeBudget SetComputeUnitLimit instruction placed ahead of the
	// verify. The ZkElgamalProof program charges a fixed cost per proof
	// type before it verifies anything (range u128 costs the entire default
	// 200,000 and u256 costs 368,000), so without a raised limit the larger
	// proofs fail with ComputationalBudgetExceeded. Left empty or zero it is
	// this proof type's own cost plus a margin, rounded up to the next
	// thousand. It cannot exceed 1,400,000, the most a transaction may have.
	ComputeUnitLimit uint32 `json:"compute_unit_limit" example:"0"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofAccount             *types.PublicKey
	proofOffset              uint64
	contextStateAccount      *types.PublicKey
	contextStateAccountOwner *types.PublicKey
	fp                       *types.PublicKey
	rbh                      *types.Hash
	dna                      *types.PublicKey
}

func (r *ContextStateVerifyFromAccountPercentageWithCapRequest) ValidateRequest() error {
	var err error

	if r.proofAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ProofAccount)); err != nil {
		return errors.New("proof_account: " + err.Error())
	}
	if v := strings.TrimSpace(r.ProofOffset); v == "" {
		return errors.New("proof_offset is required")
	} else if r.proofOffset, err = strconv.ParseUint(v, 10, 64); err != nil {
		return errors.New("proof_offset: " + err.Error())
	}
	if r.contextStateAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.contextStateAccountOwner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.ComputeUnitLimit > 1_400_000 {
		return errors.New("compute_unit_limit: exceeds 1400000, the most a transaction may have")
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyFromAccountPercentageWithCapRequest) ProofAccountKey() *types.PublicKey {
	return r.proofAccount
}
func (r *ContextStateVerifyFromAccountPercentageWithCapRequest) ToProofOffset() uint64 {
	return r.proofOffset
}
func (r *ContextStateVerifyFromAccountPercentageWithCapRequest) ContextStateAccountKey() *types.PublicKey {
	return r.contextStateAccount
}
func (r *ContextStateVerifyFromAccountPercentageWithCapRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.contextStateAccountOwner
}
func (r *ContextStateVerifyFromAccountPercentageWithCapRequest) ToComputeUnitLimit() uint32 {
	return r.ComputeUnitLimit
}
func (r *ContextStateVerifyFromAccountPercentageWithCapRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateVerifyFromAccountPercentageWithCapRequest) Blockhash() *types.Hash { return r.rbh }
func (r *ContextStateVerifyFromAccountPercentageWithCapRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyFromAccountPercentageWithCapResponse reports the built transaction.
type ContextStateVerifyFromAccountPercentageWithCapResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ProofAccount             string `json:"proof_account"`
	ProofOffset              string `json:"proof_offset"`
	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyFromAccountPercentageWithCapResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	proofAccount *types.PublicKey, proofOffset uint64, contextStateAccount *types.PublicKey, contextStateAccountOwner *types.PublicKey,
	fee uint64,
) *ContextStateVerifyFromAccountPercentageWithCapResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyFromAccountPercentageWithCapResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ProofAccount:             proofAccount.Base58(),
		ProofOffset:              strconv.FormatUint(proofOffset, 10),
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyFromAccountBatchedRangeProofU64Request verifies a BatchedRangeProofU64 proof already written into an account, and persists its
// context into an existing context-state account -- the proof-in-account form of
// context-state/verify/batched-range-proof-u64, for a proof too large to carry in one
// transaction. The instruction data is five bytes (a discriminator and a u32
// offset) however large the proof is.
type ContextStateVerifyFromAccountBatchedRangeProofU64Request struct {
	// ProofAccount holds the proof data, already written (for example with
	// record/write). Nothing checks who owns it -- the program only reads the
	// bytes -- but it has to be large enough to hold offset plus the proof.
	ProofAccount string `json:"proof_account" example:""`
	// ProofOffset is where the proof data starts within ProofAccount's data, up to
	// 4294967295. For a record account that is 33 plus wherever the proof was
	// written, so 33 for a proof written from offset 0.
	ProofOffset string `json:"proof_offset" example:""`
	// ContextStateAccount already exists, created via context-state/create.
	ContextStateAccount string `json:"context_state_account" example:""`
	// ContextStateAccountOwner is recorded as the context's owner -- the key
	// context-state/close will later require a signature from. It does not sign
	// here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// ComputeUnitLimit is the compute-unit limit the transaction is given, in
	// a ComputeBudget SetComputeUnitLimit instruction placed ahead of the
	// verify. The ZkElgamalProof program charges a fixed cost per proof
	// type before it verifies anything (range u128 costs the entire default
	// 200,000 and u256 costs 368,000), so without a raised limit the larger
	// proofs fail with ComputationalBudgetExceeded. Left empty or zero it is
	// this proof type's own cost plus a margin, rounded up to the next
	// thousand. It cannot exceed 1,400,000, the most a transaction may have.
	ComputeUnitLimit uint32 `json:"compute_unit_limit" example:"0"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofAccount             *types.PublicKey
	proofOffset              uint64
	contextStateAccount      *types.PublicKey
	contextStateAccountOwner *types.PublicKey
	fp                       *types.PublicKey
	rbh                      *types.Hash
	dna                      *types.PublicKey
}

func (r *ContextStateVerifyFromAccountBatchedRangeProofU64Request) ValidateRequest() error {
	var err error

	if r.proofAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ProofAccount)); err != nil {
		return errors.New("proof_account: " + err.Error())
	}
	if v := strings.TrimSpace(r.ProofOffset); v == "" {
		return errors.New("proof_offset is required")
	} else if r.proofOffset, err = strconv.ParseUint(v, 10, 64); err != nil {
		return errors.New("proof_offset: " + err.Error())
	}
	if r.contextStateAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.contextStateAccountOwner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.ComputeUnitLimit > 1_400_000 {
		return errors.New("compute_unit_limit: exceeds 1400000, the most a transaction may have")
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyFromAccountBatchedRangeProofU64Request) ProofAccountKey() *types.PublicKey {
	return r.proofAccount
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU64Request) ToProofOffset() uint64 {
	return r.proofOffset
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU64Request) ContextStateAccountKey() *types.PublicKey {
	return r.contextStateAccount
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU64Request) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.contextStateAccountOwner
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU64Request) ToComputeUnitLimit() uint32 {
	return r.ComputeUnitLimit
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU64Request) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU64Request) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU64Request) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyFromAccountBatchedRangeProofU64Response reports the built transaction.
type ContextStateVerifyFromAccountBatchedRangeProofU64Response struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ProofAccount             string `json:"proof_account"`
	ProofOffset              string `json:"proof_offset"`
	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyFromAccountBatchedRangeProofU64Response(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	proofAccount *types.PublicKey, proofOffset uint64, contextStateAccount *types.PublicKey, contextStateAccountOwner *types.PublicKey,
	fee uint64,
) *ContextStateVerifyFromAccountBatchedRangeProofU64Response {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyFromAccountBatchedRangeProofU64Response{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ProofAccount:             proofAccount.Base58(),
		ProofOffset:              strconv.FormatUint(proofOffset, 10),
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyFromAccountBatchedRangeProofU256Request verifies a BatchedRangeProofU256 proof already written into an account, and persists its
// context into an existing context-state account -- the proof-in-account form of
// context-state/verify/batched-range-proof-u256, for a proof too large to carry in one
// transaction. The instruction data is five bytes (a discriminator and a u32
// offset) however large the proof is.
type ContextStateVerifyFromAccountBatchedRangeProofU256Request struct {
	// ProofAccount holds the proof data, already written (for example with
	// record/write). Nothing checks who owns it -- the program only reads the
	// bytes -- but it has to be large enough to hold offset plus the proof.
	ProofAccount string `json:"proof_account" example:""`
	// ProofOffset is where the proof data starts within ProofAccount's data, up to
	// 4294967295. For a record account that is 33 plus wherever the proof was
	// written, so 33 for a proof written from offset 0.
	ProofOffset string `json:"proof_offset" example:""`
	// ContextStateAccount already exists, created via context-state/create.
	ContextStateAccount string `json:"context_state_account" example:""`
	// ContextStateAccountOwner is recorded as the context's owner -- the key
	// context-state/close will later require a signature from. It does not sign
	// here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// ComputeUnitLimit is the compute-unit limit the transaction is given, in
	// a ComputeBudget SetComputeUnitLimit instruction placed ahead of the
	// verify. The ZkElgamalProof program charges a fixed cost per proof
	// type before it verifies anything (range u128 costs the entire default
	// 200,000 and u256 costs 368,000), so without a raised limit the larger
	// proofs fail with ComputationalBudgetExceeded. Left empty or zero it is
	// this proof type's own cost plus a margin, rounded up to the next
	// thousand. It cannot exceed 1,400,000, the most a transaction may have.
	ComputeUnitLimit uint32 `json:"compute_unit_limit" example:"0"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofAccount             *types.PublicKey
	proofOffset              uint64
	contextStateAccount      *types.PublicKey
	contextStateAccountOwner *types.PublicKey
	fp                       *types.PublicKey
	rbh                      *types.Hash
	dna                      *types.PublicKey
}

func (r *ContextStateVerifyFromAccountBatchedRangeProofU256Request) ValidateRequest() error {
	var err error

	if r.proofAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ProofAccount)); err != nil {
		return errors.New("proof_account: " + err.Error())
	}
	if v := strings.TrimSpace(r.ProofOffset); v == "" {
		return errors.New("proof_offset is required")
	} else if r.proofOffset, err = strconv.ParseUint(v, 10, 64); err != nil {
		return errors.New("proof_offset: " + err.Error())
	}
	if r.contextStateAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.contextStateAccountOwner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.ComputeUnitLimit > 1_400_000 {
		return errors.New("compute_unit_limit: exceeds 1400000, the most a transaction may have")
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyFromAccountBatchedRangeProofU256Request) ProofAccountKey() *types.PublicKey {
	return r.proofAccount
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU256Request) ToProofOffset() uint64 {
	return r.proofOffset
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU256Request) ContextStateAccountKey() *types.PublicKey {
	return r.contextStateAccount
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU256Request) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.contextStateAccountOwner
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU256Request) ToComputeUnitLimit() uint32 {
	return r.ComputeUnitLimit
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU256Request) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU256Request) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateVerifyFromAccountBatchedRangeProofU256Request) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyFromAccountBatchedRangeProofU256Response reports the built transaction.
type ContextStateVerifyFromAccountBatchedRangeProofU256Response struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ProofAccount             string `json:"proof_account"`
	ProofOffset              string `json:"proof_offset"`
	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyFromAccountBatchedRangeProofU256Response(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	proofAccount *types.PublicKey, proofOffset uint64, contextStateAccount *types.PublicKey, contextStateAccountOwner *types.PublicKey,
	fee uint64,
) *ContextStateVerifyFromAccountBatchedRangeProofU256Response {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyFromAccountBatchedRangeProofU256Response{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ProofAccount:             proofAccount.Base58(),
		ProofOffset:              strconv.FormatUint(proofOffset, 10),
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyFromAccountGroupedCiphertext2HandlesValidityRequest verifies a GroupedCiphertext2HandlesValidity proof already written into an account, and persists its
// context into an existing context-state account -- the proof-in-account form of
// context-state/verify/grouped-ciphertext-2-handles-validity, for a proof too large to carry in one
// transaction. The instruction data is five bytes (a discriminator and a u32
// offset) however large the proof is.
type ContextStateVerifyFromAccountGroupedCiphertext2HandlesValidityRequest struct {
	// ProofAccount holds the proof data, already written (for example with
	// record/write). Nothing checks who owns it -- the program only reads the
	// bytes -- but it has to be large enough to hold offset plus the proof.
	ProofAccount string `json:"proof_account" example:""`
	// ProofOffset is where the proof data starts within ProofAccount's data, up to
	// 4294967295. For a record account that is 33 plus wherever the proof was
	// written, so 33 for a proof written from offset 0.
	ProofOffset string `json:"proof_offset" example:""`
	// ContextStateAccount already exists, created via context-state/create.
	ContextStateAccount string `json:"context_state_account" example:""`
	// ContextStateAccountOwner is recorded as the context's owner -- the key
	// context-state/close will later require a signature from. It does not sign
	// here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// ComputeUnitLimit is the compute-unit limit the transaction is given, in
	// a ComputeBudget SetComputeUnitLimit instruction placed ahead of the
	// verify. The ZkElgamalProof program charges a fixed cost per proof
	// type before it verifies anything (range u128 costs the entire default
	// 200,000 and u256 costs 368,000), so without a raised limit the larger
	// proofs fail with ComputationalBudgetExceeded. Left empty or zero it is
	// this proof type's own cost plus a margin, rounded up to the next
	// thousand. It cannot exceed 1,400,000, the most a transaction may have.
	ComputeUnitLimit uint32 `json:"compute_unit_limit" example:"0"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofAccount             *types.PublicKey
	proofOffset              uint64
	contextStateAccount      *types.PublicKey
	contextStateAccountOwner *types.PublicKey
	fp                       *types.PublicKey
	rbh                      *types.Hash
	dna                      *types.PublicKey
}

func (r *ContextStateVerifyFromAccountGroupedCiphertext2HandlesValidityRequest) ValidateRequest() error {
	var err error

	if r.proofAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ProofAccount)); err != nil {
		return errors.New("proof_account: " + err.Error())
	}
	if v := strings.TrimSpace(r.ProofOffset); v == "" {
		return errors.New("proof_offset is required")
	} else if r.proofOffset, err = strconv.ParseUint(v, 10, 64); err != nil {
		return errors.New("proof_offset: " + err.Error())
	}
	if r.contextStateAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.contextStateAccountOwner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.ComputeUnitLimit > 1_400_000 {
		return errors.New("compute_unit_limit: exceeds 1400000, the most a transaction may have")
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyFromAccountGroupedCiphertext2HandlesValidityRequest) ProofAccountKey() *types.PublicKey {
	return r.proofAccount
}
func (r *ContextStateVerifyFromAccountGroupedCiphertext2HandlesValidityRequest) ToProofOffset() uint64 {
	return r.proofOffset
}
func (r *ContextStateVerifyFromAccountGroupedCiphertext2HandlesValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.contextStateAccount
}
func (r *ContextStateVerifyFromAccountGroupedCiphertext2HandlesValidityRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.contextStateAccountOwner
}
func (r *ContextStateVerifyFromAccountGroupedCiphertext2HandlesValidityRequest) ToComputeUnitLimit() uint32 {
	return r.ComputeUnitLimit
}
func (r *ContextStateVerifyFromAccountGroupedCiphertext2HandlesValidityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateVerifyFromAccountGroupedCiphertext2HandlesValidityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateVerifyFromAccountGroupedCiphertext2HandlesValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyFromAccountGroupedCiphertext2HandlesValidityResponse reports the built transaction.
type ContextStateVerifyFromAccountGroupedCiphertext2HandlesValidityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ProofAccount             string `json:"proof_account"`
	ProofOffset              string `json:"proof_offset"`
	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyFromAccountGroupedCiphertext2HandlesValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	proofAccount *types.PublicKey, proofOffset uint64, contextStateAccount *types.PublicKey, contextStateAccountOwner *types.PublicKey,
	fee uint64,
) *ContextStateVerifyFromAccountGroupedCiphertext2HandlesValidityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyFromAccountGroupedCiphertext2HandlesValidityResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ProofAccount:             proofAccount.Base58(),
		ProofOffset:              strconv.FormatUint(proofOffset, 10),
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyFromAccountBatchedGroupedCiphertext2HandlesValidityRequest verifies a BatchedGroupedCiphertext2HandlesValidity proof already written into an account, and persists its
// context into an existing context-state account -- the proof-in-account form of
// context-state/verify/batched-grouped-ciphertext-2-handles-validity, for a proof too large to carry in one
// transaction. The instruction data is five bytes (a discriminator and a u32
// offset) however large the proof is.
type ContextStateVerifyFromAccountBatchedGroupedCiphertext2HandlesValidityRequest struct {
	// ProofAccount holds the proof data, already written (for example with
	// record/write). Nothing checks who owns it -- the program only reads the
	// bytes -- but it has to be large enough to hold offset plus the proof.
	ProofAccount string `json:"proof_account" example:""`
	// ProofOffset is where the proof data starts within ProofAccount's data, up to
	// 4294967295. For a record account that is 33 plus wherever the proof was
	// written, so 33 for a proof written from offset 0.
	ProofOffset string `json:"proof_offset" example:""`
	// ContextStateAccount already exists, created via context-state/create.
	ContextStateAccount string `json:"context_state_account" example:""`
	// ContextStateAccountOwner is recorded as the context's owner -- the key
	// context-state/close will later require a signature from. It does not sign
	// here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// ComputeUnitLimit is the compute-unit limit the transaction is given, in
	// a ComputeBudget SetComputeUnitLimit instruction placed ahead of the
	// verify. The ZkElgamalProof program charges a fixed cost per proof
	// type before it verifies anything (range u128 costs the entire default
	// 200,000 and u256 costs 368,000), so without a raised limit the larger
	// proofs fail with ComputationalBudgetExceeded. Left empty or zero it is
	// this proof type's own cost plus a margin, rounded up to the next
	// thousand. It cannot exceed 1,400,000, the most a transaction may have.
	ComputeUnitLimit uint32 `json:"compute_unit_limit" example:"0"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofAccount             *types.PublicKey
	proofOffset              uint64
	contextStateAccount      *types.PublicKey
	contextStateAccountOwner *types.PublicKey
	fp                       *types.PublicKey
	rbh                      *types.Hash
	dna                      *types.PublicKey
}

func (r *ContextStateVerifyFromAccountBatchedGroupedCiphertext2HandlesValidityRequest) ValidateRequest() error {
	var err error

	if r.proofAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ProofAccount)); err != nil {
		return errors.New("proof_account: " + err.Error())
	}
	if v := strings.TrimSpace(r.ProofOffset); v == "" {
		return errors.New("proof_offset is required")
	} else if r.proofOffset, err = strconv.ParseUint(v, 10, 64); err != nil {
		return errors.New("proof_offset: " + err.Error())
	}
	if r.contextStateAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.contextStateAccountOwner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.ComputeUnitLimit > 1_400_000 {
		return errors.New("compute_unit_limit: exceeds 1400000, the most a transaction may have")
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyFromAccountBatchedGroupedCiphertext2HandlesValidityRequest) ProofAccountKey() *types.PublicKey {
	return r.proofAccount
}
func (r *ContextStateVerifyFromAccountBatchedGroupedCiphertext2HandlesValidityRequest) ToProofOffset() uint64 {
	return r.proofOffset
}
func (r *ContextStateVerifyFromAccountBatchedGroupedCiphertext2HandlesValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.contextStateAccount
}
func (r *ContextStateVerifyFromAccountBatchedGroupedCiphertext2HandlesValidityRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.contextStateAccountOwner
}
func (r *ContextStateVerifyFromAccountBatchedGroupedCiphertext2HandlesValidityRequest) ToComputeUnitLimit() uint32 {
	return r.ComputeUnitLimit
}
func (r *ContextStateVerifyFromAccountBatchedGroupedCiphertext2HandlesValidityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateVerifyFromAccountBatchedGroupedCiphertext2HandlesValidityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateVerifyFromAccountBatchedGroupedCiphertext2HandlesValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyFromAccountBatchedGroupedCiphertext2HandlesValidityResponse reports the built transaction.
type ContextStateVerifyFromAccountBatchedGroupedCiphertext2HandlesValidityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ProofAccount             string `json:"proof_account"`
	ProofOffset              string `json:"proof_offset"`
	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyFromAccountBatchedGroupedCiphertext2HandlesValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	proofAccount *types.PublicKey, proofOffset uint64, contextStateAccount *types.PublicKey, contextStateAccountOwner *types.PublicKey,
	fee uint64,
) *ContextStateVerifyFromAccountBatchedGroupedCiphertext2HandlesValidityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyFromAccountBatchedGroupedCiphertext2HandlesValidityResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ProofAccount:             proofAccount.Base58(),
		ProofOffset:              strconv.FormatUint(proofOffset, 10),
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}

// ContextStateVerifyFromAccountGroupedCiphertext3HandlesValidityRequest verifies a GroupedCiphertext3HandlesValidity proof already written into an account, and persists its
// context into an existing context-state account -- the proof-in-account form of
// context-state/verify/grouped-ciphertext-3-handles-validity, for a proof too large to carry in one
// transaction. The instruction data is five bytes (a discriminator and a u32
// offset) however large the proof is.
type ContextStateVerifyFromAccountGroupedCiphertext3HandlesValidityRequest struct {
	// ProofAccount holds the proof data, already written (for example with
	// record/write). Nothing checks who owns it -- the program only reads the
	// bytes -- but it has to be large enough to hold offset plus the proof.
	ProofAccount string `json:"proof_account" example:""`
	// ProofOffset is where the proof data starts within ProofAccount's data, up to
	// 4294967295. For a record account that is 33 plus wherever the proof was
	// written, so 33 for a proof written from offset 0.
	ProofOffset string `json:"proof_offset" example:""`
	// ContextStateAccount already exists, created via context-state/create.
	ContextStateAccount string `json:"context_state_account" example:""`
	// ContextStateAccountOwner is recorded as the context's owner -- the key
	// context-state/close will later require a signature from. It does not sign
	// here.
	ContextStateAccountOwner string `json:"context_state_account_owner" example:""`

	// ComputeUnitLimit is the compute-unit limit the transaction is given, in
	// a ComputeBudget SetComputeUnitLimit instruction placed ahead of the
	// verify. The ZkElgamalProof program charges a fixed cost per proof
	// type before it verifies anything (range u128 costs the entire default
	// 200,000 and u256 costs 368,000), so without a raised limit the larger
	// proofs fail with ComputationalBudgetExceeded. Left empty or zero it is
	// this proof type's own cost plus a margin, rounded up to the next
	// thousand. It cannot exceed 1,400,000, the most a transaction may have.
	ComputeUnitLimit uint32 `json:"compute_unit_limit" example:"0"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	proofAccount             *types.PublicKey
	proofOffset              uint64
	contextStateAccount      *types.PublicKey
	contextStateAccountOwner *types.PublicKey
	fp                       *types.PublicKey
	rbh                      *types.Hash
	dna                      *types.PublicKey
}

func (r *ContextStateVerifyFromAccountGroupedCiphertext3HandlesValidityRequest) ValidateRequest() error {
	var err error

	if r.proofAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ProofAccount)); err != nil {
		return errors.New("proof_account: " + err.Error())
	}
	if v := strings.TrimSpace(r.ProofOffset); v == "" {
		return errors.New("proof_offset is required")
	} else if r.proofOffset, err = strconv.ParseUint(v, 10, 64); err != nil {
		return errors.New("proof_offset: " + err.Error())
	}
	if r.contextStateAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccount)); err != nil {
		return errors.New("context_state_account: " + err.Error())
	}
	if r.contextStateAccountOwner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ContextStateAccountOwner)); err != nil {
		return errors.New("context_state_account_owner: " + err.Error())
	}
	if r.ComputeUnitLimit > 1_400_000 {
		return errors.New("compute_unit_limit: exceeds 1400000, the most a transaction may have")
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *ContextStateVerifyFromAccountGroupedCiphertext3HandlesValidityRequest) ProofAccountKey() *types.PublicKey {
	return r.proofAccount
}
func (r *ContextStateVerifyFromAccountGroupedCiphertext3HandlesValidityRequest) ToProofOffset() uint64 {
	return r.proofOffset
}
func (r *ContextStateVerifyFromAccountGroupedCiphertext3HandlesValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.contextStateAccount
}
func (r *ContextStateVerifyFromAccountGroupedCiphertext3HandlesValidityRequest) ContextStateAccountOwnerKey() *types.PublicKey {
	return r.contextStateAccountOwner
}
func (r *ContextStateVerifyFromAccountGroupedCiphertext3HandlesValidityRequest) ToComputeUnitLimit() uint32 {
	return r.ComputeUnitLimit
}
func (r *ContextStateVerifyFromAccountGroupedCiphertext3HandlesValidityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateVerifyFromAccountGroupedCiphertext3HandlesValidityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateVerifyFromAccountGroupedCiphertext3HandlesValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateVerifyFromAccountGroupedCiphertext3HandlesValidityResponse reports the built transaction.
type ContextStateVerifyFromAccountGroupedCiphertext3HandlesValidityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	ProofAccount             string `json:"proof_account"`
	ProofOffset              string `json:"proof_offset"`
	ContextStateAccount      string `json:"context_state_account"`
	ContextStateAccountOwner string `json:"context_state_account_owner"`

	Fee SystemPayer `json:"fee"`
}

func NewContextStateVerifyFromAccountGroupedCiphertext3HandlesValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	proofAccount *types.PublicKey, proofOffset uint64, contextStateAccount *types.PublicKey, contextStateAccountOwner *types.PublicKey,
	fee uint64,
) *ContextStateVerifyFromAccountGroupedCiphertext3HandlesValidityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ContextStateVerifyFromAccountGroupedCiphertext3HandlesValidityResponse{
		Transaction:              codec.Base64.Encode(raw),
		Message:                  codec.Base64.Encode(message),
		RecentBlockhash:          tx.Message.RecentBlockhash.Base58(),
		AccountKeys:              keys,
		Signers:                  signers,
		NonceAuthority:           nonceAuth,
		ProofAccount:             proofAccount.Base58(),
		ProofOffset:              strconv.FormatUint(proofOffset, 10),
		ContextStateAccount:      contextStateAccount.Base58(),
		ContextStateAccountOwner: contextStateAccountOwner.Base58(),
		Fee:                      newSystemPayer(feePayer, fee),
	}
}
