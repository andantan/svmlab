package v2

import (
	"errors"
	"strings"

	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
)

// ContextStateCreateAccountPubkeyValidityRequest funds a new account sized
// and owned for a PubkeyValidity proof's ProofContextState<T> layout --
// System CreateAccount only, not yet written to. It must land in the same
// transaction as (and strictly before) the matching
// context-state/verify-pubkey-validity instruction: nothing stops another
// party from claiming an uninitialized account in between otherwise.
type ContextStateCreateAccountPubkeyValidityRequest struct {
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

func (r *ContextStateCreateAccountPubkeyValidityRequest) ValidateRequest() error {
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

func (r *ContextStateCreateAccountPubkeyValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateAccountPubkeyValidityRequest) RentPayerKey() *types.PublicKey { return r.rp }
func (r *ContextStateCreateAccountPubkeyValidityRequest) FeePayerKey() *types.PublicKey  { return r.fp }
func (r *ContextStateCreateAccountPubkeyValidityRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *ContextStateCreateAccountPubkeyValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateAccountPubkeyValidityResponse reports the built
// transaction.
type ContextStateCreateAccountPubkeyValidityResponse struct {
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

func NewContextStateCreateAccountPubkeyValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateAccountPubkeyValidityResponse {
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

	return &ContextStateCreateAccountPubkeyValidityResponse{
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

// ContextStateCreateAccountCiphertextCommitmentEqualityRequest funds a new
// account sized and owned for a CiphertextCommitmentEquality proof's
// ProofContextState<T> layout -- System CreateAccount only, not yet
// written to. It must land in the same transaction as (and strictly
// before) the matching
// context-state/verify-ciphertext-commitment-equality instruction:
// nothing stops another party from claiming an uninitialized account in
// between otherwise.
type ContextStateCreateAccountCiphertextCommitmentEqualityRequest struct {
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

func (r *ContextStateCreateAccountCiphertextCommitmentEqualityRequest) ValidateRequest() error {
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

func (r *ContextStateCreateAccountCiphertextCommitmentEqualityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateAccountCiphertextCommitmentEqualityRequest) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateAccountCiphertextCommitmentEqualityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateAccountCiphertextCommitmentEqualityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateCreateAccountCiphertextCommitmentEqualityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateAccountCiphertextCommitmentEqualityResponse reports
// the built transaction.
type ContextStateCreateAccountCiphertextCommitmentEqualityResponse struct {
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

func NewContextStateCreateAccountCiphertextCommitmentEqualityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateAccountCiphertextCommitmentEqualityResponse {
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

	return &ContextStateCreateAccountCiphertextCommitmentEqualityResponse{
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

// ContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidityRequest
// funds a new account sized and owned for a
// BatchedGroupedCiphertext3HandlesValidity proof's ProofContextState<T>
// layout -- System CreateAccount only, not yet written to. It must land
// in the same transaction as (and strictly before) the matching
// context-state/verify-batched-grouped-ciphertext-3-handles-validity
// instruction: nothing stops another party from claiming an uninitialized
// account in between otherwise.
type ContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidityRequest struct {
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

func (r *ContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidityRequest) ValidateRequest() error {
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

func (r *ContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidityRequest) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidityResponse
// reports the built transaction.
type ContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidityResponse struct {
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

func NewContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidityResponse {
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

	return &ContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidityResponse{
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

// ContextStateCreateAccountBatchedRangeProofU128Request funds a new
// account sized and owned for a BatchedRangeProofU128 proof's
// ProofContextState<T> layout -- System CreateAccount only, not yet
// written to. It must land in the same transaction as (and strictly
// before) the matching context-state/verify-batched-range-proof-u128
// instruction: nothing stops another party from claiming an uninitialized
// account in between otherwise.
type ContextStateCreateAccountBatchedRangeProofU128Request struct {
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

func (r *ContextStateCreateAccountBatchedRangeProofU128Request) ValidateRequest() error {
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

func (r *ContextStateCreateAccountBatchedRangeProofU128Request) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateAccountBatchedRangeProofU128Request) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateAccountBatchedRangeProofU128Request) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateAccountBatchedRangeProofU128Request) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateCreateAccountBatchedRangeProofU128Request) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateAccountBatchedRangeProofU128Response reports the
// built transaction.
type ContextStateCreateAccountBatchedRangeProofU128Response struct {
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

func NewContextStateCreateAccountBatchedRangeProofU128Response(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateAccountBatchedRangeProofU128Response {
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

	return &ContextStateCreateAccountBatchedRangeProofU128Response{
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

// ContextStateCreateAccountZeroCiphertextRequest funds a new account sized and owned
// for a ZeroCiphertext proof's ProofContextState<T> layout -- System CreateAccount
// only, not yet written to. It must land in the same transaction as (and
// strictly before) the matching context-state/verify-zero-ciphertext
// instruction: nothing stops another party from claiming an
// uninitialized account in between otherwise.
type ContextStateCreateAccountZeroCiphertextRequest struct {
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

func (r *ContextStateCreateAccountZeroCiphertextRequest) ValidateRequest() error {
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

func (r *ContextStateCreateAccountZeroCiphertextRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateAccountZeroCiphertextRequest) RentPayerKey() *types.PublicKey { return r.rp }
func (r *ContextStateCreateAccountZeroCiphertextRequest) FeePayerKey() *types.PublicKey  { return r.fp }
func (r *ContextStateCreateAccountZeroCiphertextRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *ContextStateCreateAccountZeroCiphertextRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateAccountZeroCiphertextResponse reports the built transaction.
type ContextStateCreateAccountZeroCiphertextResponse struct {
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

func NewContextStateCreateAccountZeroCiphertextResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateAccountZeroCiphertextResponse {
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

	return &ContextStateCreateAccountZeroCiphertextResponse{
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

// ContextStateCreateAccountCiphertextCiphertextEqualityRequest funds a new account sized and owned
// for a CiphertextCiphertextEquality proof's ProofContextState<T> layout -- System CreateAccount
// only, not yet written to. It must land in the same transaction as (and
// strictly before) the matching context-state/verify-ciphertext-ciphertext-equality
// instruction: nothing stops another party from claiming an
// uninitialized account in between otherwise.
type ContextStateCreateAccountCiphertextCiphertextEqualityRequest struct {
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

func (r *ContextStateCreateAccountCiphertextCiphertextEqualityRequest) ValidateRequest() error {
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

func (r *ContextStateCreateAccountCiphertextCiphertextEqualityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateAccountCiphertextCiphertextEqualityRequest) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateAccountCiphertextCiphertextEqualityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateAccountCiphertextCiphertextEqualityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateCreateAccountCiphertextCiphertextEqualityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateAccountCiphertextCiphertextEqualityResponse reports the built transaction.
type ContextStateCreateAccountCiphertextCiphertextEqualityResponse struct {
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

func NewContextStateCreateAccountCiphertextCiphertextEqualityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateAccountCiphertextCiphertextEqualityResponse {
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

	return &ContextStateCreateAccountCiphertextCiphertextEqualityResponse{
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

// ContextStateCreateAccountPercentageWithCapRequest funds a new account sized and owned
// for a PercentageWithCap proof's ProofContextState<T> layout -- System CreateAccount
// only, not yet written to. It must land in the same transaction as (and
// strictly before) the matching context-state/verify-percentage-with-cap
// instruction: nothing stops another party from claiming an
// uninitialized account in between otherwise.
type ContextStateCreateAccountPercentageWithCapRequest struct {
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

func (r *ContextStateCreateAccountPercentageWithCapRequest) ValidateRequest() error {
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

func (r *ContextStateCreateAccountPercentageWithCapRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateAccountPercentageWithCapRequest) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateAccountPercentageWithCapRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateAccountPercentageWithCapRequest) Blockhash() *types.Hash { return r.rbh }
func (r *ContextStateCreateAccountPercentageWithCapRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateAccountPercentageWithCapResponse reports the built transaction.
type ContextStateCreateAccountPercentageWithCapResponse struct {
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

func NewContextStateCreateAccountPercentageWithCapResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateAccountPercentageWithCapResponse {
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

	return &ContextStateCreateAccountPercentageWithCapResponse{
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

// ContextStateCreateAccountBatchedRangeProofU64Request funds a new account sized and owned
// for a BatchedRangeProofU64 proof's ProofContextState<T> layout -- System CreateAccount
// only, not yet written to. It must land in the same transaction as (and
// strictly before) the matching context-state/verify-batched-range-proof-u64
// instruction: nothing stops another party from claiming an
// uninitialized account in between otherwise.
type ContextStateCreateAccountBatchedRangeProofU64Request struct {
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

func (r *ContextStateCreateAccountBatchedRangeProofU64Request) ValidateRequest() error {
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

func (r *ContextStateCreateAccountBatchedRangeProofU64Request) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateAccountBatchedRangeProofU64Request) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateAccountBatchedRangeProofU64Request) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateAccountBatchedRangeProofU64Request) Blockhash() *types.Hash { return r.rbh }
func (r *ContextStateCreateAccountBatchedRangeProofU64Request) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateAccountBatchedRangeProofU64Response reports the built transaction.
type ContextStateCreateAccountBatchedRangeProofU64Response struct {
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

func NewContextStateCreateAccountBatchedRangeProofU64Response(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateAccountBatchedRangeProofU64Response {
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

	return &ContextStateCreateAccountBatchedRangeProofU64Response{
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

// ContextStateCreateAccountBatchedRangeProofU256Request funds a new account sized and owned
// for a BatchedRangeProofU256 proof's ProofContextState<T> layout -- System CreateAccount
// only, not yet written to. It must land in the same transaction as (and
// strictly before) the matching context-state/verify-batched-range-proof-u256
// instruction: nothing stops another party from claiming an
// uninitialized account in between otherwise.
type ContextStateCreateAccountBatchedRangeProofU256Request struct {
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

func (r *ContextStateCreateAccountBatchedRangeProofU256Request) ValidateRequest() error {
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

func (r *ContextStateCreateAccountBatchedRangeProofU256Request) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateAccountBatchedRangeProofU256Request) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateAccountBatchedRangeProofU256Request) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateAccountBatchedRangeProofU256Request) Blockhash() *types.Hash { return r.rbh }
func (r *ContextStateCreateAccountBatchedRangeProofU256Request) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateAccountBatchedRangeProofU256Response reports the built transaction.
type ContextStateCreateAccountBatchedRangeProofU256Response struct {
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

func NewContextStateCreateAccountBatchedRangeProofU256Response(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateAccountBatchedRangeProofU256Response {
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

	return &ContextStateCreateAccountBatchedRangeProofU256Response{
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

// ContextStateCreateAccountGroupedCiphertext2HandlesValidityRequest funds a new account sized and owned
// for a GroupedCiphertext2HandlesValidity proof's ProofContextState<T> layout -- System CreateAccount
// only, not yet written to. It must land in the same transaction as (and
// strictly before) the matching context-state/verify-grouped-ciphertext-2-handles-validity
// instruction: nothing stops another party from claiming an
// uninitialized account in between otherwise.
type ContextStateCreateAccountGroupedCiphertext2HandlesValidityRequest struct {
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

func (r *ContextStateCreateAccountGroupedCiphertext2HandlesValidityRequest) ValidateRequest() error {
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

func (r *ContextStateCreateAccountGroupedCiphertext2HandlesValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateAccountGroupedCiphertext2HandlesValidityRequest) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateAccountGroupedCiphertext2HandlesValidityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateAccountGroupedCiphertext2HandlesValidityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateCreateAccountGroupedCiphertext2HandlesValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateAccountGroupedCiphertext2HandlesValidityResponse reports the built transaction.
type ContextStateCreateAccountGroupedCiphertext2HandlesValidityResponse struct {
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

func NewContextStateCreateAccountGroupedCiphertext2HandlesValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateAccountGroupedCiphertext2HandlesValidityResponse {
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

	return &ContextStateCreateAccountGroupedCiphertext2HandlesValidityResponse{
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

// ContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidityRequest funds a new account sized and owned
// for a BatchedGroupedCiphertext2HandlesValidity proof's ProofContextState<T> layout -- System CreateAccount
// only, not yet written to. It must land in the same transaction as (and
// strictly before) the matching context-state/verify-batched-grouped-ciphertext-2-handles-validity
// instruction: nothing stops another party from claiming an
// uninitialized account in between otherwise.
type ContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidityRequest struct {
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

func (r *ContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidityRequest) ValidateRequest() error {
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

func (r *ContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidityRequest) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidityResponse reports the built transaction.
type ContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidityResponse struct {
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

func NewContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidityResponse {
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

	return &ContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidityResponse{
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

// ContextStateCreateAccountGroupedCiphertext3HandlesValidityRequest funds a new account sized and owned
// for a GroupedCiphertext3HandlesValidity proof's ProofContextState<T> layout -- System CreateAccount
// only, not yet written to. It must land in the same transaction as (and
// strictly before) the matching context-state/verify-grouped-ciphertext-3-handles-validity
// instruction: nothing stops another party from claiming an
// uninitialized account in between otherwise.
type ContextStateCreateAccountGroupedCiphertext3HandlesValidityRequest struct {
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

func (r *ContextStateCreateAccountGroupedCiphertext3HandlesValidityRequest) ValidateRequest() error {
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

func (r *ContextStateCreateAccountGroupedCiphertext3HandlesValidityRequest) ContextStateAccountKey() *types.PublicKey {
	return r.csa
}
func (r *ContextStateCreateAccountGroupedCiphertext3HandlesValidityRequest) RentPayerKey() *types.PublicKey {
	return r.rp
}
func (r *ContextStateCreateAccountGroupedCiphertext3HandlesValidityRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}
func (r *ContextStateCreateAccountGroupedCiphertext3HandlesValidityRequest) Blockhash() *types.Hash {
	return r.rbh
}
func (r *ContextStateCreateAccountGroupedCiphertext3HandlesValidityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ContextStateCreateAccountGroupedCiphertext3HandlesValidityResponse reports the built transaction.
type ContextStateCreateAccountGroupedCiphertext3HandlesValidityResponse struct {
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

func NewContextStateCreateAccountGroupedCiphertext3HandlesValidityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, contextStateAccount *types.PublicKey, space, rentExemptLamports uint64,
	nonceAuthority *types.PublicKey,
	fee uint64,
) *ContextStateCreateAccountGroupedCiphertext3HandlesValidityResponse {
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

	return &ContextStateCreateAccountGroupedCiphertext3HandlesValidityResponse{
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
