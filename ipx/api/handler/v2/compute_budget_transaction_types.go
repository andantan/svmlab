package v2

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
)

// RequestHeapFrame's valid range and step. The runtime rejects anything
// outside [minHeapFrameBytes, maxHeapFrameBytes] or not a multiple of 1024
// as InvalidInstructionData, so this is checked here rather than left to
// come back as an on-chain rejection.
const (
	minHeapFrameBytes = 32 * 1024
	maxHeapFrameBytes = 256 * 1024
)

// SetComputeUnitLimitRequest caps how many compute units the transaction
// carrying it may consume.
//
// Units is the only value the instruction itself needs, and it takes no
// accounts at all: there is nobody to name as an authority, since the limit
// only ever binds the transaction it rides in. Every other field is the
// same transaction-building boilerplate every v2 endpoint takes.
type SetComputeUnitLimitRequest struct {
	// Units is the raw compute unit ceiling, not a multiplier or a
	// percentage. Exceeding it during execution fails the transaction with
	// a compute-budget-exceeded error.
	Units string `json:"units" example:"200000"`

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
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	units    uint32
	feePayer *types.PublicKey
	rbh      *types.Hash
	dna      *types.PublicKey
}

func (r *SetComputeUnitLimitRequest) ValidateRequest() error {
	var err error

	units := strings.TrimSpace(r.Units)
	if units == "" {
		return errors.New("units is required")
	}
	parsed, err := strconv.ParseUint(units, 10, 32)
	if err != nil {
		return errors.New("units: " + err.Error())
	}
	r.units = uint32(parsed)

	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
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

func (r *SetComputeUnitLimitRequest) ToUnits() uint32               { return r.units }
func (r *SetComputeUnitLimitRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *SetComputeUnitLimitRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *SetComputeUnitLimitRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// SetComputeUnitLimitResponse reports the built transaction alongside the
// limit it carries.
type SetComputeUnitLimitResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Units string      `json:"units"`
	Fee   SystemPayer `json:"fee"`
}

func NewSetComputeUnitLimitResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	units uint32, fee uint64,
) *SetComputeUnitLimitResponse {
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

	return &SetComputeUnitLimitResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Units:           strconv.FormatUint(uint64(units), 10),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// SetComputeUnitPriceRequest sets the priority fee for the transaction
// carrying it, in micro-lamports per compute unit.
//
// MicroLamports is the only value the instruction itself needs, and it
// takes no accounts at all: there is nobody to name as an authority, since
// the price only ever binds the transaction it rides in. Every other field
// is the same transaction-building boilerplate every v2 endpoint takes.
type SetComputeUnitPriceRequest struct {
	// MicroLamports is the raw priority-fee rate: the runtime multiplies
	// this by whatever compute the transaction actually consumes to get the
	// priority fee on top of the base signature fee.
	MicroLamports string `json:"micro_lamports" example:"1000"`

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
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	microLamports uint64
	feePayer      *types.PublicKey
	rbh           *types.Hash
	dna           *types.PublicKey
}

func (r *SetComputeUnitPriceRequest) ValidateRequest() error {
	var err error

	microLamports := strings.TrimSpace(r.MicroLamports)
	if microLamports == "" {
		return errors.New("micro_lamports is required")
	}
	if r.microLamports, err = strconv.ParseUint(microLamports, 10, 64); err != nil {
		return errors.New("micro_lamports: " + err.Error())
	}

	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
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

func (r *SetComputeUnitPriceRequest) ToMicroLamports() uint64       { return r.microLamports }
func (r *SetComputeUnitPriceRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *SetComputeUnitPriceRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *SetComputeUnitPriceRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// SetComputeUnitPriceResponse reports the built transaction alongside the
// priority-fee rate it carries.
type SetComputeUnitPriceResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	MicroLamports string      `json:"micro_lamports"`
	Fee           SystemPayer `json:"fee"`
}

func NewSetComputeUnitPriceResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	microLamports uint64, fee uint64,
) *SetComputeUnitPriceResponse {
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

	return &SetComputeUnitPriceResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		MicroLamports:   strconv.FormatUint(microLamports, 10),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// RequestHeapFrameRequest resizes the heap available to the transaction
// carrying it, in bytes.
//
// Bytes is the only value the instruction itself needs, and it takes no
// accounts at all: there is nobody to name as an authority, since the frame
// only ever sizes the transaction it rides in. Every other field is the
// same transaction-building boilerplate every v2 endpoint takes.
type RequestHeapFrameRequest struct {
	// Bytes must be a multiple of 1024 in [32768, 262144] (32KiB to 256KiB);
	// the runtime rejects anything else as InvalidInstructionData, so this
	// is checked here rather than left to come back as an on-chain
	// rejection.
	Bytes string `json:"bytes" example:"65536"`

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
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	bytes    uint32
	feePayer *types.PublicKey
	rbh      *types.Hash
	dna      *types.PublicKey
}

func (r *RequestHeapFrameRequest) ValidateRequest() error {
	var err error

	bytes := strings.TrimSpace(r.Bytes)
	if bytes == "" {
		return errors.New("bytes is required")
	}
	parsed, err := strconv.ParseUint(bytes, 10, 32)
	if err != nil {
		return errors.New("bytes: " + err.Error())
	}
	if parsed < minHeapFrameBytes || parsed > maxHeapFrameBytes {
		return fmt.Errorf("bytes: %d is outside the valid range [%d, %d]", parsed, minHeapFrameBytes, maxHeapFrameBytes)
	}
	if parsed%1024 != 0 {
		return fmt.Errorf("bytes: %d is not a multiple of 1024", parsed)
	}
	r.bytes = uint32(parsed)

	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
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

func (r *RequestHeapFrameRequest) ToBytes() uint32                          { return r.bytes }
func (r *RequestHeapFrameRequest) FeePayerKey() *types.PublicKey            { return r.feePayer }
func (r *RequestHeapFrameRequest) Blockhash() *types.Hash                   { return r.rbh }
func (r *RequestHeapFrameRequest) DurableNonceAccountKey() *types.PublicKey { return r.dna }

// RequestHeapFrameResponse reports the built transaction alongside the heap
// size it carries.
type RequestHeapFrameResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Bytes string      `json:"bytes"`
	Fee   SystemPayer `json:"fee"`
}

func NewRequestHeapFrameResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	bytes uint32, fee uint64,
) *RequestHeapFrameResponse {
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

	return &RequestHeapFrameResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Bytes:           strconv.FormatUint(uint64(bytes), 10),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// SetLoadedAccountsDataSizeLimitRequest caps the total byte size of every
// account the transaction carrying it loads, across all its instructions
// and any CPIs they make.
//
// Bytes is the only value the instruction itself needs, and it takes no
// accounts at all: there is nobody to name as an authority, since the limit
// only ever bounds the transaction it rides in. Every other field is the
// same transaction-building boilerplate every v2 endpoint takes.
type SetLoadedAccountsDataSizeLimitRequest struct {
	// Bytes must be non-zero — the runtime rejects zero outright as
	// InvalidLoadedAccountsDataSizeLimit, so this is checked here rather
	// than left to come back as an on-chain rejection. Left unset, legacy
	// and v0 transactions default to 64MiB; this only ever lowers that
	// ceiling, since anything larger is clamped back down to it.
	Bytes string `json:"bytes" example:"131072"`

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
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	bytes    uint32
	feePayer *types.PublicKey
	rbh      *types.Hash
	dna      *types.PublicKey
}

func (r *SetLoadedAccountsDataSizeLimitRequest) ValidateRequest() error {
	var err error

	bytes := strings.TrimSpace(r.Bytes)
	if bytes == "" {
		return errors.New("bytes is required")
	}
	parsed, err := strconv.ParseUint(bytes, 10, 32)
	if err != nil {
		return errors.New("bytes: " + err.Error())
	}
	if parsed == 0 {
		return errors.New("bytes: must be non-zero")
	}
	r.bytes = uint32(parsed)

	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
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

func (r *SetLoadedAccountsDataSizeLimitRequest) ToBytes() uint32               { return r.bytes }
func (r *SetLoadedAccountsDataSizeLimitRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *SetLoadedAccountsDataSizeLimitRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *SetLoadedAccountsDataSizeLimitRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// SetLoadedAccountsDataSizeLimitResponse reports the built transaction
// alongside the limit it carries.
type SetLoadedAccountsDataSizeLimitResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Bytes string      `json:"bytes"`
	Fee   SystemPayer `json:"fee"`
}

func NewSetLoadedAccountsDataSizeLimitResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	bytes uint32, fee uint64,
) *SetLoadedAccountsDataSizeLimitResponse {
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

	return &SetLoadedAccountsDataSizeLimitResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Bytes:           strconv.FormatUint(uint64(bytes), 10),
		Fee:             newSystemPayer(feePayer, fee),
	}
}
