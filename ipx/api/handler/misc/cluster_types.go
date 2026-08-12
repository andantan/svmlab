package misc

import (
	"errors"
	"strconv"
	"strings"

	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
	"github.com/andantan/svmlab/internal/rpc"
)

type SlotResponse struct {
	Slot uint64 `json:"slot"`
}

func NewSlotResponse(slot uint64) *SlotResponse {
	return &SlotResponse{
		Slot: slot,
	}
}

type HealthResponse struct {
	Health string `json:"health"`
}

func NewHealthResponse(health string) *HealthResponse {
	return &HealthResponse{
		Health: health,
	}
}

type VersionResponse struct {
	Version map[string]any `json:"version"`
}

func NewVersionResponse(version map[string]any) *VersionResponse {
	return &VersionResponse{
		Version: version,
	}
}

// GenesisHashResponse reports the cluster's identity and whether it is the one
// config names.
//
// A genesis hash is not folded into a signature the way EIP-155 binds a chain
// id, so nothing on chain stops a transaction from replaying elsewhere. This
// check is the substitute: confirm the endpoint is the cluster expected before
// trusting anything else it says.
type GenesisHashResponse struct {
	GenesisHash string `json:"genesis_hash"`
	Configured  string `json:"configured"`
	Matches     bool   `json:"matches"`
}

func NewGenesisHashResponse(genesis, configured string) *GenesisHashResponse {
	return &GenesisHashResponse{
		GenesisHash: genesis,
		Configured:  configured,
		Matches:     genesis == configured,
	}
}

// BlockhashResponse carries the blockhash and the height at which it dies.
type BlockhashResponse struct {
	Blockhash            string `json:"blockhash"`
	LastValidBlockHeight uint64 `json:"last_valid_block_height"`
}

func NewBlockhashResponse(blockhash string, lastValidBlockHeight uint64) *BlockhashResponse {
	return &BlockhashResponse{
		Blockhash:            blockhash,
		LastValidBlockHeight: lastValidBlockHeight,
	}
}

// RefreshBlockhashRequest carries an unsigned transaction whose recent
// blockhash has expired, or is about to.
//
// The transaction must be unsigned. A signature commits to the exact message
// bytes it was produced over, so this only makes sense before signing —
// afterward, the blockhash has to be part of what gets re-signed, not
// silently swapped underneath an existing signature.
type RefreshBlockhashRequest struct {
	Transaction string `json:"transaction"`

	raw []byte
}

func (r *RefreshBlockhashRequest) ValidateRequest() error {
	raw, err := codec.Base64.Decode(strings.TrimSpace(r.Transaction))
	if err != nil {
		return errors.New("transaction: invalid base64: " + err.Error())
	}
	r.raw = raw

	return nil
}

func (r *RefreshBlockhashRequest) ToRaw() []byte {
	return r.raw
}

// RefreshBlockhashResponse carries the transaction with its blockhash
// replaced, plus the height that blockhash is valid through.
type RefreshBlockhashResponse struct {
	Transaction          string `json:"transaction"`
	Blockhash            string `json:"blockhash"`
	LastValidBlockHeight uint64 `json:"last_valid_block_height"`
}

func NewRefreshBlockhashResponse(raw []byte, blockhash string, lastValidBlockHeight uint64) *RefreshBlockhashResponse {
	return &RefreshBlockhashResponse{
		Transaction:          codec.Base64.Encode(raw),
		Blockhash:            blockhash,
		LastValidBlockHeight: lastValidBlockHeight,
	}
}

// SendTransactionRequest broadcasts a signed transaction.
type SendTransactionRequest struct {
	Transaction string `json:"transaction"`

	raw []byte
}

func (r *SendTransactionRequest) ValidateRequest() error {
	raw, err := types.DecodeFullySignedTransaction(r.Transaction)
	if err != nil {
		return err
	}
	r.raw = raw

	return nil
}

func (r *SendTransactionRequest) ToRaw() []byte {
	return r.raw
}

// SendTransactionResponse returns the accepted signature.
//
// Acceptance is not execution. The transaction still has to land in a block,
// which the signature status endpoint reports.
type SendTransactionResponse struct {
	Signature string `json:"signature"`
}

func NewSendTransactionResponse(sig *types.Signature) *SendTransactionResponse {
	return &SendTransactionResponse{
		Signature: sig.Base58(),
	}
}

// SimulateTransactionRequest runs a transaction without submitting it.
//
// Signatures are always verified, so the transaction must be fully signed,
// the same as send. This catches a bad signature before broadcast rather
// than after, which is most of the point of simulating first.
type SimulateTransactionRequest struct {
	Transaction string `json:"transaction"`

	raw []byte
}

func (r *SimulateTransactionRequest) ValidateRequest() error {
	raw, err := types.DecodeFullySignedTransaction(r.Transaction)
	if err != nil {
		return err
	}
	r.raw = raw

	return nil
}

func (r *SimulateTransactionRequest) ToRaw() []byte {
	return r.raw
}

// SimulateTransactionResponse carries the outcome and the program logs.
//
// The logs are the only account of why execution stopped. Nothing here
// corresponds to an EVM revert string, so a failure is a program error code
// plus whatever the program chose to print.
type SimulateTransactionResponse struct {
	Failed        bool     `json:"failed"`
	Err           string   `json:"err"`
	Logs          []string `json:"logs"`
	UnitsConsumed uint64   `json:"units_consumed"`
}

func NewSimulateTransactionResponse(v *rpc.SimulateValue) *SimulateTransactionResponse {
	out := &SimulateTransactionResponse{
		Failed: v.Failed(),
		Logs:   v.Logs,
	}
	if v.Failed() {
		out.Err = string(v.Err)
	}
	if v.UnitsConsumed != nil {
		out.UnitsConsumed = *v.UnitsConsumed
	}

	return out
}

type SignatureStatusRequest struct {
	Signature string `json:"signature"`

	signature *types.Signature
}

func (r *SignatureStatusRequest) ValidateRequest() error {
	var err error
	if r.signature, err = types.NewSignatureFromBase58(strings.TrimSpace(r.Signature)); err != nil {
		return errors.New("signature: " + err.Error())
	}

	return nil
}

func (r *SignatureStatusRequest) ToSignature() *types.Signature {
	return r.signature
}

// SignatureStatusResponse stands in for an EVM receipt.
//
// Found can stay false forever, which a receipt never does: a transaction
// whose blockhash expired is simply forgotten and will never land.
type SignatureStatusResponse struct {
	Signature          string `json:"signature"`
	Found              bool   `json:"found"`
	Slot               uint64 `json:"slot"`
	Confirmations      uint64 `json:"confirmations"`
	ConfirmationStatus string `json:"confirmation_status"`
	Failed             bool   `json:"failed"`
	Err                string `json:"err"`
}

func NewSignatureStatusResponse(sig *types.Signature, st *rpc.SignatureStatus) *SignatureStatusResponse {
	if st == nil {
		return &SignatureStatusResponse{Signature: sig.Base58()}
	}

	out := &SignatureStatusResponse{
		Signature:          sig.Base58(),
		Found:              true,
		Slot:               st.Slot,
		ConfirmationStatus: st.ConfirmationStatus,
		Failed:             st.Failed(),
	}
	if st.Confirmations != nil {
		out.Confirmations = *st.Confirmations
	}
	if st.Failed() {
		out.Err = string(st.Err)
	}

	return out
}

// FeeRequest prices a message rather than a transaction.
//
// The fee follows from the signature count and any compute budget
// instructions, both of which live in the message, so it is knowable before
// signing. There is no counterpart to a gas estimate that execution can
// exceed.
type FeeRequest struct {
	Message string `json:"message"`

	message *types.Message
}

func (r *FeeRequest) ValidateRequest() error {
	raw, err := codec.Base64.Decode(strings.TrimSpace(r.Message))
	if err != nil {
		return errors.New("message: invalid base64: " + err.Error())
	}
	if r.message, err = types.DeserializeMessage(raw); err != nil {
		return errors.New("message: " + err.Error())
	}

	return nil
}

func (r *FeeRequest) ToMessage() *types.Message {
	return r.message
}

// FeeResponse reports the fee, or valid=false when the message's blockhash has
// already expired.
type FeeResponse struct {
	Lamports string `json:"lamports"`
	SOL      string `json:"sol"`
	Valid    bool   `json:"valid"`
}

func NewFeeResponse(lamports uint64, valid bool) *FeeResponse {
	return &FeeResponse{
		Lamports: strconv.FormatUint(lamports, 10),
		SOL:      types.LamportsToSol(lamports),
		Valid:    valid,
	}
}
