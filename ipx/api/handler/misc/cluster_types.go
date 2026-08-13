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

// ReplaceBlockhashWithNonceRequest carries an unsigned transaction to rebuild
// against a durable nonce.
//
// The transaction must be unsigned, and for a stronger reason than the
// blockhash refresh next door has: this does not edit the message, it
// recompiles one. Advancing the nonce is an instruction, its accounts join
// the key list, and every index shifts around them — so a signature made
// over the old bytes is not merely stale, it is a signature over a message
// that no longer exists.
//
// The nonce authority is not a field. It is stored on the nonce account, and
// reading it there rather than taking the caller's word turns a wrong one
// into a 400 instead of an on-chain failure.
type ReplaceBlockhashWithNonceRequest struct {
	Transaction  string `json:"transaction"`
	NonceAccount string `json:"nonce_account"`

	raw          []byte
	nonceAccount *types.PublicKey
}

func (r *ReplaceBlockhashWithNonceRequest) ValidateRequest() error {
	raw, err := codec.Base64.Decode(strings.TrimSpace(r.Transaction))
	if err != nil {
		return errors.New("transaction: invalid base64: " + err.Error())
	}
	r.raw = raw

	if r.nonceAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.NonceAccount)); err != nil {
		return errors.New("nonce_account: " + err.Error())
	}

	return nil
}

func (r *ReplaceBlockhashWithNonceRequest) ToRaw() []byte {
	return r.raw
}

func (r *ReplaceBlockhashWithNonceRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

// ReplaceBlockhashWithNonceResponse mirrors the v2 build responses, so the
// result goes straight to sign and send the same way a freshly built
// transaction does.
//
// Signers is the field to read. Recompiling can add one — a nonce authority
// that was not already signing becomes a required signer — so the set here
// is not necessarily the set the caller sent in.
//
// If that authority is a key the transaction already carried as a
// non-signer, it does not get a second entry; it is the same account with
// signer added, which every instruction already holding it now sees. Signing
// is a property of the message rather than of one instruction, so there is
// no arrangement where a key signs for the nonce and not for the rest, and a
// nonce account whose authority is an address nobody can sign for leaves a
// transaction that cannot be completed.
type ReplaceBlockhashWithNonceResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	// NonceAccount and NonceAuthority are always present here, unlike the v2
	// responses where the authority doubles as the signal that a nonce was
	// used at all: this endpoint does nothing else.
	NonceAccount   string `json:"nonce_account"`
	NonceAuthority string `json:"nonce_authority"`

	Fee       string `json:"fee"`
	Size      int    `json:"size"`
	SizeLimit int    `json:"size_limit"`
}

func NewReplaceBlockhashWithNonceResponse(
	tx *types.Transaction, raw, message []byte,
	nonceAccount, nonceAuthority *types.PublicKey, fee uint64,
) *ReplaceBlockhashWithNonceResponse {
	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ReplaceBlockhashWithNonceResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAccount:    nonceAccount.Base58(),
		NonceAuthority:  nonceAuthority.Base58(),
		Fee:             strconv.FormatUint(fee, 10),
		Size:            len(raw),
		SizeLimit:       types.MaxTransactionSize,
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
