package misc

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/core/types"
	"github.com/andantan/svmlab/internal/rpc"
)

type SendTransactionRequest struct {
	handler.ChainSelector
	handler.Commitment
	Transaction string `json:"transaction"`

	// SkipPreflight disables the node-side simulation that runs before the
	// transaction is broadcast. Leaving it off surfaces most failures without
	// spending a signature, including an expired blockhash.
	SkipPreflight bool `json:"skip_preflight" example:"false"`

	tx *types.Transaction
}

func (r *SendTransactionRequest) ValidateRequest() error {
	if err := r.ValidateChainSelector(); err != nil {
		return err
	}
	if err := r.ValidateCommitment(); err != nil {
		return err
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(r.Transaction))
	if err != nil {
		return errors.New("transaction: invalid base64: " + err.Error())
	}
	if r.tx, err = types.DeserializeTransaction(raw); err != nil {
		return errors.New("transaction: " + err.Error())
	}
	if !r.tx.IsFullySigned() {
		return errors.New("transaction: is not fully signed")
	}

	return nil
}

func (r *SendTransactionRequest) ToTransaction() *types.Transaction {
	return r.tx
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

// AccountRequest names one account to read.
type AccountRequest struct {
	handler.ChainSelector
	handler.Commitment
	PublicKey string `json:"public_key" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	publicKey *types.PublicKey
}

func (r *AccountRequest) ValidateRequest() error {
	if err := r.ValidateChainSelector(); err != nil {
		return err
	}
	if err := r.ValidateCommitment(); err != nil {
		return err
	}

	var err error
	if r.publicKey, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.PublicKey)); err != nil {
		return errors.New("public_key: " + err.Error())
	}

	return nil
}

func (r *AccountRequest) ToPublicKey() *types.PublicKey {
	return r.publicKey
}

type BalanceResponse struct {
	PublicKey string `json:"public_key"`
	Lamports  string `json:"lamports"`
	SOL       string `json:"sol"`
}

func NewBalanceResponse(k *types.PublicKey, lamports uint64) *BalanceResponse {
	return &BalanceResponse{
		PublicKey: k.Base58(),
		Lamports:  strconv.FormatUint(lamports, 10),
		SOL:       types.LamportsToSol(lamports),
	}
}

// AccountResponse is an account's on-chain state.
//
// Exists is separate from the rest because a missing account is an ordinary
// answer rather than an error: most 32-byte values name an account nobody has
// created.
type AccountResponse struct {
	PublicKey  string `json:"public_key"`
	Exists     bool   `json:"exists"`
	Lamports   string `json:"lamports"`
	SOL        string `json:"sol"`
	Owner      string `json:"owner"`
	Executable bool   `json:"executable"`
	Space      uint64 `json:"space"`
	Data       string `json:"data"`
}

func NewAccountResponse(k *types.PublicKey, info *rpc.AccountInfo) *AccountResponse {
	if info == nil {
		return &AccountResponse{PublicKey: k.Base58(), Lamports: "0", SOL: "0"}
	}

	data, _ := info.Bytes()

	return &AccountResponse{
		PublicKey:  k.Base58(),
		Exists:     true,
		Lamports:   strconv.FormatUint(info.Lamports, 10),
		SOL:        types.LamportsToSol(info.Lamports),
		Owner:      info.Owner,
		Executable: info.Executable,
		Space:      info.Space,
		Data:       base64.StdEncoding.EncodeToString(data),
	}
}

// ClusterRequest asks about the cluster rather than a specific account.
type ClusterRequest struct {
	handler.ChainSelector
	handler.Commitment
}

func (r *ClusterRequest) ValidateRequest() error {
	if err := r.ValidateChainSelector(); err != nil {
		return err
	}

	return r.ValidateCommitment()
}

type SlotResponse struct {
	Slot uint64 `json:"slot"`
}

type HealthResponse struct {
	Health string `json:"health"`
}

type VersionResponse struct {
	Version map[string]any `json:"version"`
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

// BlockhashResponse carries the blockhash and the height at which it dies.
type BlockhashResponse struct {
	Blockhash            string `json:"blockhash"`
	LastValidBlockHeight uint64 `json:"last_valid_block_height"`
}

// SimulateTransactionRequest runs a transaction without submitting it.
//
// Unlike send, the transaction need not be fully signed: with sig_verify off
// the node executes it anyway, which is what makes simulation useful before
// deciding whether to sign at all.
type SimulateTransactionRequest struct {
	handler.ChainSelector
	handler.Commitment
	Transaction string `json:"transaction"`
	SigVerify   bool   `json:"sig_verify" example:"false"`

	tx *types.Transaction
}

func (r *SimulateTransactionRequest) ValidateRequest() error {
	if err := r.ValidateChainSelector(); err != nil {
		return err
	}
	if err := r.ValidateCommitment(); err != nil {
		return err
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(r.Transaction))
	if err != nil {
		return errors.New("transaction: invalid base64: " + err.Error())
	}
	if r.tx, err = types.DeserializeTransaction(raw); err != nil {
		return errors.New("transaction: " + err.Error())
	}
	if r.SigVerify && !r.tx.IsFullySigned() {
		return errors.New("transaction: sig_verify requires a fully signed transaction")
	}

	return nil
}

func (r *SimulateTransactionRequest) ToTransaction() *types.Transaction {
	return r.tx
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
	handler.ChainSelector
	Signature string `json:"signature"`

	// SearchHistory looks beyond the node's recent cache. A signature the
	// cluster has already forgotten is reported as not found without it.
	SearchHistory bool `json:"search_history" example:"true"`

	signature *types.Signature
}

func (r *SignatureStatusRequest) ValidateRequest() error {
	if err := r.ValidateChainSelector(); err != nil {
		return err
	}

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
	handler.ChainSelector
	handler.Commitment
	Message string `json:"message"`

	message *types.Message
}

func (r *FeeRequest) ValidateRequest() error {
	if err := r.ValidateChainSelector(); err != nil {
		return err
	}
	if err := r.ValidateCommitment(); err != nil {
		return err
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(r.Message))
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

// Account data sizes, each read off a live account rather than taken from
// documentation.
//
// The rent RPC takes a byte count and knows nothing about account kinds, so
// these constants are what turn "a token account" into a number.
const (
	// SpaceSystemAccount is a plain wallet: lamports and no data.
	SpaceSystemAccount uint64 = 0

	// SpaceMint was confirmed against the USDC, USDT, and wSOL mints.
	SpaceMint uint64 = 82

	// SpaceTokenAccount was confirmed against a live holder's account.
	SpaceTokenAccount uint64 = 165

	// SpaceStakeAccount was confirmed against devnet, where every one of the
	// 112969 accounts the Stake program owns has this size.
	SpaceStakeAccount uint64 = 200

	// SpaceVoteAccount was confirmed against three mainnet validators.
	SpaceVoteAccount uint64 = 3762
)

// RentExemptionResponse reports the minimum balance for a size.
//
// An EVM account has no such floor; here an account below it is subject to
// removal, which is why creating one has to meet the threshold.
type RentExemptionResponse struct {
	AccountType string `json:"account_type"`
	Space       uint64 `json:"space"`
	Lamports    string `json:"lamports"`
	SOL         string `json:"sol"`
}

func NewRentExemptionResponse(accountType string, space, lamports uint64) *RentExemptionResponse {
	return &RentExemptionResponse{
		AccountType: accountType,
		Space:       space,
		Lamports:    strconv.FormatUint(lamports, 10),
		SOL:         types.LamportsToSol(lamports),
	}
}

// AirdropRequest funds an account on devnet or testnet. Mainnet refuses it.
type AirdropRequest struct {
	handler.ChainSelector
	handler.Commitment
	PublicKey string `json:"public_key"`
	Amount    string `json:"amount" example:"1000000000"`

	publicKey *types.PublicKey
	amount    uint64
}

func (r *AirdropRequest) ValidateRequest() error {
	if err := r.ValidateChainSelector(); err != nil {
		return err
	}
	if err := r.ValidateCommitment(); err != nil {
		return err
	}

	var err error
	if r.publicKey, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.PublicKey)); err != nil {
		return errors.New("public_key: " + err.Error())
	}

	if r.amount, err = strconv.ParseUint(strings.TrimSpace(r.Amount), 10, 64); err != nil {
		return errors.New("amount: must be a decimal lamport count")
	}
	if r.amount == 0 {
		return errors.New("amount: must be greater than zero")
	}

	return nil
}

func (r *AirdropRequest) ToPublicKey() *types.PublicKey {
	return r.publicKey
}

func (r *AirdropRequest) Lamports() uint64 {
	return r.amount
}

type AirdropResponse struct {
	Signature string `json:"signature"`
}

func NewAirdropResponse(sig *types.Signature) *AirdropResponse {
	return &AirdropResponse{Signature: sig.Base58()}
}

// RawRequest passes a method straight through to the node.
//
// It exists so that a method this API has not wrapped is still reachable,
// which is most of the point of a lab.
type RawRequest struct {
	handler.ChainSelector
	Method string `json:"method" example:"getEpochInfo"`
	Params any    `json:"params"`
}

func (r *RawRequest) ValidateRequest() error {
	if err := r.ValidateChainSelector(); err != nil {
		return err
	}

	r.Method = strings.TrimSpace(r.Method)
	if r.Method == "" {
		return errors.New("method is required")
	}

	return nil
}

type BatchCall struct {
	Method string `json:"method"`
	Params any    `json:"params"`
}

// BatchRequest sends several calls in one round trip.
type BatchRequest struct {
	handler.ChainSelector
	Calls []BatchCall `json:"calls"`
}

func (r *BatchRequest) ValidateRequest() error {
	if err := r.ValidateChainSelector(); err != nil {
		return err
	}

	if len(r.Calls) == 0 {
		return errors.New("calls: at least one is required")
	}
	for i := range r.Calls {
		r.Calls[i].Method = strings.TrimSpace(r.Calls[i].Method)
		if r.Calls[i].Method == "" {
			return fmt.Errorf("calls[%d].method is required", i)
		}
	}

	return nil
}
