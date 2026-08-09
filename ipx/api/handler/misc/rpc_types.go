package misc

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/types"
	"github.com/andantan/svmlab/internal/rpc"
)

type SendTransactionRequest struct {
	Transaction string `json:"transaction"`

	tx *types.Transaction
}

func (r *SendTransactionRequest) ValidateRequest() error {
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
	PublicKey string `json:"public_key" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	publicKey *types.PublicKey
}

func (r *AccountRequest) ValidateRequest() error {
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
// Signatures are always verified, so the transaction must be fully signed,
// the same as send. This catches a bad signature before broadcast rather
// than after, which is most of the point of simulating first.
type SimulateTransactionRequest struct {
	Transaction string `json:"transaction"`

	tx *types.Transaction
}

func (r *SimulateTransactionRequest) ValidateRequest() error {
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

// The rent-exemption responses below report the minimum balance an account of
// a given size must hold to persist.
//
// An EVM account has no such floor; here an account below it is subject to
// removal, which is why creating one has to meet the threshold. Each endpoint
// has its own type, so the account kind is the type rather than a field
// repeating the route that was called.

type RentExemptionSystemResponse struct {
	Space    uint64 `json:"space"`
	Lamports string `json:"lamports"`
	SOL      string `json:"sol"`
}

func NewRentExemptionSystemResponse(lamports uint64) *RentExemptionSystemResponse {
	return &RentExemptionSystemResponse{
		Space:    core.SystemAccountSpace,
		Lamports: strconv.FormatUint(lamports, 10),
		SOL:      types.LamportsToSol(lamports),
	}
}

type RentExemptionMintResponse struct {
	Space    uint64 `json:"space"`
	Lamports string `json:"lamports"`
	SOL      string `json:"sol"`
}

func NewRentExemptionMintResponse(lamports uint64) *RentExemptionMintResponse {
	return &RentExemptionMintResponse{
		Space:    core.MintSpace,
		Lamports: strconv.FormatUint(lamports, 10),
		SOL:      types.LamportsToSol(lamports),
	}
}

type RentExemptionTokenResponse struct {
	Space    uint64 `json:"space"`
	Lamports string `json:"lamports"`
	SOL      string `json:"sol"`
}

func NewRentExemptionTokenResponse(lamports uint64) *RentExemptionTokenResponse {
	return &RentExemptionTokenResponse{
		Space:    core.TokenAccountSpace,
		Lamports: strconv.FormatUint(lamports, 10),
		SOL:      types.LamportsToSol(lamports),
	}
}

type RentExemptionStakeResponse struct {
	Space    uint64 `json:"space"`
	Lamports string `json:"lamports"`
	SOL      string `json:"sol"`
}

func NewRentExemptionStakeResponse(lamports uint64) *RentExemptionStakeResponse {
	return &RentExemptionStakeResponse{
		Space:    core.StakeAccountSpace,
		Lamports: strconv.FormatUint(lamports, 10),
		SOL:      types.LamportsToSol(lamports),
	}
}

type RentExemptionVoteResponse struct {
	Space    uint64 `json:"space"`
	Lamports string `json:"lamports"`
	SOL      string `json:"sol"`
}

func NewRentExemptionVoteResponse(lamports uint64) *RentExemptionVoteResponse {
	return &RentExemptionVoteResponse{
		Space:    core.VoteAccountSpace,
		Lamports: strconv.FormatUint(lamports, 10),
		SOL:      types.LamportsToSol(lamports),
	}
}

type RentExemptionSpaceResponse struct {
	Space    uint64 `json:"space"`
	Lamports string `json:"lamports"`
	SOL      string `json:"sol"`
}

func NewRentExemptionSpaceResponse(space, lamports uint64) *RentExemptionSpaceResponse {
	return &RentExemptionSpaceResponse{
		Space:    space,
		Lamports: strconv.FormatUint(lamports, 10),
		SOL:      types.LamportsToSol(lamports),
	}
}

// RentExemptionPublicKeyResponse names the account the size was read from,
// which the other rent endpoints have no equivalent of.
type RentExemptionPublicKeyResponse struct {
	PublicKey string `json:"public_key"`
	Space     uint64 `json:"space"`
	Lamports  string `json:"lamports"`
	SOL       string `json:"sol"`
}

func NewRentExemptionPublicKeyResponse(k *types.PublicKey, space, lamports uint64) *RentExemptionPublicKeyResponse {
	return &RentExemptionPublicKeyResponse{
		PublicKey: k.Base58(),
		Space:     space,
		Lamports:  strconv.FormatUint(lamports, 10),
		SOL:       types.LamportsToSol(lamports),
	}
}

// RentExemptionSpaceRequest asks for the minimum balance for a size given
// directly, rather than one implied by an account kind or read off a live
// account.
type RentExemptionSpaceRequest struct {
	Space string `json:"space" example:"165"`

	space uint64
}

func (r *RentExemptionSpaceRequest) ValidateRequest() error {
	space := strings.TrimSpace(r.Space)
	if space == "" {
		return errors.New("space is required")
	}

	var err error
	if r.space, err = strconv.ParseUint(space, 10, 64); err != nil {
		return errors.New("space: must be a decimal byte count")
	}
	if r.space > core.MaxPermittedDataLength {
		return fmt.Errorf("space: %d bytes exceeds the %d byte limit", r.space, core.MaxPermittedDataLength)
	}

	return nil
}

func (r *RentExemptionSpaceRequest) ToSpace() uint64 {
	return r.space
}

// AirdropAmount is what every airdrop requests.
//
// It is fixed rather than taken from the body because the faucet decides the
// real limit anyway, and asking for more than it allows fails the whole call
// rather than giving less. Half a SOL sits well inside what devnet and testnet
// hand out, so the amount was never a useful choice to offer.
const AirdropAmount = types.LamportsPerSol / 2

// AirdropRequest funds an account on devnet or testnet. Mainnet refuses it.
type AirdropRequest struct {
	PublicKey string `json:"public_key"`

	publicKey *types.PublicKey
}

func (r *AirdropRequest) ValidateRequest() error {
	var err error
	if r.publicKey, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.PublicKey)); err != nil {
		return errors.New("public_key: " + err.Error())
	}

	return nil
}

func (r *AirdropRequest) ToPublicKey() *types.PublicKey {
	return r.publicKey
}

type AirdropResponse struct {
	Signature string `json:"signature"`
	Lamports  string `json:"lamports"`
	SOL       string `json:"sol"`
}

func NewAirdropResponse(sig *types.Signature) *AirdropResponse {
	return &AirdropResponse{
		Signature: sig.Base58(),
		Lamports:  strconv.FormatUint(AirdropAmount, 10),
		SOL:       types.LamportsToSol(AirdropAmount),
	}
}

// RawRequest passes a method straight through to the node.
//
// It exists so that a method this API has not wrapped is still reachable,
// which is most of the point of a lab.
type RawRequest struct {
	Method string `json:"method" example:"getEpochInfo"`
	Params any    `json:"params"`
}

func (r *RawRequest) ValidateRequest() error {
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
	Calls []BatchCall `json:"calls"`
}

func (r *BatchRequest) ValidateRequest() error {
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

// AccountOwnerRequest names the account whose owner to read.
type AccountOwnerRequest struct {
	PublicKey string `json:"public_key" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	publicKey *types.PublicKey
}

func (r *AccountOwnerRequest) ValidateRequest() error {
	var err error
	if r.publicKey, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.PublicKey)); err != nil {
		return errors.New("public_key: " + err.Error())
	}

	return nil
}

func (r *AccountOwnerRequest) ToPublicKey() *types.PublicKey {
	return r.publicKey
}

// AccountOwnerResponse reports who owns an account, and whether that leaves it
// spendable.
//
// SystemOwned is the part worth asking for on its own. Only the owning program
// may debit an account, so an account owned by anything else cannot be moved
// with a System Program transfer, and an account owned by a non-executable
// address cannot be moved at all.
type AccountOwnerResponse struct {
	PublicKey   string `json:"public_key"`
	Exists      bool   `json:"exists"`
	Owner       string `json:"owner"`
	SystemOwned bool   `json:"system_owned"`
}

func NewAccountOwnerResponse(k *types.PublicKey, info *rpc.AccountInfo) *AccountOwnerResponse {
	if info == nil {
		return &AccountOwnerResponse{PublicKey: k.Base58()}
	}

	return &AccountOwnerResponse{
		PublicKey:   k.Base58(),
		Exists:      true,
		Owner:       info.Owner,
		SystemOwned: info.Owner == core.System.ID().Base58(),
	}
}

// NonceRequest names the nonce account to read.
type NonceRequest struct {
	PublicKey string `json:"public_key" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	publicKey *types.PublicKey
}

func (r *NonceRequest) ValidateRequest() error {
	var err error
	if r.publicKey, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.PublicKey)); err != nil {
		return errors.New("public_key: " + err.Error())
	}

	return nil
}

func (r *NonceRequest) ToPublicKey() *types.PublicKey {
	return r.publicKey
}

// NonceResponse reports what a durable nonce account holds.
//
// Initialized is separate from the rest because an account sized for a nonce
// but never initialized is an ordinary intermediate state: create-account
// allocates the 80 bytes, and they stay zero until the initializer writes
// them. Such an account reports the Legacy version and the uninitialized
// state, which is what all-zero bytes decode to.
//
// Nonce is the stored blockhash. A transaction carrying it in place of a
// recent one never expires, which is the whole point of the feature.
type NonceResponse struct {
	PublicKey            string `json:"public_key"`
	Exists               bool   `json:"exists"`
	Initialized          bool   `json:"initialized"`
	Version              uint32 `json:"version"`
	State                uint32 `json:"state"`
	Authority            string `json:"authority"`
	Nonce                string `json:"nonce"`
	LamportsPerSignature string `json:"lamports_per_signature"`
}

func NewNonceResponse(k *types.PublicKey, n *core.NonceAccount) *NonceResponse {
	return &NonceResponse{
		PublicKey:            k.Base58(),
		Exists:               true,
		Initialized:          n.Initialized(),
		Version:              n.Version,
		State:                n.State,
		Authority:            n.Authority.Base58(),
		Nonce:                n.Nonce.Base58(),
		LamportsPerSignature: strconv.FormatUint(n.LamportsPerSignature, 10),
	}
}

type RentExemptionNonceResponse struct {
	Space    uint64 `json:"space"`
	Lamports string `json:"lamports"`
	SOL      string `json:"sol"`
}

func NewRentExemptionNonceResponse(lamports uint64) *RentExemptionNonceResponse {
	return &RentExemptionNonceResponse{
		Space:    core.NonceAccountSpace,
		Lamports: strconv.FormatUint(lamports, 10),
		SOL:      types.LamportsToSol(lamports),
	}
}

// MintRequest names the mint to read.
type MintRequest struct {
	PublicKey string `json:"public_key" example:"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"`

	publicKey *types.PublicKey
}

func (r *MintRequest) ValidateRequest() error {
	var err error
	if r.publicKey, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.PublicKey)); err != nil {
		return errors.New("public_key: " + err.Error())
	}

	return nil
}

func (r *MintRequest) ToPublicKey() *types.PublicKey {
	return r.publicKey
}

// MintResponse reports what a mint account holds.
//
// This is the closest thing Solana has to an ERC-20 contract, and the fields it
// does not have are the point: no balances and no allowances, because those
// live in separate accounts owned by each holder. Supply is the only thing a
// mint knows about who holds what.
//
// MintAuthority and FreezeAuthority are empty when absent, which is different
// from being the zero address. Removing the mint authority is how a supply is
// capped and cannot be undone; a mint that was initialized without a freeze
// authority can never gain one.
type MintResponse struct {
	PublicKey       string `json:"public_key"`
	Exists          bool   `json:"exists"`
	Program         string `json:"program"`
	Initialized     bool   `json:"initialized"`
	Decimals        uint8  `json:"decimals"`
	Supply          string `json:"supply"`
	SupplyUI        string `json:"supply_ui"`
	MintAuthority   string `json:"mint_authority,omitempty"`
	FreezeAuthority string `json:"freeze_authority,omitempty"`
	Mintable        bool   `json:"mintable"`
	Freezable       bool   `json:"freezable"`
}

func NewMintResponse(k *types.PublicKey, program string, m *core.Mint) *MintResponse {
	res := &MintResponse{
		PublicKey:   k.Base58(),
		Exists:      true,
		Program:     program,
		Initialized: m.IsInitialized,
		Decimals:    m.Decimals,
		Supply:      strconv.FormatUint(m.Supply, 10),
		SupplyUI:    types.BaseUnitsToUI(m.Supply, m.Decimals),
		Mintable:    m.Mintable(),
		Freezable:   m.Freezable(),
	}
	if !m.MintAuthority.IsNil() {
		res.MintAuthority = m.MintAuthority.Base58()
	}
	if !m.FreezeAuthority.IsNil() {
		res.FreezeAuthority = m.FreezeAuthority.Base58()
	}

	return res
}

// TokenAccountRequest names the token account to read.
type TokenAccountRequest struct {
	PublicKey string `json:"public_key" example:"4qRgcVrSqs43Jy9n8w7H5EJh8FnRiTFnABjE37Dd3Ae5"`

	publicKey *types.PublicKey
}

func (r *TokenAccountRequest) ValidateRequest() error {
	var err error
	if r.publicKey, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.PublicKey)); err != nil {
		return errors.New("public_key: " + err.Error())
	}

	return nil
}

func (r *TokenAccountRequest) ToPublicKey() *types.PublicKey {
	return r.publicKey
}

// TokenAccountResponse reports what a holder account holds.
//
// Owner is not the runtime owner. That is the token program, which is what may
// write the data; Owner here is the wallet whose signature the program accepts.
//
// Amount has no decimals of its own. It is base units, and AmountUI is it
// placed against the mint's decimals, which is why reading an account means
// reading its mint too.
type TokenAccountResponse struct {
	PublicKey       string `json:"public_key"`
	Exists          bool   `json:"exists"`
	Program         string `json:"program"`
	Mint            string `json:"mint"`
	Owner           string `json:"owner"`
	Amount          string `json:"amount"`
	AmountUI        string `json:"amount_ui,omitempty"`
	Decimals        *uint8 `json:"decimals,omitempty"`
	State           string `json:"state"`
	Frozen          bool   `json:"frozen"`
	Native          bool   `json:"native"`
	RentReserve     string `json:"rent_reserve,omitempty"`
	Delegate        string `json:"delegate,omitempty"`
	DelegatedAmount string `json:"delegated_amount,omitempty"`
	CloseAuthority  string `json:"close_authority,omitempty"`
}

// tokenAccountStateName names the state rather than reporting the byte, since
// frozen is the one a caller has to act on and 2 does not say so.
func tokenAccountStateName(state uint8) string {
	switch state {
	case core.TokenAccountStateUninitialized:
		return "uninitialized"
	case core.TokenAccountStateInitialized:
		return "initialized"
	case core.TokenAccountStateFrozen:
		return "frozen"
	default:
		return "unknown"
	}
}

// NewTokenAccountResponse fills the UI amount only when the mint was read.
//
// decimals is nil when it could not be, which happens when the mint is on a
// different program or has gone. Reporting the base units alone is honest;
// guessing a scale would misstate a balance by orders of magnitude.
func NewTokenAccountResponse(k *types.PublicKey, program string, a *core.TokenAccount, decimals *uint8) *TokenAccountResponse {
	res := &TokenAccountResponse{
		PublicKey: k.Base58(),
		Exists:    true,
		Program:   program,
		Mint:      a.Mint.Base58(),
		Owner:     a.Owner.Base58(),
		Amount:    strconv.FormatUint(a.Amount, 10),
		Decimals:  decimals,
		State:     tokenAccountStateName(a.State),
		Frozen:    a.Frozen(),
		Native:    a.IsNative,
	}
	if decimals != nil {
		res.AmountUI = types.BaseUnitsToUI(a.Amount, *decimals)
	}
	if a.IsNative {
		res.RentReserve = strconv.FormatUint(a.RentReserve, 10)
	}
	if !a.Delegate.IsNil() {
		res.Delegate = a.Delegate.Base58()
		res.DelegatedAmount = strconv.FormatUint(a.Delegated(), 10)
	}
	if !a.CloseAuthority.IsNil() {
		res.CloseAuthority = a.CloseAuthority.Base58()
	}

	return res
}

// TokenAccountsByOwnerRequest lists a wallet's token accounts.
//
// Mint is optional. Naming one narrows the listing to that token, of which a
// wallet may still hold several accounts, since only the associated address is
// unique per pair. Leaving it empty lists everything the wallet holds under the
// chosen program.
//
// TokenProgram defaults to classic Token. It cannot default to both, because
// the two programs hold separate accounts and a wallet may have accounts under
// each; a listing that silently merged them would report accounts that no single
// instruction can touch together.
type TokenAccountsByOwnerRequest struct {
	Owner        string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Mint         string `json:"mint" example:""`
	TokenProgram string `json:"token_program" example:""`

	owner        *types.PublicKey
	mint         *types.PublicKey
	tokenProgram *types.PublicKey
}

func (r *TokenAccountsByOwnerRequest) ValidateRequest() error {
	var err error
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}

	if m := strings.TrimSpace(r.Mint); m != "" {
		if r.mint, err = types.NewPublicKeyFromBase58(m); err != nil {
			return errors.New("mint: " + err.Error())
		}
	}

	r.tokenProgram = core.TokenProgramID
	if p := strings.TrimSpace(r.TokenProgram); p != "" {
		if r.tokenProgram, err = types.NewPublicKeyFromBase58(p); err != nil {
			return errors.New("token_program: " + err.Error())
		}
		if _, err = core.TokenProgram(r.tokenProgram); err != nil {
			return errors.New("token_program: " + err.Error())
		}
	}

	return nil
}

func (r *TokenAccountsByOwnerRequest) OwnerKey() *types.PublicKey { return r.owner }
func (r *TokenAccountsByOwnerRequest) MintKey() *types.PublicKey  { return r.mint }
func (r *TokenAccountsByOwnerRequest) TokenProgramKey() *types.PublicKey {
	return r.tokenProgram
}

// TokenAccountsByOwnerResponse lists what the wallet holds.
type TokenAccountsByOwnerResponse struct {
	Owner    string                  `json:"owner"`
	Program  string                  `json:"program"`
	Mint     string                  `json:"mint,omitempty"`
	Count    int                     `json:"count"`
	Accounts []*TokenAccountResponse `json:"accounts"`
}

func NewTokenAccountsByOwnerResponse(owner, program, mint string, accounts []*TokenAccountResponse) *TokenAccountsByOwnerResponse {
	return &TokenAccountsByOwnerResponse{
		Owner:    owner,
		Program:  program,
		Mint:     mint,
		Count:    len(accounts),
		Accounts: accounts,
	}
}
