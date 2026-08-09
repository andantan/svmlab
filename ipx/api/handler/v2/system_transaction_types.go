package v2

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/types"
)

type SystemTransferRequest struct {
	From     string `json:"from" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	To       string `json:"to"   example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`
	Amount   string `json:"amount" example:"1000000"`
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NonceAccount may be left empty, in which case a recent blockhash is
	// fetched and the transaction expires with it. Naming one builds against
	// the value that account stores instead, so the transaction never expires,
	// and prepends the advance that consumes it. The authority is not a field:
	// it is read from the account, since it is a fact about it rather than a
	// choice.
	NonceAccount string `json:"nonce_account" example:""`

	from         *types.PublicKey
	to           *types.PublicKey
	feePayer     *types.PublicKey
	nonceAccount *types.PublicKey
	amount       uint64
}

func (r *SystemTransferRequest) ValidateRequest() error {
	var err error
	if r.from, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.From)); err != nil {
		return errors.New("from: " + err.Error())
	}
	if r.to, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.To)); err != nil {
		return errors.New("to: " + err.Error())
	}
	if r.from.Equal(r.to) {
		return errors.New("from and to are the same account")
	}

	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
	}

	amount := strings.TrimSpace(r.Amount)
	if amount == "" {
		return errors.New("amount is required")
	}
	if r.amount, err = strconv.ParseUint(amount, 10, 64); err != nil {
		return errors.New("amount: must be a decimal lamport count")
	}
	if r.amount == 0 {
		return errors.New("amount: must be greater than zero")
	}

	return nil
}

func (r *SystemTransferRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *SystemTransferRequest) FromKey() *types.PublicKey {
	return r.from
}

func (r *SystemTransferRequest) ToKey() *types.PublicKey {
	return r.to
}

func (r *SystemTransferRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *SystemTransferRequest) Lamports() uint64 {
	return r.amount
}

type SystemTransferMaxRequest struct {
	From     string `json:"from" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	To       string `json:"to"   example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NonceAccount may be left empty, in which case a recent blockhash is
	// fetched and the transaction expires with it. Naming one builds against
	// the value that account stores instead, so the transaction never expires.
	NonceAccount string `json:"nonce_account" example:""`

	from         *types.PublicKey
	to           *types.PublicKey
	feePayer     *types.PublicKey
	nonceAccount *types.PublicKey
}

func (r *SystemTransferMaxRequest) ValidateRequest() error {
	var err error
	if r.from, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.From)); err != nil {
		return errors.New("from: " + err.Error())
	}
	if r.to, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.To)); err != nil {
		return errors.New("to: " + err.Error())
	}
	if r.from.Equal(r.to) {
		return errors.New("from and to are the same account")
	}

	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *SystemTransferMaxRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *SystemTransferMaxRequest) FromKey() *types.PublicKey {
	return r.from
}

func (r *SystemTransferMaxRequest) ToKey() *types.PublicKey {
	return r.to
}

func (r *SystemTransferMaxRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

// SystemTransferResponse mirrors the v1 build response so that sign and send
// accept it unchanged, and adds the resolved amount and fee.
type SystemTransferResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries
	// a stored value rather than a fetched blockhash and the transaction does
	// not expire. It is reported because the request never named it: advancing
	// the nonce is the first instruction and that key has to sign, and the
	// server read it off the account.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	// Amount and Fee are strings for the same reason the request's amount is:
	// a JSON number is a float, so a lamport count past 2^53 would reach a
	// JavaScript client already rounded.
	Amount    string `json:"amount"`
	AmountSOL string `json:"amount_sol"`
	Fee       string `json:"fee"`
}

func NewSystemTransferResponse(tx *types.Transaction, raw, message []byte, nonceAuthority *types.PublicKey, amount, fee uint64) *SystemTransferResponse {
	// Empty unless the transaction was built against a nonce, which is what
	// makes the field double as the signal that it was.
	authority := ""
	if !nonceAuthority.IsNil() {
		authority = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &SystemTransferResponse{
		Transaction:     base64.StdEncoding.EncodeToString(raw),
		Message:         base64.StdEncoding.EncodeToString(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		Amount:          strconv.FormatUint(amount, 10),
		AmountSOL:       types.LamportsToSol(amount),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

type SystemTransferMaxResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Amount    string `json:"amount"`
	AmountSOL string `json:"amount_sol"`
	Fee       string `json:"fee"`
}

func NewSystemTransferMaxResponse(tx *types.Transaction, raw, message []byte, nonceAuthority *types.PublicKey, amount, fee uint64) *SystemTransferMaxResponse {
	authority := ""
	if !nonceAuthority.IsNil() {
		authority = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &SystemTransferMaxResponse{
		Transaction:     base64.StdEncoding.EncodeToString(raw),
		Message:         base64.StdEncoding.EncodeToString(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		Amount:          strconv.FormatUint(amount, 10),
		AmountSOL:       types.LamportsToSol(amount),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

type SystemCreateAccountRequest struct {
	From       string `json:"from" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	NewAccount string `json:"new_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`
	Owner      string `json:"owner" example:"11111111111111111111111111111111"`
	Lamports   string `json:"lamports" example:"890880"`
	Space      string `json:"space" example:"0"`
	FeePayer   string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NonceAccount may be left empty, in which case a recent blockhash is
	// fetched and the transaction expires with it. Naming one builds against
	// the value that account stores instead, so the transaction never expires.
	NonceAccount string `json:"nonce_account" example:""`

	from         *types.PublicKey
	newAccount   *types.PublicKey
	owner        *types.PublicKey
	feePayer     *types.PublicKey
	nonceAccount *types.PublicKey
	lamports     uint64
	space        uint64
}

func (r *SystemCreateAccountRequest) ValidateRequest() error {
	var err error
	if r.from, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.From)); err != nil {
		return errors.New("from: " + err.Error())
	}
	if r.newAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.NewAccount)); err != nil {
		return errors.New("new_account: " + err.Error())
	}
	if r.from.Equal(r.newAccount) {
		return errors.New("from and new_account are the same account")
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
	}

	lamports := strings.TrimSpace(r.Lamports)
	if lamports == "" {
		return errors.New("lamports is required")
	}
	if r.lamports, err = strconv.ParseUint(lamports, 10, 64); err != nil {
		return errors.New("lamports: must be a decimal lamport count")
	}

	space := strings.TrimSpace(r.Space)
	if space == "" {
		return errors.New("space is required")
	}
	if r.space, err = strconv.ParseUint(space, 10, 64); err != nil {
		return errors.New("space: must be a decimal byte count")
	}
	if r.space > core.MaxPermittedDataLength {
		return fmt.Errorf("space: %d bytes exceeds the %d byte limit", r.space, core.MaxPermittedDataLength)
	}

	return nil
}

func (r *SystemCreateAccountRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *SystemCreateAccountRequest) FromKey() *types.PublicKey {
	return r.from
}

func (r *SystemCreateAccountRequest) NewAccountKey() *types.PublicKey {
	return r.newAccount
}

func (r *SystemCreateAccountRequest) OwnerKey() *types.PublicKey {
	return r.owner
}

func (r *SystemCreateAccountRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *SystemCreateAccountRequest) ToLamports() uint64 {
	return r.lamports
}

func (r *SystemCreateAccountRequest) ToSpace() uint64 {
	return r.space
}

type SystemCreateAccountResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Lamports    string `json:"lamports"`
	LamportsSOL string `json:"lamports_sol"`

	// RentExempt is the floor the requested space had to clear. It is
	// reported because the server had to resolve it to validate lamports
	// anyway, and it is what a caller needs to know to fund the next one
	// without guessing.
	RentExempt string `json:"rent_exempt"`

	Space uint64 `json:"space"`
	Owner string `json:"owner"`
	Fee   string `json:"fee"`
}

func NewSystemCreateAccountResponse(tx *types.Transaction, raw, message []byte, owner, nonceAuthority *types.PublicKey, lamports, rentExempt, space, fee uint64) *SystemCreateAccountResponse {
	authority := ""
	if !nonceAuthority.IsNil() {
		authority = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &SystemCreateAccountResponse{
		Transaction:     base64.StdEncoding.EncodeToString(raw),
		Message:         base64.StdEncoding.EncodeToString(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		Lamports:        strconv.FormatUint(lamports, 10),
		LamportsSOL:     types.LamportsToSol(lamports),
		RentExempt:      strconv.FormatUint(rentExempt, 10),
		Space:           space,
		Owner:           owner.Base58(),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

type SystemAllocateRequest struct {
	Account  string `json:"account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`
	Space    string `json:"space" example:"128"`
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NonceAccount may be left empty, in which case a recent blockhash is
	// fetched and the transaction expires with it. Naming one builds against
	// the value that account stores instead, so the transaction never expires.
	NonceAccount string `json:"nonce_account" example:""`

	account      *types.PublicKey
	feePayer     *types.PublicKey
	nonceAccount *types.PublicKey
	space        uint64
}

func (r *SystemAllocateRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
	}

	space := strings.TrimSpace(r.Space)
	if space == "" {
		return errors.New("space is required")
	}
	if r.space, err = strconv.ParseUint(space, 10, 64); err != nil {
		return errors.New("space: must be a decimal byte count")
	}
	if r.space == 0 {
		return errors.New("space: must be greater than zero")
	}
	if r.space > core.MaxPermittedDataLength {
		return fmt.Errorf("space: %d bytes exceeds the %d byte limit", r.space, core.MaxPermittedDataLength)
	}

	return nil
}

func (r *SystemAllocateRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *SystemAllocateRequest) AccountKey() *types.PublicKey {
	return r.account
}

func (r *SystemAllocateRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *SystemAllocateRequest) ToSpace() uint64 {
	return r.space
}

type SystemAllocateResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Space uint64 `json:"space"`

	// RentExempt is the balance the account must hold once it is this size.
	// Growing an account raises its floor, so a balance that was exempt
	// before the call can stop being exempt after it.
	RentExempt string `json:"rent_exempt"`

	Fee string `json:"fee"`
}

func NewSystemAllocateResponse(tx *types.Transaction, raw, message []byte, nonceAuthority *types.PublicKey, space, rentExempt, fee uint64) *SystemAllocateResponse {
	authority := ""
	if !nonceAuthority.IsNil() {
		authority = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &SystemAllocateResponse{
		Transaction:     base64.StdEncoding.EncodeToString(raw),
		Message:         base64.StdEncoding.EncodeToString(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		Space:           space,
		RentExempt:      strconv.FormatUint(rentExempt, 10),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

type SystemAssignRequest struct {
	Account  string `json:"account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`
	Owner    string `json:"owner" example:"11111111111111111111111111111111"`
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NonceAccount may be left empty, in which case a recent blockhash is
	// fetched and the transaction expires with it. Naming one builds against
	// the value that account stores instead, so the transaction never expires.
	NonceAccount string `json:"nonce_account" example:""`

	account      *types.PublicKey
	owner        *types.PublicKey
	feePayer     *types.PublicKey
	nonceAccount *types.PublicKey
}

func (r *SystemAssignRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *SystemAssignRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *SystemAssignRequest) AccountKey() *types.PublicKey {
	return r.account
}

func (r *SystemAssignRequest) OwnerKey() *types.PublicKey {
	return r.owner
}

func (r *SystemAssignRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

type SystemAssignResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Owner string `json:"owner"`
	Fee   string `json:"fee"`
}

func NewSystemAssignResponse(tx *types.Transaction, raw, message []byte, owner, nonceAuthority *types.PublicKey, fee uint64) *SystemAssignResponse {
	authority := ""
	if !nonceAuthority.IsNil() {
		authority = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &SystemAssignResponse{
		Transaction:     base64.StdEncoding.EncodeToString(raw),
		Message:         base64.StdEncoding.EncodeToString(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		Owner:           owner.Base58(),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// SystemSeedCreateAccountRequest creates an account at a derived address.
//
// The address is not a field: it follows from base, seed, and the owner, and
// the runtime recomputes it and rejects a mismatch. The owner is fixed to the
// System Program for the same reason it is in create-account.
type SystemSeedCreateAccountRequest struct {
	From     string `json:"from" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Base     string `json:"base" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Seed     string `json:"seed" example:"vault-1"`
	Owner    string `json:"owner" example:"11111111111111111111111111111111"`
	Lamports string `json:"lamports" example:"890880"`
	Space    string `json:"space" example:"0"`
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NonceAccount may be left empty, in which case a recent blockhash is
	// fetched and the transaction expires with it. Naming one builds against
	// the value that account stores instead, so the transaction never expires.
	NonceAccount string `json:"nonce_account" example:""`

	from         *types.PublicKey
	base         *types.PublicKey
	owner        *types.PublicKey
	feePayer     *types.PublicKey
	nonceAccount *types.PublicKey
	lamports     uint64
	space        uint64
}

func (r *SystemSeedCreateAccountRequest) ValidateRequest() error {
	var err error
	if r.from, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.From)); err != nil {
		return errors.New("from: " + err.Error())
	}
	if r.base, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Base)); err != nil {
		return errors.New("base: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
	}

	r.Seed = strings.TrimSpace(r.Seed)
	if r.Seed == "" {
		return errors.New("seed is required")
	}
	if len(r.Seed) > types.MaxSeedLength {
		return fmt.Errorf("seed: %d bytes exceeds the %d byte limit", len(r.Seed), types.MaxSeedLength)
	}

	lamports := strings.TrimSpace(r.Lamports)
	if lamports == "" {
		return errors.New("lamports is required")
	}
	if r.lamports, err = strconv.ParseUint(lamports, 10, 64); err != nil {
		return errors.New("lamports: must be a decimal lamport count")
	}

	space := strings.TrimSpace(r.Space)
	if space == "" {
		return errors.New("space is required")
	}
	if r.space, err = strconv.ParseUint(space, 10, 64); err != nil {
		return errors.New("space: must be a decimal byte count")
	}
	if r.space > core.MaxPermittedDataLength {
		return fmt.Errorf("space: %d bytes exceeds the %d byte limit", r.space, core.MaxPermittedDataLength)
	}

	return nil
}

func (r *SystemSeedCreateAccountRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *SystemSeedCreateAccountRequest) FromKey() *types.PublicKey {
	return r.from
}

func (r *SystemSeedCreateAccountRequest) BaseKey() *types.PublicKey {
	return r.base
}

func (r *SystemSeedCreateAccountRequest) OwnerKey() *types.PublicKey {
	return r.owner
}

func (r *SystemSeedCreateAccountRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *SystemSeedCreateAccountRequest) ToLamports() uint64 {
	return r.lamports
}

func (r *SystemSeedCreateAccountRequest) ToSpace() uint64 {
	return r.space
}

type SystemSeedCreateAccountResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	// DerivedAddress is what base, seed, and owner produce. It is the account
	// being created, and it is absent from signers because nobody holds a
	// secret for it.
	DerivedAddress string `json:"derived_address"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Lamports    string `json:"lamports"`
	LamportsSOL string `json:"lamports_sol"`
	RentExempt  string `json:"rent_exempt"`
	Space       uint64 `json:"space"`
	Owner       string `json:"owner"`
	Fee         string `json:"fee"`
}

func NewSystemSeedCreateAccountResponse(tx *types.Transaction, raw, message []byte, derived, owner, nonceAuthority *types.PublicKey, lamports, rentExempt, space, fee uint64) *SystemSeedCreateAccountResponse {
	authority := ""
	if !nonceAuthority.IsNil() {
		authority = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &SystemSeedCreateAccountResponse{
		Transaction:     base64.StdEncoding.EncodeToString(raw),
		Message:         base64.StdEncoding.EncodeToString(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		DerivedAddress:  derived.Base58(),
		NonceAuthority:  authority,
		Lamports:        strconv.FormatUint(lamports, 10),
		LamportsSOL:     types.LamportsToSol(lamports),
		RentExempt:      strconv.FormatUint(rentExempt, 10),
		Space:           space,
		Owner:           owner.Base58(),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// SystemSeedTransferRequest moves lamports out of a derived address.
//
// Owner is the one the address was derived for, not a new one. It is often the
// System Program, but an address derived for a program it has not been
// assigned to yet is still System-owned and still spendable this way.
type SystemSeedTransferRequest struct {
	Base     string `json:"base" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Seed     string `json:"seed" example:"vault-1"`
	Owner    string `json:"owner" example:"11111111111111111111111111111111"`
	To       string `json:"to" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`
	Amount   string `json:"amount" example:"1000000"`
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NonceAccount may be left empty, in which case a recent blockhash is
	// fetched and the transaction expires with it. Naming one builds against
	// the value that account stores instead, so the transaction never expires.
	NonceAccount string `json:"nonce_account" example:""`

	base         *types.PublicKey
	owner        *types.PublicKey
	to           *types.PublicKey
	feePayer     *types.PublicKey
	nonceAccount *types.PublicKey
	amount       uint64
}

func (r *SystemSeedTransferRequest) ValidateRequest() error {
	var err error
	if r.base, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Base)); err != nil {
		return errors.New("base: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}
	if r.to, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.To)); err != nil {
		return errors.New("to: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
	}

	r.Seed = strings.TrimSpace(r.Seed)
	if r.Seed == "" {
		return errors.New("seed is required")
	}
	if len(r.Seed) > types.MaxSeedLength {
		return fmt.Errorf("seed: %d bytes exceeds the %d byte limit", len(r.Seed), types.MaxSeedLength)
	}

	amount := strings.TrimSpace(r.Amount)
	if amount == "" {
		return errors.New("amount is required")
	}
	if r.amount, err = strconv.ParseUint(amount, 10, 64); err != nil {
		return errors.New("amount: must be a decimal lamport count")
	}
	if r.amount == 0 {
		return errors.New("amount: must be greater than zero")
	}

	return nil
}

func (r *SystemSeedTransferRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *SystemSeedTransferRequest) BaseKey() *types.PublicKey {
	return r.base
}

func (r *SystemSeedTransferRequest) OwnerKey() *types.PublicKey {
	return r.owner
}

func (r *SystemSeedTransferRequest) ToKey() *types.PublicKey {
	return r.to
}

func (r *SystemSeedTransferRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *SystemSeedTransferRequest) ToLamports() uint64 {
	return r.amount
}

type SystemSeedTransferResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`
	DerivedAddress  string   `json:"derived_address"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Amount    string `json:"amount"`
	AmountSOL string `json:"amount_sol"`
	Fee       string `json:"fee"`
}

func NewSystemSeedTransferResponse(tx *types.Transaction, raw, message []byte, derived, nonceAuthority *types.PublicKey, amount, fee uint64) *SystemSeedTransferResponse {
	authority := ""
	if !nonceAuthority.IsNil() {
		authority = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &SystemSeedTransferResponse{
		Transaction:     base64.StdEncoding.EncodeToString(raw),
		Message:         base64.StdEncoding.EncodeToString(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		DerivedAddress:  derived.Base58(),
		NonceAuthority:  authority,
		Amount:          strconv.FormatUint(amount, 10),
		AmountSOL:       types.LamportsToSol(amount),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

type SystemSeedAllocateRequest struct {
	Base     string `json:"base" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Seed     string `json:"seed" example:"vault-1"`
	Owner    string `json:"owner" example:"11111111111111111111111111111111"`
	Space    string `json:"space" example:"165"`
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NonceAccount may be left empty, in which case a recent blockhash is
	// fetched and the transaction expires with it. Naming one builds against
	// the value that account stores instead, so the transaction never expires.
	NonceAccount string `json:"nonce_account" example:""`

	base         *types.PublicKey
	owner        *types.PublicKey
	feePayer     *types.PublicKey
	nonceAccount *types.PublicKey
	space        uint64
}

func (r *SystemSeedAllocateRequest) ValidateRequest() error {
	var err error
	if r.base, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Base)); err != nil {
		return errors.New("base: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
	}

	r.Seed = strings.TrimSpace(r.Seed)
	if r.Seed == "" {
		return errors.New("seed is required")
	}
	if len(r.Seed) > types.MaxSeedLength {
		return fmt.Errorf("seed: %d bytes exceeds the %d byte limit", len(r.Seed), types.MaxSeedLength)
	}

	space := strings.TrimSpace(r.Space)
	if space == "" {
		return errors.New("space is required")
	}
	if r.space, err = strconv.ParseUint(space, 10, 64); err != nil {
		return errors.New("space: must be a decimal byte count")
	}
	if r.space == 0 {
		return errors.New("space: must be greater than zero")
	}
	if r.space > core.MaxPermittedDataLength {
		return fmt.Errorf("space: %d bytes exceeds the %d byte limit", r.space, core.MaxPermittedDataLength)
	}

	return nil
}

func (r *SystemSeedAllocateRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *SystemSeedAllocateRequest) BaseKey() *types.PublicKey {
	return r.base
}

func (r *SystemSeedAllocateRequest) OwnerKey() *types.PublicKey {
	return r.owner
}

func (r *SystemSeedAllocateRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *SystemSeedAllocateRequest) ToSpace() uint64 {
	return r.space
}

type SystemSeedAllocateResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`
	DerivedAddress  string   `json:"derived_address"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Space      uint64 `json:"space"`
	RentExempt string `json:"rent_exempt"`
	Fee        string `json:"fee"`
}

func NewSystemSeedAllocateResponse(tx *types.Transaction, raw, message []byte, derived, nonceAuthority *types.PublicKey, space, rentExempt, fee uint64) *SystemSeedAllocateResponse {
	authority := ""
	if !nonceAuthority.IsNil() {
		authority = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &SystemSeedAllocateResponse{
		Transaction:     base64.StdEncoding.EncodeToString(raw),
		Message:         base64.StdEncoding.EncodeToString(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		DerivedAddress:  derived.Base58(),
		NonceAuthority:  authority,
		Space:           space,
		RentExempt:      strconv.FormatUint(rentExempt, 10),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// SystemSeedAssignRequest hands a derived account to the program it was
// derived for.
//
// There is no separate new-owner field. One owner does both jobs: it is what
// the address is derived from and what the account is assigned to, so an
// account can only be handed to the program its own address already encodes.
type SystemSeedAssignRequest struct {
	Base     string `json:"base" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Seed     string `json:"seed" example:"vault-1"`
	Owner    string `json:"owner" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NonceAccount may be left empty, in which case a recent blockhash is
	// fetched and the transaction expires with it. Naming one builds against
	// the value that account stores instead, so the transaction never expires.
	NonceAccount string `json:"nonce_account" example:""`

	base         *types.PublicKey
	owner        *types.PublicKey
	feePayer     *types.PublicKey
	nonceAccount *types.PublicKey
}

func (r *SystemSeedAssignRequest) ValidateRequest() error {
	var err error
	if r.base, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Base)); err != nil {
		return errors.New("base: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
	}

	r.Seed = strings.TrimSpace(r.Seed)
	if r.Seed == "" {
		return errors.New("seed is required")
	}
	if len(r.Seed) > types.MaxSeedLength {
		return fmt.Errorf("seed: %d bytes exceeds the %d byte limit", len(r.Seed), types.MaxSeedLength)
	}

	return nil
}

func (r *SystemSeedAssignRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *SystemSeedAssignRequest) BaseKey() *types.PublicKey {
	return r.base
}

func (r *SystemSeedAssignRequest) OwnerKey() *types.PublicKey {
	return r.owner
}

func (r *SystemSeedAssignRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

type SystemSeedAssignResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`
	DerivedAddress  string   `json:"derived_address"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Owner string `json:"owner"`
	Fee   string `json:"fee"`
}

func NewSystemSeedAssignResponse(tx *types.Transaction, raw, message []byte, derived, owner, nonceAuthority *types.PublicKey, fee uint64) *SystemSeedAssignResponse {
	authority := ""
	if !nonceAuthority.IsNil() {
		authority = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &SystemSeedAssignResponse{
		Transaction:     base64.StdEncoding.EncodeToString(raw),
		Message:         base64.StdEncoding.EncodeToString(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		DerivedAddress:  derived.Base58(),
		NonceAuthority:  authority,
		Owner:           owner.Base58(),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

type SystemSeedTransferMaxRequest struct {
	Base     string `json:"base" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Seed     string `json:"seed" example:"vault-1"`
	Owner    string `json:"owner" example:"11111111111111111111111111111111"`
	To       string `json:"to" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NonceAccount may be left empty, in which case a recent blockhash is
	// fetched and the transaction expires with it. Naming one builds against
	// the value that account stores instead, so the transaction never expires.
	NonceAccount string `json:"nonce_account" example:""`

	base         *types.PublicKey
	owner        *types.PublicKey
	to           *types.PublicKey
	feePayer     *types.PublicKey
	nonceAccount *types.PublicKey
}

func (r *SystemSeedTransferMaxRequest) ValidateRequest() error {
	var err error
	if r.base, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Base)); err != nil {
		return errors.New("base: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}
	if r.to, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.To)); err != nil {
		return errors.New("to: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
	}

	r.Seed = strings.TrimSpace(r.Seed)
	if r.Seed == "" {
		return errors.New("seed is required")
	}
	if len(r.Seed) > types.MaxSeedLength {
		return fmt.Errorf("seed: %d bytes exceeds the %d byte limit", len(r.Seed), types.MaxSeedLength)
	}

	return nil
}

func (r *SystemSeedTransferMaxRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *SystemSeedTransferMaxRequest) BaseKey() *types.PublicKey {
	return r.base
}

func (r *SystemSeedTransferMaxRequest) OwnerKey() *types.PublicKey {
	return r.owner
}

func (r *SystemSeedTransferMaxRequest) ToKey() *types.PublicKey {
	return r.to
}

func (r *SystemSeedTransferMaxRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

type SystemSeedTransferMaxResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`
	DerivedAddress  string   `json:"derived_address"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Amount    string `json:"amount"`
	AmountSOL string `json:"amount_sol"`
	Fee       string `json:"fee"`
}

func NewSystemSeedTransferMaxResponse(tx *types.Transaction, raw, message []byte, derived, nonceAuthority *types.PublicKey, amount, fee uint64) *SystemSeedTransferMaxResponse {
	authority := ""
	if !nonceAuthority.IsNil() {
		authority = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &SystemSeedTransferMaxResponse{
		Transaction:     base64.StdEncoding.EncodeToString(raw),
		Message:         base64.StdEncoding.EncodeToString(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		DerivedAddress:  derived.Base58(),
		NonceAuthority:  authority,
		Amount:          strconv.FormatUint(amount, 10),
		AmountSOL:       types.LamportsToSol(amount),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// SystemNonceCreateRequest creates and initializes a durable nonce account in
// one transaction.
//
// Neither the size nor the funding is a field. A nonce account is always
// exactly NonceAccountSpace bytes, and the amount that has to sit in it is the
// rent-exempt minimum for that size, so both follow from what the account is
// rather than from a choice the caller makes.
type SystemNonceCreateRequest struct {
	From string `json:"from" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NewNonceAccount is the account being created. It is named apart from
	// NonceAccount because both are nonce accounts and only their roles
	// differ: this one is what the transaction produces, that one is what the
	// transaction is built against.
	NewNonceAccount string `json:"new_nonce_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	FeePayer  string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NonceAccount may be left empty, in which case a recent blockhash is
	// fetched and the transaction expires with it. Naming one builds against
	// the value that account stores instead, so the transaction never expires.
	// It has to be an account other than the one being created.
	NonceAccount string `json:"nonce_account" example:""`

	from            *types.PublicKey
	newNonceAccount *types.PublicKey
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	nonceAccount    *types.PublicKey
}

func (r *SystemNonceCreateRequest) ValidateRequest() error {
	var err error
	if r.from, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.From)); err != nil {
		return errors.New("from: " + err.Error())
	}
	if r.newNonceAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.NewNonceAccount)); err != nil {
		return errors.New("new_nonce_account: " + err.Error())
	}
	if r.from.Equal(r.newNonceAccount) {
		return errors.New("from and new_nonce_account are the same account")
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
		if r.nonceAccount.Equal(r.newNonceAccount) {
			return errors.New("nonce_account: cannot be the account being created, which holds no nonce yet")
		}
	}

	return nil
}

func (r *SystemNonceCreateRequest) FromKey() *types.PublicKey {
	return r.from
}

func (r *SystemNonceCreateRequest) NewNonceAccountKey() *types.PublicKey {
	return r.newNonceAccount
}

func (r *SystemNonceCreateRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *SystemNonceCreateRequest) AuthorityKey() *types.PublicKey {
	return r.authority
}

func (r *SystemNonceCreateRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

type SystemNonceCreateResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`
	NewNonceAccount string   `json:"new_nonce_account"`
	Authority       string   `json:"authority"`

	// NonceAuthority belongs to the account named in the request's
	// nonce_account, not to the one being created, and is present only when
	// one was named. Authority above is what the new account gains.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Lamports    string `json:"lamports"`
	LamportsSOL string `json:"lamports_sol"`
	Space       uint64 `json:"space"`
	Fee         string `json:"fee"`
}

func NewSystemNonceCreateResponse(tx *types.Transaction, raw, message []byte, newNonceAccount, authority, nonceAuthority *types.PublicKey, lamports, fee uint64) *SystemNonceCreateResponse {
	nonceAuthorityBase58 := ""
	if !nonceAuthority.IsNil() {
		nonceAuthorityBase58 = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &SystemNonceCreateResponse{
		Transaction:     base64.StdEncoding.EncodeToString(raw),
		Message:         base64.StdEncoding.EncodeToString(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NewNonceAccount: newNonceAccount.Base58(),
		Authority:       authority.Base58(),
		NonceAuthority:  nonceAuthorityBase58,
		Lamports:        strconv.FormatUint(lamports, 10),
		LamportsSOL:     types.LamportsToSol(lamports),
		Space:           core.NonceAccountSpace,
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// SystemNonceInitializeRequest turns an account that already exists into a
// durable nonce account.
//
// nonce/create-account covers the ordinary case in one transaction. This one
// is for an address that cannot be created any more: CreateAccount refuses an
// account that already holds lamports, so an address someone funded first can
// only become a nonce account through the initializer alone.
type SystemNonceInitializeRequest struct {
	// NewNonceAccount already exists but is not a nonce account yet, which is
	// what this makes it. It is named apart from NonceAccount because both are
	// nonce accounts by the end and only their roles differ.
	NewNonceAccount string `json:"new_nonce_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	FeePayer  string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NonceAccount may be left empty, in which case a recent blockhash is
	// fetched and the transaction expires with it. Naming one builds against
	// the value that account stores instead, so the transaction never expires.
	// It has to be an account other than the one being initialized, which
	// holds no nonce to build against yet.
	NonceAccount string `json:"nonce_account" example:""`

	newNonceAccount *types.PublicKey
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	nonceAccount    *types.PublicKey
}

func (r *SystemNonceInitializeRequest) ValidateRequest() error {
	var err error
	if r.newNonceAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.NewNonceAccount)); err != nil {
		return errors.New("new_nonce_account: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
		if r.nonceAccount.Equal(r.newNonceAccount) {
			return errors.New("nonce_account: cannot be the account being initialized, which holds no nonce yet")
		}
	}

	return nil
}

func (r *SystemNonceInitializeRequest) NewNonceAccountKey() *types.PublicKey {
	return r.newNonceAccount
}

func (r *SystemNonceInitializeRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *SystemNonceInitializeRequest) AuthorityKey() *types.PublicKey {
	return r.authority
}

func (r *SystemNonceInitializeRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

type SystemNonceInitializeResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`
	NewNonceAccount string   `json:"new_nonce_account"`
	Authority       string   `json:"authority"`

	// NonceAuthority belongs to the account named in the request's
	// nonce_account, not to the one being initialized, and is present only
	// when one was named. Authority above is what the new account gains.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Fee string `json:"fee"`
}

func NewSystemNonceInitializeResponse(tx *types.Transaction, raw, message []byte, newNonceAccount, authority, nonceAuthority *types.PublicKey, fee uint64) *SystemNonceInitializeResponse {
	nonceAuthorityBase58 := ""
	if !nonceAuthority.IsNil() {
		nonceAuthorityBase58 = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &SystemNonceInitializeResponse{
		Transaction:     base64.StdEncoding.EncodeToString(raw),
		Message:         base64.StdEncoding.EncodeToString(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NewNonceAccount: newNonceAccount.Base58(),
		Authority:       authority.Base58(),
		NonceAuthority:  nonceAuthorityBase58,
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// SystemNonceAdvanceRequest rotates the value stored in a nonce account.
//
// Advancing is what consumes a nonce. A transaction built against one carries
// it in place of a recent blockhash and runs this as its first instruction, so
// the value it was built for is gone by the time it finishes and the same
// transaction cannot land twice.
type SystemNonceAdvanceRequest struct {
	// TargetNonceAccount is the account whose stored value this rotates. It is
	// named apart from NonceAccount because both are nonce accounts and only
	// their roles differ: this one is what the instruction acts on, that one
	// is what the transaction is built against.
	TargetNonceAccount string `json:"target_nonce_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	FeePayer  string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NonceAccount may be left empty, in which case a recent blockhash is
	// fetched and the transaction expires with it. Naming one builds against
	// the value that account stores instead, so the transaction never expires.
	// It has to be an account other than the target: the runtime refuses a
	// transaction that advances the same nonce twice.
	NonceAccount string `json:"nonce_account" example:""`

	targetNonceAccount *types.PublicKey
	authority          *types.PublicKey
	feePayer           *types.PublicKey
	nonceAccount       *types.PublicKey
}

func (r *SystemNonceAdvanceRequest) ValidateRequest() error {
	var err error
	if r.targetNonceAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TargetNonceAccount)); err != nil {
		return errors.New("target_nonce_account: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
		if r.nonceAccount.Equal(r.targetNonceAccount) {
			return errors.New("nonce_account: cannot be the target, since a transaction may advance a nonce only once")
		}
	}

	return nil
}

func (r *SystemNonceAdvanceRequest) TargetNonceAccountKey() *types.PublicKey {
	return r.targetNonceAccount
}

func (r *SystemNonceAdvanceRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *SystemNonceAdvanceRequest) AuthorityKey() *types.PublicKey {
	return r.authority
}

func (r *SystemNonceAdvanceRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

type SystemNonceAdvanceResponse struct {
	Transaction        string   `json:"transaction"`
	Message            string   `json:"message"`
	RecentBlockhash    string   `json:"recent_blockhash"`
	AccountKeys        []string `json:"account_keys"`
	Signers            []string `json:"signers"`
	TargetNonceAccount string   `json:"target_nonce_account"`
	Authority          string   `json:"authority"`

	// NonceAuthority belongs to the account named in the request's
	// nonce_account, not to the target, and is present only when one was
	// named. Authority above is the target's.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	// CurrentNonce is what the target holds now, before this transaction
	// lands. Any transaction already built against it stops being valid once
	// this one executes.
	CurrentNonce string `json:"current_nonce"`

	Fee string `json:"fee"`
}

func NewSystemNonceAdvanceResponse(tx *types.Transaction, raw, message []byte, targetNonceAccount, authority, nonceAuthority *types.PublicKey, currentNonce *types.Hash, fee uint64) *SystemNonceAdvanceResponse {
	nonceAuthorityBase58 := ""
	if !nonceAuthority.IsNil() {
		nonceAuthorityBase58 = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &SystemNonceAdvanceResponse{
		Transaction:        base64.StdEncoding.EncodeToString(raw),
		Message:            base64.StdEncoding.EncodeToString(message),
		RecentBlockhash:    tx.Message.RecentBlockhash.Base58(),
		AccountKeys:        keys,
		Signers:            signers,
		TargetNonceAccount: targetNonceAccount.Base58(),
		Authority:          authority.Base58(),
		NonceAuthority:     nonceAuthorityBase58,
		CurrentNonce:       currentNonce.Base58(),
		Fee:                strconv.FormatUint(fee, 10),
	}
}

// SystemNonceWithdrawRequest takes part of a nonce account's balance.
//
// Only part of it. Taking everything closes the account and the runtime
// applies a further rule to that, so it has its own endpoint: what stays here
// has to keep the account rent exempt at its size, or it would be subject to
// removal while still holding a nonce something was built against.
type SystemNonceWithdrawRequest struct {
	// TargetNonceAccount is the account being withdrawn from. It is named
	// apart from NonceAccount because both are nonce accounts and only their
	// roles differ: this one is what the instruction acts on, that one is what
	// the transaction is built against.
	TargetNonceAccount string `json:"target_nonce_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	To        string `json:"to" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Amount    string `json:"amount" example:"1000000"`
	FeePayer  string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NonceAccount may be left empty, in which case a recent blockhash is
	// fetched and the transaction expires with it. Naming one builds against
	// the value that account stores instead, so the transaction never expires.
	// It has to be an account other than the target: the runtime refuses a
	// transaction that advances the same nonce twice.
	NonceAccount string `json:"nonce_account" example:""`

	targetNonceAccount *types.PublicKey
	authority          *types.PublicKey
	to                 *types.PublicKey
	feePayer           *types.PublicKey
	nonceAccount       *types.PublicKey
	amount             uint64
}

func (r *SystemNonceWithdrawRequest) ValidateRequest() error {
	var err error
	if r.targetNonceAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TargetNonceAccount)); err != nil {
		return errors.New("target_nonce_account: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.to, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.To)); err != nil {
		return errors.New("to: " + err.Error())
	}
	if r.targetNonceAccount.Equal(r.to) {
		return errors.New("target_nonce_account and to are the same account")
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
		if r.nonceAccount.Equal(r.targetNonceAccount) {
			return errors.New("nonce_account: cannot be the target, since a transaction may advance a nonce only once")
		}
	}

	amount := strings.TrimSpace(r.Amount)
	if amount == "" {
		return errors.New("amount is required")
	}
	if r.amount, err = strconv.ParseUint(amount, 10, 64); err != nil {
		return errors.New("amount: must be a decimal lamport count")
	}
	if r.amount == 0 {
		return errors.New("amount: must be greater than zero")
	}

	return nil
}

func (r *SystemNonceWithdrawRequest) TargetNonceAccountKey() *types.PublicKey {
	return r.targetNonceAccount
}

func (r *SystemNonceWithdrawRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *SystemNonceWithdrawRequest) AuthorityKey() *types.PublicKey {
	return r.authority
}

func (r *SystemNonceWithdrawRequest) ToKey() *types.PublicKey {
	return r.to
}

func (r *SystemNonceWithdrawRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *SystemNonceWithdrawRequest) ToLamports() uint64 {
	return r.amount
}

type SystemNonceWithdrawResponse struct {
	Transaction        string   `json:"transaction"`
	Message            string   `json:"message"`
	RecentBlockhash    string   `json:"recent_blockhash"`
	AccountKeys        []string `json:"account_keys"`
	Signers            []string `json:"signers"`
	TargetNonceAccount string   `json:"target_nonce_account"`
	Authority          string   `json:"authority"`

	// NonceAuthority belongs to the account named in the request's
	// nonce_account, not to the target, and is present only when one was
	// named. Authority above is the target's.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Amount    string `json:"amount"`
	AmountSOL string `json:"amount_sol"`

	// Remaining is what the target keeps, which has to stay at or above the
	// rent-exempt minimum for its size.
	Remaining string `json:"remaining"`

	Fee string `json:"fee"`
}

func NewSystemNonceWithdrawResponse(tx *types.Transaction, raw, message []byte, targetNonceAccount, authority, nonceAuthority *types.PublicKey, amount, remaining, fee uint64) *SystemNonceWithdrawResponse {
	nonceAuthorityBase58 := ""
	if !nonceAuthority.IsNil() {
		nonceAuthorityBase58 = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &SystemNonceWithdrawResponse{
		Transaction:        base64.StdEncoding.EncodeToString(raw),
		Message:            base64.StdEncoding.EncodeToString(message),
		RecentBlockhash:    tx.Message.RecentBlockhash.Base58(),
		AccountKeys:        keys,
		Signers:            signers,
		TargetNonceAccount: targetNonceAccount.Base58(),
		Authority:          authority.Base58(),
		NonceAuthority:     nonceAuthorityBase58,
		Amount:             strconv.FormatUint(amount, 10),
		AmountSOL:          types.LamportsToSol(amount),
		Remaining:          strconv.FormatUint(remaining, 10),
		Fee:                strconv.FormatUint(fee, 10),
	}
}

// SystemNonceWithdrawMaxRequest empties a nonce account, which closes it.
//
// There is no amount: taking anything less leaves the account open and is what
// nonce/withdraw does. The fee payer cannot be the nonce account itself, since
// the balance being withdrawn is the same balance the fee would come from.
type SystemNonceWithdrawMaxRequest struct {
	// TargetNonceAccount is the account being emptied and thereby closed. It
	// is named apart from NonceAccount because both are nonce accounts and
	// only their roles differ: this one is what the instruction acts on, that
	// one is what the transaction is built against.
	TargetNonceAccount string `json:"target_nonce_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	To        string `json:"to" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	FeePayer  string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NonceAccount may be left empty, in which case a recent blockhash is
	// fetched and the transaction expires with it. Naming one builds against
	// the value that account stores instead, so the transaction never expires.
	// It has to be an account other than the target, which could not be closed
	// anyway once this transaction has just advanced it.
	NonceAccount string `json:"nonce_account" example:""`

	targetNonceAccount *types.PublicKey
	authority          *types.PublicKey
	to                 *types.PublicKey
	feePayer           *types.PublicKey
	nonceAccount       *types.PublicKey
}

func (r *SystemNonceWithdrawMaxRequest) ValidateRequest() error {
	var err error
	if r.targetNonceAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TargetNonceAccount)); err != nil {
		return errors.New("target_nonce_account: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.to, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.To)); err != nil {
		return errors.New("to: " + err.Error())
	}
	if r.targetNonceAccount.Equal(r.to) {
		return errors.New("target_nonce_account and to are the same account")
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}
	if r.targetNonceAccount.Equal(r.feePayer) {
		return errors.New("fee_payer: cannot be the target nonce account, whose whole balance is being withdrawn")
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
		if r.nonceAccount.Equal(r.targetNonceAccount) {
			return errors.New("nonce_account: cannot be the target, whose stored value this transaction would have just advanced to the current blockhash, which blocks closing it")
		}
	}

	return nil
}

func (r *SystemNonceWithdrawMaxRequest) TargetNonceAccountKey() *types.PublicKey {
	return r.targetNonceAccount
}

func (r *SystemNonceWithdrawMaxRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *SystemNonceWithdrawMaxRequest) AuthorityKey() *types.PublicKey {
	return r.authority
}

func (r *SystemNonceWithdrawMaxRequest) ToKey() *types.PublicKey {
	return r.to
}

func (r *SystemNonceWithdrawMaxRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

type SystemNonceWithdrawMaxResponse struct {
	Transaction        string   `json:"transaction"`
	Message            string   `json:"message"`
	RecentBlockhash    string   `json:"recent_blockhash"`
	AccountKeys        []string `json:"account_keys"`
	Signers            []string `json:"signers"`
	TargetNonceAccount string   `json:"target_nonce_account"`
	Authority          string   `json:"authority"`

	// NonceAuthority belongs to the account named in the request's
	// nonce_account, not to the target, and is present only when one was
	// named. Authority above is the target's.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Amount    string `json:"amount"`
	AmountSOL string `json:"amount_sol"`
	Fee       string `json:"fee"`
}

func NewSystemNonceWithdrawMaxResponse(tx *types.Transaction, raw, message []byte, targetNonceAccount, authority, nonceAuthority *types.PublicKey, amount, fee uint64) *SystemNonceWithdrawMaxResponse {
	nonceAuthorityBase58 := ""
	if !nonceAuthority.IsNil() {
		nonceAuthorityBase58 = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &SystemNonceWithdrawMaxResponse{
		Transaction:        base64.StdEncoding.EncodeToString(raw),
		Message:            base64.StdEncoding.EncodeToString(message),
		RecentBlockhash:    tx.Message.RecentBlockhash.Base58(),
		AccountKeys:        keys,
		Signers:            signers,
		TargetNonceAccount: targetNonceAccount.Base58(),
		Authority:          authority.Base58(),
		NonceAuthority:     nonceAuthorityBase58,
		Amount:             strconv.FormatUint(amount, 10),
		AmountSOL:          types.LamportsToSol(amount),
		Fee:                strconv.FormatUint(fee, 10),
	}
}

// SystemNonceAuthorizeRequest hands control of a nonce account to another key.
//
// The stored nonce and the balance are untouched. Only who may advance and
// withdraw changes, which also invalidates anything the old authority signed
// but never submitted: such a transaction advances the nonce as its first
// instruction, and that now needs a signature the old authority cannot give.
type SystemNonceAuthorizeRequest struct {
	// TargetNonceAccount is the account whose authority changes. It is named
	// apart from NonceAccount because both are nonce accounts and only their
	// roles differ: this one is what the instruction acts on, that one is what
	// the transaction is built against.
	TargetNonceAccount string `json:"target_nonce_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	Authority    string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	NewAuthority string `json:"new_authority" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`
	FeePayer     string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NonceAccount may be left empty, in which case a recent blockhash is
	// fetched and the transaction expires with it. Naming one builds against
	// the value that account stores instead, so the transaction never expires.
	// It has to be an account other than the target: the runtime refuses a
	// transaction that advances the same nonce twice.
	NonceAccount string `json:"nonce_account" example:""`

	targetNonceAccount *types.PublicKey
	authority          *types.PublicKey
	newAuthority       *types.PublicKey
	feePayer           *types.PublicKey
	nonceAccount       *types.PublicKey
}

func (r *SystemNonceAuthorizeRequest) ValidateRequest() error {
	var err error
	if r.targetNonceAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TargetNonceAccount)); err != nil {
		return errors.New("target_nonce_account: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.newAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.NewAuthority)); err != nil {
		return errors.New("new_authority: " + err.Error())
	}
	if r.authority.Equal(r.newAuthority) {
		return errors.New("new_authority: is already the authority")
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
		if r.nonceAccount.Equal(r.targetNonceAccount) {
			return errors.New("nonce_account: cannot be the target, since a transaction may advance a nonce only once")
		}
	}

	return nil
}

func (r *SystemNonceAuthorizeRequest) TargetNonceAccountKey() *types.PublicKey {
	return r.targetNonceAccount
}

func (r *SystemNonceAuthorizeRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *SystemNonceAuthorizeRequest) AuthorityKey() *types.PublicKey {
	return r.authority
}

func (r *SystemNonceAuthorizeRequest) NewAuthorityKey() *types.PublicKey {
	return r.newAuthority
}

func (r *SystemNonceAuthorizeRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

type SystemNonceAuthorizeResponse struct {
	Transaction        string   `json:"transaction"`
	Message            string   `json:"message"`
	RecentBlockhash    string   `json:"recent_blockhash"`
	AccountKeys        []string `json:"account_keys"`
	Signers            []string `json:"signers"`
	TargetNonceAccount string   `json:"target_nonce_account"`
	Authority          string   `json:"authority"`
	NewAuthority       string   `json:"new_authority"`

	// NonceAuthority belongs to the account named in the request's
	// nonce_account, not to the target, and is present only when one was
	// named. Authority above is the target's.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Fee string `json:"fee"`
}

func NewSystemNonceAuthorizeResponse(tx *types.Transaction, raw, message []byte, targetNonceAccount, authority, newAuthority, nonceAuthority *types.PublicKey, fee uint64) *SystemNonceAuthorizeResponse {
	nonceAuthorityBase58 := ""
	if !nonceAuthority.IsNil() {
		nonceAuthorityBase58 = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &SystemNonceAuthorizeResponse{
		Transaction:        base64.StdEncoding.EncodeToString(raw),
		Message:            base64.StdEncoding.EncodeToString(message),
		RecentBlockhash:    tx.Message.RecentBlockhash.Base58(),
		AccountKeys:        keys,
		Signers:            signers,
		TargetNonceAccount: targetNonceAccount.Base58(),
		Authority:          authority.Base58(),
		NewAuthority:       newAuthority.Base58(),
		NonceAuthority:     nonceAuthorityBase58,
		Fee:                strconv.FormatUint(fee, 10),
	}
}

// SystemNonceUpgradeRequest migrates a Legacy nonce account to the current
// version.
//
// There is no authority field because nothing signs: the migration is not a
// privileged operation, only a rewrite of how the same state is stored, so
// anyone willing to pay the fee may upgrade anyone's account.
//
// Nothing this project creates can be upgraded. Initialize has written the
// current version for a long time, so only accounts predating that change are
// Legacy, and no instruction can produce one now.
type SystemNonceUpgradeRequest struct {
	// TargetNonceAccount is the Legacy account being migrated. It is named
	// apart from NonceAccount because both are nonce accounts and only their
	// roles differ: this one is what the instruction acts on, that one is what
	// the transaction is built against.
	TargetNonceAccount string `json:"target_nonce_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NonceAccount may be left empty, in which case a recent blockhash is
	// fetched and the transaction expires with it. Naming one builds against
	// the value that account stores instead, so the transaction never expires.
	// It has to be an account other than the target, which is Legacy and so
	// not something to build against.
	NonceAccount string `json:"nonce_account" example:""`

	targetNonceAccount *types.PublicKey
	feePayer           *types.PublicKey
	nonceAccount       *types.PublicKey
}

func (r *SystemNonceUpgradeRequest) ValidateRequest() error {
	var err error
	if r.targetNonceAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TargetNonceAccount)); err != nil {
		return errors.New("target_nonce_account: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
		if r.nonceAccount.Equal(r.targetNonceAccount) {
			return errors.New("nonce_account: cannot be the target, which is being migrated by this same transaction")
		}
	}

	return nil
}

func (r *SystemNonceUpgradeRequest) TargetNonceAccountKey() *types.PublicKey {
	return r.targetNonceAccount
}

func (r *SystemNonceUpgradeRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *SystemNonceUpgradeRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

type SystemNonceUpgradeResponse struct {
	Transaction        string   `json:"transaction"`
	Message            string   `json:"message"`
	RecentBlockhash    string   `json:"recent_blockhash"`
	AccountKeys        []string `json:"account_keys"`
	Signers            []string `json:"signers"`
	TargetNonceAccount string   `json:"target_nonce_account"`

	// NonceAuthority belongs to the account named in the request's
	// nonce_account, and is present only when one was named. The target has an
	// authority too, but nothing signs for an upgrade, so it is not reported.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Version uint32 `json:"version"`
	Fee     string `json:"fee"`
}

func NewSystemNonceUpgradeResponse(tx *types.Transaction, raw, message []byte, targetNonceAccount, nonceAuthority *types.PublicKey, version uint32, fee uint64) *SystemNonceUpgradeResponse {
	nonceAuthorityBase58 := ""
	if !nonceAuthority.IsNil() {
		nonceAuthorityBase58 = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &SystemNonceUpgradeResponse{
		Transaction:        base64.StdEncoding.EncodeToString(raw),
		Message:            base64.StdEncoding.EncodeToString(message),
		RecentBlockhash:    tx.Message.RecentBlockhash.Base58(),
		AccountKeys:        keys,
		Signers:            signers,
		TargetNonceAccount: targetNonceAccount.Base58(),
		NonceAuthority:     nonceAuthorityBase58,
		Version:            version,
		Fee:                strconv.FormatUint(fee, 10),
	}
}
