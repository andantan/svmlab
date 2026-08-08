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

	from     *types.PublicKey
	to       *types.PublicKey
	feePayer *types.PublicKey
	amount   uint64
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

	from     *types.PublicKey
	to       *types.PublicKey
	feePayer *types.PublicKey
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

	return nil
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

	// Amount and Fee are strings for the same reason the request's amount is:
	// a JSON number is a float, so a lamport count past 2^53 would reach a
	// JavaScript client already rounded.
	Amount    string `json:"amount"`
	AmountSOL string `json:"amount_sol"`
	Fee       string `json:"fee"`
}

func NewSystemTransferResponse(tx *types.Transaction, raw, message []byte, amount, fee uint64) *SystemTransferResponse {
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
	Amount          string   `json:"amount"`
	AmountSOL       string   `json:"amount_sol"`
	Fee             string   `json:"fee"`
}

func NewSystemTransferMaxResponse(tx *types.Transaction, raw, message []byte, amount, fee uint64) *SystemTransferMaxResponse {
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
		Amount:          strconv.FormatUint(amount, 10),
		AmountSOL:       types.LamportsToSol(amount),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

type SystemCreateAccountRequest struct {
	From       string `json:"from" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	NewAccount string `json:"new_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`
	Lamports   string `json:"lamports" example:"890880"`
	Space      string `json:"space" example:"0"`
	FeePayer   string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	from       *types.PublicKey
	newAccount *types.PublicKey
	feePayer   *types.PublicKey
	lamports   uint64
	space      uint64
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
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
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

func (r *SystemCreateAccountRequest) FromKey() *types.PublicKey {
	return r.from
}

func (r *SystemCreateAccountRequest) NewAccountKey() *types.PublicKey {
	return r.newAccount
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
	Lamports        string   `json:"lamports"`
	LamportsSOL     string   `json:"lamports_sol"`

	// RentExempt is the floor the requested space had to clear. It is
	// reported because the server had to resolve it to validate lamports
	// anyway, and it is what a caller needs to know to fund the next one
	// without guessing.
	RentExempt string `json:"rent_exempt"`

	Space uint64 `json:"space"`
	Owner string `json:"owner"`
	Fee   string `json:"fee"`
}

func NewSystemCreateAccountResponse(tx *types.Transaction, raw, message []byte, owner *types.PublicKey, lamports, rentExempt, space, fee uint64) *SystemCreateAccountResponse {
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

	account  *types.PublicKey
	feePayer *types.PublicKey
	space    uint64
}

func (r *SystemAllocateRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
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
	Space           uint64   `json:"space"`

	// RentExempt is the balance the account must hold once it is this size.
	// Growing an account raises its floor, so a balance that was exempt
	// before the call can stop being exempt after it.
	RentExempt string `json:"rent_exempt"`

	Fee string `json:"fee"`
}

func NewSystemAllocateResponse(tx *types.Transaction, raw, message []byte, space, rentExempt, fee uint64) *SystemAllocateResponse {
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
		Space:           space,
		RentExempt:      strconv.FormatUint(rentExempt, 10),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

type SystemAssignRequest struct {
	Account  string `json:"account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`
	Owner    string `json:"owner" example:"11111111111111111111111111111111"`
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	account  *types.PublicKey
	owner    *types.PublicKey
	feePayer *types.PublicKey
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

	return nil
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
	Owner           string   `json:"owner"`
	Fee             string   `json:"fee"`
}

func NewSystemAssignResponse(tx *types.Transaction, raw, message []byte, owner *types.PublicKey, fee uint64) *SystemAssignResponse {
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
		Owner:           owner.Base58(),
		Fee:             strconv.FormatUint(fee, 10),
	}
}
