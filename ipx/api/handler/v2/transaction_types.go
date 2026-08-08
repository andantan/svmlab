package v2

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

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
