package v2

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/core/types"
)

// AmountMax asks for the largest transfer the sender can make.
//
// Resolving it needs the sender's balance and the fee, so it costs extra RPC
// calls that a fixed amount does not.
const AmountMax = "max"

type TransferRequest struct {
	handler.ChainSelector
	From string `json:"from" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	To   string `json:"to"   example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// Amount is a decimal lamport count, or "max" to send everything the
	// sender can. It is a string so that the two forms share one field and so
	// that a u64 survives a JSON round trip: JSON numbers are floats, and
	// values past 2^53 would lose precision silently.
	Amount string `json:"amount" example:"1000000"`

	// FeePayer defaults to the sender. Paying from a different account is
	// common on Solana, and it changes what "max" means: the sender can send
	// its whole balance when someone else covers the fee.
	FeePayer string `json:"fee_payer" example:""`

	// RecentBlockhash may be left empty, in which case it is fetched.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// AllowUnfundedRecipient permits sending to an account that does not exist
	// yet. It defaults to false because base58 carries no checksum: a single
	// mistyped character decodes to a different valid address, and an account
	// nobody has ever funded is the only signal that separates a typo from an
	// intended new account. solana transfer guards the same way.
	AllowUnfundedRecipient bool `json:"allow_unfunded_recipient" example:"false"`

	from      *types.PublicKey
	to        *types.PublicKey
	feePayer  *types.PublicKey
	blockhash *types.Hash
	amount    uint64
	max       bool
}

func (r *TransferRequest) ValidateRequest() error {
	if err := r.ValidateChainSelector(); err != nil {
		return err
	}

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

	r.feePayer = r.from
	if fp := strings.TrimSpace(r.FeePayer); fp != "" {
		if r.feePayer, err = types.NewPublicKeyFromBase58(fp); err != nil {
			return errors.New("fee_payer: " + err.Error())
		}
	}

	if bh := strings.TrimSpace(r.RecentBlockhash); bh != "" {
		if r.blockhash, err = types.NewHashFromBase58(bh); err != nil {
			return errors.New("recent_blockhash: " + err.Error())
		}
	}

	switch amount := strings.TrimSpace(strings.ToLower(r.Amount)); amount {
	case "":
		return errors.New("amount is required")
	case AmountMax:
		r.max = true
	default:
		if r.amount, err = strconv.ParseUint(amount, 10, 64); err != nil {
			return errors.New(`amount: must be a decimal lamport count or "max"`)
		}
		if r.amount == 0 {
			return errors.New("amount: must be greater than zero")
		}
	}

	return nil
}

func (r *TransferRequest) FromKey() *types.PublicKey {
	return r.from
}

func (r *TransferRequest) ToKey() *types.PublicKey {
	return r.to
}

func (r *TransferRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *TransferRequest) Blockhash() *types.Hash {
	return r.blockhash
}

func (r *TransferRequest) Lamports() uint64 {
	return r.amount
}

func (r *TransferRequest) IsMax() bool {
	return r.max
}

// PaysOwnFee reports whether the sender is also the fee payer, which decides
// how much "max" leaves behind.
func (r *TransferRequest) PaysOwnFee() bool {
	return r.from.Equal(r.feePayer)
}

// TransferResponse mirrors the v1 build response so that sign and send accept
// it unchanged, and adds the resolved amount and fee.
//
// Both matter most for "max", where the caller did not name a number and the
// server decided one.
type TransferResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`
	Header          Header   `json:"header"`
	Size            int      `json:"size"`

	// Amount and Fee are strings for the same reason the request's amount is:
	// a JSON number is a float, so a lamport count past 2^53 would reach a
	// JavaScript client already rounded.
	Amount    string `json:"amount"`
	AmountSOL string `json:"amount_sol"`
	Fee       string `json:"fee"`
}

type Header struct {
	NumRequiredSignatures       uint8 `json:"num_required_signatures"`
	NumReadonlySignedAccounts   uint8 `json:"num_readonly_signed_accounts"`
	NumReadonlyUnsignedAccounts uint8 `json:"num_readonly_unsigned_accounts"`
}

func NewTransferResponse(tx *types.Transaction, raw, message []byte, amount, fee uint64) *TransferResponse {
	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &TransferResponse{
		Transaction:     base64.StdEncoding.EncodeToString(raw),
		Message:         base64.StdEncoding.EncodeToString(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		Header: Header{
			NumRequiredSignatures:       tx.Message.Header.NumRequiredSignatures,
			NumReadonlySignedAccounts:   tx.Message.Header.NumReadonlySignedAccounts,
			NumReadonlyUnsignedAccounts: tx.Message.Header.NumReadonlyUnsignedAccounts,
		},
		Size:      len(raw),
		Amount:    strconv.FormatUint(amount, 10),
		AmountSOL: types.LamportsToSol(amount),
		Fee:       strconv.FormatUint(fee, 10),
	}
}
