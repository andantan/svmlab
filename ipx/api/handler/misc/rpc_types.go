package misc

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/core/types"
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
