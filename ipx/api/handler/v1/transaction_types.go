package v1

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/andantan/svmlab/core/types"
)

// Account is one account an instruction touches.
//
// Both flags are required rather than inferred. The runtime rejects an
// instruction whose declared privileges do not match what the program needs,
// so guessing them here would turn a caller's mistake into a cluster error.
type Account struct {
	PublicKey  string `json:"public_key"  example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	IsSigner   bool   `json:"is_signer"   example:"true"`
	IsWritable bool   `json:"is_writable" example:"true"`
}

// Instruction is a single program call.
//
// Data is base64 rather than hex because that is the encoding the RPC layer
// uses for every byte string, and it carries no ABI: each program defines its
// own layout, so nothing here can validate it beyond decoding.
type Instruction struct {
	ProgramID string    `json:"program_id" example:"11111111111111111111111111111111"`
	Accounts  []Account `json:"accounts"`
	Data      string    `json:"data"       example:"AgAAAECcAAAAAAAA"`
}

type BuildTransactionRequest struct {
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash may be left empty, in which case it is fetched from the
	// cluster. Supplying it makes the call deterministic, which is what allows
	// the same request to reproduce identical bytes.
	RecentBlockhash string        `json:"recent_blockhash" example:""`
	Instructions    []Instruction `json:"instructions"`

	feePayer     *types.PublicKey
	blockhash    *types.Hash
	instructions []*types.Instruction
}

func (r *BuildTransactionRequest) ValidateRequest() error {
	var err error
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	if bh := strings.TrimSpace(r.RecentBlockhash); bh != "" {
		if r.blockhash, err = types.NewHashFromBase58(bh); err != nil {
			return errors.New("recent_blockhash: " + err.Error())
		}
	}

	if len(r.Instructions) == 0 {
		return errors.New("instructions: at least one is required")
	}

	r.instructions = make([]*types.Instruction, len(r.Instructions))
	for i, ix := range r.Instructions {
		programID, err := types.NewPublicKeyFromBase58(strings.TrimSpace(ix.ProgramID))
		if err != nil {
			return fmt.Errorf("instructions[%d].program_id: %s", i, err)
		}

		accounts := make([]*types.Account, len(ix.Accounts))
		for j, a := range ix.Accounts {
			key, err := types.NewPublicKeyFromBase58(strings.TrimSpace(a.PublicKey))
			if err != nil {
				return fmt.Errorf("instructions[%d].accounts[%d].public_key: %s", i, j, err)
			}
			accounts[j] = types.NewAccount(key, a.IsSigner, a.IsWritable)
		}

		data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ix.Data))
		if err != nil {
			return fmt.Errorf("instructions[%d].data: invalid base64: %s", i, err)
		}

		r.instructions[i] = types.NewInstruction(programID, accounts, data)
	}

	return nil
}

func (r *BuildTransactionRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *BuildTransactionRequest) Blockhash() *types.Hash {
	return r.blockhash
}

func (r *BuildTransactionRequest) ToInstructions() []*types.Instruction {
	return r.instructions
}

// BuildTransactionResponse carries the compiled result.
//
// Message is the payload every signer signs, exposed separately so the
// compilation can be inspected without decoding the transaction. AccountKeys
// and the header counts are what the compilation actually decided: which keys
// were kept, in what order, and with which privileges.
type BuildTransactionResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`
	Header          Header   `json:"header"`
	Size            int      `json:"size"`
}

type Header struct {
	NumRequiredSignatures       uint8 `json:"num_required_signatures"`
	NumReadonlySignedAccounts   uint8 `json:"num_readonly_signed_accounts"`
	NumReadonlyUnsignedAccounts uint8 `json:"num_readonly_unsigned_accounts"`
}

func NewBuildTransactionResponse(tx *types.Transaction, raw, message []byte) *BuildTransactionResponse {
	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &BuildTransactionResponse{
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
		Size: len(raw),
	}
}
