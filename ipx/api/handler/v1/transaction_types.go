package v1

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/andantan/svmlab/api/handler"
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
	handler.ChainSelector
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
	if err := r.ValidateChainSelector(); err != nil {
		return err
	}

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

// SignTransactionRequest signs without broadcasting.
//
// Signers are named by public key and resolved against config.yaml, so no
// secret travels in a request body or turns up in an access log. It also means
// the server can only sign for accounts it was configured with.
//
// Keys may be supplied across several calls, since each fills only its own
// slot, which is how a transaction moves between co-signers.
type SignTransactionRequest struct {
	Transaction string   `json:"transaction"`
	PublicKeys  []string `json:"public_keys" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	tx *types.Transaction
}

func (r *SignTransactionRequest) ValidateRequest() error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(r.Transaction))
	if err != nil {
		return errors.New("transaction: invalid base64: " + err.Error())
	}
	if r.tx, err = types.DeserializeTransaction(raw); err != nil {
		return errors.New("transaction: " + err.Error())
	}

	if len(r.PublicKeys) == 0 {
		return errors.New("public_keys: at least one is required")
	}
	for i := range r.PublicKeys {
		r.PublicKeys[i] = strings.TrimSpace(r.PublicKeys[i])
		if r.PublicKeys[i] == "" {
			return fmt.Errorf("public_keys[%d]: must not be empty", i)
		}
	}

	return nil
}

func (r *SignTransactionRequest) ToTransaction() *types.Transaction {
	return r.tx
}

// SignTransactionResponse reports the signed bytes and which slots are filled.
//
// TransactionID is empty until every slot is filled, because the id is the fee
// payer's signature and a partially signed transaction does not yet have one to
// stand behind it.
type SignTransactionResponse struct {
	Transaction   string   `json:"transaction"`
	TransactionID string   `json:"transaction_id"`
	Signatures    []string `json:"signatures"`
	FullySigned   bool     `json:"fully_signed"`
}

func NewSignTransactionResponse(tx *types.Transaction, raw []byte) *SignTransactionResponse {
	signatures := make([]string, len(tx.Signatures))
	for i, sig := range tx.Signatures {
		if sig.IsZero() {
			continue
		}
		signatures[i] = sig.Base58()
	}

	var id string
	if tx.IsFullySigned() {
		if sig, err := tx.ID(); err == nil {
			id = sig.Base58()
		}
	}

	return &SignTransactionResponse{
		Transaction:   base64.StdEncoding.EncodeToString(raw),
		TransactionID: id,
		Signatures:    signatures,
		FullySigned:   tx.IsFullySigned(),
	}
}

type SendTransactionRequest struct {
	handler.ChainSelector
	handler.Commitment
	Transaction string `json:"transaction"`

	// SkipPreflight disables the node-side simulation that runs before the
	// transaction is broadcast. Leaving it off surfaces most failures without
	// spending a signature.
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
