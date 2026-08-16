package v2

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
)

// SystemPayer is one signer's contribution: who it is and what
// it moved, in both units.
type SystemPayer struct {
	Payer    string `json:"payer"`
	Lamports string `json:"lamports"`
	SOL      string `json:"sol"`
}

func newSystemPayer(payer *types.PublicKey, lamports uint64) SystemPayer {
	return SystemPayer{
		Payer:    payer.Base58(),
		Lamports: strconv.FormatUint(lamports, 10),
		SOL:      types.LamportsToSol(lamports),
	}
}

type SystemTransferRequest struct {
	// FundingPayer is the account debited. It signs the transaction as the
	// transfer authority, whether or not it also pays the fee.
	FundingPayer string `json:"funding_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecipientAccount is the account credited. It must already exist: this
	// is a plain transfer between two accounts, not a way to bring a new one
	// into existence.
	RecipientAccount string `json:"recipient_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// Lamports is the raw amount moved from FundingPayer to RecipientAccount.
	Lamports string `json:"lamports" example:"1000000"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as FundingPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	fup *types.PublicKey
	ra  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
	l   uint64
}

func (r *SystemTransferRequest) ValidateRequest() error {
	var err error
	if r.fup, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FundingPayer)); err != nil {
		return errors.New("funding_payer: " + err.Error())
	}
	if r.ra, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RecipientAccount)); err != nil {
		return errors.New("recipient_account: " + err.Error())
	}
	if r.fup.Equal(r.ra) {
		return errors.New("funding_payer and recipient_account are the same account")
	}

	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	l := strings.TrimSpace(r.Lamports)
	if l == "" {
		return errors.New("lamports is required")
	}
	if r.l, err = strconv.ParseUint(l, 10, 64); err != nil {
		return errors.New("lamports: must be a decimal lamport count")
	}
	if r.l == 0 {
		return errors.New("lamports: must be greater than zero")
	}

	return nil
}

func (r *SystemTransferRequest) FundingPayerKey() *types.PublicKey {
	return r.fup
}

func (r *SystemTransferRequest) RecipientAccountKey() *types.PublicKey {
	return r.ra
}

func (r *SystemTransferRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemTransferRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemTransferRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}

func (r *SystemTransferRequest) ToLamports() uint64 {
	return r.l
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

	// Funding reports the transfer itself: who sent it and how much.
	Funding SystemPayer `json:"funding"`

	Fee SystemPayer `json:"fee"`
}

func NewSystemTransferResponse(tx *types.Transaction, raw, message []byte, fundingPayer, feePayer, nonceAuthority *types.PublicKey, lamports, fee uint64) *SystemTransferResponse {
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		Funding:         newSystemPayer(fundingPayer, lamports),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

type SystemTransferMaxRequest struct {
	// FundingPayer is the account drained. It signs the transaction as the
	// transfer authority, whether or not it also pays the fee.
	FundingPayer string `json:"funding_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecipientAccount is the account credited. It must already exist: this
	// is a plain transfer between two accounts, not a way to bring a new
	// one into existence.
	RecipientAccount string `json:"recipient_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as FundingPayer, in which case the fee is deducted from what
	// is sent.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	fup *types.PublicKey
	ra  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *SystemTransferMaxRequest) ValidateRequest() error {
	var err error
	if r.fup, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FundingPayer)); err != nil {
		return errors.New("funding_payer: " + err.Error())
	}
	if r.ra, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RecipientAccount)); err != nil {
		return errors.New("recipient_account: " + err.Error())
	}
	if r.fup.Equal(r.ra) {
		return errors.New("funding_payer and recipient_account are the same account")
	}

	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *SystemTransferMaxRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemTransferMaxRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemTransferMaxRequest) FundingPayerKey() *types.PublicKey {
	return r.fup
}

func (r *SystemTransferMaxRequest) RecipientAccountKey() *types.PublicKey {
	return r.ra
}

func (r *SystemTransferMaxRequest) FeePayerKey() *types.PublicKey {
	return r.fp
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

	Funding SystemPayer `json:"funding"`
	Fee     SystemPayer `json:"fee"`
}

func NewSystemTransferMaxResponse(tx *types.Transaction, raw, message []byte, fundingPayer, feePayer, nonceAuthority *types.PublicKey, lamports, fee uint64) *SystemTransferMaxResponse {
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		Funding:         newSystemPayer(fundingPayer, lamports),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// SystemTransferSpreadTarget is one recipient and what they receive.
//
// One entry compiles to one Transfer instruction, so the list length is the
// instruction count, and it is what pushes a transaction toward the size
// limit. There is no per-entry sender: every transfer here leaves the same
// account, which is what keeps the signer count at one or two.
type SystemTransferSpreadTarget struct {
	// RecipientAccount is the account credited. It must already exist: this
	// is a plain transfer between accounts, not a way to bring a new one
	// into existence.
	RecipientAccount string `json:"recipient_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// Lamports is the raw amount moved from the request's FundingPayer to
	// RecipientAccount.
	Lamports string `json:"lamports" example:"100000000"`

	ra *types.PublicKey
	l  uint64
}

func (t *SystemTransferSpreadTarget) RecipientAccountKey() *types.PublicKey {
	return t.ra
}

func (t *SystemTransferSpreadTarget) ToLamports() uint64 {
	return t.l
}

// SystemTransferSpreadRequest moves lamports from one account to several in a
// single transaction.
//
// There is no max variant. Sending everything one account holds is a single
// amount, and there is no reading of how it should be divided among several
// recipients.
type SystemTransferSpreadRequest struct {
	// FundingPayer is the account debited for every transfer. It signs the
	// transaction as the transfer authority, whether or not it also pays the
	// fee.
	FundingPayer string `json:"funding_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Transfers lists the recipients and their amounts, in the order the
	// instructions are executed and the response echoes them back. There is
	// no upper bound here beyond what fits in one transaction.
	Transfers []SystemTransferSpreadTarget `json:"transfers"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as FundingPayer, in which case the fee is deducted from its
	// balance alongside every transfer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	fup *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
	tot uint64
}

func (r *SystemTransferSpreadRequest) ValidateRequest() error {
	var err error
	if r.fup, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FundingPayer)); err != nil {
		return errors.New("funding_payer: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	// There is no upper bound here. How many recipients fit is a question of
	// bytes rather than of count, and serialization answers it exactly against
	// types.MaxTransactionSize once the transaction is assembled.
	if len(r.Transfers) == 0 {
		return errors.New("transfers is required")
	}

	// Two entries paying the same address would both land, so this is a rule
	// rather than a runtime constraint. It is a rule because one request
	// stating an address twice is far more likely a mistake than an intent,
	// and the index of the earlier entry is reported so it can be found.
	seen := make(map[string]int, len(r.Transfers))

	for i := range r.Transfers {
		t := &r.Transfers[i]

		if t.ra, err = types.NewPublicKeyFromBase58(strings.TrimSpace(t.RecipientAccount)); err != nil {
			return fmt.Errorf("transfers[%d].recipient_account: %s", i, err)
		}
		if r.fup.Equal(t.ra) {
			return fmt.Errorf("transfers[%d].recipient_account: is the funding_payer", i)
		}
		if first, ok := seen[t.ra.Base58()]; ok {
			return fmt.Errorf("transfers[%d].recipient_account: already named by transfers[%d]", i, first)
		}
		seen[t.ra.Base58()] = i

		lamports := strings.TrimSpace(t.Lamports)
		if lamports == "" {
			return fmt.Errorf("transfers[%d].lamports is required", i)
		}
		if t.l, err = strconv.ParseUint(lamports, 10, 64); err != nil {
			return fmt.Errorf("transfers[%d].lamports: must be a decimal lamport count", i)
		}
		if t.l == 0 {
			return fmt.Errorf("transfers[%d].lamports: must be greater than zero", i)
		}

		// The total is what the balance is checked against, so it has to be a
		// real sum. Every other endpoint moves one amount and cannot overflow;
		// this one adds up to sixty-four and would wrap into a total small
		// enough to pass, leaving the runtime to fail what looked fundable.
		if r.tot+t.l < r.tot {
			return fmt.Errorf("transfers[%d].lamports: the total exceeds what a u64 can hold", i)
		}
		r.tot += t.l
	}

	return nil
}

func (r *SystemTransferSpreadRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemTransferSpreadRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemTransferSpreadRequest) FundingPayerKey() *types.PublicKey {
	return r.fup
}

func (r *SystemTransferSpreadRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}

func (r *SystemTransferSpreadRequest) Targets() []SystemTransferSpreadTarget {
	return r.Transfers
}

// Total is the sum of every amount, resolved during validation because that is
// where the overflow it could hide was ruled out.
func (r *SystemTransferSpreadRequest) Total() uint64 {
	return r.tot
}

// SystemTransferSpreadTargetResponse echoes one recipient with its amount in
// SOL beside the lamport count.
type SystemTransferSpreadTargetResponse struct {
	RecipientAccount string `json:"recipient_account"`
	Lamports         string `json:"lamports"`
	SOL              string `json:"sol"`
}

type SystemTransferSpreadResponse struct {
	Transaction     string `json:"transaction"`
	Message         string `json:"message"`
	RecentBlockhash string `json:"recent_blockhash"`

	// AccountKeys is shorter than the transfer list plus two. The sender
	// appears in every instruction and the System Program in all of them, yet
	// each is one key here: compiling a message deduplicates account keys and
	// the instructions address them by index. This is the first endpoint whose
	// response shows that.
	AccountKeys []string `json:"account_keys"`

	Signers []string `json:"signers"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Transfers []SystemTransferSpreadTargetResponse `json:"transfers"`

	// Funding is the funding_payer's total spend across every transfer.
	Funding SystemPayer `json:"funding"`

	Fee SystemPayer `json:"fee"`

	// Size and SizeLimit are what bounds this endpoint. A transaction travels
	// in one packet and cannot be split, so the recipient count is really a
	// byte count, and reporting both lets a caller work out how many more
	// would fit rather than discovering it by being refused.
	Size      int `json:"size"`
	SizeLimit int `json:"size_limit"`
}

func NewSystemTransferSpreadResponse(tx *types.Transaction, raw, message []byte, fundingPayer, feePayer, nonceAuthority *types.PublicKey, targets []SystemTransferSpreadTarget, total, fee uint64) *SystemTransferSpreadResponse {
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

	transfers := make([]SystemTransferSpreadTargetResponse, len(targets))
	for i := range targets {
		transfers[i] = SystemTransferSpreadTargetResponse{
			RecipientAccount: targets[i].RecipientAccountKey().Base58(),
			Lamports:         strconv.FormatUint(targets[i].ToLamports(), 10),
			SOL:              types.LamportsToSol(targets[i].ToLamports()),
		}
	}

	return &SystemTransferSpreadResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		Transfers:       transfers,
		Funding:         newSystemPayer(fundingPayer, total),
		Fee:             newSystemPayer(feePayer, fee),
		Size:            len(raw),
		SizeLimit:       types.MaxTransactionSize,
	}
}

type SystemTransferCollectSource struct {
	// FundingPayer is debited. It signs the transaction as the transfer
	// authority for its own instruction, whether or not it also pays the fee.
	FundingPayer string `json:"funding_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Lamports is the raw amount moved from FundingPayer to the request's
	// RecipientAccount. It must be left unset when Max is true: the two name
	// the amount in mutually exclusive ways, and naming both leaves no
	// reading of which one is meant.
	Lamports string `json:"lamports" example:"100000000"`

	// Max sweeps FundingPayer's entire balance instead of a chosen amount.
	// When it is also FeePayer, the fee comes out of that same balance first;
	// every other source's Lamports is untouched by any fee.
	Max bool `json:"max" example:"false"`

	fup *types.PublicKey
	l   uint64
}

func (s *SystemTransferCollectSource) FundingPayerKey() *types.PublicKey {
	return s.fup
}

// ToLamports is the amount named for a fixed source. It is meaningless for a
// Max source, whose amount is not known until the request resolves against a
// live balance.
func (s *SystemTransferCollectSource) ToLamports() uint64 {
	return s.l
}

func (s *SystemTransferCollectSource) IsMax() bool {
	return s.Max
}

// SystemTransferCollectRequest moves lamports from several accounts into one
// in a single transaction — the inverse of transfer/spread. Every source
// signs its own instruction, so this is a multi-party transaction: as many
// signatures are needed as sources named, plus fee_payer.
type SystemTransferCollectRequest struct {
	// RecipientAccount is the account credited by every source. It must
	// already exist: this is a plain transfer between accounts, not a way to
	// bring a new one into existence.
	RecipientAccount string `json:"recipient_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// Transfers lists the funding payers and their amounts, in the order the
	// instructions are executed and the response echoes them back. There is
	// no upper bound here beyond what fits in one transaction.
	Transfers []SystemTransferCollectSource `json:"transfers"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as any one source, in which case the fee is deducted from its
	// balance alongside its own transfer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	ra  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *SystemTransferCollectRequest) ValidateRequest() error {
	var err error
	if r.ra, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RecipientAccount)); err != nil {
		return errors.New("recipient_account: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	if len(r.Transfers) == 0 {
		return errors.New("transfers is required")
	}

	// Two entries debiting the same address would both land, so this is a
	// rule rather than a runtime constraint. It is a rule because one request
	// naming an address twice is far more likely a mistake than an intent,
	// and the index of the earlier entry is reported so it can be found.
	seen := make(map[string]int, len(r.Transfers))

	for i := range r.Transfers {
		s := &r.Transfers[i]

		if s.fup, err = types.NewPublicKeyFromBase58(strings.TrimSpace(s.FundingPayer)); err != nil {
			return fmt.Errorf("transfers[%d].funding_payer: %s", i, err)
		}
		if s.fup.Equal(r.ra) {
			return fmt.Errorf("transfers[%d].funding_payer: is recipient_account", i)
		}
		if first, ok := seen[s.fup.Base58()]; ok {
			return fmt.Errorf("transfers[%d].funding_payer: already named by transfers[%d]", i, first)
		}
		seen[s.fup.Base58()] = i

		lamports := strings.TrimSpace(s.Lamports)
		if s.Max {
			if lamports != "" {
				return fmt.Errorf("transfers[%d].lamports: must not be set when max is true", i)
			}
			continue
		}

		if lamports == "" {
			return fmt.Errorf("transfers[%d].lamports is required", i)
		}
		if s.l, err = strconv.ParseUint(lamports, 10, 64); err != nil {
			return fmt.Errorf("transfers[%d].lamports: must be a decimal lamport count", i)
		}
		if s.l == 0 {
			return fmt.Errorf("transfers[%d].lamports: must be greater than zero", i)
		}
	}

	return nil
}

func (r *SystemTransferCollectRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemTransferCollectRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemTransferCollectRequest) RecipientAccountKey() *types.PublicKey {
	return r.ra
}

func (r *SystemTransferCollectRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}

func (r *SystemTransferCollectRequest) TransferList() []SystemTransferCollectSource {
	return r.Transfers
}

// SystemTransferCollectSourceResponse echoes one source with its amount in
// SOL beside the lamport count. Lamports and SOL are always the amount
// actually moved, resolved against a live balance when Max was true rather
// than echoing back a field the request left empty.
type SystemTransferCollectSourceResponse struct {
	FundingPayer string `json:"funding_payer"`
	Lamports     string `json:"lamports"`
	SOL          string `json:"sol"`
	Max          bool   `json:"max"`
}

type SystemTransferCollectResponse struct {
	Transaction     string `json:"transaction"`
	Message         string `json:"message"`
	RecentBlockhash string `json:"recent_blockhash"`

	// AccountKeys is shorter than the source list plus two. The recipient
	// appears in every instruction and the System Program in all of them, yet
	// each is one key here: compiling a message deduplicates account keys and
	// the instructions address them by index.
	AccountKeys []string `json:"account_keys"`

	// Signers lists every source alongside fee_payer: unlike transfer/spread,
	// this is a multi-party transaction, and each source signs only for its
	// own instruction.
	Signers []string `json:"signers"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Transfers []SystemTransferCollectSourceResponse `json:"transfers"`

	// Recipient reports the account credited and the total collected into it
	// across every transfer.
	Recipient SystemPayer `json:"recipient"`

	Fee SystemPayer `json:"fee"`

	// Size and SizeLimit are what bounds this endpoint. A transaction travels
	// in one packet and cannot be split, so the transfer count is really a
	// byte count, and reporting both lets a caller work out how many more
	// would fit rather than discovering it by being refused.
	Size      int `json:"size"`
	SizeLimit int `json:"size_limit"`
}

func NewSystemTransferCollectResponse(tx *types.Transaction, raw, message []byte, recipient, feePayer, nonceAuthority *types.PublicKey, sources []SystemTransferCollectSource, resolved []uint64, total, fee uint64) *SystemTransferCollectResponse {
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

	sourceResponses := make([]SystemTransferCollectSourceResponse, len(sources))
	for i := range sources {
		sourceResponses[i] = SystemTransferCollectSourceResponse{
			FundingPayer: sources[i].FundingPayerKey().Base58(),
			Lamports:     strconv.FormatUint(resolved[i], 10),
			SOL:          types.LamportsToSol(resolved[i]),
			Max:          sources[i].IsMax(),
		}
	}

	return &SystemTransferCollectResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		Transfers:       sourceResponses,
		Recipient:       newSystemPayer(recipient, total),
		Fee:             newSystemPayer(feePayer, fee),
		Size:            len(raw),
		SizeLimit:       types.MaxTransactionSize,
	}
}

type SystemCreateAccountRequest struct {
	// NewAccount is the account created. It signs alongside RentPayer, since
	// an address does not exist until whoever holds its private key
	// authorizes its creation. It must not already exist.
	NewAccount string `json:"new_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	// RentPayer funds NewAccount's creation for exactly the rent-exemption
	// minimum for a zero-byte account — always, and only that amount. There
	// is no way to fund it beyond that minimum here: this endpoint only ever
	// brings an account into existence, empty. Reserving space is a separate
	// call to allocate, and topping up its balance further is a separate
	// transfer.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	na  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
	rp  *types.PublicKey
}

func (r *SystemCreateAccountRequest) ValidateRequest() error {
	var err error
	if r.na, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.NewAccount)); err != nil {
		return errors.New("new_account: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}
	if r.fp.Equal(r.na) {
		return errors.New("fee_payer and new_account are the same account")
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	rp := strings.TrimSpace(r.RentPayer)
	if rp == "" {
		return errors.New("rent_payer is required")
	}
	if r.rp, err = types.NewPublicKeyFromBase58(rp); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.rp.Equal(r.na) {
		return errors.New("rent_payer and new_account are the same account")
	}

	return nil
}

func (r *SystemCreateAccountRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemCreateAccountRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemCreateAccountRequest) RentPayerKey() *types.PublicKey {
	return r.rp
}

func (r *SystemCreateAccountRequest) NewAccountKey() *types.PublicKey {
	return r.na
}

func (r *SystemCreateAccountRequest) FeePayerKey() *types.PublicKey {
	return r.fp
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

	// Rent reports what funds CreateAccount itself. Its lamports are always
	// exactly the rent-exemption minimum for a zero-byte account, never more
	// or less.
	Rent SystemPayer `json:"rent"`

	Fee SystemPayer `json:"fee"`
}

func NewSystemCreateAccountResponse(tx *types.Transaction, raw, message []byte, rentPayer, feePayer, nonceAuthority *types.PublicKey, rentLamports, fee uint64) *SystemCreateAccountResponse {
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		Rent:            newSystemPayer(rentPayer, rentLamports),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

type SystemAllocateRequest struct {
	// Account must already exist, be owned by the System Program, and not
	// already be allocated space — Allocate only ever sets a size once, on
	// an account that does not yet have one.
	Account string `json:"account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	Space string `json:"space" example:"128"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	// RentPayer covers the shortfall, if any, between Account's current
	// balance and the rent-exemption minimum for Space: a transfer from
	// RentPayer for exactly that shortfall is prepended ahead of the
	// allocation. Required even when Account already holds enough and no
	// such transfer ends up being built. It may be the same account as
	// Account, but only when Account already holds enough on its own — a
	// shortfall has nowhere to come from in that case.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	account *types.PublicKey
	fp      *types.PublicKey
	rbh     *types.Hash
	dna     *types.PublicKey
	rp      *types.PublicKey
	space   uint64
}

func (r *SystemAllocateRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	rp := strings.TrimSpace(r.RentPayer)
	if rp == "" {
		return errors.New("rent_payer is required")
	}
	if r.rp, err = types.NewPublicKeyFromBase58(rp); err != nil {
		return errors.New("rent_payer: " + err.Error())
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

func (r *SystemAllocateRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemAllocateRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemAllocateRequest) AccountKey() *types.PublicKey {
	return r.account
}

func (r *SystemAllocateRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}

func (r *SystemAllocateRequest) RentPayerKey() *types.PublicKey {
	return r.rp
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

	// Rent reports RentPayer and the shortfall it covered. Its lamports are
	// zero, and no transfer was actually prepended, when Account's balance
	// already reached the rent-exemption minimum for Space.
	Rent SystemPayer `json:"rent"`

	Fee SystemPayer `json:"fee"`
}

func NewSystemAllocateResponse(tx *types.Transaction, raw, message []byte, rentPayer, feePayer, nonceAuthority *types.PublicKey, space, rentLamports, fee uint64) *SystemAllocateResponse {
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		Space:           space,
		Rent:            newSystemPayer(rentPayer, rentLamports),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

type SystemAssignRequest struct {
	// Account must already exist and already be owned by the System Program:
	// only the current owner may reassign an account, and the System Program
	// is the only owner exposing this as a callable instruction.
	Account string `json:"account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// Owner must be executable: only the owning program may debit an account
	// or write its data, so an account handed to a plain address is locked
	// permanently. Pass the System Program to leave it as an ordinary account.
	Owner string `json:"owner" example:"11111111111111111111111111111111"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	a   *types.PublicKey
	o   *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *SystemAssignRequest) ValidateRequest() error {
	var err error
	if r.a, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.o, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *SystemAssignRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemAssignRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemAssignRequest) AccountKey() *types.PublicKey {
	return r.a
}

func (r *SystemAssignRequest) OwnerKey() *types.PublicKey {
	return r.o
}

func (r *SystemAssignRequest) FeePayerKey() *types.PublicKey {
	return r.fp
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

	Owner string      `json:"owner"`
	Fee   SystemPayer `json:"fee"`
}

func NewSystemAssignResponse(tx *types.Transaction, raw, message []byte, owner, feePayer, nonceAuthority *types.PublicKey, fee uint64) *SystemAssignResponse {
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		Owner:           owner.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// SystemSeedCreateAccountRequest creates a zero-byte account at a derived
// address, owned by the System Program itself.
//
// The address is not a field: it follows from base, seed, and the System
// Program as owner, and the runtime recomputes it and rejects a mismatch.
// Reserving space is a separate call to seed/allocate, and handing the
// account to another program is a separate call to seed/assign — the same
// split as create-account, allocate, and assign for a keypair account.
type SystemSeedCreateAccountRequest struct {
	// Base signs in the derived account's place: nobody holds a secret for
	// SHA256(base || seed || owner), so whoever controls base controls every
	// address derived from it.
	Base string `json:"base" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	Seed string `json:"seed" example:"vault-1"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	// RentPayer funds the derived account's creation for exactly the
	// rent-exemption minimum for a zero-byte account — always, and only that
	// amount. There is no way to fund it beyond that minimum here: this
	// endpoint only ever brings a plain account into existence, empty, and
	// topping up its balance further is a separate transfer.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	b   *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
	rp  *types.PublicKey
	d   *types.PublicKey
}

func (r *SystemSeedCreateAccountRequest) ValidateRequest() error {
	var err error
	if r.b, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Base)); err != nil {
		return errors.New("base: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	r.Seed = strings.TrimSpace(r.Seed)
	if r.Seed == "" {
		return errors.New("seed is required")
	}
	if len(r.Seed) > types.MaxSeedLength {
		return fmt.Errorf("seed: %d bytes exceeds the %d byte limit", len(r.Seed), types.MaxSeedLength)
	}

	if r.d, err = types.CreateWithSeed(r.b, r.Seed, core.System.ID()); err != nil {
		return fmt.Errorf("seed: %w", err)
	}

	rp := strings.TrimSpace(r.RentPayer)
	if rp == "" {
		return errors.New("rent_payer is required")
	}
	if r.rp, err = types.NewPublicKeyFromBase58(rp); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.rp.Equal(r.d) {
		return errors.New("rent_payer and the derived account are the same account")
	}

	return nil
}

func (r *SystemSeedCreateAccountRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemSeedCreateAccountRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemSeedCreateAccountRequest) BaseKey() *types.PublicKey {
	return r.b
}

func (r *SystemSeedCreateAccountRequest) DerivedKey() *types.PublicKey {
	return r.d
}

func (r *SystemSeedCreateAccountRequest) RentPayerKey() *types.PublicKey {
	return r.rp
}

func (r *SystemSeedCreateAccountRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}

type SystemSeedCreateAccountResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	// DerivedAddress is what base, seed, and the System Program produce. It
	// is the account being created, and it is absent from signers because
	// nobody holds a secret for it.
	DerivedAddress string `json:"derived_address"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	// Rent reports what funds CreateAccountWithSeed itself. Its lamports are
	// always exactly the rent-exemption minimum for a zero-byte account,
	// never more or less.
	Rent SystemPayer `json:"rent"`

	Fee SystemPayer `json:"fee"`
}

func NewSystemSeedCreateAccountResponse(tx *types.Transaction, raw, message []byte, derived, rentPayer, feePayer, nonceAuthority *types.PublicKey, rentLamports, fee uint64) *SystemSeedCreateAccountResponse {
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		DerivedAddress:  derived.Base58(),
		NonceAuthority:  authority,
		Rent:            newSystemPayer(rentPayer, rentLamports),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// SystemSeedTransferRequest moves lamports out of SHA256(base || seed ||
// System Program), the same derived account seed/create-account brings into
// existence.
//
// The account debited is the derived address, not Base itself: nobody holds
// a secret for a derived address, so Base signs in its place, and it is Base
// that has to hold nothing of its own for this to work.
type SystemSeedTransferRequest struct {
	Base string `json:"base" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	Seed string `json:"seed" example:"vault-1"`

	// RecipientAccount is the account credited. It must already exist: this
	// is a plain transfer between two accounts, not a way to bring a new one
	// into existence.
	RecipientAccount string `json:"recipient_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// Lamports is the raw amount moved from the derived account to
	// RecipientAccount.
	Lamports string `json:"lamports" example:"1000000"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as Base, but not the same account as the derived address,
	// which has no key to sign with.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	b   *types.PublicKey
	ra  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
	d   *types.PublicKey
	l   uint64
}

func (r *SystemSeedTransferRequest) ValidateRequest() error {
	var err error
	if r.b, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Base)); err != nil {
		return errors.New("base: " + err.Error())
	}

	r.Seed = strings.TrimSpace(r.Seed)
	if r.Seed == "" {
		return errors.New("seed is required")
	}
	if len(r.Seed) > types.MaxSeedLength {
		return fmt.Errorf("seed: %d bytes exceeds the %d byte limit", len(r.Seed), types.MaxSeedLength)
	}

	if r.d, err = types.CreateWithSeed(r.b, r.Seed, core.System.ID()); err != nil {
		return fmt.Errorf("seed: %w", err)
	}

	if r.ra, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RecipientAccount)); err != nil {
		return errors.New("recipient_account: " + err.Error())
	}
	if r.d.Equal(r.ra) {
		return errors.New("the derived account and recipient_account are the same account")
	}

	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}
	if r.fp.Equal(r.d) {
		return errors.New("fee_payer and the derived account are the same account, and the derived account has no key to sign with")
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	lamports := strings.TrimSpace(r.Lamports)
	if lamports == "" {
		return errors.New("lamports is required")
	}
	if r.l, err = strconv.ParseUint(lamports, 10, 64); err != nil {
		return errors.New("lamports: must be a decimal lamport count")
	}
	if r.l == 0 {
		return errors.New("lamports: must be greater than zero")
	}

	return nil
}

func (r *SystemSeedTransferRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemSeedTransferRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemSeedTransferRequest) BaseKey() *types.PublicKey {
	return r.b
}

func (r *SystemSeedTransferRequest) DerivedKey() *types.PublicKey {
	return r.d
}

func (r *SystemSeedTransferRequest) RecipientAccountKey() *types.PublicKey {
	return r.ra
}

func (r *SystemSeedTransferRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}

func (r *SystemSeedTransferRequest) ToLamports() uint64 {
	return r.l
}

type SystemSeedTransferResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	// Funding reports the transfer itself: the derived account debited, and
	// how much.
	Funding SystemPayer `json:"funding"`

	Fee SystemPayer `json:"fee"`
}

func NewSystemSeedTransferResponse(tx *types.Transaction, raw, message []byte, derived, feePayer, nonceAuthority *types.PublicKey, lamports, fee uint64) *SystemSeedTransferResponse {
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		Funding:         newSystemPayer(derived, lamports),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// SystemSeedAllocateRequest reserves data space on SHA256(base || seed ||
// System Program), the same derived account seed/create-account brings into
// existence.
//
// The account sized is the derived address, not Base itself: nobody holds a
// secret for a derived address, so Base signs in its place.
type SystemSeedAllocateRequest struct {
	Base string `json:"base" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	Seed string `json:"seed" example:"vault-1"`

	Space string `json:"space" example:"128"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	// RentPayer covers the shortfall, if any, between the derived account's
	// current balance and the rent-exemption minimum for Space: a transfer
	// from RentPayer for exactly that shortfall is prepended ahead of the
	// allocation. Required even when the derived account already holds
	// enough and no such transfer ends up being built. It may be the same
	// account as the derived address, but only when the derived address
	// already holds enough on its own — a shortfall has nowhere to come from
	// in that case.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	b   *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
	rp  *types.PublicKey
	d   *types.PublicKey
	s   uint64
}

func (r *SystemSeedAllocateRequest) ValidateRequest() error {
	var err error
	if r.b, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Base)); err != nil {
		return errors.New("base: " + err.Error())
	}

	r.Seed = strings.TrimSpace(r.Seed)
	if r.Seed == "" {
		return errors.New("seed is required")
	}
	if len(r.Seed) > types.MaxSeedLength {
		return fmt.Errorf("seed: %d bytes exceeds the %d byte limit", len(r.Seed), types.MaxSeedLength)
	}

	if r.d, err = types.CreateWithSeed(r.b, r.Seed, core.System.ID()); err != nil {
		return fmt.Errorf("seed: %w", err)
	}

	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	rp := strings.TrimSpace(r.RentPayer)
	if rp == "" {
		return errors.New("rent_payer is required")
	}
	if r.rp, err = types.NewPublicKeyFromBase58(rp); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}

	space := strings.TrimSpace(r.Space)
	if space == "" {
		return errors.New("space is required")
	}
	if r.s, err = strconv.ParseUint(space, 10, 64); err != nil {
		return errors.New("space: must be a decimal byte count")
	}
	if r.s == 0 {
		return errors.New("space: must be greater than zero")
	}
	if r.s > core.MaxPermittedDataLength {
		return fmt.Errorf("space: %d bytes exceeds the %d byte limit", r.s, core.MaxPermittedDataLength)
	}

	return nil
}

func (r *SystemSeedAllocateRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemSeedAllocateRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemSeedAllocateRequest) BaseKey() *types.PublicKey {
	return r.b
}

func (r *SystemSeedAllocateRequest) DerivedKey() *types.PublicKey {
	return r.d
}

func (r *SystemSeedAllocateRequest) RentPayerKey() *types.PublicKey {
	return r.rp
}

func (r *SystemSeedAllocateRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}

func (r *SystemSeedAllocateRequest) ToSpace() uint64 {
	return r.s
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

	Space uint64 `json:"space"`

	// Rent reports RentPayer and the shortfall it covered. Its lamports are
	// zero, and no transfer was actually prepended, when the derived
	// account's balance already reached the rent-exemption minimum for
	// Space.
	Rent SystemPayer `json:"rent"`

	Fee SystemPayer `json:"fee"`
}

func NewSystemSeedAllocateResponse(tx *types.Transaction, raw, message []byte, derived, rentPayer, feePayer, nonceAuthority *types.PublicKey, space, rentLamports, fee uint64) *SystemSeedAllocateResponse {
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		DerivedAddress:  derived.Base58(),
		NonceAuthority:  authority,
		Space:           space,
		Rent:            newSystemPayer(rentPayer, rentLamports),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// SystemSeedAssignRequest hands a derived account to the program it was
// derived for.
//
// There is no separate new-owner field. One owner does both jobs: it is what
// the address is derived from and what the account is assigned to, so an
// account can only be handed to the program its own address already encodes.
// This is why Owner is not fixed to the System Program the way it is on
// seed/create-account, seed/allocate, and seed/transfer: it names the target
// program, and a derived account only qualifies here if base, seed, and this
// exact owner were chosen together from the start. An account brought into
// existence through seed/create-account never qualifies, since that always
// derives against the System Program — Owner named here would either be the
// System Program itself, which is a no-op, or a different value, which
// points at an entirely different, unrelated address rather than reassigning
// the one seed/create-account made.
type SystemSeedAssignRequest struct {
	Base string `json:"base" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	Seed string `json:"seed" example:"vault-1"`

	// Owner is both the program the derived account is handed to and the
	// value base, seed, and this field must have been combined with from the
	// start to name that account at all. It must be executable: only the
	// owning program may debit an account or write its data, so assigning to
	// a plain address locks the account and its lamports permanently.
	Owner string `json:"owner" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	base    *types.PublicKey
	o       *types.PublicKey
	fp      *types.PublicKey
	rbh     *types.Hash
	dna     *types.PublicKey
	derived *types.PublicKey
}

func (r *SystemSeedAssignRequest) ValidateRequest() error {
	var err error
	if r.base, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Base)); err != nil {
		return errors.New("base: " + err.Error())
	}
	if r.o, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	r.Seed = strings.TrimSpace(r.Seed)
	if r.Seed == "" {
		return errors.New("seed is required")
	}
	if len(r.Seed) > types.MaxSeedLength {
		return fmt.Errorf("seed: %d bytes exceeds the %d byte limit", len(r.Seed), types.MaxSeedLength)
	}

	if r.derived, err = types.CreateWithSeed(r.base, r.Seed, r.o); err != nil {
		return fmt.Errorf("seed: %w", err)
	}

	return nil
}

func (r *SystemSeedAssignRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemSeedAssignRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemSeedAssignRequest) BaseKey() *types.PublicKey {
	return r.base
}

func (r *SystemSeedAssignRequest) DerivedKey() *types.PublicKey {
	return r.derived
}

func (r *SystemSeedAssignRequest) OwnerKey() *types.PublicKey {
	return r.o
}

func (r *SystemSeedAssignRequest) FeePayerKey() *types.PublicKey {
	return r.fp
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

	Owner string      `json:"owner"`
	Fee   SystemPayer `json:"fee"`
}

func NewSystemSeedAssignResponse(tx *types.Transaction, raw, message []byte, derived, owner, feePayer, nonceAuthority *types.PublicKey, fee uint64) *SystemSeedAssignResponse {
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		DerivedAddress:  derived.Base58(),
		NonceAuthority:  authority,
		Owner:           owner.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// SystemSeedTransferMaxRequest moves everything SHA256(base || seed ||
// System Program) holds, the same derived account seed/create-account brings
// into existence.
//
// The account drained is the derived address, not Base itself: nobody holds
// a secret for a derived address, so Base signs in its place.
type SystemSeedTransferMaxRequest struct {
	Base string `json:"base" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	Seed string `json:"seed" example:"vault-1"`

	// RecipientAccount is the account credited. It must already exist: this
	// is a plain transfer between two accounts, not a way to bring a new one
	// into existence.
	RecipientAccount string `json:"recipient_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as Base, but not the same account as the derived address,
	// which has no key to sign with.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	b   *types.PublicKey
	ra  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
	d   *types.PublicKey
}

func (r *SystemSeedTransferMaxRequest) ValidateRequest() error {
	var err error
	if r.b, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Base)); err != nil {
		return errors.New("base: " + err.Error())
	}

	r.Seed = strings.TrimSpace(r.Seed)
	if r.Seed == "" {
		return errors.New("seed is required")
	}
	if len(r.Seed) > types.MaxSeedLength {
		return fmt.Errorf("seed: %d bytes exceeds the %d byte limit", len(r.Seed), types.MaxSeedLength)
	}

	if r.d, err = types.CreateWithSeed(r.b, r.Seed, core.System.ID()); err != nil {
		return fmt.Errorf("seed: %w", err)
	}

	if r.ra, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RecipientAccount)); err != nil {
		return errors.New("recipient_account: " + err.Error())
	}
	if r.d.Equal(r.ra) {
		return errors.New("the derived account and recipient_account are the same account")
	}

	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}
	if r.fp.Equal(r.d) {
		return errors.New("fee_payer and the derived account are the same account, and the derived account has no key to sign with")
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *SystemSeedTransferMaxRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemSeedTransferMaxRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemSeedTransferMaxRequest) BaseKey() *types.PublicKey {
	return r.b
}

func (r *SystemSeedTransferMaxRequest) DerivedKey() *types.PublicKey {
	return r.d
}

func (r *SystemSeedTransferMaxRequest) RecipientAccountKey() *types.PublicKey {
	return r.ra
}

func (r *SystemSeedTransferMaxRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}

type SystemSeedTransferMaxResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	// Funding reports the transfer itself: the derived account drained, and
	// how much that turned out to be.
	Funding SystemPayer `json:"funding"`

	Fee SystemPayer `json:"fee"`
}

func NewSystemSeedTransferMaxResponse(tx *types.Transaction, raw, message []byte, derived, feePayer, nonceAuthority *types.PublicKey, lamports, fee uint64) *SystemSeedTransferMaxResponse {
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		Funding:         newSystemPayer(derived, lamports),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// SystemNonceCreateRequest funds a new account and hands it to the System
// Program, sized correctly for a nonce account but not initialized.
//
// This is deliberately the low-level half only: initializing it is a
// separate call (nonce/initialize), and nothing stops somebody else from
// initializing it first in between with their own authority. A caller who
// wants that race closed should build create+initialize as two instructions
// in one transaction themselves. Neither the size nor the funding is a
// field. A nonce account is always exactly NonceAccountSpace bytes, and the
// amount that has to sit in it is the rent-exempt minimum for that size, so
// both follow from what the account is rather than from a choice the caller
// makes.
type SystemNonceCreateRequest struct {
	// NewNonceAccount is the account created. It signs alongside RentPayer,
	// since an address does not exist until whoever holds its private key
	// authorizes its creation. It must not already exist.
	NewNonceAccount string `json:"new_nonce_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice. It has to be an account other than NewNonceAccount, which
	// holds no nonce yet.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	// RentPayer funds NewNonceAccount's creation for exactly the
	// rent-exemption minimum for a nonce account's fixed size — always, and
	// only that amount. Neither the size nor the funding is a choice: a
	// nonce account is always exactly NonceAccountSpace bytes, and the
	// amount that has to sit in it follows from that.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	rp  *types.PublicKey
	nna *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *SystemNonceCreateRequest) ValidateRequest() error {
	var err error
	if r.nna, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.NewNonceAccount)); err != nil {
		return errors.New("new_nonce_account: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
		if r.dna.Equal(r.nna) {
			return errors.New("durable_nonce_account: cannot be the account being created, which holds no nonce yet")
		}
	}

	rp := strings.TrimSpace(r.RentPayer)
	if rp == "" {
		return errors.New("rent_payer is required")
	}
	if r.rp, err = types.NewPublicKeyFromBase58(rp); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.rp.Equal(r.nna) {
		return errors.New("rent_payer and new_nonce_account are the same account")
	}

	return nil
}

func (r *SystemNonceCreateRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemNonceCreateRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemNonceCreateRequest) RentPayerKey() *types.PublicKey {
	return r.rp
}

func (r *SystemNonceCreateRequest) NewNonceAccountKey() *types.PublicKey {
	return r.nna
}

func (r *SystemNonceCreateRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}

type SystemNonceCreateResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`
	NewNonceAccount string   `json:"new_nonce_account"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries
	// a stored value rather than a fetched blockhash. It belongs to
	// durable_nonce_account, not to NewNonceAccount: this endpoint never
	// initializes NewNonceAccount, so it gains no authority of its own here.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Space uint64 `json:"space"`

	// Rent reports what funds the creation. Its lamports are always exactly
	// the rent-exemption minimum for a nonce account's fixed size, never more
	// or less.
	Rent SystemPayer `json:"rent"`

	Fee SystemPayer `json:"fee"`
}

func NewSystemNonceCreateResponse(tx *types.Transaction, raw, message []byte, newNonceAccount, rentPayer, feePayer, nonceAuthority *types.PublicKey, rentLamports, fee uint64) *SystemNonceCreateResponse {
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NewNonceAccount: newNonceAccount.Base58(),
		NonceAuthority:  nonceAuthorityBase58,
		Space:           core.NonceAccountSpace,
		Rent:            newSystemPayer(rentPayer, rentLamports),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// SystemNonceInitializeRequest turns an account that already exists into a
// durable nonce account.
//
// This is the natural pairing for nonce/create-account, which only creates
// the account and never initializes it. Nothing stops somebody else from
// initializing it first in between, with their own authority; a caller who
// wants that race closed should build create+initialize as two instructions
// in one transaction themselves. This is also the only path left for an
// address that cannot be created any more: CreateAccount refuses an account
// that already holds lamports, so an address someone funded first can only
// become a nonce account through this initializer alone.
type SystemNonceInitializeRequest struct {
	// NonceAccount must already exist, be owned by the System Program, and be
	// exactly NonceAccountSpace bytes — this endpoint doesn't create it, only
	// writes the nonce state into a slot that's already there, and it does
	// not sign: no authority of its own is needed to accept one. It is named
	// apart from DurableNonceAccount because both name a nonce account, and
	// only their roles differ: this one is what the instruction acts on, that
	// one is only what prices and expiry-proofs the transaction.
	NonceAccount string `json:"nonce_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice. It has to be an account other than NonceAccount, which
	// holds no nonce to build against yet.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	na  *types.PublicKey
	a   *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *SystemNonceInitializeRequest) ValidateRequest() error {
	var err error
	if r.na, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.NonceAccount)); err != nil {
		return errors.New("nonce_account: " + err.Error())
	}
	if r.a, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
		if r.dna.Equal(r.na) {
			return errors.New("durable_nonce_account: cannot be the account being initialized, which holds no nonce yet")
		}
	}

	return nil
}

func (r *SystemNonceInitializeRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemNonceInitializeRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemNonceInitializeRequest) NonceAccountKey() *types.PublicKey {
	return r.na
}

func (r *SystemNonceInitializeRequest) AuthorityKey() *types.PublicKey {
	return r.a
}

func (r *SystemNonceInitializeRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}

type SystemNonceInitializeResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`
	NonceAccount    string   `json:"nonce_account"`
	Authority       string   `json:"authority"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash. It belongs to
	// durable_nonce_account, not to NonceAccount — Authority above is what
	// NonceAccount gains.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Fee SystemPayer `json:"fee"`
}

func NewSystemNonceInitializeResponse(tx *types.Transaction, raw, message []byte, nonceAccount, authority, feePayer, nonceAuthority *types.PublicKey, fee uint64) *SystemNonceInitializeResponse {
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAccount:    nonceAccount.Base58(),
		Authority:       authority.Base58(),
		NonceAuthority:  nonceAuthorityBase58,
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// SystemNonceAdvanceRequest rotates the value stored in a nonce account.
//
// Advancing is what consumes a nonce. A transaction built against one carries
// it in place of a recent blockhash and runs this as its first instruction, so
// the value it was built for is gone by the time it finishes and the same
// transaction cannot land twice.
type SystemNonceAdvanceRequest struct {
	// NonceAccount must already exist, be owned by the System Program, be
	// exactly NonceAccountSpace bytes, and already be initialized — Advance
	// rotates a stored value, it does not create one. It is named apart from
	// DurableNonceAccount because both name a nonce account, and only their
	// roles differ: this one is what the instruction acts on, that one is
	// only what prices and expiry-proofs the transaction.
	NonceAccount string `json:"nonce_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice. It has to be an account other than NonceAccount: the
	// runtime refuses a transaction that advances the same nonce twice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	na  *types.PublicKey
	a   *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *SystemNonceAdvanceRequest) ValidateRequest() error {
	var err error
	if r.na, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.NonceAccount)); err != nil {
		return errors.New("nonce_account: " + err.Error())
	}
	if r.a, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
		if r.dna.Equal(r.na) {
			return errors.New("durable_nonce_account: cannot be nonce_account, since a transaction may advance a nonce only once")
		}
	}

	return nil
}

func (r *SystemNonceAdvanceRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemNonceAdvanceRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemNonceAdvanceRequest) NonceAccountKey() *types.PublicKey {
	return r.na
}

func (r *SystemNonceAdvanceRequest) AuthorityKey() *types.PublicKey {
	return r.a
}

func (r *SystemNonceAdvanceRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}

type SystemNonceAdvanceResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`
	NonceAccount    string   `json:"nonce_account"`
	Authority       string   `json:"authority"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash. It belongs to
	// durable_nonce_account, not to NonceAccount — Authority above is
	// NonceAccount's.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	// CurrentNonce is what NonceAccount holds now, before this transaction
	// lands. Any transaction already built against it stops being valid once
	// this one executes.
	CurrentNonce string `json:"current_nonce"`

	Fee SystemPayer `json:"fee"`
}

func NewSystemNonceAdvanceResponse(tx *types.Transaction, raw, message []byte, nonceAccount, authority, feePayer, nonceAuthority *types.PublicKey, currentNonce *types.Hash, fee uint64) *SystemNonceAdvanceResponse {
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAccount:    nonceAccount.Base58(),
		Authority:       authority.Base58(),
		NonceAuthority:  nonceAuthorityBase58,
		CurrentNonce:    currentNonce.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// SystemNonceWithdrawRequest takes part of a nonce account's balance.
//
// Only part of it. Taking everything closes the account and the runtime
// applies a further rule to that, so it has its own endpoint: what stays here
// has to keep the account rent exempt at its size, or it would be subject to
// removal while still holding a nonce something was built against.
type SystemNonceWithdrawRequest struct {
	// NonceAccount is withdrawn from. It is named apart from
	// DurableNonceAccount because both name a nonce account, and only their
	// roles differ: this one is what the instruction acts on, that one is
	// only what prices and expiry-proofs the transaction.
	NonceAccount string `json:"nonce_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecipientAccount is the account credited. It must already exist: this
	// is a plain transfer between two accounts, not a way to bring a new one
	// into existence.
	RecipientAccount string `json:"recipient_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// Lamports is the raw amount moved from NonceAccount to RecipientAccount.
	// Taking everything closes the account and the runtime applies a further
	// rule to that, so it has its own endpoint: what stays here has to keep
	// NonceAccount rent exempt at its size.
	Lamports string `json:"lamports" example:"1000000"`

	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice. It has to be an account other than NonceAccount: the
	// runtime refuses a transaction that advances the same nonce twice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	na  *types.PublicKey
	a   *types.PublicKey
	ra  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
	l   uint64
}

func (r *SystemNonceWithdrawRequest) ValidateRequest() error {
	var err error
	if r.na, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.NonceAccount)); err != nil {
		return errors.New("nonce_account: " + err.Error())
	}
	if r.a, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.ra, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RecipientAccount)); err != nil {
		return errors.New("recipient_account: " + err.Error())
	}
	if r.na.Equal(r.ra) {
		return errors.New("nonce_account and recipient_account are the same account")
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
		if r.dna.Equal(r.na) {
			return errors.New("durable_nonce_account: cannot be nonce_account, since a transaction may advance a nonce only once")
		}
	}

	lamports := strings.TrimSpace(r.Lamports)
	if lamports == "" {
		return errors.New("lamports is required")
	}
	if r.l, err = strconv.ParseUint(lamports, 10, 64); err != nil {
		return errors.New("lamports: must be a decimal lamport count")
	}
	if r.l == 0 {
		return errors.New("lamports: must be greater than zero")
	}

	return nil
}

func (r *SystemNonceWithdrawRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemNonceWithdrawRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemNonceWithdrawRequest) NonceAccountKey() *types.PublicKey {
	return r.na
}

func (r *SystemNonceWithdrawRequest) AuthorityKey() *types.PublicKey {
	return r.a
}

func (r *SystemNonceWithdrawRequest) RecipientAccountKey() *types.PublicKey {
	return r.ra
}

func (r *SystemNonceWithdrawRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}

func (r *SystemNonceWithdrawRequest) ToLamports() uint64 {
	return r.l
}

type SystemNonceWithdrawResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`
	NonceAccount    string   `json:"nonce_account"`
	Authority       string   `json:"authority"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash. It belongs to
	// durable_nonce_account, not to NonceAccount — Authority above is
	// NonceAccount's.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	// Withdrawal reports NonceAccount and how much was taken from it.
	Withdrawal SystemPayer `json:"withdrawal"`

	// Remaining is what NonceAccount keeps, which has to stay at or above the
	// rent-exempt minimum for its size.
	Remaining string `json:"remaining"`

	Fee SystemPayer `json:"fee"`
}

func NewSystemNonceWithdrawResponse(tx *types.Transaction, raw, message []byte, nonceAccount, authority, feePayer, nonceAuthority *types.PublicKey, lamports, remaining, fee uint64) *SystemNonceWithdrawResponse {
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAccount:    nonceAccount.Base58(),
		Authority:       authority.Base58(),
		NonceAuthority:  nonceAuthorityBase58,
		Withdrawal:      newSystemPayer(nonceAccount, lamports),
		Remaining:       strconv.FormatUint(remaining, 10),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// SystemNonceWithdrawMaxRequest empties a nonce account, which closes it.
//
// There is no amount: taking anything less leaves the account open and is what
// nonce/withdraw does. The fee payer cannot be the nonce account itself, since
// the balance being withdrawn is the same balance the fee would come from.
type SystemNonceWithdrawMaxRequest struct {
	// NonceAccount is emptied and thereby closed. It is named apart from
	// DurableNonceAccount because both name a nonce account, and only their
	// roles differ: this one is what the instruction acts on, that one is
	// only what prices and expiry-proofs the transaction.
	NonceAccount string `json:"nonce_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecipientAccount is the account credited. It must already exist: this
	// is a plain transfer between two accounts, not a way to bring a new one
	// into existence.
	RecipientAccount string `json:"recipient_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// FeePayer signs and pays the transaction fee. It cannot be NonceAccount
	// itself, since the balance being withdrawn is the same balance the fee
	// would come from.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice. It has to be an account other than NonceAccount, which
	// could not be closed anyway once this transaction has just advanced it.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	na  *types.PublicKey
	a   *types.PublicKey
	ra  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *SystemNonceWithdrawMaxRequest) ValidateRequest() error {
	var err error
	if r.na, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.NonceAccount)); err != nil {
		return errors.New("nonce_account: " + err.Error())
	}
	if r.a, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.ra, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RecipientAccount)); err != nil {
		return errors.New("recipient_account: " + err.Error())
	}
	if r.na.Equal(r.ra) {
		return errors.New("nonce_account and recipient_account are the same account")
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}
	if r.na.Equal(r.fp) {
		return errors.New("fee_payer: cannot be nonce_account, whose whole balance is being withdrawn")
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
		if r.dna.Equal(r.na) {
			return errors.New("durable_nonce_account: cannot be nonce_account, whose stored value this transaction would have just advanced to the current blockhash, which blocks closing it")
		}
	}

	return nil
}

func (r *SystemNonceWithdrawMaxRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemNonceWithdrawMaxRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemNonceWithdrawMaxRequest) NonceAccountKey() *types.PublicKey {
	return r.na
}

func (r *SystemNonceWithdrawMaxRequest) AuthorityKey() *types.PublicKey {
	return r.a
}

func (r *SystemNonceWithdrawMaxRequest) RecipientAccountKey() *types.PublicKey {
	return r.ra
}

func (r *SystemNonceWithdrawMaxRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}

type SystemNonceWithdrawMaxResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`
	NonceAccount    string   `json:"nonce_account"`
	Authority       string   `json:"authority"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash. It belongs to
	// durable_nonce_account, not to NonceAccount — Authority above is
	// NonceAccount's.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	// Withdrawal reports NonceAccount and its entire balance, which this
	// closes the account by taking.
	Withdrawal SystemPayer `json:"withdrawal"`

	Fee SystemPayer `json:"fee"`
}

func NewSystemNonceWithdrawMaxResponse(tx *types.Transaction, raw, message []byte, nonceAccount, authority, feePayer, nonceAuthority *types.PublicKey, lamports, fee uint64) *SystemNonceWithdrawMaxResponse {
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAccount:    nonceAccount.Base58(),
		Authority:       authority.Base58(),
		NonceAuthority:  nonceAuthorityBase58,
		Withdrawal:      newSystemPayer(nonceAccount, lamports),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// SystemNonceAuthorizeRequest hands control of a nonce account to another key.
//
// The stored nonce and the balance are untouched. Only who may advance and
// withdraw changes, which also invalidates anything the old authority signed
// but never submitted: such a transaction advances the nonce as its first
// instruction, and that now needs a signature the old authority cannot give.
type SystemNonceAuthorizeRequest struct {
	// NonceAccount must already exist, be owned by the System Program, be
	// exactly NonceAccountSpace bytes, and already be initialized — Authorize
	// hands off control of a nonce account, it does not create one. It is
	// named apart from DurableNonceAccount because both name a nonce
	// account, and only their roles differ: this one is what the instruction
	// acts on, that one is only what prices and expiry-proofs the transaction.
	NonceAccount string `json:"nonce_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	NewAuthority string `json:"new_authority" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice. It has to be an account other than NonceAccount: the
	// runtime refuses a transaction that advances the same nonce twice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	nAcc *types.PublicKey
	a    *types.PublicKey
	na   *types.PublicKey
	fp   *types.PublicKey
	rbh  *types.Hash
	dna  *types.PublicKey
}

func (r *SystemNonceAuthorizeRequest) ValidateRequest() error {
	var err error
	if r.nAcc, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.NonceAccount)); err != nil {
		return errors.New("nonce_account: " + err.Error())
	}
	if r.a, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.na, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.NewAuthority)); err != nil {
		return errors.New("new_authority: " + err.Error())
	}
	if r.a.Equal(r.na) {
		return errors.New("new_authority: is already the authority")
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
		if r.dna.Equal(r.nAcc) {
			return errors.New("durable_nonce_account: cannot be nonce_account, since a transaction may advance a nonce only once")
		}
	}

	return nil
}

func (r *SystemNonceAuthorizeRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemNonceAuthorizeRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemNonceAuthorizeRequest) NonceAccountKey() *types.PublicKey {
	return r.nAcc
}

func (r *SystemNonceAuthorizeRequest) AuthorityKey() *types.PublicKey {
	return r.a
}

func (r *SystemNonceAuthorizeRequest) NewAuthorityKey() *types.PublicKey {
	return r.na
}

func (r *SystemNonceAuthorizeRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}

type SystemNonceAuthorizeResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`
	NonceAccount    string   `json:"nonce_account"`
	Authority       string   `json:"authority"`
	NewAuthority    string   `json:"new_authority"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries a
	// stored value rather than a fetched blockhash. It belongs to
	// durable_nonce_account, not to NonceAccount — Authority above is
	// NonceAccount's, before this transaction lands.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Fee SystemPayer `json:"fee"`
}

func NewSystemNonceAuthorizeResponse(tx *types.Transaction, raw, message []byte, nonceAccount, authority, newAuthority, feePayer, nonceAuthority *types.PublicKey, fee uint64) *SystemNonceAuthorizeResponse {
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAccount:    nonceAccount.Base58(),
		Authority:       authority.Base58(),
		NewAuthority:    newAuthority.Base58(),
		NonceAuthority:  nonceAuthorityBase58,
		Fee:             newSystemPayer(feePayer, fee),
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
	// NonceAccount is the Legacy account being migrated. It is named apart
	// from DurableNonceAccount because both name a nonce account, and only
	// their roles differ: this one is what the instruction acts on, that one
	// is only what prices and expiry-proofs the transaction.
	NonceAccount string `json:"nonce_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the account, since it is a fact about it rather
	// than a choice. It has to be an account other than NonceAccount, which is
	// Legacy and so not something to build against.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	na  *types.PublicKey
	fp  *types.PublicKey
	rbh *types.Hash
	dna *types.PublicKey
}

func (r *SystemNonceUpgradeRequest) ValidateRequest() error {
	var err error
	if r.na, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.NonceAccount)); err != nil {
		return errors.New("nonce_account: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
		if r.dna.Equal(r.na) {
			return errors.New("durable_nonce_account: cannot be nonce_account, which is being migrated by this same transaction")
		}
	}

	return nil
}

func (r *SystemNonceUpgradeRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SystemNonceUpgradeRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SystemNonceUpgradeRequest) NonceAccountKey() *types.PublicKey {
	return r.na
}

func (r *SystemNonceUpgradeRequest) FeePayerKey() *types.PublicKey {
	return r.fp
}

type SystemNonceUpgradeResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`
	NonceAccount    string   `json:"nonce_account"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries
	// a stored value rather than a fetched blockhash. NonceAccount has an
	// authority too, but nothing signs for an upgrade, so it is not reported.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Version uint32      `json:"version"`
	Fee     SystemPayer `json:"fee"`
}

func NewSystemNonceUpgradeResponse(tx *types.Transaction, raw, message []byte, nonceAccount, feePayer, nonceAuthority *types.PublicKey, version uint32, fee uint64) *SystemNonceUpgradeResponse {
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAccount:    nonceAccount.Base58(),
		NonceAuthority:  nonceAuthorityBase58,
		Version:         version,
		Fee:             newSystemPayer(feePayer, fee),
	}
}
