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

// CreateMintRequest funds and initializes an 82-byte mint in one transaction.
//
// A mint created without initializing carries a real risk: anybody can
// initialize an uninitialized Token-owned account before its intended owner
// does, which is why these are always the same two instructions rather than
// two endpoints.
type CreateMintRequest struct {
	From            string `json:"from" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Mint            string `json:"mint" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`
	MintAuthority   string `json:"mint_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	FreezeAuthority string `json:"freeze_authority" example:""`
	Decimals        uint8  `json:"decimals" example:"6"`
	FeePayer        string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instructions to: classic Token
	// or Token-2022. It is required rather than defaulted, since a mint
	// belongs to exactly one of the two forever and defaulting would make
	// picking wrong silent. It is an address rather than a name because that
	// is what actually selects the program on chain: Token-2022 is not an
	// enum value, it is a different account, and a third Token
	// implementation would need no change here to be reachable.
	Program string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	// NonceAccount may be left empty, in which case a recent blockhash is
	// fetched and the transaction expires with it. Naming one builds against
	// the value that account stores instead, so the transaction never
	// expires.
	NonceAccount string `json:"nonce_account" example:""`

	from            *types.PublicKey
	mint            *types.PublicKey
	mintAuthority   *types.PublicKey
	freezeAuthority *types.PublicKey
	feePayer        *types.PublicKey
	nonceAccount    *types.PublicKey
	tokenProgramID  *types.PublicKey
}

func (r *CreateMintRequest) ValidateRequest() error {
	var err error
	if r.from, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.From)); err != nil {
		return errors.New("from: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.from.Equal(r.mint) {
		return errors.New("from and mint are the same account")
	}
	if r.mintAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.MintAuthority)); err != nil {
		return errors.New("mint_authority: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	// An absent freeze authority means the mint is created with none, and
	// that decision cannot be undone later: it is not "leave it alone", it is
	// permanent. There is no separate flag here the way SetAuthority needs
	// one, because a mint that does not exist yet has no prior authority a
	// typo could accidentally remove.
	if fa := strings.TrimSpace(r.FreezeAuthority); fa != "" {
		if r.freezeAuthority, err = types.NewPublicKeyFromBase58(fa); err != nil {
			return errors.New("freeze_authority: " + err.Error())
		}
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
	}

	program := strings.TrimSpace(r.Program)
	if program == "" {
		return errors.New("program is required")
	}
	if r.tokenProgramID, err = types.NewPublicKeyFromBase58(program); err != nil {
		return errors.New("program: " + err.Error())
	}
	if !r.tokenProgramID.Equal(core.TokenProgramID) && !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is neither the Token nor the Token-2022 program", r.tokenProgramID)
	}

	return nil
}

func (r *CreateMintRequest) FromKey() *types.PublicKey {
	return r.from
}

func (r *CreateMintRequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *CreateMintRequest) MintAuthorityKey() *types.PublicKey {
	return r.mintAuthority
}

func (r *CreateMintRequest) FreezeAuthorityKey() *types.PublicKey {
	return r.freezeAuthority
}

func (r *CreateMintRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *CreateMintRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *CreateMintRequest) ToDecimals() uint8 {
	return r.Decimals
}

// TokenProgramID returns the resolved program account, either
// core.TokenProgramID or core.Token2022ProgramID. core.TokenProgram(id) turns
// it into a builder.
func (r *CreateMintRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// CreateMintResponse mirrors the v1/System build response shape, plus what
// this endpoint had to resolve to validate: the rent-exempt minimum for an
// 82-byte account and the mint's own field values.
type CreateMintResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	// NonceAuthority is present only when the transaction was built against a
	// durable nonce, so it doubles as the signal that RecentBlockhash carries
	// a stored value rather than a fetched blockhash.
	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint            string `json:"mint"`
	Program         string `json:"program"`
	MintAuthority   string `json:"mint_authority"`
	FreezeAuthority string `json:"freeze_authority,omitempty"`
	Decimals        uint8  `json:"decimals"`

	RentExempt string `json:"rent_exempt"`
	Fee        string `json:"fee"`
}

func NewCreateMintResponse(
	tx *types.Transaction, raw, message []byte,
	mint, tokenProgram, mintAuthority, freezeAuthority, nonceAuthority *types.PublicKey,
	decimals uint8, rentExempt, fee uint64,
) *CreateMintResponse {
	authority := ""
	if !nonceAuthority.IsNil() {
		authority = nonceAuthority.Base58()
	}

	freeze := ""
	if !freezeAuthority.IsNil() {
		freeze = freezeAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &CreateMintResponse{
		Transaction:     base64.StdEncoding.EncodeToString(raw),
		Message:         base64.StdEncoding.EncodeToString(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		Mint:            mint.Base58(),
		Program:         tokenProgram.Base58(),
		MintAuthority:   mintAuthority.Base58(),
		FreezeAuthority: freeze,
		Decimals:        decimals,
		RentExempt:      strconv.FormatUint(rentExempt, 10),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// CreateAccountRequest funds and initializes a 165-byte token account in one
// transaction.
//
// This produces a plain keypair account rather than an associated one: the
// address is whatever key was generated for it, and nothing can rediscover it
// from the wallet and mint the way an associated token account can be. It is
// still what to use when a wallet wants more than one account for the same
// mint, since the associated address is one per pair.
type CreateAccountRequest struct {
	From     string `json:"from" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Account  string `json:"account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`
	Mint     string `json:"mint" example:""`
	Owner    string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instructions to: classic Token
	// or Token-2022. It is required rather than defaulted, since a token
	// account belongs to exactly one of the two forever, and it must agree
	// with the mint's own owning program or the instruction fails on chain.
	Program string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	NonceAccount string `json:"nonce_account" example:""`

	from           *types.PublicKey
	account        *types.PublicKey
	mint           *types.PublicKey
	owner          *types.PublicKey
	feePayer       *types.PublicKey
	nonceAccount   *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *CreateAccountRequest) ValidateRequest() error {
	var err error
	if r.from, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.From)); err != nil {
		return errors.New("from: " + err.Error())
	}
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.from.Equal(r.account) {
		return errors.New("from and account are the same account")
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
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

	program := strings.TrimSpace(r.Program)
	if program == "" {
		return errors.New("program is required")
	}
	if r.tokenProgramID, err = types.NewPublicKeyFromBase58(program); err != nil {
		return errors.New("program: " + err.Error())
	}
	if !r.tokenProgramID.Equal(core.TokenProgramID) && !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is neither the Token nor the Token-2022 program", r.tokenProgramID)
	}

	return nil
}

func (r *CreateAccountRequest) FromKey() *types.PublicKey {
	return r.from
}

func (r *CreateAccountRequest) AccountKey() *types.PublicKey {
	return r.account
}

func (r *CreateAccountRequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *CreateAccountRequest) OwnerKey() *types.PublicKey {
	return r.owner
}

func (r *CreateAccountRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *CreateAccountRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

// TokenProgramID returns the resolved program account, either
// core.TokenProgramID or core.Token2022ProgramID. core.TokenProgram(id) turns
// it into a builder.
func (r *CreateAccountRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// CreateAccountResponse mirrors CreateMintResponse's shape for the same
// reason: what the server had to resolve to validate is what a caller needs
// to know to build the next transaction without guessing.
type CreateAccountResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Mint    string `json:"mint"`
	Owner   string `json:"owner"`
	Program string `json:"program"`

	RentExempt string `json:"rent_exempt"`
	Fee        string `json:"fee"`
}

func NewCreateAccountResponse(
	tx *types.Transaction, raw, message []byte,
	account, mint, owner, tokenProgram, nonceAuthority *types.PublicKey,
	rentExempt, fee uint64,
) *CreateAccountResponse {
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

	return &CreateAccountResponse{
		Transaction:     base64.StdEncoding.EncodeToString(raw),
		Message:         base64.StdEncoding.EncodeToString(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		Account:         account.Base58(),
		Mint:            mint.Base58(),
		Owner:           owner.Base58(),
		Program:         tokenProgram.Base58(),
		RentExempt:      strconv.FormatUint(rentExempt, 10),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// MintToCheckedRequest creates new supply into an existing token account.
//
// Amount is base units, not a UI decimal string; decimals is metadata read
// from the mint, not the unit amount is expressed in. Decimals is taken from
// the request and checked against the mint rather than filled in from it,
// since reading the mint to supply the value would defeat what the checked
// variants exist for: catching a client that formatted an amount against the
// wrong decimals before it becomes an on-chain failure.
type MintToCheckedRequest struct {
	Mint        string `json:"mint" example:""`
	Destination string `json:"destination" example:""`
	Authority   string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Amount      string `json:"amount" example:"1000000"`
	Decimals    uint8  `json:"decimals" example:"6"`
	FeePayer    string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program     string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	// MultisigSigners is empty for a single-signer authority. Non-empty, the
	// authority itself does not sign; the named members do, in its place.
	MultisigSigners []string `json:"multisig_signers"`

	NonceAccount string `json:"nonce_account" example:""`

	mint            *types.PublicKey
	destination     *types.PublicKey
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	nonceAccount    *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
	amount          uint64
}

func (r *MintToCheckedRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.destination, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Destination)); err != nil {
		return errors.New("destination: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	amount := strings.TrimSpace(r.Amount)
	if amount == "" {
		return errors.New("amount is required")
	}
	if r.amount, err = strconv.ParseUint(amount, 10, 64); err != nil {
		return errors.New("amount: must be a decimal base-unit count")
	}
	if r.amount == 0 {
		return errors.New("amount: must be greater than zero")
	}

	r.multisigSigners = make([]*types.PublicKey, len(r.MultisigSigners))
	for i, s := range r.MultisigSigners {
		if r.multisigSigners[i], err = types.NewPublicKeyFromBase58(strings.TrimSpace(s)); err != nil {
			return fmt.Errorf("multisig_signers[%d]: %s", i, err)
		}
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
	}

	program := strings.TrimSpace(r.Program)
	if program == "" {
		return errors.New("program is required")
	}
	if r.tokenProgramID, err = types.NewPublicKeyFromBase58(program); err != nil {
		return errors.New("program: " + err.Error())
	}
	if !r.tokenProgramID.Equal(core.TokenProgramID) && !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is neither the Token nor the Token-2022 program", r.tokenProgramID)
	}

	return nil
}

func (r *MintToCheckedRequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *MintToCheckedRequest) DestinationKey() *types.PublicKey {
	return r.destination
}

func (r *MintToCheckedRequest) AuthorityKey() *types.PublicKey {
	return r.authority
}

func (r *MintToCheckedRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *MintToCheckedRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *MintToCheckedRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

func (r *MintToCheckedRequest) ToAmount() uint64 {
	return r.amount
}

func (r *MintToCheckedRequest) ToDecimals() uint8 {
	return r.Decimals
}

func (r *MintToCheckedRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

type MintToCheckedResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint        string `json:"mint"`
	Destination string `json:"destination"`
	Authority   string `json:"authority"`
	Program     string `json:"program"`
	Amount      string `json:"amount"`
	Decimals    uint8  `json:"decimals"`
	Fee         string `json:"fee"`
}

func NewMintToCheckedResponse(
	tx *types.Transaction, raw, message []byte,
	mint, destination, authority, tokenProgram, nonceAuthority *types.PublicKey,
	amount uint64, decimals uint8, fee uint64,
) *MintToCheckedResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &MintToCheckedResponse{
		Transaction:     base64.StdEncoding.EncodeToString(raw),
		Message:         base64.StdEncoding.EncodeToString(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Destination:     destination.Base58(),
		Authority:       authority.Base58(),
		Program:         tokenProgram.Base58(),
		Amount:          strconv.FormatUint(amount, 10),
		Decimals:        decimals,
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// TransferCheckedRequest moves a balance between two token accounts of the
// same mint.
//
// It never sends to a wallet address directly: a transfer moves between
// *token accounts*, and a caller with only a wallet address needs the
// recipient's associated token account created first.
type TransferCheckedRequest struct {
	Source      string `json:"source" example:""`
	Mint        string `json:"mint" example:""`
	Destination string `json:"destination" example:""`
	Authority   string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Amount      string `json:"amount" example:"250000"`
	Decimals    uint8  `json:"decimals" example:"6"`
	FeePayer    string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program     string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	// MultisigSigners is empty for a single-signer authority. Non-empty, the
	// authority itself does not sign; the named members do, in its place.
	MultisigSigners []string `json:"multisig_signers"`

	NonceAccount string `json:"nonce_account" example:""`

	source          *types.PublicKey
	mint            *types.PublicKey
	destination     *types.PublicKey
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	nonceAccount    *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
	amount          uint64
}

func (r *TransferCheckedRequest) ValidateRequest() error {
	var err error
	if r.source, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Source)); err != nil {
		return errors.New("source: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.destination, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Destination)); err != nil {
		return errors.New("destination: " + err.Error())
	}
	if r.source.Equal(r.destination) {
		return errors.New("source and destination are the same account")
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	amount := strings.TrimSpace(r.Amount)
	if amount == "" {
		return errors.New("amount is required")
	}
	if r.amount, err = strconv.ParseUint(amount, 10, 64); err != nil {
		return errors.New("amount: must be a decimal base-unit count")
	}
	if r.amount == 0 {
		return errors.New("amount: must be greater than zero")
	}

	r.multisigSigners = make([]*types.PublicKey, len(r.MultisigSigners))
	for i, s := range r.MultisigSigners {
		if r.multisigSigners[i], err = types.NewPublicKeyFromBase58(strings.TrimSpace(s)); err != nil {
			return fmt.Errorf("multisig_signers[%d]: %s", i, err)
		}
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
	}

	program := strings.TrimSpace(r.Program)
	if program == "" {
		return errors.New("program is required")
	}
	if r.tokenProgramID, err = types.NewPublicKeyFromBase58(program); err != nil {
		return errors.New("program: " + err.Error())
	}
	if !r.tokenProgramID.Equal(core.TokenProgramID) && !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is neither the Token nor the Token-2022 program", r.tokenProgramID)
	}

	return nil
}

func (r *TransferCheckedRequest) SourceKey() *types.PublicKey {
	return r.source
}

func (r *TransferCheckedRequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *TransferCheckedRequest) DestinationKey() *types.PublicKey {
	return r.destination
}

func (r *TransferCheckedRequest) AuthorityKey() *types.PublicKey {
	return r.authority
}

func (r *TransferCheckedRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *TransferCheckedRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *TransferCheckedRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

func (r *TransferCheckedRequest) ToAmount() uint64 {
	return r.amount
}

func (r *TransferCheckedRequest) ToDecimals() uint8 {
	return r.Decimals
}

func (r *TransferCheckedRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

type TransferCheckedResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Source      string `json:"source"`
	Mint        string `json:"mint"`
	Destination string `json:"destination"`
	Authority   string `json:"authority"`
	Program     string `json:"program"`
	Amount      string `json:"amount"`
	Decimals    uint8  `json:"decimals"`
	Fee         string `json:"fee"`
}

func NewTransferCheckedResponse(
	tx *types.Transaction, raw, message []byte,
	source, mint, destination, authority, tokenProgram, nonceAuthority *types.PublicKey,
	amount uint64, decimals uint8, fee uint64,
) *TransferCheckedResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &TransferCheckedResponse{
		Transaction:     base64.StdEncoding.EncodeToString(raw),
		Message:         base64.StdEncoding.EncodeToString(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Source:          source.Base58(),
		Mint:            mint.Base58(),
		Destination:     destination.Base58(),
		Authority:       authority.Base58(),
		Program:         tokenProgram.Base58(),
		Amount:          strconv.FormatUint(amount, 10),
		Decimals:        decimals,
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// BurnCheckedRequest destroys supply held by an account.
//
// The authority is the account's owner or delegate, not the mint's authority:
// burning spends a balance, so it is the holder's to authorize.
type BurnCheckedRequest struct {
	Account   string `json:"account" example:""`
	Mint      string `json:"mint" example:""`
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Amount    string `json:"amount" example:"1000"`
	Decimals  uint8  `json:"decimals" example:"6"`
	FeePayer  string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program   string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	// MultisigSigners is empty for a single-signer authority. Non-empty, the
	// authority itself does not sign; the named members do, in its place.
	MultisigSigners []string `json:"multisig_signers"`

	NonceAccount string `json:"nonce_account" example:""`

	account         *types.PublicKey
	mint            *types.PublicKey
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	nonceAccount    *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
	amount          uint64
}

func (r *BurnCheckedRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	amount := strings.TrimSpace(r.Amount)
	if amount == "" {
		return errors.New("amount is required")
	}
	if r.amount, err = strconv.ParseUint(amount, 10, 64); err != nil {
		return errors.New("amount: must be a decimal base-unit count")
	}
	if r.amount == 0 {
		return errors.New("amount: must be greater than zero")
	}

	r.multisigSigners = make([]*types.PublicKey, len(r.MultisigSigners))
	for i, s := range r.MultisigSigners {
		if r.multisigSigners[i], err = types.NewPublicKeyFromBase58(strings.TrimSpace(s)); err != nil {
			return fmt.Errorf("multisig_signers[%d]: %s", i, err)
		}
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
	}

	program := strings.TrimSpace(r.Program)
	if program == "" {
		return errors.New("program is required")
	}
	if r.tokenProgramID, err = types.NewPublicKeyFromBase58(program); err != nil {
		return errors.New("program: " + err.Error())
	}
	if !r.tokenProgramID.Equal(core.TokenProgramID) && !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is neither the Token nor the Token-2022 program", r.tokenProgramID)
	}

	return nil
}

func (r *BurnCheckedRequest) AccountKey() *types.PublicKey {
	return r.account
}

func (r *BurnCheckedRequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *BurnCheckedRequest) AuthorityKey() *types.PublicKey {
	return r.authority
}

func (r *BurnCheckedRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *BurnCheckedRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *BurnCheckedRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

func (r *BurnCheckedRequest) ToAmount() uint64 {
	return r.amount
}

func (r *BurnCheckedRequest) ToDecimals() uint8 {
	return r.Decimals
}

func (r *BurnCheckedRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

type BurnCheckedResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account   string `json:"account"`
	Mint      string `json:"mint"`
	Authority string `json:"authority"`
	Program   string `json:"program"`
	Amount    string `json:"amount"`
	Decimals  uint8  `json:"decimals"`
	Fee       string `json:"fee"`
}

func NewBurnCheckedResponse(
	tx *types.Transaction, raw, message []byte,
	account, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	amount uint64, decimals uint8, fee uint64,
) *BurnCheckedResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &BurnCheckedResponse{
		Transaction:     base64.StdEncoding.EncodeToString(raw),
		Message:         base64.StdEncoding.EncodeToString(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		Program:         tokenProgram.Base58(),
		Amount:          strconv.FormatUint(amount, 10),
		Decimals:        decimals,
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// CloseAccountRequest reclaims a token account's rent.
//
// The account has to hold no tokens first; the balance is not swept, it has to
// already be zero. A wrapped SOL account is the exception, since its balance
// is its lamports rather than a separate token amount, and closing it is how
// SOL is unwrapped. There is no checked variant, since there is no amount to
// check.
type CloseAccountRequest struct {
	Account     string `json:"account" example:""`
	Destination string `json:"destination" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Authority   string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	FeePayer    string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program     string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	// MultisigSigners is empty for a single-signer authority. Non-empty, the
	// authority itself does not sign; the named members do, in its place.
	MultisigSigners []string `json:"multisig_signers"`

	NonceAccount string `json:"nonce_account" example:""`

	account         *types.PublicKey
	destination     *types.PublicKey
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	nonceAccount    *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *CloseAccountRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.destination, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Destination)); err != nil {
		return errors.New("destination: " + err.Error())
	}
	if r.account.Equal(r.destination) {
		return errors.New("account and destination are the same account")
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	r.multisigSigners = make([]*types.PublicKey, len(r.MultisigSigners))
	for i, s := range r.MultisigSigners {
		if r.multisigSigners[i], err = types.NewPublicKeyFromBase58(strings.TrimSpace(s)); err != nil {
			return fmt.Errorf("multisig_signers[%d]: %s", i, err)
		}
	}

	if na := strings.TrimSpace(r.NonceAccount); na != "" {
		if r.nonceAccount, err = types.NewPublicKeyFromBase58(na); err != nil {
			return errors.New("nonce_account: " + err.Error())
		}
	}

	program := strings.TrimSpace(r.Program)
	if program == "" {
		return errors.New("program is required")
	}
	if r.tokenProgramID, err = types.NewPublicKeyFromBase58(program); err != nil {
		return errors.New("program: " + err.Error())
	}
	if !r.tokenProgramID.Equal(core.TokenProgramID) && !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is neither the Token nor the Token-2022 program", r.tokenProgramID)
	}

	return nil
}

func (r *CloseAccountRequest) AccountKey() *types.PublicKey {
	return r.account
}

func (r *CloseAccountRequest) DestinationKey() *types.PublicKey {
	return r.destination
}

func (r *CloseAccountRequest) AuthorityKey() *types.PublicKey {
	return r.authority
}

func (r *CloseAccountRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *CloseAccountRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *CloseAccountRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

func (r *CloseAccountRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

type CloseAccountResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account     string `json:"account"`
	Destination string `json:"destination"`
	Authority   string `json:"authority"`
	Program     string `json:"program"`

	// ReclaimedLamports is the account's balance at the moment it was read,
	// which is what closing hands to destination. It can change between this
	// response and the transaction landing if anything else touches the
	// account first.
	ReclaimedLamports string `json:"reclaimed_lamports"`
	Fee               string `json:"fee"`
}

func NewCloseAccountResponse(
	tx *types.Transaction, raw, message []byte,
	account, destination, authority, tokenProgram, nonceAuthority *types.PublicKey,
	reclaimedLamports, fee uint64,
) *CloseAccountResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &CloseAccountResponse{
		Transaction:       base64.StdEncoding.EncodeToString(raw),
		Message:           base64.StdEncoding.EncodeToString(message),
		RecentBlockhash:   tx.Message.RecentBlockhash.Base58(),
		AccountKeys:       keys,
		Signers:           signers,
		NonceAuthority:    nonceAuth,
		Account:           account.Base58(),
		Destination:       destination.Base58(),
		Authority:         authority.Base58(),
		Program:           tokenProgram.Base58(),
		ReclaimedLamports: strconv.FormatUint(reclaimedLamports, 10),
		Fee:               strconv.FormatUint(fee, 10),
	}
}
