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

// CreateMintRequest funds and initializes an 82-byte mint in one transaction.
//
// A mint created without initializing carries a real risk: anybody can
// initialize an uninitialized Token-owned account before its intended owner
// does, which is why these are always the same two instructions rather than
// two endpoints.
type CreateMintRequest struct {
	// RentPayer funds Mint's creation for exactly the rent-exemption minimum
	// for an 82-byte account, and is a separate balance from FeePayer.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Mint is the account created and initialized. It signs alongside
	// RentPayer, since an address does not exist until whoever holds its
	// private key authorizes its creation. It must not already exist.
	Mint string `json:"mint" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// MintAuthority is who can mint new supply going forward. It need not be
	// RentPayer or FeePayer, and is not required to sign this transaction:
	// InitializeMint2 only records it, it does not check it against a signer.
	MintAuthority string `json:"mint_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FreezeAuthority may be left empty, in which case the mint is created
	// with no freeze authority at all, permanently: there is no separate flag
	// here the way SetAuthority needs one, since a mint that does not exist
	// yet has no prior authority a typo could accidentally clear.
	FreezeAuthority string `json:"freeze_authority" example:""`

	// Decimals fixes how the raw integer amount this mint moves is displayed
	// as a UI amount, and cannot be changed after creation.
	Decimals uint8 `json:"decimals" example:"6"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instructions to: classic Token
	// or Token-2022. It is required rather than defaulted, since a mint
	// belongs to exactly one of the two forever and defaulting would make
	// picking wrong silent. It is an address rather than a name because that
	// is what actually selects the program on chain: Token-2022 is not an
	// enum value, it is a different account, and a third Token
	// implementation would need no change here to be reachable.
	Program string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

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

	rentPayer       *types.PublicKey
	mint            *types.PublicKey
	mintAuthority   *types.PublicKey
	freezeAuthority *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
}

func (r *CreateMintRequest) ValidateRequest() error {
	var err error
	if r.rentPayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.rentPayer.Equal(r.mint) {
		return errors.New("rent_payer and mint are the same account")
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

func (r *CreateMintRequest) RentPayerKey() *types.PublicKey {
	return r.rentPayer
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

func (r *CreateMintRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *CreateMintRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
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

	// Rent reports what funds CreateMint itself. Its lamports are always
	// exactly the rent-exemption minimum for an 82-byte account, never more
	// or less.
	Rent SystemPayer `json:"rent"`
	Fee  SystemPayer `json:"fee"`
}

func NewCreateMintResponse(
	tx *types.Transaction, raw, message []byte,
	rentPayer, feePayer, mint, tokenProgram, mintAuthority, freezeAuthority, nonceAuthority *types.PublicKey,
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		Mint:            mint.Base58(),
		Program:         tokenProgram.Base58(),
		MintAuthority:   mintAuthority.Base58(),
		FreezeAuthority: freeze,
		Decimals:        decimals,
		Rent:            newSystemPayer(rentPayer, rentExempt),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// CreateKTARequest funds and initializes a 165-byte keypair token account
// (KTA) in one transaction.
//
// This produces a plain keypair account rather than an associated one (see
// CreateATARequest): the address is whatever key was generated for it, and
// nothing can rediscover it from the wallet and mint the way an associated
// token account can be. It is still what to use when a wallet wants more
// than one account for the same mint, since the associated address is one
// per pair.
type CreateKTARequest struct {
	// RentPayer funds TokenAccount's creation for exactly the rent-exemption
	// minimum for a 165-byte account, and is a separate balance from
	// FeePayer.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// TokenAccount is created and initialized as a holder account for Mint.
	// It signs alongside RentPayer, since an address does not exist until
	// whoever holds its private key authorizes its creation. It must not
	// already exist.
	TokenAccount string `json:"token_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// Mint is the token TokenAccount is initialized to hold, and must already
	// exist.
	Mint string `json:"mint" example:""`

	// Owner is who can transfer, burn, or otherwise authorize spending from
	// TokenAccount. It need not be RentPayer or FeePayer, and is not required
	// to sign this transaction: InitializeAccount3 only records it, it does
	// not check it against a signer, which is exactly the risk that keeps
	// this endpoint from splitting into two.
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instructions to: classic Token
	// or Token-2022. It is required rather than defaulted, since a token
	// account belongs to exactly one of the two forever, and it must agree
	// with the mint's own owning program or the instruction fails on chain.
	Program string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

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

	rentPayer      *types.PublicKey
	tokenAccount   *types.PublicKey
	mint           *types.PublicKey
	owner          *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *CreateKTARequest) ValidateRequest() error {
	var err error
	if r.rentPayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
	}
	if r.rentPayer.Equal(r.tokenAccount) {
		return errors.New("rent_payer and token_account are the same account")
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

func (r *CreateKTARequest) RentPayerKey() *types.PublicKey {
	return r.rentPayer
}

func (r *CreateKTARequest) TokenAccountKey() *types.PublicKey {
	return r.tokenAccount
}

func (r *CreateKTARequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *CreateKTARequest) OwnerKey() *types.PublicKey {
	return r.owner
}

func (r *CreateKTARequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *CreateKTARequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *CreateKTARequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// TokenProgramID returns the resolved program account, either
// core.TokenProgramID or core.Token2022ProgramID. core.TokenProgram(id) turns
// it into a builder.
func (r *CreateKTARequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// CreateKTAResponse mirrors CreateMintResponse's shape for the same
// reason: what the server had to resolve to validate is what a caller needs
// to know to build the next transaction without guessing.
type CreateKTAResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	TokenAccount string `json:"token_account"`
	Mint         string `json:"mint"`
	Owner        string `json:"owner"`
	Program      string `json:"program"`

	// Rent reports what funds CreateAccount itself. Its lamports are always
	// exactly the rent-exemption minimum for a 165-byte account, never more
	// or less.
	Rent SystemPayer `json:"rent"`
	Fee  SystemPayer `json:"fee"`
}

func NewCreateKTAResponse(
	tx *types.Transaction, raw, message []byte,
	rentPayer, feePayer, tokenAccount, mint, owner, tokenProgram, nonceAuthority *types.PublicKey,
	rentExempt, fee uint64,
) *CreateKTAResponse {
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

	return &CreateKTAResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		TokenAccount:    tokenAccount.Base58(),
		Mint:            mint.Base58(),
		Owner:           owner.Base58(),
		Program:         tokenProgram.Base58(),
		Rent:            newSystemPayer(rentPayer, rentExempt),
		Fee:             newSystemPayer(feePayer, fee),
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
	// Mint is the token whose supply grows. It must already exist, and its
	// own MintAuthority is what this request has to name to be honored.
	Mint string `json:"mint" example:""`

	// TokenAccount is credited with the newly minted supply. It must already
	// exist and hold Mint.
	TokenAccount string `json:"token_account" example:""`

	// MintAuthority is Mint's mint authority, not TokenAccount's owner or
	// delegate: minting checks who is allowed to create new supply, not who
	// is allowed to move what already exists.
	MintAuthority string `json:"mint_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Amount is the raw base-unit count to mint, not a UI decimal string.
	Amount string `json:"amount" example:"1000000"`

	// Decimals is checked against Mint's own stored value rather than
	// trusted, which is the whole point of the checked variant: catching a
	// client that formatted Amount against the wrong decimals as a 400
	// instead of an on-chain failure.
	Decimals uint8 `json:"decimals" example:"6"`

	// FeePayer signs and pays the transaction fee. Minting moves no lamports
	// of its own, so this is the only balance this endpoint ever checks.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022. It is required rather than defaulted, since a token
	// account belongs to exactly one of the two forever, and it must agree
	// with the mint's own owning program or the instruction fails on chain.
	Program string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	// MultisigSigners is empty for a single-signer authority. Non-empty, the
	// authority itself does not sign; the named members do, in its place.
	MultisigSigners []string `json:"multisig_signers"`

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

	mint            *types.PublicKey
	tokenAccount    *types.PublicKey
	mintAuthority   *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
	amount          uint64
}

func (r *MintToCheckedRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("tokenAccount: " + err.Error())
	}
	if r.mintAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.MintAuthority)); err != nil {
		return errors.New("mint_authority: " + err.Error())
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

func (r *MintToCheckedRequest) TokenAccountKey() *types.PublicKey {
	return r.tokenAccount
}

func (r *MintToCheckedRequest) MintAuthorityKey() *types.PublicKey {
	return r.mintAuthority
}

func (r *MintToCheckedRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *MintToCheckedRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *MintToCheckedRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
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

	Mint          string      `json:"mint"`
	TokenAccount  string      `json:"token_account"`
	MintAuthority string      `json:"mint_authority"`
	Program       string      `json:"program"`
	Amount        string      `json:"amount"`
	Decimals      uint8       `json:"decimals"`
	Fee           SystemPayer `json:"fee"`
}

func NewMintToCheckedResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, tokenAccount, mintAuthority, tokenProgram, nonceAuthority *types.PublicKey,
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		TokenAccount:    tokenAccount.Base58(),
		MintAuthority:   mintAuthority.Base58(),
		Program:         tokenProgram.Base58(),
		Amount:          strconv.FormatUint(amount, 10),
		Decimals:        decimals,
		Fee:             newSystemPayer(feePayer, fee),
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
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
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
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
		Transaction:       codec.Base64.Encode(raw),
		Message:           codec.Base64.Encode(message),
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

// CreateATARequest creates the canonical associated token account (ATA) for
// a wallet and mint.
//
// There is no account field: the address is derived rather than chosen, which
// is the whole point. Nothing generates a keypair for it and nothing has to
// remember where it went, since anyone holding the wallet and the mint can
// recompute it. This is what sets it apart from a keypair token account
// (KTA, see CreateKTARequest): an ATA is one per wallet-mint pair, found by
// derivation rather than by remembering an address, and never needs its own
// signature to be created.
type CreateATARequest struct {
	// RentPayer covers the rent-exemption deposit, distinct from FeePayer:
	// the two are separate balances to check, and a caller funding somebody
	// else's associated account pays this one without necessarily paying the
	// transaction fee.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Wallet is who ends up owning the account, which need not be RentPayer.
	// Funding somebody else's associated account is ordinary: the address is
	// theirs either way.
	Wallet string `json:"wallet" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`
	Mint   string `json:"mint" example:""`

	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program is a seed of the derived address, not only the program the
	// account belongs to, so one wallet has a different associated account
	// for classic Token than for Token-2022 over the same mint.
	Program string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	NonceAccount string `json:"nonce_account" example:""`

	rentPayer      *types.PublicKey
	wallet         *types.PublicKey
	mint           *types.PublicKey
	feePayer       *types.PublicKey
	nonceAccount   *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *CreateATARequest) ValidateRequest() error {
	var err error
	if r.rentPayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.wallet, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Wallet)); err != nil {
		return errors.New("wallet: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
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

func (r *CreateATARequest) RentPayerKey() *types.PublicKey {
	return r.rentPayer
}

func (r *CreateATARequest) WalletKey() *types.PublicKey {
	return r.wallet
}

func (r *CreateATARequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *CreateATARequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *CreateATARequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *CreateATARequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// CreateATAResponse reports the derived address and its bump,
// which the caller never supplied and would otherwise have to derive to know.
type CreateATAResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Bump    uint8  `json:"bump"`
	Wallet  string `json:"wallet"`
	Mint    string `json:"mint"`
	Program string `json:"program"`

	RentExempt string `json:"rent_exempt"`
	Fee        string `json:"fee"`
}

func NewCreateATAResponse(
	tx *types.Transaction, raw, message []byte,
	account, wallet, mint, tokenProgram, nonceAuthority *types.PublicKey,
	bump uint8, rentExempt, fee uint64,
) *CreateATAResponse {
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

	return &CreateATAResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Bump:            bump,
		Wallet:          wallet.Base58(),
		Mint:            mint.Base58(),
		Program:         tokenProgram.Base58(),
		RentExempt:      strconv.FormatUint(rentExempt, 10),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// CreateATAIdempotentRequest is CreateATARequest's own type, kept separate
// rather than shared, even though every field is identical. The two
// endpoints build different instructions and validate differently in one
// respect — this one tolerates the account already existing — and giving
// each its own request type is what keeps that difference from leaking into
// a shared struct neither endpoint fully owns.
type CreateATAIdempotentRequest struct {
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Wallet    string `json:"wallet" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`
	Mint      string `json:"mint" example:""`
	FeePayer  string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program   string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	NonceAccount string `json:"nonce_account" example:""`

	rentPayer      *types.PublicKey
	wallet         *types.PublicKey
	mint           *types.PublicKey
	feePayer       *types.PublicKey
	nonceAccount   *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *CreateATAIdempotentRequest) ValidateRequest() error {
	var err error
	if r.rentPayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.wallet, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Wallet)); err != nil {
		return errors.New("wallet: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
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

func (r *CreateATAIdempotentRequest) RentPayerKey() *types.PublicKey {
	return r.rentPayer
}

func (r *CreateATAIdempotentRequest) WalletKey() *types.PublicKey {
	return r.wallet
}

func (r *CreateATAIdempotentRequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *CreateATAIdempotentRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *CreateATAIdempotentRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *CreateATAIdempotentRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// CreateATAIdempotentResponse is CreateATAResponse's own type, for the same
// reason the request above has its own: nothing here differs from it in
// shape, but nothing forces the two to stay that way just because they
// happen to agree today.
type CreateATAIdempotentResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Bump    uint8  `json:"bump"`
	Wallet  string `json:"wallet"`
	Mint    string `json:"mint"`
	Program string `json:"program"`

	RentExempt string `json:"rent_exempt"`
	Fee        string `json:"fee"`
}

func NewCreateATAIdempotentResponse(
	tx *types.Transaction, raw, message []byte,
	account, wallet, mint, tokenProgram, nonceAuthority *types.PublicKey,
	bump uint8, rentExempt, fee uint64,
) *CreateATAIdempotentResponse {
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

	return &CreateATAIdempotentResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Bump:            bump,
		Wallet:          wallet.Base58(),
		Mint:            mint.Base58(),
		Program:         tokenProgram.Base58(),
		RentExempt:      strconv.FormatUint(rentExempt, 10),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// TransferToWalletRequest moves a balance between the associated token
// accounts of two wallets for a mint, deriving both addresses rather than
// taking either directly.
//
// Account and Destination are wallet addresses, not token accounts: that is
// the entire reason this endpoint exists rather than being transfer-checked
// with a flag. transfer-checked moves between exact token account addresses
// a caller already knows, which is also the endpoint for a source that is
// not an associated account, such as one made by create-account. This one
// is the "wallet to wallet" convenience: neither side computes an
// associated address first.
type TransferToWalletRequest struct {
	// Account is the sender's wallet. Its associated token account is
	// derived rather than accepted directly, and unlike Destination it is
	// never created: an account nobody has funded has nothing to send, so a
	// missing source fails rather than being created empty.
	Account     string `json:"account" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Mint        string `json:"mint" example:""`
	Destination string `json:"destination" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// Authority signs for the source account. It is usually Account itself,
	// but kept as its own field because it need not be: a delegate approved
	// for no more than its delegated amount may sign in Account's place, the
	// same rule transfer-checked applies to any source.
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Amount    string `json:"amount" example:"250000"`
	Decimals  uint8  `json:"decimals" example:"6"`

	// RentPayer covers the rent-exemption deposit if destination's
	// associated account does not exist yet, distinct from FeePayer in the
	// same way create-ata's is: a caller funding somebody else's account
	// need not also be covering the transaction fee.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	FeePayer  string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program   string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	// MultisigSigners is empty for a single-signer authority. Non-empty, the
	// authority itself does not sign; the named members do, in its place.
	MultisigSigners []string `json:"multisig_signers"`

	NonceAccount string `json:"nonce_account" example:""`

	account         *types.PublicKey
	mint            *types.PublicKey
	destination     *types.PublicKey
	authority       *types.PublicKey
	rentPayer       *types.PublicKey
	feePayer        *types.PublicKey
	nonceAccount    *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
	amount          uint64
}

func (r *TransferToWalletRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.destination, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Destination)); err != nil {
		return errors.New("destination: " + err.Error())
	}
	if r.account.Equal(r.destination) {
		return errors.New("account and destination are the same wallet")
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.rentPayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
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

func (r *TransferToWalletRequest) AccountKey() *types.PublicKey {
	return r.account
}

func (r *TransferToWalletRequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *TransferToWalletRequest) DestinationKey() *types.PublicKey {
	return r.destination
}

func (r *TransferToWalletRequest) AuthorityKey() *types.PublicKey {
	return r.authority
}

func (r *TransferToWalletRequest) RentPayerKey() *types.PublicKey {
	return r.rentPayer
}

func (r *TransferToWalletRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *TransferToWalletRequest) NonceAccountKey() *types.PublicKey {
	return r.nonceAccount
}

func (r *TransferToWalletRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

func (r *TransferToWalletRequest) ToAmount() uint64 {
	return r.amount
}

func (r *TransferToWalletRequest) ToDecimals() uint8 {
	return r.Decimals
}

func (r *TransferToWalletRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// TransferToWalletResponse reports both derived associated accounts, neither
// of which the caller supplied, alongside what transfer-checked reports.
//
// Account and Destination echo the two wallet addresses the request named.
// SourceAssociatedAccount and DestinationAssociatedAccount are the different
// thing derived from each: the actual token accounts the transfer moves
// between.
type TransferToWalletResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account                      string `json:"account"`
	SourceAssociatedAccount      string `json:"source_associated_account"`
	Mint                         string `json:"mint"`
	Destination                  string `json:"destination"`
	DestinationAssociatedAccount string `json:"destination_associated_account"`
	Authority                    string `json:"authority"`
	Program                      string `json:"program"`
	Amount                       string `json:"amount"`
	Decimals                     uint8  `json:"decimals"`

	// CreatedATA records whether an idempotent create was prepended for the
	// destination, since the same request against an already-funded
	// destination does not need one. The source associated account is never
	// created by this endpoint, so there is nothing equivalent to record for
	// it.
	CreatedATA bool   `json:"created_ata"`
	RentExempt string `json:"rent_exempt,omitempty"`
	Fee        string `json:"fee"`
}

func NewTransferToWalletResponse(
	tx *types.Transaction, raw, message []byte,
	account, sourceAssociatedAccount, mint, destination, destinationAssociatedAccount, authority, tokenProgram, nonceAuthority *types.PublicKey,
	amount uint64, decimals uint8, createdATA bool, rentExempt, fee uint64,
) *TransferToWalletResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	rent := ""
	if createdATA {
		rent = strconv.FormatUint(rentExempt, 10)
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &TransferToWalletResponse{
		Transaction:                  codec.Base64.Encode(raw),
		Message:                      codec.Base64.Encode(message),
		RecentBlockhash:              tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                  keys,
		Signers:                      signers,
		NonceAuthority:               nonceAuth,
		Account:                      account.Base58(),
		SourceAssociatedAccount:      sourceAssociatedAccount.Base58(),
		Mint:                         mint.Base58(),
		Destination:                  destination.Base58(),
		DestinationAssociatedAccount: destinationAssociatedAccount.Base58(),
		Authority:                    authority.Base58(),
		Program:                      tokenProgram.Base58(),
		Amount:                       strconv.FormatUint(amount, 10),
		Decimals:                     decimals,
		CreatedATA:                   createdATA,
		RentExempt:                   rent,
		Fee:                          strconv.FormatUint(fee, 10),
	}
}

// ApproveCheckedRequest names a delegation to grant over an account.
//
// Account is the one existing token account whose balance the delegate may
// move, matching burn-checked and close-account's naming rather than
// transfer-checked's source/destination pair, since approve has only the one
// token account: delegate is a bare key, never itself a token account.
type ApproveCheckedRequest struct {
	Account   string `json:"account" example:""`
	Mint      string `json:"mint" example:""`
	Delegate  string `json:"delegate" example:""`
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Amount    string `json:"amount" example:"500000"`
	Decimals  uint8  `json:"decimals" example:"6"`
	FeePayer  string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program   string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	// MultisigSigners is empty for a single-signer authority. Non-empty, the
	// authority itself does not sign; the named members do, in its place.
	MultisigSigners []string `json:"multisig_signers"`

	NonceAccount string `json:"nonce_account" example:""`

	account         *types.PublicKey
	mint            *types.PublicKey
	delegate        *types.PublicKey
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	nonceAccount    *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
	amount          uint64
}

func (r *ApproveCheckedRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.delegate, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Delegate)); err != nil {
		return errors.New("delegate: " + err.Error())
	}
	if r.account.Equal(r.delegate) {
		return errors.New("account and delegate are the same account")
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

func (r *ApproveCheckedRequest) AccountKey() *types.PublicKey          { return r.account }
func (r *ApproveCheckedRequest) MintKey() *types.PublicKey             { return r.mint }
func (r *ApproveCheckedRequest) DelegateKey() *types.PublicKey         { return r.delegate }
func (r *ApproveCheckedRequest) AuthorityKey() *types.PublicKey        { return r.authority }
func (r *ApproveCheckedRequest) FeePayerKey() *types.PublicKey         { return r.feePayer }
func (r *ApproveCheckedRequest) NonceAccountKey() *types.PublicKey     { return r.nonceAccount }
func (r *ApproveCheckedRequest) TokenProgramID() *types.PublicKey      { return r.tokenProgramID }
func (r *ApproveCheckedRequest) ToMultisigSigners() []*types.PublicKey { return r.multisigSigners }
func (r *ApproveCheckedRequest) ToAmount() uint64                      { return r.amount }
func (r *ApproveCheckedRequest) ToDecimals() uint8                     { return r.Decimals }

// ApproveCheckedResponse reports the delegation just built.
type ApproveCheckedResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account   string `json:"account"`
	Mint      string `json:"mint"`
	Delegate  string `json:"delegate"`
	Authority string `json:"authority"`
	Program   string `json:"program"`
	Amount    string `json:"amount"`
	Decimals  uint8  `json:"decimals"`
	Fee       string `json:"fee"`
}

func NewApproveCheckedResponse(
	tx *types.Transaction, raw, message []byte,
	account, mint, delegate, authority, tokenProgram, nonceAuthority *types.PublicKey,
	amount uint64, decimals uint8, fee uint64,
) *ApproveCheckedResponse {
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

	return &ApproveCheckedResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Mint:            mint.Base58(),
		Delegate:        delegate.Base58(),
		Authority:       authority.Base58(),
		Program:         tokenProgram.Base58(),
		Amount:          strconv.FormatUint(amount, 10),
		Decimals:        decimals,
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// RevokeRequest names the account whose delegation should be cleared.
//
// There is no delegate field. The program clears whichever one is stored
// without being told which, so naming one here would only be a way to get it
// wrong; there is also no mint, since revoking touches no balance and needs
// nothing decoded from it.
type RevokeRequest struct {
	Account   string `json:"account" example:""`
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	FeePayer  string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program   string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	// MultisigSigners is empty for a single-signer authority. Non-empty, the
	// authority itself does not sign; the named members do, in its place.
	MultisigSigners []string `json:"multisig_signers"`

	NonceAccount string `json:"nonce_account" example:""`

	account         *types.PublicKey
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	nonceAccount    *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *RevokeRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
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

func (r *RevokeRequest) AccountKey() *types.PublicKey          { return r.account }
func (r *RevokeRequest) AuthorityKey() *types.PublicKey        { return r.authority }
func (r *RevokeRequest) FeePayerKey() *types.PublicKey         { return r.feePayer }
func (r *RevokeRequest) NonceAccountKey() *types.PublicKey     { return r.nonceAccount }
func (r *RevokeRequest) TokenProgramID() *types.PublicKey      { return r.tokenProgramID }
func (r *RevokeRequest) ToMultisigSigners() []*types.PublicKey { return r.multisigSigners }

// RevokeResponse reports the cleared delegation.
type RevokeResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account   string `json:"account"`
	Authority string `json:"authority"`
	Program   string `json:"program"`
	Fee       string `json:"fee"`
}

func NewRevokeResponse(
	tx *types.Transaction, raw, message []byte,
	account, authority, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *RevokeResponse {
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

	return &RevokeResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Authority:       authority.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// SetMintAuthorityReplaceRequest SetMintAuthorityReplace replaces a mint's mint authority with a new key.
type SetMintAuthorityReplaceRequest struct {
	Mint         string `json:"mint" example:""`
	Authority    string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	NewAuthority string `json:"new_authority" example:""`
	FeePayer     string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program      string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	// MultisigSigners is empty for a single-signer authority. Non-empty, the
	// authority itself does not sign; the named members do, in its place.
	MultisigSigners []string `json:"multisig_signers"`

	NonceAccount string `json:"nonce_account" example:""`

	mint            *types.PublicKey
	authority       *types.PublicKey
	newAuthority    *types.PublicKey
	feePayer        *types.PublicKey
	nonceAccount    *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *SetMintAuthorityReplaceRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	newAuthority := strings.TrimSpace(r.NewAuthority)
	if newAuthority == "" {
		return errors.New("new_authority is required")
	}
	if r.newAuthority, err = types.NewPublicKeyFromBase58(newAuthority); err != nil {
		return errors.New("new_authority: " + err.Error())
	}
	if r.authority.Equal(r.newAuthority) {
		return errors.New("new_authority: is already the current authority")
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

func (r *SetMintAuthorityReplaceRequest) MintKey() *types.PublicKey         { return r.mint }
func (r *SetMintAuthorityReplaceRequest) AuthorityKey() *types.PublicKey    { return r.authority }
func (r *SetMintAuthorityReplaceRequest) NewAuthorityKey() *types.PublicKey { return r.newAuthority }
func (r *SetMintAuthorityReplaceRequest) FeePayerKey() *types.PublicKey     { return r.feePayer }
func (r *SetMintAuthorityReplaceRequest) NonceAccountKey() *types.PublicKey { return r.nonceAccount }
func (r *SetMintAuthorityReplaceRequest) TokenProgramID() *types.PublicKey  { return r.tokenProgramID }
func (r *SetMintAuthorityReplaceRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// SetMintAuthorityReplaceResponse reports the authority change just built.
type SetMintAuthorityReplaceResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint         string `json:"mint"`
	Authority    string `json:"authority"`
	NewAuthority string `json:"new_authority"`
	Program      string `json:"program"`
	Fee          string `json:"fee"`
}

func NewSetMintAuthorityReplaceResponse(
	tx *types.Transaction, raw, message []byte,
	mint, authority, tokenProgram, nonceAuthority *types.PublicKey, newAuthority *types.PublicKey,
	fee uint64,
) *SetMintAuthorityReplaceResponse {
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

	return &SetMintAuthorityReplaceResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		NewAuthority:    newAuthority.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// SetMintAuthorityClearRequest SetMintAuthorityClear removes a mint's mint authority permanently.
//
// Once cleared, no endpoint can set it again: the program stores this as a
// COption and rejects nothing here, but nothing can ever sign as an authority
// that is now None. This is how a supply is capped forever.
type SetMintAuthorityClearRequest struct {
	Mint      string `json:"mint" example:""`
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	FeePayer  string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program   string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	// MultisigSigners is empty for a single-signer authority. Non-empty, the
	// authority itself does not sign; the named members do, in its place.
	MultisigSigners []string `json:"multisig_signers"`

	NonceAccount string `json:"nonce_account" example:""`

	mint            *types.PublicKey
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	nonceAccount    *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *SetMintAuthorityClearRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
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

func (r *SetMintAuthorityClearRequest) MintKey() *types.PublicKey         { return r.mint }
func (r *SetMintAuthorityClearRequest) AuthorityKey() *types.PublicKey    { return r.authority }
func (r *SetMintAuthorityClearRequest) FeePayerKey() *types.PublicKey     { return r.feePayer }
func (r *SetMintAuthorityClearRequest) NonceAccountKey() *types.PublicKey { return r.nonceAccount }
func (r *SetMintAuthorityClearRequest) TokenProgramID() *types.PublicKey  { return r.tokenProgramID }
func (r *SetMintAuthorityClearRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// SetMintAuthorityClearResponse reports the authority change just built.
type SetMintAuthorityClearResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint      string `json:"mint"`
	Authority string `json:"authority"`
	Cleared   bool   `json:"cleared"`
	Program   string `json:"program"`
	Fee       string `json:"fee"`
}

func NewSetMintAuthorityClearResponse(
	tx *types.Transaction, raw, message []byte,
	mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *SetMintAuthorityClearResponse {
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

	return &SetMintAuthorityClearResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		Cleared:         true,
		Program:         tokenProgram.Base58(),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// SetFreezeAuthorityReplaceRequest SetFreezeAuthorityReplace replaces a mint's freeze authority with a new key.
type SetFreezeAuthorityReplaceRequest struct {
	Mint         string `json:"mint" example:""`
	Authority    string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	NewAuthority string `json:"new_authority" example:""`
	FeePayer     string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program      string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	// MultisigSigners is empty for a single-signer authority. Non-empty, the
	// authority itself does not sign; the named members do, in its place.
	MultisigSigners []string `json:"multisig_signers"`

	NonceAccount string `json:"nonce_account" example:""`

	mint            *types.PublicKey
	authority       *types.PublicKey
	newAuthority    *types.PublicKey
	feePayer        *types.PublicKey
	nonceAccount    *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *SetFreezeAuthorityReplaceRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	newAuthority := strings.TrimSpace(r.NewAuthority)
	if newAuthority == "" {
		return errors.New("new_authority is required")
	}
	if r.newAuthority, err = types.NewPublicKeyFromBase58(newAuthority); err != nil {
		return errors.New("new_authority: " + err.Error())
	}
	if r.authority.Equal(r.newAuthority) {
		return errors.New("new_authority: is already the current authority")
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

func (r *SetFreezeAuthorityReplaceRequest) MintKey() *types.PublicKey         { return r.mint }
func (r *SetFreezeAuthorityReplaceRequest) AuthorityKey() *types.PublicKey    { return r.authority }
func (r *SetFreezeAuthorityReplaceRequest) NewAuthorityKey() *types.PublicKey { return r.newAuthority }
func (r *SetFreezeAuthorityReplaceRequest) FeePayerKey() *types.PublicKey     { return r.feePayer }
func (r *SetFreezeAuthorityReplaceRequest) NonceAccountKey() *types.PublicKey { return r.nonceAccount }
func (r *SetFreezeAuthorityReplaceRequest) TokenProgramID() *types.PublicKey  { return r.tokenProgramID }
func (r *SetFreezeAuthorityReplaceRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// SetFreezeAuthorityReplaceResponse reports the authority change just built.
type SetFreezeAuthorityReplaceResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint         string `json:"mint"`
	Authority    string `json:"authority"`
	NewAuthority string `json:"new_authority"`
	Program      string `json:"program"`
	Fee          string `json:"fee"`
}

func NewSetFreezeAuthorityReplaceResponse(
	tx *types.Transaction, raw, message []byte,
	mint, authority, tokenProgram, nonceAuthority *types.PublicKey, newAuthority *types.PublicKey,
	fee uint64,
) *SetFreezeAuthorityReplaceResponse {
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

	return &SetFreezeAuthorityReplaceResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		NewAuthority:    newAuthority.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// SetFreezeAuthorityClearRequest SetFreezeAuthorityClear removes a mint's freeze authority permanently.
//
// Once cleared, no holder of this mint can ever be frozen again, and nothing
// can restore the capability: there is no authority left to sign the change.
type SetFreezeAuthorityClearRequest struct {
	Mint      string `json:"mint" example:""`
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	FeePayer  string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program   string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	// MultisigSigners is empty for a single-signer authority. Non-empty, the
	// authority itself does not sign; the named members do, in its place.
	MultisigSigners []string `json:"multisig_signers"`

	NonceAccount string `json:"nonce_account" example:""`

	mint            *types.PublicKey
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	nonceAccount    *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *SetFreezeAuthorityClearRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
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

func (r *SetFreezeAuthorityClearRequest) MintKey() *types.PublicKey         { return r.mint }
func (r *SetFreezeAuthorityClearRequest) AuthorityKey() *types.PublicKey    { return r.authority }
func (r *SetFreezeAuthorityClearRequest) FeePayerKey() *types.PublicKey     { return r.feePayer }
func (r *SetFreezeAuthorityClearRequest) NonceAccountKey() *types.PublicKey { return r.nonceAccount }
func (r *SetFreezeAuthorityClearRequest) TokenProgramID() *types.PublicKey  { return r.tokenProgramID }
func (r *SetFreezeAuthorityClearRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// SetFreezeAuthorityClearResponse reports the authority change just built.
type SetFreezeAuthorityClearResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint      string `json:"mint"`
	Authority string `json:"authority"`
	Cleared   bool   `json:"cleared"`
	Program   string `json:"program"`
	Fee       string `json:"fee"`
}

func NewSetFreezeAuthorityClearResponse(
	tx *types.Transaction, raw, message []byte,
	mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *SetFreezeAuthorityClearResponse {
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

	return &SetFreezeAuthorityClearResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		Cleared:         true,
		Program:         tokenProgram.Base58(),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// SetAccountOwnerReplaceRequest SetAccountOwnerReplace replaces a token account's owner with a new key.
//
// There is no clear variant. The account's owner field is a plain Pubkey on
// chain, not a COption, so there is no representation for "no owner" to set
// it to; the program rejects a None authority here rather than accepting one
// it could never store.
type SetAccountOwnerReplaceRequest struct {
	Account      string `json:"account" example:""`
	Authority    string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	NewAuthority string `json:"new_authority" example:""`
	FeePayer     string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program      string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	// MultisigSigners is empty for a single-signer authority. Non-empty, the
	// authority itself does not sign; the named members do, in its place.
	MultisigSigners []string `json:"multisig_signers"`

	NonceAccount string `json:"nonce_account" example:""`

	account         *types.PublicKey
	authority       *types.PublicKey
	newAuthority    *types.PublicKey
	feePayer        *types.PublicKey
	nonceAccount    *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *SetAccountOwnerReplaceRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	newAuthority := strings.TrimSpace(r.NewAuthority)
	if newAuthority == "" {
		return errors.New("new_authority is required")
	}
	if r.newAuthority, err = types.NewPublicKeyFromBase58(newAuthority); err != nil {
		return errors.New("new_authority: " + err.Error())
	}
	if r.authority.Equal(r.newAuthority) {
		return errors.New("new_authority: is already the current authority")
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

func (r *SetAccountOwnerReplaceRequest) AccountKey() *types.PublicKey      { return r.account }
func (r *SetAccountOwnerReplaceRequest) AuthorityKey() *types.PublicKey    { return r.authority }
func (r *SetAccountOwnerReplaceRequest) NewAuthorityKey() *types.PublicKey { return r.newAuthority }
func (r *SetAccountOwnerReplaceRequest) FeePayerKey() *types.PublicKey     { return r.feePayer }
func (r *SetAccountOwnerReplaceRequest) NonceAccountKey() *types.PublicKey { return r.nonceAccount }
func (r *SetAccountOwnerReplaceRequest) TokenProgramID() *types.PublicKey  { return r.tokenProgramID }
func (r *SetAccountOwnerReplaceRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// SetAccountOwnerReplaceResponse reports the authority change just built.
type SetAccountOwnerReplaceResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account      string `json:"account"`
	Authority    string `json:"authority"`
	NewAuthority string `json:"new_authority"`
	Program      string `json:"program"`
	Fee          string `json:"fee"`
}

func NewSetAccountOwnerReplaceResponse(
	tx *types.Transaction, raw, message []byte,
	account, authority, tokenProgram, nonceAuthority *types.PublicKey, newAuthority *types.PublicKey,
	fee uint64,
) *SetAccountOwnerReplaceResponse {
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

	return &SetAccountOwnerReplaceResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Authority:       authority.Base58(),
		NewAuthority:    newAuthority.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// SetCloseAuthorityReplaceRequest SetCloseAuthorityReplace replaces a token account's close authority with a new
// key.
//
// The current authority is whichever one is already recorded: the account's
// close authority if one is set, otherwise its owner, the same rule
// close-account itself checks.
type SetCloseAuthorityReplaceRequest struct {
	Account      string `json:"account" example:""`
	Authority    string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	NewAuthority string `json:"new_authority" example:""`
	FeePayer     string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program      string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	// MultisigSigners is empty for a single-signer authority. Non-empty, the
	// authority itself does not sign; the named members do, in its place.
	MultisigSigners []string `json:"multisig_signers"`

	NonceAccount string `json:"nonce_account" example:""`

	account         *types.PublicKey
	authority       *types.PublicKey
	newAuthority    *types.PublicKey
	feePayer        *types.PublicKey
	nonceAccount    *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *SetCloseAuthorityReplaceRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	newAuthority := strings.TrimSpace(r.NewAuthority)
	if newAuthority == "" {
		return errors.New("new_authority is required")
	}
	if r.newAuthority, err = types.NewPublicKeyFromBase58(newAuthority); err != nil {
		return errors.New("new_authority: " + err.Error())
	}
	if r.authority.Equal(r.newAuthority) {
		return errors.New("new_authority: is already the current authority")
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

func (r *SetCloseAuthorityReplaceRequest) AccountKey() *types.PublicKey      { return r.account }
func (r *SetCloseAuthorityReplaceRequest) AuthorityKey() *types.PublicKey    { return r.authority }
func (r *SetCloseAuthorityReplaceRequest) NewAuthorityKey() *types.PublicKey { return r.newAuthority }
func (r *SetCloseAuthorityReplaceRequest) FeePayerKey() *types.PublicKey     { return r.feePayer }
func (r *SetCloseAuthorityReplaceRequest) NonceAccountKey() *types.PublicKey { return r.nonceAccount }
func (r *SetCloseAuthorityReplaceRequest) TokenProgramID() *types.PublicKey  { return r.tokenProgramID }
func (r *SetCloseAuthorityReplaceRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// SetCloseAuthorityReplaceResponse reports the authority change just built.
type SetCloseAuthorityReplaceResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account      string `json:"account"`
	Authority    string `json:"authority"`
	NewAuthority string `json:"new_authority"`
	Program      string `json:"program"`
	Fee          string `json:"fee"`
}

func NewSetCloseAuthorityReplaceResponse(
	tx *types.Transaction, raw, message []byte,
	account, authority, tokenProgram, nonceAuthority *types.PublicKey, newAuthority *types.PublicKey,
	fee uint64,
) *SetCloseAuthorityReplaceResponse {
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

	return &SetCloseAuthorityReplaceResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Authority:       authority.Base58(),
		NewAuthority:    newAuthority.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// SetCloseAuthorityClearRequest SetCloseAuthorityClear removes a token account's close authority.
//
// Unlike the mint authorities, this one is recoverable: the account's owner
// never goes away, and close-account already falls back to the owner when no
// close authority is set, so clearing this only reverts to that default.
type SetCloseAuthorityClearRequest struct {
	Account   string `json:"account" example:""`
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	FeePayer  string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program   string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	// MultisigSigners is empty for a single-signer authority. Non-empty, the
	// authority itself does not sign; the named members do, in its place.
	MultisigSigners []string `json:"multisig_signers"`

	NonceAccount string `json:"nonce_account" example:""`

	account         *types.PublicKey
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	nonceAccount    *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *SetCloseAuthorityClearRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
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

func (r *SetCloseAuthorityClearRequest) AccountKey() *types.PublicKey      { return r.account }
func (r *SetCloseAuthorityClearRequest) AuthorityKey() *types.PublicKey    { return r.authority }
func (r *SetCloseAuthorityClearRequest) FeePayerKey() *types.PublicKey     { return r.feePayer }
func (r *SetCloseAuthorityClearRequest) NonceAccountKey() *types.PublicKey { return r.nonceAccount }
func (r *SetCloseAuthorityClearRequest) TokenProgramID() *types.PublicKey  { return r.tokenProgramID }
func (r *SetCloseAuthorityClearRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// SetCloseAuthorityClearResponse reports the authority change just built.
type SetCloseAuthorityClearResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account   string `json:"account"`
	Authority string `json:"authority"`
	Cleared   bool   `json:"cleared"`
	Program   string `json:"program"`
	Fee       string `json:"fee"`
}

func NewSetCloseAuthorityClearResponse(
	tx *types.Transaction, raw, message []byte,
	account, authority, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *SetCloseAuthorityClearResponse {
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

	return &SetCloseAuthorityClearResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Authority:       authority.Base58(),
		Cleared:         true,
		Program:         tokenProgram.Base58(),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// FreezeAccountRequest names the token account to suspend.
//
// authority must be the mint's freeze authority, not the account's owner or
// any delegate. Freezing is a mint-level power: it exists so whoever controls
// a mint can suspend any account holding it, which is a different axis from
// who may spend an account's own balance.
type FreezeAccountRequest struct {
	Account   string `json:"account" example:""`
	Mint      string `json:"mint" example:""`
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
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
}

func (r *FreezeAccountRequest) ValidateRequest() error {
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

func (r *FreezeAccountRequest) AccountKey() *types.PublicKey          { return r.account }
func (r *FreezeAccountRequest) MintKey() *types.PublicKey             { return r.mint }
func (r *FreezeAccountRequest) AuthorityKey() *types.PublicKey        { return r.authority }
func (r *FreezeAccountRequest) FeePayerKey() *types.PublicKey         { return r.feePayer }
func (r *FreezeAccountRequest) NonceAccountKey() *types.PublicKey     { return r.nonceAccount }
func (r *FreezeAccountRequest) TokenProgramID() *types.PublicKey      { return r.tokenProgramID }
func (r *FreezeAccountRequest) ToMultisigSigners() []*types.PublicKey { return r.multisigSigners }

// FreezeAccountResponse reports the suspended account.
type FreezeAccountResponse struct {
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
	Fee       string `json:"fee"`
}

func NewFreezeAccountResponse(
	tx *types.Transaction, raw, message []byte,
	account, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *FreezeAccountResponse {
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

	return &FreezeAccountResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             strconv.FormatUint(fee, 10),
	}
}

// ThawAccountRequest names the token account to resume.
//
// The same rule as FreezeAccountRequest applies: authority is the mint's
// freeze authority, since thawing is undoing a mint-level suspension rather
// than anything the account's own owner controls.
type ThawAccountRequest struct {
	Account   string `json:"account" example:""`
	Mint      string `json:"mint" example:""`
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
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
}

func (r *ThawAccountRequest) ValidateRequest() error {
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

func (r *ThawAccountRequest) AccountKey() *types.PublicKey          { return r.account }
func (r *ThawAccountRequest) MintKey() *types.PublicKey             { return r.mint }
func (r *ThawAccountRequest) AuthorityKey() *types.PublicKey        { return r.authority }
func (r *ThawAccountRequest) FeePayerKey() *types.PublicKey         { return r.feePayer }
func (r *ThawAccountRequest) NonceAccountKey() *types.PublicKey     { return r.nonceAccount }
func (r *ThawAccountRequest) TokenProgramID() *types.PublicKey      { return r.tokenProgramID }
func (r *ThawAccountRequest) ToMultisigSigners() []*types.PublicKey { return r.multisigSigners }

// ThawAccountResponse reports the resumed account.
type ThawAccountResponse struct {
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
	Fee       string `json:"fee"`
}

func NewThawAccountResponse(
	tx *types.Transaction, raw, message []byte,
	account, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *ThawAccountResponse {
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

	return &ThawAccountResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             strconv.FormatUint(fee, 10),
	}
}
