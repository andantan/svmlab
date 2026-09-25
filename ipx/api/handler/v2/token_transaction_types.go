package v2

import (
	"errors"
	"fmt"
	"math"
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
// CreateMintRequest funds a new account and hands it to the Token Program,
// sized and owned correctly for a mint but not initialized.
//
// This is deliberately the low-level half only: initializing it is a separate
// call (initialize-mint2, or initialize-mint for the original opcode), and
// nothing stops somebody else from initializing it first in between with
// their own authority. A caller who wants that race closed should build the
// pair as two instructions in one transaction themselves; this endpoint takes
// no mint_authority/freeze_authority/decimals at all, since it never builds
// the instruction that would use them.
type CreateMintRequest struct {
	// RentPayer funds Mint's creation for exactly the rent-exemption minimum
	// for an 82-byte account, and is a separate balance from FeePayer.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Mint is the account created. It signs alongside RentPayer, since an
	// address does not exist until whoever holds its private key authorizes
	// its creation. It must not already exist.
	Mint string `json:"mint" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token
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

	rentPayer      *types.PublicKey
	mint           *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
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

func (r *CreateMintRequest) RentPayerKey() *types.PublicKey {
	return r.rentPayer
}

func (r *CreateMintRequest) MintKey() *types.PublicKey {
	return r.mint
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

// TokenProgramID returns the resolved program account, either
// core.TokenProgramID or core.Token2022ProgramID. core.TokenProgram(id) turns
// it into a builder.
func (r *CreateMintRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// CreateMintResponse mirrors the v1/System build response shape, plus what
// this endpoint had to resolve to validate: the rent-exempt minimum for an
// 82-byte account. There is no mint_authority/freeze_authority/decimals to
// report, since this never initializes Mint.
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

	Mint    string `json:"mint"`
	Program string `json:"program"`

	// Rent reports what funds CreateMint itself. Its lamports are always
	// exactly the rent-exemption minimum for an 82-byte account, never more
	// or less.
	Rent SystemPayer `json:"rent"`
	Fee  SystemPayer `json:"fee"`
}

func NewCreateMintResponse(
	tx *types.Transaction, raw, message []byte,
	rentPayer, feePayer, mint, tokenProgram, nonceAuthority *types.PublicKey,
	rentExempt, fee uint64,
) *CreateMintResponse {
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

	return &CreateMintResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		Mint:            mint.Base58(),
		Program:         tokenProgram.Base58(),
		Rent:            newSystemPayer(rentPayer, rentExempt),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// InitializeMintRequest turns an already-existing, correctly sized,
// Token-owned account into a mint using the original InitializeMint opcode,
// which carries the rent sysvar as a read-only account alongside mint. The
// program stopped reading it once rent collection was disabled; this exists
// only for compatibility with the original opcode. See
// InitializeMint2Request for the variant without it.
type InitializeMintRequest struct {
	// Mint is the account initialized. It must already exist, must be owned
	// by Program, and must be exactly 82 bytes and uninitialized. It does not
	// sign: it has already been created by the time this runs, and nothing
	// about initializing it needs its authority.
	Mint string `json:"mint" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// MintAuthority is who can mint new supply going forward. It is not
	// required to sign this transaction: InitializeMint only records it, it
	// does not check it against a signer.
	MintAuthority string `json:"mint_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FreezeAuthority may be left empty, in which case the mint is
	// initialized with no freeze authority at all, permanently.
	FreezeAuthority string `json:"freeze_authority" example:""`

	// Decimals fixes how the raw integer amount this mint moves is displayed
	// as a UI amount, and cannot be changed after initialization.
	Decimals uint8 `json:"decimals" example:"6"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022. It must match the program that already owns Mint.
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

	mint            *types.PublicKey
	mintAuthority   *types.PublicKey
	freezeAuthority *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
}

func (r *InitializeMintRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.mintAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.MintAuthority)); err != nil {
		return errors.New("mint_authority: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	// An absent freeze authority means the mint is initialized with none, and
	// that decision cannot be undone later.
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

func (r *InitializeMintRequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *InitializeMintRequest) MintAuthorityKey() *types.PublicKey {
	return r.mintAuthority
}

func (r *InitializeMintRequest) FreezeAuthorityKey() *types.PublicKey {
	return r.freezeAuthority
}

func (r *InitializeMintRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *InitializeMintRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *InitializeMintRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *InitializeMintRequest) ToDecimals() uint8 {
	return r.Decimals
}

// TokenProgramID returns the resolved program account, either
// core.TokenProgramID or core.Token2022ProgramID. core.TokenProgram(id) turns
// it into a builder.
func (r *InitializeMintRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeMintResponse mirrors InitializeMint2Response; the rent sysvar
// InitializeMint reads and InitializeMint2 does not is not reported, since it
// changes nothing this API surfaces.
type InitializeMintResponse struct {
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

	Fee SystemPayer `json:"fee"`
}

func NewInitializeMintResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, tokenProgram, mintAuthority, freezeAuthority, nonceAuthority *types.PublicKey,
	decimals uint8, fee uint64,
) *InitializeMintResponse {
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

	return &InitializeMintResponse{
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
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// InitializeMint2Request turns an already-existing, correctly sized,
// Token-owned account into a mint.
//
// Unlike CreateMintRequest, this never creates the account: mint names an
// account that must already exist (see system/create-account), be owned by
// Program, and be exactly core.MintSpace bytes and uninitialized. Nothing
// stops somebody else from initializing it first between its creation and
// this call, which is the same race CreateMint's single-transaction design
// exists to avoid; this endpoint is for callers who accept that race
// themselves, e.g. because the create and initialize happen in the same
// transaction some other way (compat, batch, or client-assembled).
type InitializeMint2Request struct {
	// Mint is the account initialized. It must already exist, must be owned
	// by Program, and must be exactly 82 bytes and uninitialized. It does not
	// sign: it has already been created by the time this runs, and nothing
	// about initializing it needs its authority.
	Mint string `json:"mint" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// MintAuthority is who can mint new supply going forward. It is not
	// required to sign this transaction: InitializeMint2 only records it, it
	// does not check it against a signer.
	MintAuthority string `json:"mint_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FreezeAuthority may be left empty, in which case the mint is
	// initialized with no freeze authority at all, permanently.
	FreezeAuthority string `json:"freeze_authority" example:""`

	// Decimals fixes how the raw integer amount this mint moves is displayed
	// as a UI amount, and cannot be changed after initialization.
	Decimals uint8 `json:"decimals" example:"6"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022. It must match the program that already owns Mint.
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

	mint            *types.PublicKey
	mintAuthority   *types.PublicKey
	freezeAuthority *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
}

func (r *InitializeMint2Request) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.mintAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.MintAuthority)); err != nil {
		return errors.New("mint_authority: " + err.Error())
	}
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	// An absent freeze authority means the mint is initialized with none, and
	// that decision cannot be undone later.
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

func (r *InitializeMint2Request) MintKey() *types.PublicKey {
	return r.mint
}

func (r *InitializeMint2Request) MintAuthorityKey() *types.PublicKey {
	return r.mintAuthority
}

func (r *InitializeMint2Request) FreezeAuthorityKey() *types.PublicKey {
	return r.freezeAuthority
}

func (r *InitializeMint2Request) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *InitializeMint2Request) Blockhash() *types.Hash {
	return r.rbh
}

func (r *InitializeMint2Request) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *InitializeMint2Request) ToDecimals() uint8 {
	return r.Decimals
}

// TokenProgramID returns the resolved program account, either
// core.TokenProgramID or core.Token2022ProgramID. core.TokenProgram(id) turns
// it into a builder.
func (r *InitializeMint2Request) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeMint2Response mirrors CreateMintResponse, minus the rent it never
// pays: the account already existed and was already funded before this ran.
type InitializeMint2Response struct {
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

	Fee SystemPayer `json:"fee"`
}

func NewInitializeMint2Response(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, tokenProgram, mintAuthority, freezeAuthority, nonceAuthority *types.PublicKey,
	decimals uint8, fee uint64,
) *InitializeMint2Response {
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

	return &InitializeMint2Response{
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
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// InitializeAccountRequest turns an already-existing, correctly sized,
// Token-owned account into a holder account for one mint, using the original
// InitializeAccount opcode: owner is passed as a read-only account alongside
// the rent sysvar. InitializeAccount3 drops both; this exists only for
// compatibility with the original opcode.
//
// Unlike CreateKTARequest, this never creates the account: token_account
// names an account that must already exist, be owned by Program, and be
// exactly core.TokenAccountSpace bytes and uninitialized. Nothing stops
// somebody else from initializing it first between its creation and this
// call, which is the same race CreateKTA's single-transaction design exists
// to avoid; this endpoint is for callers who accept that race themselves.
type InitializeAccountRequest struct {
	// TokenAccount is the account initialized as a holder account for Mint.
	// It must already exist, must be owned by Program, and must be exactly
	// 165 bytes and uninitialized. It does not sign.
	TokenAccount string `json:"token_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// Mint is the token TokenAccount is initialized to hold, and must already
	// exist.
	Mint string `json:"mint" example:""`

	// Owner is who can transfer, burn, or otherwise authorize spending from
	// TokenAccount. It is not required to sign this transaction:
	// InitializeAccount only records it, it does not check it against a
	// signer.
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022. It must match the program that already owns TokenAccount
	// and Mint.
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

	tokenAccount   *types.PublicKey
	mint           *types.PublicKey
	owner          *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *InitializeAccountRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
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

func (r *InitializeAccountRequest) TokenAccountKey() *types.PublicKey {
	return r.tokenAccount
}

func (r *InitializeAccountRequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *InitializeAccountRequest) OwnerKey() *types.PublicKey {
	return r.owner
}

func (r *InitializeAccountRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *InitializeAccountRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *InitializeAccountRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// TokenProgramID returns the resolved program account, either
// core.TokenProgramID or core.Token2022ProgramID. core.TokenProgram(id) turns
// it into a builder.
func (r *InitializeAccountRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeAccountResponse mirrors CreateKTAResponse, minus the rent it
// never pays: the account already existed and was already funded before this
// ran.
type InitializeAccountResponse struct {
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

	Fee SystemPayer `json:"fee"`
}

func NewInitializeAccountResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, mint, owner, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *InitializeAccountResponse {
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

	return &InitializeAccountResponse{
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
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// InitializeAccount2Request is InitializeAccountRequest against the 2
// variant: owner still travels in the request, but on chain it rides in the
// instruction data rather than as an account. The rent sysvar is still read.
// InitializeAccount3 drops that too; this exists only for compatibility with
// this opcode.
type InitializeAccount2Request struct {
	TokenAccount string `json:"token_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`
	Mint         string `json:"mint" example:""`
	Owner        string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	FeePayer     string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program      string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	RecentBlockhash     string `json:"recent_blockhash" example:""`
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	tokenAccount   *types.PublicKey
	mint           *types.PublicKey
	owner          *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *InitializeAccount2Request) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
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

func (r *InitializeAccount2Request) TokenAccountKey() *types.PublicKey {
	return r.tokenAccount
}

func (r *InitializeAccount2Request) MintKey() *types.PublicKey {
	return r.mint
}

func (r *InitializeAccount2Request) OwnerKey() *types.PublicKey {
	return r.owner
}

func (r *InitializeAccount2Request) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *InitializeAccount2Request) Blockhash() *types.Hash {
	return r.rbh
}

func (r *InitializeAccount2Request) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *InitializeAccount2Request) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeAccount2Response mirrors InitializeAccountResponse.
type InitializeAccount2Response struct {
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

	Fee SystemPayer `json:"fee"`
}

func NewInitializeAccount2Response(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, mint, owner, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *InitializeAccount2Response {
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

	return &InitializeAccount2Response{
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
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// InitializeAccount3Request is InitializeAccount2Request against the 3
// variant: owner still travels in the request and rides in the instruction
// data, but the rent sysvar InitializeAccount2 still reads is dropped too.
// This is the natural pairing for create-kta, which only creates the account
// and never initializes it.
type InitializeAccount3Request struct {
	TokenAccount string `json:"token_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`
	Mint         string `json:"mint" example:""`
	Owner        string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	FeePayer     string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program      string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	RecentBlockhash     string `json:"recent_blockhash" example:""`
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	tokenAccount   *types.PublicKey
	mint           *types.PublicKey
	owner          *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *InitializeAccount3Request) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
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

func (r *InitializeAccount3Request) TokenAccountKey() *types.PublicKey {
	return r.tokenAccount
}

func (r *InitializeAccount3Request) MintKey() *types.PublicKey {
	return r.mint
}

func (r *InitializeAccount3Request) OwnerKey() *types.PublicKey {
	return r.owner
}

func (r *InitializeAccount3Request) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *InitializeAccount3Request) Blockhash() *types.Hash {
	return r.rbh
}

func (r *InitializeAccount3Request) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *InitializeAccount3Request) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeAccount3Response mirrors InitializeAccount2Response.
type InitializeAccount3Response struct {
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

	Fee SystemPayer `json:"fee"`
}

func NewInitializeAccount3Response(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, mint, owner, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *InitializeAccount3Response {
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

	return &InitializeAccount3Response{
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
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// InitializeWrappedSolRequest is InitializeAccount3Request with mint fixed
// to whichever mint Program's own native mint is, rather than taken from the
// request.
//
// There is no separate create-wrapped-sol or wrap-sol composite: this pairs
// with create-kta/create-ata the same way initialize-account3 does, and
// funding it is a plain system/transfer followed by sync-native — nothing
// about wrapping SOL needs an instruction bundle of its own. Classic Token's
// native mint is the fixed NativeMintID; Token-2022's is a separate address
// derived as its own PDA (see core.token.NativeMint), never the same as
// classic's, since a wrapped-SOL account under one program can never hold
// the other's native mint.
type InitializeWrappedSolRequest struct {
	// TokenAccount is the account initialized. It must already exist, must
	// be owned by Program, and must be at least 165 bytes and uninitialized.
	TokenAccount string `json:"token_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// Owner is who can transfer, unwrap, or otherwise authorize spending
	// from TokenAccount. It is not required to sign this transaction:
	// InitializeAccount3 only records it, it does not check it against a
	// signer.
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token
	// or Token-2022. It also selects which native mint TokenAccount is
	// initialized against — the two programs never share one.
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

	tokenAccount   *types.PublicKey
	owner          *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *InitializeWrappedSolRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
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

func (r *InitializeWrappedSolRequest) TokenAccountKey() *types.PublicKey {
	return r.tokenAccount
}

func (r *InitializeWrappedSolRequest) OwnerKey() *types.PublicKey {
	return r.owner
}

func (r *InitializeWrappedSolRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *InitializeWrappedSolRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *InitializeWrappedSolRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *InitializeWrappedSolRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeWrappedSolResponse mirrors InitializeAccount3Response, reporting
// the resolved Mint since the request never names one.
type InitializeWrappedSolResponse struct {
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

	Fee SystemPayer `json:"fee"`
}

func NewInitializeWrappedSolResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, mint, owner, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *InitializeWrappedSolResponse {
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

	return &InitializeWrappedSolResponse{
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
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// SyncNativeRequest recomputes a wrapped-SOL account's token balance from
// its lamports.
//
// A wrapped-SOL account's amount is not the same field as its lamports:
// lamports can change independently, by a plain System transfer landing on
// the account directly (funding it further, the way any account can be
// funded), and nothing updates amount when that happens. This is the only
// instruction that reconciles the two. There is no authority: recomputing a
// derived value from what the account already holds needs nobody's
// permission, the same way reading a balance needs none.
type SyncNativeRequest struct {
	// TokenAccount must already exist, be owned by Program, and actually be
	// a wrapped-SOL account — the program rejects one that is not.
	TokenAccount string `json:"token_account" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022.
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

	tokenAccount   *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *SyncNativeRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
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

func (r *SyncNativeRequest) TokenAccountKey() *types.PublicKey {
	return r.tokenAccount
}

func (r *SyncNativeRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *SyncNativeRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *SyncNativeRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *SyncNativeRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// SyncNativeResponse reports EstimatedAmount, computed client-side as
// TokenAccount's lamports minus its stored rent-exempt reserve at read time
// — an estimate, not the value the program itself will use, since lamports
// could change again before this lands.
type SyncNativeResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	TokenAccount string `json:"token_account"`
	Mint         string `json:"mint"`
	Program      string `json:"program"`

	EstimatedAmount SystemPayer `json:"estimated_amount"`
	Fee             SystemPayer `json:"fee"`
}

func NewSyncNativeResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, mint, tokenProgram, nonceAuthority *types.PublicKey,
	estimatedAmount, fee uint64,
) *SyncNativeResponse {
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

	return &SyncNativeResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		TokenAccount:    tokenAccount.Base58(),
		Mint:            mint.Base58(),
		Program:         tokenProgram.Base58(),
		EstimatedAmount: newSystemPayer(tokenAccount, estimatedAmount),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// UnwrapLamportsRequest pulls exactly Amount lamports directly out of a
// wrapped-SOL account without closing it.
//
// Unlike close-account, source_token_account is never consumed: it stays
// exactly as it was, still rent-exempt and still wrapping whatever is left.
// The instruction's amount is an optional u64 on the wire (a one-byte tag,
// not the 4-byte COption tag older instructions use); this endpoint always
// sends it present, and unwrap-lamports/max always sends it absent, rather
// than one endpoint whose meaning changes with an empty field.
// source_token_account_authority is source_token_account's owner, or its
// delegate for no more than what was delegated — spending wrapped SOL out as
// raw lamports is a spend, so it follows the same rule as transfer-checked
// and burn-checked rather than close-account's
// close_authority.unwrap_or(owner).
type UnwrapLamportsRequest struct {
	// SourceTokenAccount is debited and never closed. It must already
	// exist, be owned by Program, and actually be a wrapped-SOL account.
	SourceTokenAccount string `json:"source_token_account" example:""`

	// DestinationTokenAccount receives the unwrapped lamports directly, as
	// plain SOL rather than tokens — it need not be a token account at all.
	DestinationTokenAccount string `json:"destination_token_account" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// SourceTokenAccountAuthority is SourceTokenAccount's owner, or its
	// delegate for no more than what was delegated.
	SourceTokenAccountAuthority string `json:"source_token_account_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Amount is the raw base-unit (lamport) count to unwrap, not a UI
	// decimal string.
	Amount string `json:"amount" example:"250000"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token
	// or Token-2022.
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

	sourceTokenAccount          *types.PublicKey
	destinationTokenAccount     *types.PublicKey
	sourceTokenAccountAuthority *types.PublicKey
	feePayer                    *types.PublicKey
	rbh                         *types.Hash
	dna                         *types.PublicKey
	tokenProgramID              *types.PublicKey
	multisigSigners             []*types.PublicKey
	amount                      uint64
}

func (r *UnwrapLamportsRequest) ValidateRequest() error {
	var err error
	if r.sourceTokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.SourceTokenAccount)); err != nil {
		return errors.New("source_token_account: " + err.Error())
	}
	if r.destinationTokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.DestinationTokenAccount)); err != nil {
		return errors.New("destination_token_account: " + err.Error())
	}
	if r.sourceTokenAccount.Equal(r.destinationTokenAccount) {
		return errors.New("source_token_account and destination_token_account are the same account")
	}
	if r.sourceTokenAccountAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.SourceTokenAccountAuthority)); err != nil {
		return errors.New("source_token_account_authority: " + err.Error())
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

func (r *UnwrapLamportsRequest) SourceTokenAccountKey() *types.PublicKey {
	return r.sourceTokenAccount
}
func (r *UnwrapLamportsRequest) DestinationTokenAccountKey() *types.PublicKey {
	return r.destinationTokenAccount
}
func (r *UnwrapLamportsRequest) SourceTokenAccountAuthorityKey() *types.PublicKey {
	return r.sourceTokenAccountAuthority
}
func (r *UnwrapLamportsRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *UnwrapLamportsRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *UnwrapLamportsRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *UnwrapLamportsRequest) TokenProgramID() *types.PublicKey      { return r.tokenProgramID }
func (r *UnwrapLamportsRequest) ToMultisigSigners() []*types.PublicKey { return r.multisigSigners }
func (r *UnwrapLamportsRequest) ToAmount() uint64                      { return r.amount }

// UnwrapLamportsResponse reports the caller-given Amount, since that is
// exactly what the instruction was built to move.
type UnwrapLamportsResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	SourceTokenAccount          string      `json:"source_token_account"`
	DestinationTokenAccount     string      `json:"destination_token_account"`
	SourceTokenAccountAuthority string      `json:"source_token_account_authority"`
	Program                     string      `json:"program"`
	Amount                      SystemPayer `json:"amount"`
	Fee                         SystemPayer `json:"fee"`
}

func NewUnwrapLamportsResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, sourceTokenAccount, destinationTokenAccount, sourceTokenAccountAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	amount, fee uint64,
) *UnwrapLamportsResponse {
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

	return &UnwrapLamportsResponse{
		Transaction:                 codec.Base64.Encode(raw),
		Message:                     codec.Base64.Encode(message),
		RecentBlockhash:             tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                 keys,
		Signers:                     signers,
		NonceAuthority:              nonceAuth,
		SourceTokenAccount:          sourceTokenAccount.Base58(),
		DestinationTokenAccount:     destinationTokenAccount.Base58(),
		SourceTokenAccountAuthority: sourceTokenAccountAuthority.Base58(),
		Program:                     tokenProgram.Base58(),
		Amount:                      newSystemPayer(destinationTokenAccount, amount),
		Fee:                         newSystemPayer(feePayer, fee),
	}
}

// UnwrapLamportsMaxRequest pulls a wrapped-SOL account's entire balance out
// as lamports without closing it.
//
// Same as UnwrapLamportsRequest, except the instruction's amount goes out
// absent, which the program reads as the whole wrapped balance. The account
// is left holding exactly its rent-exempt reserve, still initialized and
// still wrapped SOL, ready to be funded again — which is what separates this
// from close-account.
type UnwrapLamportsMaxRequest struct {
	// SourceTokenAccount is debited and never closed. It must already
	// exist, be owned by Program, and actually be a wrapped-SOL account.
	SourceTokenAccount string `json:"source_token_account" example:""`

	// DestinationTokenAccount receives the unwrapped lamports directly, as
	// plain SOL rather than tokens — it need not be a token account at all.
	DestinationTokenAccount string `json:"destination_token_account" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// SourceTokenAccountAuthority is SourceTokenAccount's owner, or its
	// delegate for no more than what was delegated.
	SourceTokenAccountAuthority string `json:"source_token_account_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token
	// or Token-2022.
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

	sourceTokenAccount          *types.PublicKey
	destinationTokenAccount     *types.PublicKey
	sourceTokenAccountAuthority *types.PublicKey
	feePayer                    *types.PublicKey
	rbh                         *types.Hash
	dna                         *types.PublicKey
	tokenProgramID              *types.PublicKey
	multisigSigners             []*types.PublicKey
}

func (r *UnwrapLamportsMaxRequest) ValidateRequest() error {
	var err error
	if r.sourceTokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.SourceTokenAccount)); err != nil {
		return errors.New("source_token_account: " + err.Error())
	}
	if r.destinationTokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.DestinationTokenAccount)); err != nil {
		return errors.New("destination_token_account: " + err.Error())
	}
	if r.sourceTokenAccount.Equal(r.destinationTokenAccount) {
		return errors.New("source_token_account and destination_token_account are the same account")
	}
	if r.sourceTokenAccountAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.SourceTokenAccountAuthority)); err != nil {
		return errors.New("source_token_account_authority: " + err.Error())
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

func (r *UnwrapLamportsMaxRequest) SourceTokenAccountKey() *types.PublicKey {
	return r.sourceTokenAccount
}
func (r *UnwrapLamportsMaxRequest) DestinationTokenAccountKey() *types.PublicKey {
	return r.destinationTokenAccount
}
func (r *UnwrapLamportsMaxRequest) SourceTokenAccountAuthorityKey() *types.PublicKey {
	return r.sourceTokenAccountAuthority
}
func (r *UnwrapLamportsMaxRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *UnwrapLamportsMaxRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *UnwrapLamportsMaxRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *UnwrapLamportsMaxRequest) TokenProgramID() *types.PublicKey      { return r.tokenProgramID }
func (r *UnwrapLamportsMaxRequest) ToMultisigSigners() []*types.PublicKey { return r.multisigSigners }

// UnwrapLamportsMaxResponse reports EstimatedAmount, source_token_account's
// wrapped balance at read time: the program decides the real figure when
// this lands, and the balance could change before then.
type UnwrapLamportsMaxResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	SourceTokenAccount          string      `json:"source_token_account"`
	DestinationTokenAccount     string      `json:"destination_token_account"`
	SourceTokenAccountAuthority string      `json:"source_token_account_authority"`
	Program                     string      `json:"program"`
	EstimatedAmount             SystemPayer `json:"estimated_amount"`
	Fee                         SystemPayer `json:"fee"`
}

func NewUnwrapLamportsMaxResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, sourceTokenAccount, destinationTokenAccount, sourceTokenAccountAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	amount, fee uint64,
) *UnwrapLamportsMaxResponse {
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

	return &UnwrapLamportsMaxResponse{
		Transaction:                 codec.Base64.Encode(raw),
		Message:                     codec.Base64.Encode(message),
		RecentBlockhash:             tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                 keys,
		Signers:                     signers,
		NonceAuthority:              nonceAuth,
		SourceTokenAccount:          sourceTokenAccount.Base58(),
		DestinationTokenAccount:     destinationTokenAccount.Base58(),
		SourceTokenAccountAuthority: sourceTokenAccountAuthority.Base58(),
		Program:                     tokenProgram.Base58(),
		EstimatedAmount:             newSystemPayer(destinationTokenAccount, amount),
		Fee:                         newSystemPayer(feePayer, fee),
	}
}

// InitializeMultisigRequest turns an already-existing, correctly sized,
// Token-owned account into a multisig, using the original opcode that
// carries the rent sysvar as a read-only account alongside the multisig.
// InitializeMultisig2Request drops it; this exists only for compatibility
// with the original opcode. This is the natural pairing for create-multisig,
// which only creates the account and never initializes it.
type InitializeMultisigRequest struct {
	// MultisigAccount is the account initialized. It must already exist,
	// must be owned by Program, and must be exactly 355 bytes and
	// uninitialized. It does not sign: nothing about becoming a registered
	// signer needs proving here, only once the multisig is actually used as
	// an authority.
	MultisigAccount string `json:"multisig_account" example:""`

	// M is how many of Signers must sign in the multisig's place, wherever
	// it is later named as an authority. The program enforces
	// 1 <= m <= len(signers) <= 11.
	M uint8 `json:"m" example:"2"`

	// Signers is who is enrolled. Order is preserved in the response, but the
	// program itself treats membership as a set: any m of them may sign.
	Signers []string `json:"signers"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022. It must match the program that already owns
	// MultisigAccount.
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

	multisigAccount *types.PublicKey
	signers         []*types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
}

func (r *InitializeMultisigRequest) ValidateRequest() error {
	var err error
	if r.multisigAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.MultisigAccount)); err != nil {
		return errors.New("multisig_account: " + err.Error())
	}

	if len(r.Signers) == 0 {
		return errors.New("signers: at least one signer is required")
	}
	if len(r.Signers) > core.MaxMultisigSigners {
		return fmt.Errorf("signers: %d exceeds the limit of %d", len(r.Signers), core.MaxMultisigSigners)
	}
	r.signers = make([]*types.PublicKey, len(r.Signers))
	for i, s := range r.Signers {
		if r.signers[i], err = types.NewPublicKeyFromBase58(strings.TrimSpace(s)); err != nil {
			return fmt.Errorf("signers[%d]: %s", i, err)
		}
	}
	if int(r.M) < core.MinMultisigSigners || int(r.M) > len(r.signers) {
		return fmt.Errorf("m: must be between 1 and %d, got %d", len(r.signers), r.M)
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

func (r *InitializeMultisigRequest) MultisigAccountKey() *types.PublicKey {
	return r.multisigAccount
}

func (r *InitializeMultisigRequest) ToM() uint8 {
	return r.M
}

func (r *InitializeMultisigRequest) SignerKeys() []*types.PublicKey {
	return r.signers
}

func (r *InitializeMultisigRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *InitializeMultisigRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *InitializeMultisigRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *InitializeMultisigRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeMultisigResponse mirrors the other initialize-* responses, plus
// what a multisig is: m of n named signers rather than a single authority.
type InitializeMultisigResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	MultisigAccount string   `json:"multisig_account"`
	Program         string   `json:"program"`
	M               uint8    `json:"m"`
	N               uint8    `json:"n"`
	MultisigSigners []string `json:"multisig_signers"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializeMultisigResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, multisigAccount, tokenProgram, nonceAuthority *types.PublicKey, signers []*types.PublicKey,
	m uint8, fee uint64,
) *InitializeMultisigResponse {
	authority := ""
	if !nonceAuthority.IsNil() {
		authority = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	txSigners := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		txSigners[i] = k.Base58()
	}

	multisigSigners := make([]string, len(signers))
	for i, s := range signers {
		multisigSigners[i] = s.Base58()
	}

	return &InitializeMultisigResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         txSigners,
		NonceAuthority:  authority,
		MultisigAccount: multisigAccount.Base58(),
		Program:         tokenProgram.Base58(),
		M:               m,
		N:               uint8(len(signers)),
		MultisigSigners: multisigSigners,
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// InitializeMultisig2Request is InitializeMultisigRequest against the 2
// variant: the rent sysvar InitializeMultisig reads is dropped. This is the
// one create-mint's peers would use if a multisig ever gained a
// single-transaction composite; today it exists standing alone.
type InitializeMultisig2Request struct {
	MultisigAccount string   `json:"multisig_account" example:""`
	M               uint8    `json:"m" example:"2"`
	Signers         []string `json:"signers"`
	FeePayer        string   `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program         string   `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	RecentBlockhash     string `json:"recent_blockhash" example:""`
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	multisigAccount *types.PublicKey
	signers         []*types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
}

func (r *InitializeMultisig2Request) ValidateRequest() error {
	var err error
	if r.multisigAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.MultisigAccount)); err != nil {
		return errors.New("multisig_account: " + err.Error())
	}

	if len(r.Signers) == 0 {
		return errors.New("signers: at least one signer is required")
	}
	if len(r.Signers) > core.MaxMultisigSigners {
		return fmt.Errorf("signers: %d exceeds the limit of %d", len(r.Signers), core.MaxMultisigSigners)
	}
	r.signers = make([]*types.PublicKey, len(r.Signers))
	for i, s := range r.Signers {
		if r.signers[i], err = types.NewPublicKeyFromBase58(strings.TrimSpace(s)); err != nil {
			return fmt.Errorf("signers[%d]: %s", i, err)
		}
	}
	if int(r.M) < core.MinMultisigSigners || int(r.M) > len(r.signers) {
		return fmt.Errorf("m: must be between 1 and %d, got %d", len(r.signers), r.M)
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

func (r *InitializeMultisig2Request) MultisigAccountKey() *types.PublicKey {
	return r.multisigAccount
}

func (r *InitializeMultisig2Request) ToM() uint8 {
	return r.M
}

func (r *InitializeMultisig2Request) SignerKeys() []*types.PublicKey {
	return r.signers
}

func (r *InitializeMultisig2Request) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *InitializeMultisig2Request) Blockhash() *types.Hash {
	return r.rbh
}

func (r *InitializeMultisig2Request) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *InitializeMultisig2Request) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeMultisig2Response mirrors InitializeMultisigResponse.
type InitializeMultisig2Response struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	MultisigAccount string   `json:"multisig_account"`
	Program         string   `json:"program"`
	M               uint8    `json:"m"`
	N               uint8    `json:"n"`
	MultisigSigners []string `json:"multisig_signers"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializeMultisig2Response(
	tx *types.Transaction, raw, message []byte,
	feePayer, multisigAccount, tokenProgram, nonceAuthority *types.PublicKey, signers []*types.PublicKey,
	m uint8, fee uint64,
) *InitializeMultisig2Response {
	authority := ""
	if !nonceAuthority.IsNil() {
		authority = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	txSigners := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		txSigners[i] = k.Base58()
	}

	multisigSigners := make([]string, len(signers))
	for i, s := range signers {
		multisigSigners[i] = s.Base58()
	}

	return &InitializeMultisig2Response{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         txSigners,
		NonceAuthority:  authority,
		MultisigAccount: multisigAccount.Base58(),
		Program:         tokenProgram.Base58(),
		M:               m,
		N:               uint8(len(signers)),
		MultisigSigners: multisigSigners,
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// InitializeImmutableOwnerRequest permanently locks a token account's owner
// field against SetAuthority.
//
// This is a Token-2022 extension: it needs extension space appended after
// the classic 165-byte layout, which classic Token accounts never have. On
// Token-2022 it attaches the real extension; on classic Token, upstream
// documents this opcode as a no-op, kept only so the Associated Token
// Account program can call it on either program without branching. Program
// therefore accepts either, the same as every other endpoint in this file.
// There is no authority: nothing about locking the owner field needs
// proving.
type InitializeImmutableOwnerRequest struct {
	// TokenAccount is the account whose owner field is locked. It must
	// already exist, be owned by Program, and — on Token-2022 — carry the
	// extension space this instruction writes to. This endpoint does not
	// verify that itself, since parsing Token-2022 extension layouts is its
	// own separate undertaking; a mismatch fails on chain instead.
	TokenAccount string `json:"token_account" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token
	// or Token-2022. On Token-2022 this attaches the real extension; on
	// classic Token it is a documented no-op, kept for compatibility with
	// the Associated Token Account program's own create flow.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	tokenAccount   *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *InitializeImmutableOwnerRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
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

func (r *InitializeImmutableOwnerRequest) TokenAccountKey() *types.PublicKey {
	return r.tokenAccount
}

func (r *InitializeImmutableOwnerRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *InitializeImmutableOwnerRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *InitializeImmutableOwnerRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *InitializeImmutableOwnerRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeImmutableOwnerResponse mirrors the other initialize-* responses;
// there is no authority or role field to report, since this locks a
// property of TokenAccount itself rather than naming anyone.
type InitializeImmutableOwnerResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	TokenAccount string `json:"token_account"`
	Program      string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializeImmutableOwnerResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *InitializeImmutableOwnerResponse {
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

	return &InitializeImmutableOwnerResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		TokenAccount:    tokenAccount.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// CreateKTARequest funds a new account and hands it to the Token Program,
// sized and owned correctly for a keypair token holder account (KTA) but not
// initialized.
//
// This is deliberately the low-level half only: initializing it is a separate
// call (initialize-account3, or initialize-account/initialize-account2 for
// the original opcodes), and nothing stops somebody else from initializing it
// first in between, naming their own wallet as owner. A caller who wants
// that race closed should build the pair as two instructions in one
// transaction themselves; this endpoint takes no mint or owner at all, since
// it never builds the instruction that would use them.
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

	// TokenAccount is created. It signs alongside RentPayer, since an address
	// does not exist until whoever holds its private key authorizes its
	// creation. It must not already exist.
	TokenAccount string `json:"token_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token
	// or Token-2022. It is required rather than defaulted, since a token
	// account belongs to exactly one of the two forever.
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
// to know to build the next transaction without guessing. There is no mint
// or owner to report, since this never initializes TokenAccount.
type CreateKTAResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	TokenAccount string `json:"token_account"`
	Program      string `json:"program"`

	// Rent reports what funds CreateAccount itself. Its lamports are always
	// exactly the rent-exemption minimum for a 165-byte account, never more
	// or less.
	Rent SystemPayer `json:"rent"`
	Fee  SystemPayer `json:"fee"`
}

func NewCreateKTAResponse(
	tx *types.Transaction, raw, message []byte,
	rentPayer, feePayer, tokenAccount, tokenProgram, nonceAuthority *types.PublicKey,
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
		Program:         tokenProgram.Base58(),
		Rent:            newSystemPayer(rentPayer, rentExempt),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// CreateMultisigRequest funds a new account and hands it to the Token
// Program, sized and owned correctly for a multisig but not initialized.
//
// This is deliberately the low-level half only, the same as CreateMintRequest
// and CreateKTARequest: initializing it is a separate call
// (initialize-multisig2, or initialize-multisig for the original opcode),
// and nothing stops somebody else from initializing it first in between with
// their own m and signers. A caller who wants that race closed should build
// create+initialize as two instructions in one transaction themselves.
type CreateMultisigRequest struct {
	// RentPayer funds MultisigAccount's creation for exactly the
	// rent-exemption minimum for a 355-byte account, and is a separate
	// balance from FeePayer.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// MultisigAccount is the account created. It signs alongside RentPayer,
	// since an address does not exist until whoever holds its private key
	// authorizes its creation. It must not already exist.
	MultisigAccount string `json:"multisig_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022.
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
	multisigAccount *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
}

func (r *CreateMultisigRequest) ValidateRequest() error {
	var err error
	if r.rentPayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.multisigAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.MultisigAccount)); err != nil {
		return errors.New("multisig_account: " + err.Error())
	}
	if r.rentPayer.Equal(r.multisigAccount) {
		return errors.New("rent_payer and multisig_account are the same account")
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

func (r *CreateMultisigRequest) RentPayerKey() *types.PublicKey {
	return r.rentPayer
}

func (r *CreateMultisigRequest) MultisigAccountKey() *types.PublicKey {
	return r.multisigAccount
}

func (r *CreateMultisigRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *CreateMultisigRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *CreateMultisigRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// TokenProgramID returns the resolved program account, either
// core.TokenProgramID or core.Token2022ProgramID. core.TokenProgram(id) turns
// it into a builder.
func (r *CreateMultisigRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// CreateMultisigResponse mirrors CreateKTAResponse's shape for the same
// reason: what the server had to resolve to validate is what a caller needs
// to know to build the next transaction without guessing. There is no m or
// signers to report, since this never initializes MultisigAccount.
type CreateMultisigResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	MultisigAccount string `json:"multisig_account"`
	Program         string `json:"program"`

	// Rent reports what funds CreateMultisig itself. Its lamports are always
	// exactly the rent-exemption minimum for a 355-byte account, never more
	// or less.
	Rent SystemPayer `json:"rent"`
	Fee  SystemPayer `json:"fee"`
}

func NewCreateMultisigResponse(
	tx *types.Transaction, raw, message []byte,
	rentPayer, feePayer, multisigAccount, tokenProgram, nonceAuthority *types.PublicKey,
	rentExempt, fee uint64,
) *CreateMultisigResponse {
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

	return &CreateMultisigResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  authority,
		MultisigAccount: multisigAccount.Base58(),
		Program:         tokenProgram.Base58(),
		Rent:            newSystemPayer(rentPayer, rentExempt),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// TransferRequest moves tokens between two accounts, the original opcode.
//
// Unlike TransferCheckedRequest, there is no mint field and no decimals:
// neither is named or verified against the accounts, which is exactly the
// failure mode the checked variant exists to catch. Mint is still resolved
// server-side, from source_token_account's own stored value, so the
// response can report what actually moved and destination_token_account can
// still be checked against it.
type TransferRequest struct {
	// SourceTokenAccount is debited. It must already exist and not be
	// frozen.
	SourceTokenAccount string `json:"source_token_account" example:""`

	// DestinationTokenAccount is credited. It must already exist, hold the
	// same mint as SourceTokenAccount, and not be frozen: a transfer moves
	// between *token accounts*, never to a wallet address directly.
	DestinationTokenAccount string `json:"destination_token_account" example:""`

	// SourceTokenAccountAuthority is SourceTokenAccount's owner, or its
	// delegate for no more than what was delegated.
	SourceTokenAccountAuthority string `json:"source_token_account_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Amount is the raw base-unit count to move, not a UI decimal string.
	Amount string `json:"amount" example:"250000"`

	// FeePayer signs and pays the transaction fee. A transfer moves no
	// lamports of its own, so this is the only balance this endpoint ever
	// checks.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token
	// or Token-2022. It must agree with both accounts' own owning program
	// or the instruction fails on chain.
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

	sourceTokenAccount          *types.PublicKey
	destinationTokenAccount     *types.PublicKey
	sourceTokenAccountAuthority *types.PublicKey
	feePayer                    *types.PublicKey
	rbh                         *types.Hash
	dna                         *types.PublicKey
	tokenProgramID              *types.PublicKey
	multisigSigners             []*types.PublicKey
	amount                      uint64
}

func (r *TransferRequest) ValidateRequest() error {
	var err error
	if r.sourceTokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.SourceTokenAccount)); err != nil {
		return errors.New("source_token_account: " + err.Error())
	}
	if r.destinationTokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.DestinationTokenAccount)); err != nil {
		return errors.New("destination_token_account: " + err.Error())
	}
	if r.sourceTokenAccount.Equal(r.destinationTokenAccount) {
		return errors.New("source_token_account and destination_token_account are the same account")
	}
	if r.sourceTokenAccountAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.SourceTokenAccountAuthority)); err != nil {
		return errors.New("source_token_account_authority: " + err.Error())
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

func (r *TransferRequest) SourceTokenAccountKey() *types.PublicKey { return r.sourceTokenAccount }
func (r *TransferRequest) DestinationTokenAccountKey() *types.PublicKey {
	return r.destinationTokenAccount
}
func (r *TransferRequest) SourceTokenAccountAuthorityKey() *types.PublicKey {
	return r.sourceTokenAccountAuthority
}
func (r *TransferRequest) FeePayerKey() *types.PublicKey            { return r.feePayer }
func (r *TransferRequest) Blockhash() *types.Hash                   { return r.rbh }
func (r *TransferRequest) DurableNonceAccountKey() *types.PublicKey { return r.dna }
func (r *TransferRequest) TokenProgramID() *types.PublicKey         { return r.tokenProgramID }
func (r *TransferRequest) ToAmount() uint64                         { return r.amount }
func (r *TransferRequest) ToMultisigSigners() []*types.PublicKey    { return r.multisigSigners }

// TransferResponse mirrors TransferCheckedResponse, minus decimals: there is
// none to check or report. Mint is still reported, resolved server-side from
// source_token_account rather than taken from the request.
type TransferResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	SourceTokenAccount          string      `json:"source_token_account"`
	Mint                        string      `json:"mint"`
	DestinationTokenAccount     string      `json:"destination_token_account"`
	SourceTokenAccountAuthority string      `json:"source_token_account_authority"`
	Program                     string      `json:"program"`
	Amount                      string      `json:"amount"`
	Fee                         SystemPayer `json:"fee"`
}

func NewTransferResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, sourceTokenAccount, mint, destinationTokenAccount, sourceTokenAccountAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	amount, fee uint64,
) *TransferResponse {
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

	return &TransferResponse{
		Transaction:                 codec.Base64.Encode(raw),
		Message:                     codec.Base64.Encode(message),
		RecentBlockhash:             tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                 keys,
		Signers:                     signers,
		NonceAuthority:              nonceAuth,
		SourceTokenAccount:          sourceTokenAccount.Base58(),
		Mint:                        mint.Base58(),
		DestinationTokenAccount:     destinationTokenAccount.Base58(),
		SourceTokenAccountAuthority: sourceTokenAccountAuthority.Base58(),
		Program:                     tokenProgram.Base58(),
		Amount:                      strconv.FormatUint(amount, 10),
		Fee:                         newSystemPayer(feePayer, fee),
	}
}

// TransferMaxRequest sweeps a token account's entire balance to another
// token account, the original opcode.
//
// Same as TransferRequest, except the amount moved is
// source_token_account's current balance rather than a caller-given one,
// mirroring transfer-checked/max. Unlike a lamport sweep,
// source_token_account carries no rent-exemption floor tied to its token
// balance, so it is always swept all the way to zero.
type TransferMaxRequest struct {
	SourceTokenAccount          string `json:"source_token_account" example:""`
	DestinationTokenAccount     string `json:"destination_token_account" example:""`
	SourceTokenAccountAuthority string `json:"source_token_account_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	FeePayer                    string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program                     string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	MultisigSigners []string `json:"multisig_signers"`

	RecentBlockhash     string `json:"recent_blockhash" example:""`
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	sourceTokenAccount          *types.PublicKey
	destinationTokenAccount     *types.PublicKey
	sourceTokenAccountAuthority *types.PublicKey
	feePayer                    *types.PublicKey
	rbh                         *types.Hash
	dna                         *types.PublicKey
	tokenProgramID              *types.PublicKey
	multisigSigners             []*types.PublicKey
}

func (r *TransferMaxRequest) ValidateRequest() error {
	var err error
	if r.sourceTokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.SourceTokenAccount)); err != nil {
		return errors.New("source_token_account: " + err.Error())
	}
	if r.destinationTokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.DestinationTokenAccount)); err != nil {
		return errors.New("destination_token_account: " + err.Error())
	}
	if r.sourceTokenAccount.Equal(r.destinationTokenAccount) {
		return errors.New("source_token_account and destination_token_account are the same account")
	}
	if r.sourceTokenAccountAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.SourceTokenAccountAuthority)); err != nil {
		return errors.New("source_token_account_authority: " + err.Error())
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

func (r *TransferMaxRequest) SourceTokenAccountKey() *types.PublicKey { return r.sourceTokenAccount }
func (r *TransferMaxRequest) DestinationTokenAccountKey() *types.PublicKey {
	return r.destinationTokenAccount
}
func (r *TransferMaxRequest) SourceTokenAccountAuthorityKey() *types.PublicKey {
	return r.sourceTokenAccountAuthority
}
func (r *TransferMaxRequest) FeePayerKey() *types.PublicKey            { return r.feePayer }
func (r *TransferMaxRequest) Blockhash() *types.Hash                   { return r.rbh }
func (r *TransferMaxRequest) DurableNonceAccountKey() *types.PublicKey { return r.dna }
func (r *TransferMaxRequest) TokenProgramID() *types.PublicKey         { return r.tokenProgramID }
func (r *TransferMaxRequest) ToMultisigSigners() []*types.PublicKey    { return r.multisigSigners }

// TransferMaxResponse mirrors TransferResponse, plus what this endpoint had
// to resolve to validate: source_token_account's actual balance at build
// time, which is what Amount reports here since there is no caller-given
// amount to echo back.
type TransferMaxResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	SourceTokenAccount          string      `json:"source_token_account"`
	Mint                        string      `json:"mint"`
	DestinationTokenAccount     string      `json:"destination_token_account"`
	SourceTokenAccountAuthority string      `json:"source_token_account_authority"`
	Program                     string      `json:"program"`
	Amount                      string      `json:"amount"`
	Fee                         SystemPayer `json:"fee"`
}

func NewTransferMaxResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, sourceTokenAccount, mint, destinationTokenAccount, sourceTokenAccountAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	amount, fee uint64,
) *TransferMaxResponse {
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

	return &TransferMaxResponse{
		Transaction:                 codec.Base64.Encode(raw),
		Message:                     codec.Base64.Encode(message),
		RecentBlockhash:             tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                 keys,
		Signers:                     signers,
		NonceAuthority:              nonceAuth,
		SourceTokenAccount:          sourceTokenAccount.Base58(),
		Mint:                        mint.Base58(),
		DestinationTokenAccount:     destinationTokenAccount.Base58(),
		SourceTokenAccountAuthority: sourceTokenAccountAuthority.Base58(),
		Program:                     tokenProgram.Base58(),
		Amount:                      strconv.FormatUint(amount, 10),
		Fee:                         newSystemPayer(feePayer, fee),
	}
}

// ApproveRequest grants a delegate spending rights over a token account, the
// original opcode.
//
// Unlike ApproveCheckedRequest, there is no mint field and no decimals:
// neither is named or verified against the account. Mint is still resolved
// server-side, from token_account's own stored value, so the response can
// report it.
type ApproveRequest struct {
	// TokenAccount is debited if the delegation is ever spent. It must
	// already exist.
	TokenAccount string `json:"token_account" example:""`

	// Delegate is who may spend up to Amount from TokenAccount going
	// forward, replacing any prior delegation entirely rather than adding to
	// it.
	Delegate string `json:"delegate" example:""`

	// TokenAccountOwner must be TokenAccount's owner, never an existing
	// delegate: re-delegating would let a delegate hand its own spending
	// rights to a third party the owner never chose.
	TokenAccountOwner string `json:"token_account_owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Amount is the raw base-unit count Delegate may spend, not a UI decimal
	// string.
	Amount string `json:"amount" example:"500000"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022.
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

	tokenAccount      *types.PublicKey
	delegate          *types.PublicKey
	tokenAccountOwner *types.PublicKey
	feePayer          *types.PublicKey
	rbh               *types.Hash
	dna               *types.PublicKey
	tokenProgramID    *types.PublicKey
	multisigSigners   []*types.PublicKey
	amount            uint64
}

func (r *ApproveRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
	}
	if r.delegate, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Delegate)); err != nil {
		return errors.New("delegate: " + err.Error())
	}
	if r.tokenAccount.Equal(r.delegate) {
		return errors.New("token_account and delegate are the same account")
	}
	if r.tokenAccountOwner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccountOwner)); err != nil {
		return errors.New("token_account_owner: " + err.Error())
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

func (r *ApproveRequest) TokenAccountKey() *types.PublicKey      { return r.tokenAccount }
func (r *ApproveRequest) DelegateKey() *types.PublicKey          { return r.delegate }
func (r *ApproveRequest) TokenAccountOwnerKey() *types.PublicKey { return r.tokenAccountOwner }
func (r *ApproveRequest) FeePayerKey() *types.PublicKey          { return r.feePayer }
func (r *ApproveRequest) Blockhash() *types.Hash                 { return r.rbh }
func (r *ApproveRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ApproveRequest) TokenProgramID() *types.PublicKey      { return r.tokenProgramID }
func (r *ApproveRequest) ToMultisigSigners() []*types.PublicKey { return r.multisigSigners }
func (r *ApproveRequest) ToAmount() uint64                      { return r.amount }

// ApproveResponse mirrors ApproveCheckedResponse, minus decimals. Mint is
// still reported, resolved server-side from token_account.
type ApproveResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	TokenAccount      string      `json:"token_account"`
	Mint              string      `json:"mint"`
	Delegate          string      `json:"delegate"`
	TokenAccountOwner string      `json:"token_account_owner"`
	Program           string      `json:"program"`
	Amount            string      `json:"amount"`
	Fee               SystemPayer `json:"fee"`
}

func NewApproveResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, mint, delegate, tokenAccountOwner, tokenProgram, nonceAuthority *types.PublicKey,
	amount, fee uint64,
) *ApproveResponse {
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

	return &ApproveResponse{
		Transaction:       codec.Base64.Encode(raw),
		Message:           codec.Base64.Encode(message),
		RecentBlockhash:   tx.Message.RecentBlockhash.Base58(),
		AccountKeys:       keys,
		Signers:           signers,
		NonceAuthority:    nonceAuth,
		TokenAccount:      tokenAccount.Base58(),
		Mint:              mint.Base58(),
		Delegate:          delegate.Base58(),
		TokenAccountOwner: tokenAccountOwner.Base58(),
		Program:           tokenProgram.Base58(),
		Amount:            strconv.FormatUint(amount, 10),
		Fee:               newSystemPayer(feePayer, fee),
	}
}

// ApproveMaxRequest grants a delegate the maximum representable amount, the
// original opcode.
//
// Same as ApproveRequest, except no amount is read at all: it grants
// math.MaxUint64 directly, mirroring approve-checked/max and the standard
// effectively-unlimited approval pattern. There is no mint field either,
// since neither the base nor the max variant needs one on chain; it is
// still resolved server-side from token_account for the response.
type ApproveMaxRequest struct {
	TokenAccount      string `json:"token_account" example:""`
	Delegate          string `json:"delegate" example:""`
	TokenAccountOwner string `json:"token_account_owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	FeePayer          string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program           string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	MultisigSigners []string `json:"multisig_signers"`

	RecentBlockhash     string `json:"recent_blockhash" example:""`
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	tokenAccount      *types.PublicKey
	delegate          *types.PublicKey
	tokenAccountOwner *types.PublicKey
	feePayer          *types.PublicKey
	rbh               *types.Hash
	dna               *types.PublicKey
	tokenProgramID    *types.PublicKey
	multisigSigners   []*types.PublicKey
}

func (r *ApproveMaxRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
	}
	if r.delegate, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Delegate)); err != nil {
		return errors.New("delegate: " + err.Error())
	}
	if r.tokenAccount.Equal(r.delegate) {
		return errors.New("token_account and delegate are the same account")
	}
	if r.tokenAccountOwner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccountOwner)); err != nil {
		return errors.New("token_account_owner: " + err.Error())
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

func (r *ApproveMaxRequest) TokenAccountKey() *types.PublicKey      { return r.tokenAccount }
func (r *ApproveMaxRequest) DelegateKey() *types.PublicKey          { return r.delegate }
func (r *ApproveMaxRequest) TokenAccountOwnerKey() *types.PublicKey { return r.tokenAccountOwner }
func (r *ApproveMaxRequest) FeePayerKey() *types.PublicKey          { return r.feePayer }
func (r *ApproveMaxRequest) Blockhash() *types.Hash                 { return r.rbh }
func (r *ApproveMaxRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ApproveMaxRequest) TokenProgramID() *types.PublicKey      { return r.tokenProgramID }
func (r *ApproveMaxRequest) ToMultisigSigners() []*types.PublicKey { return r.multisigSigners }

// ApproveMaxResponse mirrors ApproveResponse, reporting MaxAmount so a
// caller does not have to hardcode the maximum representable base-unit
// amount themselves to know what was actually granted.
type ApproveMaxResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	TokenAccount      string      `json:"token_account"`
	Mint              string      `json:"mint"`
	Delegate          string      `json:"delegate"`
	TokenAccountOwner string      `json:"token_account_owner"`
	Program           string      `json:"program"`
	MaxAmount         string      `json:"max_amount"`
	Fee               SystemPayer `json:"fee"`
}

func NewApproveMaxResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, mint, delegate, tokenAccountOwner, tokenProgram, nonceAuthority *types.PublicKey,
	maxAmount, fee uint64,
) *ApproveMaxResponse {
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

	return &ApproveMaxResponse{
		Transaction:       codec.Base64.Encode(raw),
		Message:           codec.Base64.Encode(message),
		RecentBlockhash:   tx.Message.RecentBlockhash.Base58(),
		AccountKeys:       keys,
		Signers:           signers,
		NonceAuthority:    nonceAuth,
		TokenAccount:      tokenAccount.Base58(),
		Mint:              mint.Base58(),
		Delegate:          delegate.Base58(),
		TokenAccountOwner: tokenAccountOwner.Base58(),
		Program:           tokenProgram.Base58(),
		MaxAmount:         strconv.FormatUint(maxAmount, 10),
		Fee:               newSystemPayer(feePayer, fee),
	}
}

// MintToRequest creates new supply into an existing token account, the
// original opcode.
//
// Unlike MintToCheckedRequest, there is no decimals field: it is neither
// named nor verified against the mint.
type MintToRequest struct {
	// Mint is the token whose supply grows. It must already exist, and its
	// own MintAuthority is what this request has to name to be honored.
	Mint string `json:"mint" example:""`

	// TokenAccount is credited with the newly minted supply. It must already
	// exist and hold Mint.
	TokenAccount string `json:"token_account" example:""`

	// MintAuthority is Mint's mint authority, not TokenAccount's owner or
	// delegate.
	MintAuthority string `json:"mint_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Amount is the raw base-unit count to mint, not a UI decimal string.
	Amount string `json:"amount" example:"1000000"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022.
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

func (r *MintToRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
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

func (r *MintToRequest) MintKey() *types.PublicKey          { return r.mint }
func (r *MintToRequest) TokenAccountKey() *types.PublicKey  { return r.tokenAccount }
func (r *MintToRequest) MintAuthorityKey() *types.PublicKey { return r.mintAuthority }
func (r *MintToRequest) FeePayerKey() *types.PublicKey      { return r.feePayer }
func (r *MintToRequest) Blockhash() *types.Hash             { return r.rbh }
func (r *MintToRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *MintToRequest) TokenProgramID() *types.PublicKey      { return r.tokenProgramID }
func (r *MintToRequest) ToAmount() uint64                      { return r.amount }
func (r *MintToRequest) ToMultisigSigners() []*types.PublicKey { return r.multisigSigners }

// MintToResponse mirrors MintToCheckedResponse, minus decimals.
type MintToResponse struct {
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
	Fee           SystemPayer `json:"fee"`
}

func NewMintToResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, tokenAccount, mintAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	amount, fee uint64,
) *MintToResponse {
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

	return &MintToResponse{
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
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// BurnRequest destroys supply held by a token account, the original opcode.
//
// Unlike BurnCheckedRequest, there is no decimals field: it is neither named
// nor verified against the mint.
type BurnRequest struct {
	// TokenAccount is debited and never credited elsewhere: burning destroys
	// supply rather than moving it. It must already exist and hold Mint.
	TokenAccount string `json:"token_account" example:""`

	// Mint is what TokenAccount must hold.
	Mint string `json:"mint" example:""`

	// TokenAccountAuthority is TokenAccount's owner, or its delegate for no
	// more than what was delegated.
	TokenAccountAuthority string `json:"token_account_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Amount is the raw base-unit count to destroy, not a UI decimal string.
	Amount string `json:"amount" example:"1000"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022.
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

	tokenAccount          *types.PublicKey
	mint                  *types.PublicKey
	tokenAccountAuthority *types.PublicKey
	feePayer              *types.PublicKey
	rbh                   *types.Hash
	dna                   *types.PublicKey
	tokenProgramID        *types.PublicKey
	multisigSigners       []*types.PublicKey
	amount                uint64
}

func (r *BurnRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.tokenAccountAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccountAuthority)); err != nil {
		return errors.New("token_account_authority: " + err.Error())
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

func (r *BurnRequest) TokenAccountKey() *types.PublicKey { return r.tokenAccount }
func (r *BurnRequest) MintKey() *types.PublicKey         { return r.mint }
func (r *BurnRequest) TokenAccountAuthorityKey() *types.PublicKey {
	return r.tokenAccountAuthority
}
func (r *BurnRequest) FeePayerKey() *types.PublicKey            { return r.feePayer }
func (r *BurnRequest) Blockhash() *types.Hash                   { return r.rbh }
func (r *BurnRequest) DurableNonceAccountKey() *types.PublicKey { return r.dna }
func (r *BurnRequest) TokenProgramID() *types.PublicKey         { return r.tokenProgramID }
func (r *BurnRequest) ToAmount() uint64                         { return r.amount }
func (r *BurnRequest) ToMultisigSigners() []*types.PublicKey    { return r.multisigSigners }

// BurnResponse mirrors BurnCheckedResponse, minus decimals.
type BurnResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	TokenAccount          string      `json:"token_account"`
	Mint                  string      `json:"mint"`
	TokenAccountAuthority string      `json:"token_account_authority"`
	Program               string      `json:"program"`
	Amount                string      `json:"amount"`
	Fee                   SystemPayer `json:"fee"`
}

func NewBurnResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, mint, tokenAccountAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	amount, fee uint64,
) *BurnResponse {
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

	return &BurnResponse{
		Transaction:           codec.Base64.Encode(raw),
		Message:               codec.Base64.Encode(message),
		RecentBlockhash:       tx.Message.RecentBlockhash.Base58(),
		AccountKeys:           keys,
		Signers:               signers,
		NonceAuthority:        nonceAuth,
		TokenAccount:          tokenAccount.Base58(),
		Mint:                  mint.Base58(),
		TokenAccountAuthority: tokenAccountAuthority.Base58(),
		Program:               tokenProgram.Base58(),
		Amount:                strconv.FormatUint(amount, 10),
		Fee:                   newSystemPayer(feePayer, fee),
	}
}

// BurnMaxRequest destroys a token account's entire balance, the original
// opcode.
//
// Same as BurnRequest, except the amount destroyed is token_account's
// current balance rather than a caller-given one, mirroring
// burn-checked/max. Unlike a lamport sweep, token_account carries no
// rent-exemption floor tied to its token balance, so it is always swept all
// the way to zero.
type BurnMaxRequest struct {
	TokenAccount          string `json:"token_account" example:""`
	Mint                  string `json:"mint" example:""`
	TokenAccountAuthority string `json:"token_account_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	FeePayer              string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program               string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	MultisigSigners []string `json:"multisig_signers"`

	RecentBlockhash     string `json:"recent_blockhash" example:""`
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	tokenAccount          *types.PublicKey
	mint                  *types.PublicKey
	tokenAccountAuthority *types.PublicKey
	feePayer              *types.PublicKey
	rbh                   *types.Hash
	dna                   *types.PublicKey
	tokenProgramID        *types.PublicKey
	multisigSigners       []*types.PublicKey
}

func (r *BurnMaxRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.tokenAccountAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccountAuthority)); err != nil {
		return errors.New("token_account_authority: " + err.Error())
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

func (r *BurnMaxRequest) TokenAccountKey() *types.PublicKey { return r.tokenAccount }
func (r *BurnMaxRequest) MintKey() *types.PublicKey         { return r.mint }
func (r *BurnMaxRequest) TokenAccountAuthorityKey() *types.PublicKey {
	return r.tokenAccountAuthority
}
func (r *BurnMaxRequest) FeePayerKey() *types.PublicKey            { return r.feePayer }
func (r *BurnMaxRequest) Blockhash() *types.Hash                   { return r.rbh }
func (r *BurnMaxRequest) DurableNonceAccountKey() *types.PublicKey { return r.dna }
func (r *BurnMaxRequest) TokenProgramID() *types.PublicKey         { return r.tokenProgramID }
func (r *BurnMaxRequest) ToMultisigSigners() []*types.PublicKey    { return r.multisigSigners }

// BurnMaxResponse mirrors BurnResponse, plus what this endpoint had to
// resolve to validate: token_account's actual balance at build time, which
// is what Amount reports here since there is no caller-given amount to echo
// back.
type BurnMaxResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	TokenAccount          string      `json:"token_account"`
	Mint                  string      `json:"mint"`
	TokenAccountAuthority string      `json:"token_account_authority"`
	Program               string      `json:"program"`
	Amount                string      `json:"amount"`
	Fee                   SystemPayer `json:"fee"`
}

func NewBurnMaxResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, mint, tokenAccountAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	amount, fee uint64,
) *BurnMaxResponse {
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

	return &BurnMaxResponse{
		Transaction:           codec.Base64.Encode(raw),
		Message:               codec.Base64.Encode(message),
		RecentBlockhash:       tx.Message.RecentBlockhash.Base58(),
		AccountKeys:           keys,
		Signers:               signers,
		NonceAuthority:        nonceAuth,
		TokenAccount:          tokenAccount.Base58(),
		Mint:                  mint.Base58(),
		TokenAccountAuthority: tokenAccountAuthority.Base58(),
		Program:               tokenProgram.Base58(),
		Amount:                strconv.FormatUint(amount, 10),
		Fee:                   newSystemPayer(feePayer, fee),
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
	// SourceTokenAccount is debited. It must already exist, hold Mint, and
	// not be frozen.
	SourceTokenAccount string `json:"source_token_account" example:""`

	// Mint is what both token accounts must hold, and is the source of the
	// decimals checked against.
	Mint string `json:"mint" example:""`

	// DestinationTokenAccount is credited. It must already exist, hold Mint,
	// and not be frozen: a transfer moves between *token accounts*, never to
	// a wallet address directly, and a caller with only a wallet address
	// needs the recipient's associated token account created first.
	DestinationTokenAccount string `json:"destination_token_account" example:""`

	// SourceTokenAccountAuthority is SourceTokenAccount's owner, or its
	// delegate for no more than what was delegated. A transfer spends a
	// balance, so it is the holder's to authorize, not the mint's — unlike
	// minting, which checks the mint's own authority instead.
	SourceTokenAccountAuthority string `json:"source_token_account_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Amount is the raw base-unit count to move, not a UI decimal string.
	Amount string `json:"amount" example:"250000"`

	// Decimals is checked against Mint's own stored value rather than
	// trusted, which is the whole point of the checked variant: catching a
	// client that formatted Amount against the wrong decimals as a 400
	// instead of an on-chain failure.
	Decimals uint8 `json:"decimals" example:"6"`

	// FeePayer signs and pays the transaction fee. A transfer moves no
	// lamports of its own, so this is the only balance this endpoint ever
	// checks.
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

	sourceTokenAccount          *types.PublicKey
	mint                        *types.PublicKey
	destinationTokenAccount     *types.PublicKey
	sourceTokenAccountAuthority *types.PublicKey
	feePayer                    *types.PublicKey
	rbh                         *types.Hash
	dna                         *types.PublicKey
	tokenProgramID              *types.PublicKey
	multisigSigners             []*types.PublicKey
	amount                      uint64
}

func (r *TransferCheckedRequest) ValidateRequest() error {
	var err error
	if r.sourceTokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.SourceTokenAccount)); err != nil {
		return errors.New("source_token_account: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.destinationTokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.DestinationTokenAccount)); err != nil {
		return errors.New("destination_token_account: " + err.Error())
	}
	if r.sourceTokenAccount.Equal(r.destinationTokenAccount) {
		return errors.New("source_token_account and destination_token_account are the same account")
	}
	if r.sourceTokenAccountAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.SourceTokenAccountAuthority)); err != nil {
		return errors.New("source_token_account_authority: " + err.Error())
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

func (r *TransferCheckedRequest) SourceTokenAccountKey() *types.PublicKey {
	return r.sourceTokenAccount
}

func (r *TransferCheckedRequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *TransferCheckedRequest) DestinationTokenAccountKey() *types.PublicKey {
	return r.destinationTokenAccount
}

func (r *TransferCheckedRequest) SourceTokenAccountAuthorityKey() *types.PublicKey {
	return r.sourceTokenAccountAuthority
}

func (r *TransferCheckedRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *TransferCheckedRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *TransferCheckedRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
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

	SourceTokenAccount          string      `json:"source_token_account"`
	Mint                        string      `json:"mint"`
	DestinationTokenAccount     string      `json:"destination_token_account"`
	SourceTokenAccountAuthority string      `json:"source_token_account_authority"`
	Program                     string      `json:"program"`
	Amount                      string      `json:"amount"`
	Decimals                    uint8       `json:"decimals"`
	Fee                         SystemPayer `json:"fee"`
}

func NewTransferCheckedResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, sourceTokenAccount, mint, destinationTokenAccount, sourceTokenAccountAuthority, tokenProgram, nonceAuthority *types.PublicKey,
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
		Transaction:                 codec.Base64.Encode(raw),
		Message:                     codec.Base64.Encode(message),
		RecentBlockhash:             tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                 keys,
		Signers:                     signers,
		NonceAuthority:              nonceAuth,
		SourceTokenAccount:          sourceTokenAccount.Base58(),
		Mint:                        mint.Base58(),
		DestinationTokenAccount:     destinationTokenAccount.Base58(),
		SourceTokenAccountAuthority: sourceTokenAccountAuthority.Base58(),
		Program:                     tokenProgram.Base58(),
		Amount:                      strconv.FormatUint(amount, 10),
		Decimals:                    decimals,
		Fee:                         newSystemPayer(feePayer, fee),
	}
}

// TransferCheckedMaxRequest is transfer-checked's own type, for the same
// reason create-account's and create-account-idempotent's are separate: it
// sweeps SourceTokenAccount's entire current balance rather than taking one,
// so there is no Amount field to share.
//
// Unlike a lamport sweep, there is no rent-exemption floor a token balance
// has to clear: a token account can hold zero tokens and still exist, so
// SourceTokenAccount can always be swept all the way to zero regardless of
// whether it also happens to be FeePayer — that overlap is a lamport
// concern, and this moves none of its own.
type TransferCheckedMaxRequest struct {
	// SourceTokenAccount is swept to zero. It must already exist, hold Mint,
	// and not be frozen.
	SourceTokenAccount string `json:"source_token_account" example:""`

	// Mint is what both token accounts must hold, and is the source of the
	// decimals checked against.
	Mint string `json:"mint" example:""`

	// DestinationTokenAccount is credited. It must already exist, hold Mint,
	// and not be frozen: a transfer moves between *token accounts*, never to
	// a wallet address directly.
	DestinationTokenAccount string `json:"destination_token_account" example:""`

	// SourceTokenAccountAuthority is SourceTokenAccount's owner, or its
	// delegate for no more than what was delegated — checked against the
	// balance actually swept, resolved at request time, not a caller-given
	// amount.
	SourceTokenAccountAuthority string `json:"source_token_account_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee. A transfer moves no
	// lamports of its own, so this is the only balance this endpoint ever
	// checks.
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

	sourceTokenAccount          *types.PublicKey
	mint                        *types.PublicKey
	destinationTokenAccount     *types.PublicKey
	sourceTokenAccountAuthority *types.PublicKey
	feePayer                    *types.PublicKey
	rbh                         *types.Hash
	dna                         *types.PublicKey
	tokenProgramID              *types.PublicKey
	multisigSigners             []*types.PublicKey
}

func (r *TransferCheckedMaxRequest) ValidateRequest() error {
	var err error
	if r.sourceTokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.SourceTokenAccount)); err != nil {
		return errors.New("source_token_account: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.destinationTokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.DestinationTokenAccount)); err != nil {
		return errors.New("destination_token_account: " + err.Error())
	}
	if r.sourceTokenAccount.Equal(r.destinationTokenAccount) {
		return errors.New("source_token_account and destination_token_account are the same account")
	}
	if r.sourceTokenAccountAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.SourceTokenAccountAuthority)); err != nil {
		return errors.New("source_token_account_authority: " + err.Error())
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

func (r *TransferCheckedMaxRequest) SourceTokenAccountKey() *types.PublicKey {
	return r.sourceTokenAccount
}

func (r *TransferCheckedMaxRequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *TransferCheckedMaxRequest) DestinationTokenAccountKey() *types.PublicKey {
	return r.destinationTokenAccount
}

func (r *TransferCheckedMaxRequest) SourceTokenAccountAuthorityKey() *types.PublicKey {
	return r.sourceTokenAccountAuthority
}

func (r *TransferCheckedMaxRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *TransferCheckedMaxRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *TransferCheckedMaxRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *TransferCheckedMaxRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

func (r *TransferCheckedMaxRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// TransferCheckedMaxResponse mirrors TransferCheckedResponse's shape, plus
// what this endpoint had to resolve to validate: SourceTokenAccount's actual
// balance at build time, which is what Amount reports here since there is no
// caller-given amount to echo back.
type TransferCheckedMaxResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	SourceTokenAccount          string      `json:"source_token_account"`
	Mint                        string      `json:"mint"`
	DestinationTokenAccount     string      `json:"destination_token_account"`
	SourceTokenAccountAuthority string      `json:"source_token_account_authority"`
	Program                     string      `json:"program"`
	Amount                      string      `json:"amount"`
	Decimals                    uint8       `json:"decimals"`
	Fee                         SystemPayer `json:"fee"`
}

func NewTransferCheckedMaxResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, sourceTokenAccount, mint, destinationTokenAccount, sourceTokenAccountAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	amount uint64, decimals uint8, fee uint64,
) *TransferCheckedMaxResponse {
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

	return &TransferCheckedMaxResponse{
		Transaction:                 codec.Base64.Encode(raw),
		Message:                     codec.Base64.Encode(message),
		RecentBlockhash:             tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                 keys,
		Signers:                     signers,
		NonceAuthority:              nonceAuth,
		SourceTokenAccount:          sourceTokenAccount.Base58(),
		Mint:                        mint.Base58(),
		DestinationTokenAccount:     destinationTokenAccount.Base58(),
		SourceTokenAccountAuthority: sourceTokenAccountAuthority.Base58(),
		Program:                     tokenProgram.Base58(),
		Amount:                      strconv.FormatUint(amount, 10),
		Decimals:                    decimals,
		Fee:                         newSystemPayer(feePayer, fee),
	}
}

// BurnCheckedRequest destroys supply held by a token account.
//
// TokenAccountAuthority is the account's owner or delegate, not the mint's
// authority: burning spends a balance, so it is the holder's to authorize.
type BurnCheckedRequest struct {
	// TokenAccount is debited and never credited elsewhere: burning destroys
	// supply rather than moving it. It must already exist and hold Mint.
	TokenAccount string `json:"token_account" example:""`

	// Mint is what TokenAccount must hold, and is the source of the decimals
	// checked against.
	Mint string `json:"mint" example:""`

	// TokenAccountAuthority is TokenAccount's owner, or its delegate for no
	// more than what was delegated. Burning spends a balance, so it is the
	// holder's to authorize, not the mint's — unlike minting, which checks
	// the mint's own authority instead.
	TokenAccountAuthority string `json:"token_account_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Amount is the raw base-unit count to destroy, not a UI decimal string.
	Amount string `json:"amount" example:"1000"`

	// Decimals is checked against Mint's own stored value rather than
	// trusted, which is the whole point of the checked variant: catching a
	// client that formatted Amount against the wrong decimals as a 400
	// instead of an on-chain failure.
	Decimals uint8 `json:"decimals" example:"6"`

	// FeePayer signs and pays the transaction fee. Burning moves no lamports
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

	tokenAccount          *types.PublicKey
	mint                  *types.PublicKey
	tokenAccountAuthority *types.PublicKey
	feePayer              *types.PublicKey
	rbh                   *types.Hash
	dna                   *types.PublicKey
	tokenProgramID        *types.PublicKey
	multisigSigners       []*types.PublicKey
	amount                uint64
}

func (r *BurnCheckedRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.tokenAccountAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccountAuthority)); err != nil {
		return errors.New("token_account_authority: " + err.Error())
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

func (r *BurnCheckedRequest) TokenAccountKey() *types.PublicKey {
	return r.tokenAccount
}

func (r *BurnCheckedRequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *BurnCheckedRequest) TokenAccountAuthorityKey() *types.PublicKey {
	return r.tokenAccountAuthority
}

func (r *BurnCheckedRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *BurnCheckedRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *BurnCheckedRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
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

	TokenAccount          string      `json:"token_account"`
	Mint                  string      `json:"mint"`
	TokenAccountAuthority string      `json:"token_account_authority"`
	Program               string      `json:"program"`
	Amount                string      `json:"amount"`
	Decimals              uint8       `json:"decimals"`
	Fee                   SystemPayer `json:"fee"`
}

func NewBurnCheckedResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, mint, tokenAccountAuthority, tokenProgram, nonceAuthority *types.PublicKey,
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
		Transaction:           codec.Base64.Encode(raw),
		Message:               codec.Base64.Encode(message),
		RecentBlockhash:       tx.Message.RecentBlockhash.Base58(),
		AccountKeys:           keys,
		Signers:               signers,
		NonceAuthority:        nonceAuth,
		TokenAccount:          tokenAccount.Base58(),
		Mint:                  mint.Base58(),
		TokenAccountAuthority: tokenAccountAuthority.Base58(),
		Program:               tokenProgram.Base58(),
		Amount:                strconv.FormatUint(amount, 10),
		Decimals:              decimals,
		Fee:                   newSystemPayer(feePayer, fee),
	}
}

// BurnCheckedMaxRequest destroys a token account's entire balance.
//
// Same as BurnCheckedRequest, except the amount destroyed is
// TokenAccount's current balance rather than a caller-given one, mirroring
// TransferCheckedMaxRequest. Unlike a lamport sweep, TokenAccount carries no
// rent-exemption floor of its own tied to its token balance, so it is always
// swept all the way to zero.
type BurnCheckedMaxRequest struct {
	// TokenAccount is debited and never credited elsewhere: burning destroys
	// supply rather than moving it. It must already exist and hold Mint.
	TokenAccount string `json:"token_account" example:""`

	// Mint is what TokenAccount must hold, and is the source of the decimals
	// checked against.
	Mint string `json:"mint" example:""`

	// TokenAccountAuthority is TokenAccount's owner, or its delegate for no
	// more than what was delegated — checked against the balance actually
	// swept, resolved at request time, not a caller-given amount.
	TokenAccountAuthority string `json:"token_account_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee. Burning moves no lamports
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

	tokenAccount          *types.PublicKey
	mint                  *types.PublicKey
	tokenAccountAuthority *types.PublicKey
	feePayer              *types.PublicKey
	rbh                   *types.Hash
	dna                   *types.PublicKey
	tokenProgramID        *types.PublicKey
	multisigSigners       []*types.PublicKey
}

func (r *BurnCheckedMaxRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.tokenAccountAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccountAuthority)); err != nil {
		return errors.New("token_account_authority: " + err.Error())
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

func (r *BurnCheckedMaxRequest) TokenAccountKey() *types.PublicKey {
	return r.tokenAccount
}

func (r *BurnCheckedMaxRequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *BurnCheckedMaxRequest) TokenAccountAuthorityKey() *types.PublicKey {
	return r.tokenAccountAuthority
}

func (r *BurnCheckedMaxRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *BurnCheckedMaxRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *BurnCheckedMaxRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *BurnCheckedMaxRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

func (r *BurnCheckedMaxRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// BurnCheckedMaxResponse mirrors BurnCheckedResponse's shape, plus what this
// endpoint had to resolve to validate: TokenAccount's actual balance at build
// time, which is what Amount reports here since there is no caller-given
// amount to echo back.
type BurnCheckedMaxResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	TokenAccount          string      `json:"token_account"`
	Mint                  string      `json:"mint"`
	TokenAccountAuthority string      `json:"token_account_authority"`
	Program               string      `json:"program"`
	Amount                string      `json:"amount"`
	Decimals              uint8       `json:"decimals"`
	Fee                   SystemPayer `json:"fee"`
}

func NewBurnCheckedMaxResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, mint, tokenAccountAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	amount uint64, decimals uint8, fee uint64,
) *BurnCheckedMaxResponse {
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

	return &BurnCheckedMaxResponse{
		Transaction:           codec.Base64.Encode(raw),
		Message:               codec.Base64.Encode(message),
		RecentBlockhash:       tx.Message.RecentBlockhash.Base58(),
		AccountKeys:           keys,
		Signers:               signers,
		NonceAuthority:        nonceAuth,
		TokenAccount:          tokenAccount.Base58(),
		Mint:                  mint.Base58(),
		TokenAccountAuthority: tokenAccountAuthority.Base58(),
		Program:               tokenProgram.Base58(),
		Amount:                strconv.FormatUint(amount, 10),
		Decimals:              decimals,
		Fee:                   newSystemPayer(feePayer, fee),
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
	// TokenAccount is closed. It must already hold no tokens (a wrapped SOL
	// account is the one exception, closed to unwrap its lamport balance).
	TokenAccount string `json:"token_account" example:""`

	// RecipientAccount receives TokenAccount's entire reclaimed lamport
	// balance. It must already exist; this is not a way to bring a new
	// account into existence.
	RecipientAccount string `json:"recipient_account" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// TokenAccountCloseAuthority is checked against
	// close_authority.unwrap_or(owner): once a close authority is set on
	// TokenAccount, it alone may close it, and the owner who set it can no
	// longer do so directly.
	TokenAccountCloseAuthority string `json:"token_account_close_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
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

	tokenAccount               *types.PublicKey
	recipientAccount           *types.PublicKey
	tokenAccountCloseAuthority *types.PublicKey
	feePayer                   *types.PublicKey
	rbh                        *types.Hash
	dna                        *types.PublicKey
	tokenProgramID             *types.PublicKey
	multisigSigners            []*types.PublicKey
}

func (r *CloseAccountRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
	}
	if r.recipientAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RecipientAccount)); err != nil {
		return errors.New("recipient_account: " + err.Error())
	}
	if r.tokenAccount.Equal(r.recipientAccount) {
		return errors.New("token_account and recipient_account are the same account")
	}
	if r.tokenAccountCloseAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccountCloseAuthority)); err != nil {
		return errors.New("token_account_close_authority: " + err.Error())
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

func (r *CloseAccountRequest) TokenAccountKey() *types.PublicKey {
	return r.tokenAccount
}

func (r *CloseAccountRequest) RecipientAccountKey() *types.PublicKey {
	return r.recipientAccount
}

func (r *CloseAccountRequest) TokenAccountCloseAuthorityKey() *types.PublicKey {
	return r.tokenAccountCloseAuthority
}

func (r *CloseAccountRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *CloseAccountRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *CloseAccountRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
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

	TokenAccount               string `json:"token_account"`
	RecipientAccount           string `json:"recipient_account"`
	TokenAccountCloseAuthority string `json:"token_account_close_authority"`
	Program                    string `json:"program"`

	// Reclaimed reports TokenAccount's balance at the moment it was read,
	// which is what closing hands to recipient_account. It can change
	// between this response and the transaction landing if anything else
	// touches the account first.
	Reclaimed SystemPayer `json:"reclaimed"`
	Fee       SystemPayer `json:"fee"`
}

func NewCloseAccountResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, recipientAccount, tokenAccountCloseAuthority, tokenProgram, nonceAuthority *types.PublicKey,
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
		Transaction:                codec.Base64.Encode(raw),
		Message:                    codec.Base64.Encode(message),
		RecentBlockhash:            tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                keys,
		Signers:                    signers,
		NonceAuthority:             nonceAuth,
		TokenAccount:               tokenAccount.Base58(),
		RecipientAccount:           recipientAccount.Base58(),
		TokenAccountCloseAuthority: tokenAccountCloseAuthority.Base58(),
		Program:                    tokenProgram.Base58(),
		Reclaimed:                  newSystemPayer(recipientAccount, reclaimedLamports),
		Fee:                        newSystemPayer(feePayer, fee),
	}
}

// WithdrawExcessLamportsRequest recovers whatever lamports a Token-owned
// account holds beyond its own rent-exempt minimum.
//
// Unlike close-account, Account is never consumed: it stays exactly as it
// was, still rent-exempt and still carrying whatever mint, token, or
// multisig state it held. This is for the ordinary way an account ends up
// overfunded — a plain System transfer landing on it by mistake, since
// System's own Transfer takes any account regardless of who owns it — not
// for anything close-account already covers.
//
// Authority is not resolved client-side. Which role the program actually
// checks depends on what Account is (a mint's close authority extension, a
// token account's close_authority.unwrap_or(owner), or a multisig's own
// enrolled signers), and this endpoint has no Token-2022 extension parser to
// settle that ahead of time, so a wrong Authority fails on chain rather than
// as a 400. Unverified opcode: confirm this instruction exists on the
// deployed program before relying on it.
type WithdrawExcessLamportsRequest struct {
	// Account is read for its excess, never closed or resized. It must
	// already exist and be owned by Program; it may be a mint, a token
	// account, or a multisig.
	Account string `json:"account" example:""`

	// Destination receives the recovered lamports. It must already exist;
	// this is not a way to bring a new account into existence.
	Destination string `json:"destination" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Authority is whichever role Account's actual type requires — see the
	// type doc. It is not verified against Account here.
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022.
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

	account         *types.PublicKey
	destination     *types.PublicKey
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *WithdrawExcessLamportsRequest) ValidateRequest() error {
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

func (r *WithdrawExcessLamportsRequest) AccountKey() *types.PublicKey     { return r.account }
func (r *WithdrawExcessLamportsRequest) DestinationKey() *types.PublicKey { return r.destination }
func (r *WithdrawExcessLamportsRequest) AuthorityKey() *types.PublicKey   { return r.authority }
func (r *WithdrawExcessLamportsRequest) FeePayerKey() *types.PublicKey    { return r.feePayer }
func (r *WithdrawExcessLamportsRequest) Blockhash() *types.Hash           { return r.rbh }
func (r *WithdrawExcessLamportsRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *WithdrawExcessLamportsRequest) TokenProgramID() *types.PublicKey { return r.tokenProgramID }
func (r *WithdrawExcessLamportsRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// WithdrawExcessLamportsResponse reports EstimatedRecovered, computed
// client-side as Account's balance minus the rent-exemption minimum for its
// actual size at read time — an estimate, not the value the program itself
// will use, since that is computed fresh on chain at landing time and this
// account's balance or size could change first.
type WithdrawExcessLamportsResponse struct {
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

	EstimatedRecovered SystemPayer `json:"estimated_recovered"`
	Fee                SystemPayer `json:"fee"`
}

func NewWithdrawExcessLamportsResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, account, destination, authority, tokenProgram, nonceAuthority *types.PublicKey,
	estimatedRecovered, fee uint64,
) *WithdrawExcessLamportsResponse {
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

	return &WithdrawExcessLamportsResponse{
		Transaction:        codec.Base64.Encode(raw),
		Message:            codec.Base64.Encode(message),
		RecentBlockhash:    tx.Message.RecentBlockhash.Base58(),
		AccountKeys:        keys,
		Signers:            signers,
		NonceAuthority:     nonceAuth,
		Account:            account.Base58(),
		Destination:        destination.Base58(),
		Authority:          authority.Base58(),
		Program:            tokenProgram.Base58(),
		EstimatedRecovered: newSystemPayer(destination, estimatedRecovered),
		Fee:                newSystemPayer(feePayer, fee),
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

	// Owner is who ends up owning the account, which need not be RentPayer.
	// Funding somebody else's associated account is ordinary: the address is
	// theirs either way.
	Owner string `json:"owner" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// Mint is the token the associated account is derived and initialized to
	// hold, and must already exist.
	Mint string `json:"mint" example:""`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program is a seed of the derived address, not only the program the
	// account belongs to, so one owner has a different associated account
	// for classic Token than for Token-2022 over the same mint.
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
	wallet         *types.PublicKey
	mint           *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *CreateATARequest) ValidateRequest() error {
	var err error
	if r.rentPayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.wallet, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
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

func (r *CreateATARequest) RentPayerKey() *types.PublicKey {
	return r.rentPayer
}

func (r *CreateATARequest) OwnerKey() *types.PublicKey {
	return r.wallet
}

func (r *CreateATARequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *CreateATARequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *CreateATARequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *CreateATARequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
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

	AssociatedTokenAccount string `json:"associated_token_account"`
	Bump                   uint8  `json:"bump"`
	Owner                  string `json:"owner"`
	Mint                   string `json:"mint"`
	Program                string `json:"program"`

	// Rent reports what funds the associated account's creation. Its
	// lamports are always exactly the rent-exemption minimum for a 165-byte
	// account, never more or less.
	Rent SystemPayer `json:"rent"`
	Fee  SystemPayer `json:"fee"`
}

func NewCreateATAResponse(
	tx *types.Transaction, raw, message []byte,
	rentPayer, feePayer, associatedTokenAccount, owner, mint, tokenProgram, nonceAuthority *types.PublicKey,
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
		Transaction:            codec.Base64.Encode(raw),
		Message:                codec.Base64.Encode(message),
		RecentBlockhash:        tx.Message.RecentBlockhash.Base58(),
		AccountKeys:            keys,
		Signers:                signers,
		NonceAuthority:         nonceAuth,
		AssociatedTokenAccount: associatedTokenAccount.Base58(),
		Bump:                   bump,
		Owner:                  owner.Base58(),
		Mint:                   mint.Base58(),
		Program:                tokenProgram.Base58(),
		Rent:                   newSystemPayer(rentPayer, rentExempt),
		Fee:                    newSystemPayer(feePayer, fee),
	}
}

// CreateATAIdempotentRequest is CreateATARequest's own type, kept separate
// rather than shared, even though every field is identical. The two
// endpoints build different instructions and validate differently in one
// respect — this one tolerates the account already existing — and giving
// each its own request type is what keeps that difference from leaking into
// a shared struct neither endpoint fully owns.
type CreateATAIdempotentRequest struct {
	// RentPayer covers the rent-exemption deposit, distinct from FeePayer:
	// the two are separate balances to check, and a caller funding somebody
	// else's associated account pays this one without necessarily paying the
	// transaction fee.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Owner is who ends up owning the account, which need not be RentPayer.
	// Funding somebody else's associated account is ordinary: the address is
	// theirs either way.
	Owner string `json:"owner" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// Mint is the token the associated account is derived and initialized to
	// hold, and must already exist.
	Mint string `json:"mint" example:""`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as RentPayer.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program is a seed of the derived address, not only the program the
	// account belongs to, so one owner has a different associated account
	// for classic Token than for Token-2022 over the same mint.
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
	wallet         *types.PublicKey
	mint           *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *CreateATAIdempotentRequest) ValidateRequest() error {
	var err error
	if r.rentPayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.wallet, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
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

func (r *CreateATAIdempotentRequest) RentPayerKey() *types.PublicKey {
	return r.rentPayer
}

func (r *CreateATAIdempotentRequest) OwnerKey() *types.PublicKey {
	return r.wallet
}

func (r *CreateATAIdempotentRequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *CreateATAIdempotentRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *CreateATAIdempotentRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *CreateATAIdempotentRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
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

	AssociatedTokenAccount string `json:"associated_token_account"`
	Bump                   uint8  `json:"bump"`
	Owner                  string `json:"owner"`
	Mint                   string `json:"mint"`
	Program                string `json:"program"`

	// Rent reports what funds the associated account's creation. Its
	// lamports are always exactly the rent-exemption minimum for a 165-byte
	// account, never more or less.
	Rent SystemPayer `json:"rent"`
	Fee  SystemPayer `json:"fee"`
}

func NewCreateATAIdempotentResponse(
	tx *types.Transaction, raw, message []byte,
	rentPayer, feePayer, associatedTokenAccount, owner, mint, tokenProgram, nonceAuthority *types.PublicKey,
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
		Transaction:            codec.Base64.Encode(raw),
		Message:                codec.Base64.Encode(message),
		RecentBlockhash:        tx.Message.RecentBlockhash.Base58(),
		AccountKeys:            keys,
		Signers:                signers,
		NonceAuthority:         nonceAuth,
		AssociatedTokenAccount: associatedTokenAccount.Base58(),
		Bump:                   bump,
		Owner:                  owner.Base58(),
		Mint:                   mint.Base58(),
		Program:                tokenProgram.Base58(),
		Rent:                   newSystemPayer(rentPayer, rentExempt),
		Fee:                    newSystemPayer(feePayer, fee),
	}
}

// ATARecoverNestedRequest recovers a nested associated token account: one
// that was mistakenly created by deriving from another associated account as
// if it were a wallet. Wallet, OwnerMint, and NestedMint are exactly
// RecoverNested's three seeds; every address the instruction actually
// touches is derived from them internally, none is a request field.
type ATARecoverNestedRequest struct {
	// Wallet is the real owner, and the only one who signs: closing the
	// nested account pays its reclaimed lamports back to Wallet's own
	// associated account for OwnerMint, so only the real owner may authorize
	// that.
	Wallet string `json:"wallet" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// OwnerMint is the mint of the associated account that was mistakenly
	// used as a wallet — deriving Wallet's associated account for OwnerMint
	// is what produced the address the nested account was wrongly created
	// under.
	OwnerMint string `json:"owner_mint" example:""`

	// NestedMint is the mint of the nested account itself, the one being
	// recovered and closed. It must differ from OwnerMint.
	NestedMint string `json:"nested_mint" example:""`

	// FeePayer signs and pays the transaction fee. It may be the same
	// account as Wallet.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program is a seed of every derived address, so one wallet has
	// different owner, nested, and destination accounts for classic Token
	// than for Token-2022 over the same mints.
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

	wallet         *types.PublicKey
	ownerMint      *types.PublicKey
	nestedMint     *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *ATARecoverNestedRequest) ValidateRequest() error {
	var err error
	if r.wallet, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Wallet)); err != nil {
		return errors.New("wallet: " + err.Error())
	}
	if r.ownerMint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.OwnerMint)); err != nil {
		return errors.New("owner_mint: " + err.Error())
	}
	if r.nestedMint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.NestedMint)); err != nil {
		return errors.New("nested_mint: " + err.Error())
	}
	if r.ownerMint.Equal(r.nestedMint) {
		return errors.New("owner_mint and nested_mint are the same account")
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

func (r *ATARecoverNestedRequest) WalletKey() *types.PublicKey     { return r.wallet }
func (r *ATARecoverNestedRequest) OwnerMintKey() *types.PublicKey  { return r.ownerMint }
func (r *ATARecoverNestedRequest) NestedMintKey() *types.PublicKey { return r.nestedMint }
func (r *ATARecoverNestedRequest) FeePayerKey() *types.PublicKey   { return r.feePayer }
func (r *ATARecoverNestedRequest) Blockhash() *types.Hash          { return r.rbh }
func (r *ATARecoverNestedRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ATARecoverNestedRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// ATARecoverNestedResponse reports the built transaction plus the three
// addresses RecoverNested derived internally, none of which were request
// fields: OwnerAccount is the associated account mistaken for a wallet,
// NestedAccount is the one being closed, and Destination is where its
// balance ends up — Wallet's real associated account for NestedMint.
type ATARecoverNestedResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Wallet        string `json:"wallet"`
	OwnerMint     string `json:"owner_mint"`
	NestedMint    string `json:"nested_mint"`
	Program       string `json:"program"`
	OwnerAccount  string `json:"owner_account"`
	NestedAccount string `json:"nested_account"`
	Destination   string `json:"destination"`

	Fee SystemPayer `json:"fee"`
}

func NewATARecoverNestedResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, wallet, ownerMint, nestedMint, tokenProgram, nonceAuthority *types.PublicKey,
	ownerAccount, nestedAccount, destination *types.PublicKey,
	fee uint64,
) *ATARecoverNestedResponse {
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

	return &ATARecoverNestedResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Wallet:          wallet.Base58(),
		OwnerMint:       ownerMint.Base58(),
		NestedMint:      nestedMint.Base58(),
		Program:         tokenProgram.Base58(),
		OwnerAccount:    ownerAccount.Base58(),
		NestedAccount:   nestedAccount.Base58(),
		Destination:     destination.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// TransferFromATARequest moves a balance from Owner's associated token
// account to an arbitrary token account, deriving only the source address
// rather than taking it directly.
//
// This is transfer-checked's own sibling for exactly one side: Owner is a
// wallet address, and its associated token account is derived from it and
// Mint rather than accepted directly, the same way create-ata's is. It is
// never created here, unlike an ATA-based destination elsewhere in this
// package — an account nobody has funded has nothing to send, so a missing
// source fails rather than being created empty. DestinationTokenAccount, by
// contrast, is an exact token account address the caller already knows,
// keypair or associated, exactly as transfer-checked takes it: this
// endpoint only ever saves the caller deriving one side.
type TransferFromATARequest struct {
	// Owner is the sender's wallet. Its associated token account is derived
	// from Owner and Mint rather than accepted directly, and is never
	// created if absent.
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Mint is what the derived source and DestinationTokenAccount must both
	// hold, and is the source of the decimals checked against.
	Mint string `json:"mint" example:""`

	// DestinationTokenAccount is credited. It must already exist, hold Mint,
	// and not be frozen — an exact address, not a wallet to derive from.
	DestinationTokenAccount string `json:"destination_token_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// SourceTokenAccountAuthority is the derived source account's owner, or
	// its delegate for no more than what was delegated. A transfer spends a
	// balance, so it is the holder's to authorize, not the mint's.
	SourceTokenAccountAuthority string `json:"source_token_account_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Amount is the raw base-unit count to move, not a UI decimal string.
	Amount string `json:"amount" example:"250000"`

	// Decimals is checked against Mint's own stored value rather than
	// trusted, which is the whole point of the checked variant: catching a
	// client that formatted Amount against the wrong decimals as a 400
	// instead of an on-chain failure.
	Decimals uint8 `json:"decimals" example:"6"`

	// FeePayer signs and pays the transaction fee. A transfer moves no
	// lamports of its own, so this is the only balance this endpoint ever
	// checks.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program is a seed of the derived source address, not only the program
	// both token accounts belong to, so one owner has a different
	// associated account for classic Token than for Token-2022 over the
	// same mint.
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

	owner                       *types.PublicKey
	mint                        *types.PublicKey
	destinationTokenAccount     *types.PublicKey
	sourceTokenAccountAuthority *types.PublicKey
	feePayer                    *types.PublicKey
	rbh                         *types.Hash
	dna                         *types.PublicKey
	tokenProgramID              *types.PublicKey
	multisigSigners             []*types.PublicKey
	amount                      uint64
}

func (r *TransferFromATARequest) ValidateRequest() error {
	var err error
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.destinationTokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.DestinationTokenAccount)); err != nil {
		return errors.New("destination_token_account: " + err.Error())
	}
	if r.sourceTokenAccountAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.SourceTokenAccountAuthority)); err != nil {
		return errors.New("source_token_account_authority: " + err.Error())
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

func (r *TransferFromATARequest) OwnerKey() *types.PublicKey {
	return r.owner
}

func (r *TransferFromATARequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *TransferFromATARequest) DestinationTokenAccountKey() *types.PublicKey {
	return r.destinationTokenAccount
}

func (r *TransferFromATARequest) SourceTokenAccountAuthorityKey() *types.PublicKey {
	return r.sourceTokenAccountAuthority
}

func (r *TransferFromATARequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *TransferFromATARequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *TransferFromATARequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *TransferFromATARequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

func (r *TransferFromATARequest) ToAmount() uint64 {
	return r.amount
}

func (r *TransferFromATARequest) ToDecimals() uint8 {
	return r.Decimals
}

func (r *TransferFromATARequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// TransferFromATAResponse reports the derived source account, which the
// caller never supplied and would otherwise have to derive to know,
// alongside what transfer-checked reports.
type TransferFromATAResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	SourceTokenAccount          string      `json:"source_token_account"`
	Owner                       string      `json:"owner"`
	Mint                        string      `json:"mint"`
	DestinationTokenAccount     string      `json:"destination_token_account"`
	SourceTokenAccountAuthority string      `json:"source_token_account_authority"`
	Program                     string      `json:"program"`
	Amount                      string      `json:"amount"`
	Decimals                    uint8       `json:"decimals"`
	Fee                         SystemPayer `json:"fee"`
}

func NewTransferFromATAResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, sourceTokenAccount, owner, mint, destinationTokenAccount, sourceTokenAccountAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	amount uint64, decimals uint8, fee uint64,
) *TransferFromATAResponse {
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

	return &TransferFromATAResponse{
		Transaction:                 codec.Base64.Encode(raw),
		Message:                     codec.Base64.Encode(message),
		RecentBlockhash:             tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                 keys,
		Signers:                     signers,
		NonceAuthority:              nonceAuth,
		SourceTokenAccount:          sourceTokenAccount.Base58(),
		Owner:                       owner.Base58(),
		Mint:                        mint.Base58(),
		DestinationTokenAccount:     destinationTokenAccount.Base58(),
		SourceTokenAccountAuthority: sourceTokenAccountAuthority.Base58(),
		Program:                     tokenProgram.Base58(),
		Amount:                      strconv.FormatUint(amount, 10),
		Decimals:                    decimals,
		Fee:                         newSystemPayer(feePayer, fee),
	}
}

// TransferFromATAMaxRequest is transfer-from-ata's own type, for the same
// reason transfer-checked-max's is: it sweeps the derived source's entire
// current balance rather than taking one, so there is no Amount field to
// share, and Decimals is resolved from the mint rather than taken from the
// caller, since there is no client-computed amount left to protect against a
// wrong decimals assumption.
type TransferFromATAMaxRequest struct {
	// Owner is the sender's wallet. Its associated token account is derived
	// from Owner and Mint rather than accepted directly, and is swept to
	// zero.
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Mint is what the derived source and DestinationTokenAccount must both
	// hold.
	Mint string `json:"mint" example:""`

	// DestinationTokenAccount is credited. It must already exist, hold Mint,
	// and not be frozen — an exact address, not a wallet to derive from.
	DestinationTokenAccount string `json:"destination_token_account" example:"Cc81es6UdN5EwjE27Pv4ZFaQhd6yh4XG5n11SNd8pmxo"`

	// SourceTokenAccountAuthority is the derived source account's owner, or
	// its delegate for no more than what was delegated — checked against the
	// balance actually swept, resolved at request time, not a caller-given
	// amount.
	SourceTokenAccountAuthority string `json:"source_token_account_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee. A transfer moves no
	// lamports of its own, so this is the only balance this endpoint ever
	// checks.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program is a seed of the derived source address, not only the program
	// both token accounts belong to, so one owner has a different
	// associated account for classic Token than for Token-2022 over the
	// same mint.
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

	owner                       *types.PublicKey
	mint                        *types.PublicKey
	destinationTokenAccount     *types.PublicKey
	sourceTokenAccountAuthority *types.PublicKey
	feePayer                    *types.PublicKey
	rbh                         *types.Hash
	dna                         *types.PublicKey
	tokenProgramID              *types.PublicKey
	multisigSigners             []*types.PublicKey
}

func (r *TransferFromATAMaxRequest) ValidateRequest() error {
	var err error
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.destinationTokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.DestinationTokenAccount)); err != nil {
		return errors.New("destination_token_account: " + err.Error())
	}
	if r.sourceTokenAccountAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.SourceTokenAccountAuthority)); err != nil {
		return errors.New("source_token_account_authority: " + err.Error())
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

func (r *TransferFromATAMaxRequest) OwnerKey() *types.PublicKey {
	return r.owner
}

func (r *TransferFromATAMaxRequest) MintKey() *types.PublicKey {
	return r.mint
}

func (r *TransferFromATAMaxRequest) DestinationTokenAccountKey() *types.PublicKey {
	return r.destinationTokenAccount
}

func (r *TransferFromATAMaxRequest) SourceTokenAccountAuthorityKey() *types.PublicKey {
	return r.sourceTokenAccountAuthority
}

func (r *TransferFromATAMaxRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}

func (r *TransferFromATAMaxRequest) Blockhash() *types.Hash {
	return r.rbh
}

func (r *TransferFromATAMaxRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

func (r *TransferFromATAMaxRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

func (r *TransferFromATAMaxRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// TransferFromATAMaxResponse reports the derived source account, which the
// caller never supplied and would otherwise have to derive to know,
// alongside what transfer-checked-max reports.
type TransferFromATAMaxResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	SourceTokenAccount          string      `json:"source_token_account"`
	Owner                       string      `json:"owner"`
	Mint                        string      `json:"mint"`
	DestinationTokenAccount     string      `json:"destination_token_account"`
	SourceTokenAccountAuthority string      `json:"source_token_account_authority"`
	Program                     string      `json:"program"`
	Amount                      string      `json:"amount"`
	Decimals                    uint8       `json:"decimals"`
	Fee                         SystemPayer `json:"fee"`
}

func NewTransferFromATAMaxResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, sourceTokenAccount, owner, mint, destinationTokenAccount, sourceTokenAccountAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	amount uint64, decimals uint8, fee uint64,
) *TransferFromATAMaxResponse {
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

	return &TransferFromATAMaxResponse{
		Transaction:                 codec.Base64.Encode(raw),
		Message:                     codec.Base64.Encode(message),
		RecentBlockhash:             tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                 keys,
		Signers:                     signers,
		NonceAuthority:              nonceAuth,
		SourceTokenAccount:          sourceTokenAccount.Base58(),
		Owner:                       owner.Base58(),
		Mint:                        mint.Base58(),
		DestinationTokenAccount:     destinationTokenAccount.Base58(),
		SourceTokenAccountAuthority: sourceTokenAccountAuthority.Base58(),
		Program:                     tokenProgram.Base58(),
		Amount:                      strconv.FormatUint(amount, 10),
		Decimals:                    decimals,
		Fee:                         newSystemPayer(feePayer, fee),
	}
}

// ApproveCheckedRequest names a delegation to grant over a token account.
//
// TokenAccount is the one existing token account whose balance the delegate
// may move, matching burn-checked and close-account's naming rather than
// transfer-checked's source/destination pair, since approve has only the one
// token account: delegate is a bare key, never itself a token account.
type ApproveCheckedRequest struct {
	// TokenAccount is debited if the delegation is ever spent. It must
	// already exist and hold Mint.
	TokenAccount string `json:"token_account" example:""`

	// Mint is what TokenAccount must hold, and is the source of the decimals
	// checked against.
	Mint string `json:"mint" example:""`

	// Delegate is who may spend up to Amount from TokenAccount going
	// forward, replacing any prior delegation entirely rather than adding to
	// it.
	Delegate string `json:"delegate" example:""`

	// TokenAccountOwner must be TokenAccount's owner, never an existing
	// delegate: re-delegating would let a delegate hand its own spending
	// rights to a third party the owner never chose.
	TokenAccountOwner string `json:"token_account_owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Amount is the raw base-unit count Delegate may spend, not a UI decimal
	// string.
	Amount string `json:"amount" example:"500000"`

	// Decimals is checked against Mint's own stored value rather than
	// trusted, which is the whole point of the checked variant: catching a
	// client that formatted Amount against the wrong decimals as a 400
	// instead of an on-chain failure.
	Decimals uint8 `json:"decimals" example:"6"`

	// FeePayer signs and pays the transaction fee.
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

	tokenAccount      *types.PublicKey
	mint              *types.PublicKey
	delegate          *types.PublicKey
	tokenAccountOwner *types.PublicKey
	feePayer          *types.PublicKey
	rbh               *types.Hash
	dna               *types.PublicKey
	tokenProgramID    *types.PublicKey
	multisigSigners   []*types.PublicKey
	amount            uint64
}

func (r *ApproveCheckedRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.delegate, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Delegate)); err != nil {
		return errors.New("delegate: " + err.Error())
	}
	if r.tokenAccount.Equal(r.delegate) {
		return errors.New("token_account and delegate are the same account")
	}
	if r.tokenAccountOwner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccountOwner)); err != nil {
		return errors.New("token_account_owner: " + err.Error())
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

func (r *ApproveCheckedRequest) TokenAccountKey() *types.PublicKey      { return r.tokenAccount }
func (r *ApproveCheckedRequest) MintKey() *types.PublicKey              { return r.mint }
func (r *ApproveCheckedRequest) DelegateKey() *types.PublicKey          { return r.delegate }
func (r *ApproveCheckedRequest) TokenAccountOwnerKey() *types.PublicKey { return r.tokenAccountOwner }
func (r *ApproveCheckedRequest) FeePayerKey() *types.PublicKey          { return r.feePayer }
func (r *ApproveCheckedRequest) Blockhash() *types.Hash                 { return r.rbh }
func (r *ApproveCheckedRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
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

	TokenAccount      string      `json:"token_account"`
	Mint              string      `json:"mint"`
	Delegate          string      `json:"delegate"`
	TokenAccountOwner string      `json:"token_account_owner"`
	Program           string      `json:"program"`
	Amount            string      `json:"amount"`
	Decimals          uint8       `json:"decimals"`
	Fee               SystemPayer `json:"fee"`
}

func NewApproveCheckedResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, mint, delegate, tokenAccountOwner, tokenProgram, nonceAuthority *types.PublicKey,
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
		Transaction:       codec.Base64.Encode(raw),
		Message:           codec.Base64.Encode(message),
		RecentBlockhash:   tx.Message.RecentBlockhash.Base58(),
		AccountKeys:       keys,
		Signers:           signers,
		NonceAuthority:    nonceAuth,
		TokenAccount:      tokenAccount.Base58(),
		Mint:              mint.Base58(),
		Delegate:          delegate.Base58(),
		TokenAccountOwner: tokenAccountOwner.Base58(),
		Program:           tokenProgram.Base58(),
		Amount:            strconv.FormatUint(amount, 10),
		Decimals:          decimals,
		Fee:               newSystemPayer(feePayer, fee),
	}
}

// ApproveCheckedMaxRequest is approve-checked's own type, for the same
// reason transfer-checked-max's is: it grants Delegate the maximum
// representable base-unit amount rather than one the caller names, so there
// is no Amount field to share, and Decimals is resolved from the mint rather
// than taken from the caller.
//
// This is the effectively-unlimited approval pattern: MaxAmount is far
// beyond any real balance, so re-approving after the balance changes is
// never needed, and the delegate can still only ever move what
// TokenAccount actually holds — the amount here is a ceiling, not a
// balance, so a value with no real balance behind it is not a stale or
// dangerous grant, only an unreachable one.
type ApproveCheckedMaxRequest struct {
	// TokenAccount is debited if the delegation is ever spent. It must
	// already exist and hold Mint.
	TokenAccount string `json:"token_account" example:""`

	// Mint is what TokenAccount must hold.
	Mint string `json:"mint" example:""`

	// Delegate is who may spend from TokenAccount going forward, up to the
	// maximum representable amount, replacing any prior delegation entirely
	// rather than adding to it.
	Delegate string `json:"delegate" example:""`

	// TokenAccountOwner must be TokenAccount's owner, never an existing
	// delegate: re-delegating would let a delegate hand its own spending
	// rights to a third party the owner never chose.
	TokenAccountOwner string `json:"token_account_owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
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

	tokenAccount      *types.PublicKey
	mint              *types.PublicKey
	delegate          *types.PublicKey
	tokenAccountOwner *types.PublicKey
	feePayer          *types.PublicKey
	rbh               *types.Hash
	dna               *types.PublicKey
	tokenProgramID    *types.PublicKey
	multisigSigners   []*types.PublicKey
}

func (r *ApproveCheckedMaxRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.delegate, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Delegate)); err != nil {
		return errors.New("delegate: " + err.Error())
	}
	if r.tokenAccount.Equal(r.delegate) {
		return errors.New("token_account and delegate are the same account")
	}
	if r.tokenAccountOwner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccountOwner)); err != nil {
		return errors.New("token_account_owner: " + err.Error())
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

func (r *ApproveCheckedMaxRequest) TokenAccountKey() *types.PublicKey { return r.tokenAccount }
func (r *ApproveCheckedMaxRequest) MintKey() *types.PublicKey         { return r.mint }
func (r *ApproveCheckedMaxRequest) DelegateKey() *types.PublicKey     { return r.delegate }
func (r *ApproveCheckedMaxRequest) TokenAccountOwnerKey() *types.PublicKey {
	return r.tokenAccountOwner
}
func (r *ApproveCheckedMaxRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *ApproveCheckedMaxRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *ApproveCheckedMaxRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ApproveCheckedMaxRequest) TokenProgramID() *types.PublicKey      { return r.tokenProgramID }
func (r *ApproveCheckedMaxRequest) ToMultisigSigners() []*types.PublicKey { return r.multisigSigners }

// ApproveCheckedMaxResponse reports the delegation just built, including
// MaxAmount so a caller does not have to hardcode the maximum representable
// base-unit amount themselves to know what was actually granted.
type ApproveCheckedMaxResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	TokenAccount      string      `json:"token_account"`
	Mint              string      `json:"mint"`
	Delegate          string      `json:"delegate"`
	TokenAccountOwner string      `json:"token_account_owner"`
	Program           string      `json:"program"`
	MaxAmount         string      `json:"max_amount"`
	Decimals          uint8       `json:"decimals"`
	Fee               SystemPayer `json:"fee"`
}

func NewApproveCheckedMaxResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, mint, delegate, tokenAccountOwner, tokenProgram, nonceAuthority *types.PublicKey,
	maxAmount uint64, decimals uint8, fee uint64,
) *ApproveCheckedMaxResponse {
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

	return &ApproveCheckedMaxResponse{
		Transaction:       codec.Base64.Encode(raw),
		Message:           codec.Base64.Encode(message),
		RecentBlockhash:   tx.Message.RecentBlockhash.Base58(),
		AccountKeys:       keys,
		Signers:           signers,
		NonceAuthority:    nonceAuth,
		TokenAccount:      tokenAccount.Base58(),
		Mint:              mint.Base58(),
		Delegate:          delegate.Base58(),
		TokenAccountOwner: tokenAccountOwner.Base58(),
		Program:           tokenProgram.Base58(),
		MaxAmount:         strconv.FormatUint(maxAmount, 10),
		Decimals:          decimals,
		Fee:               newSystemPayer(feePayer, fee),
	}
}

// RevokeRequest names the account whose delegation should be cleared.
//
// There is no delegate field. The program clears whichever one is stored
// without being told which, so naming one here would only be a way to get it
// wrong; there is also no mint, since revoking touches no balance and needs
// nothing decoded from it.
type RevokeRequest struct {
	// TokenAccount has its delegate and delegated amount cleared, whatever
	// they currently are.
	TokenAccount string `json:"token_account" example:""`

	// TokenAccountOwner must be TokenAccount's owner, matching
	// approve-checked's rule that only the owner may grant one: a delegate
	// holds no authority over the delegation itself, only over what it was
	// allowed to spend.
	TokenAccountOwner string `json:"token_account_owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
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

	tokenAccount      *types.PublicKey
	tokenAccountOwner *types.PublicKey
	feePayer          *types.PublicKey
	rbh               *types.Hash
	dna               *types.PublicKey
	tokenProgramID    *types.PublicKey
	multisigSigners   []*types.PublicKey
}

func (r *RevokeRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
	}
	if r.tokenAccountOwner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccountOwner)); err != nil {
		return errors.New("token_account_owner: " + err.Error())
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

func (r *RevokeRequest) TokenAccountKey() *types.PublicKey      { return r.tokenAccount }
func (r *RevokeRequest) TokenAccountOwnerKey() *types.PublicKey { return r.tokenAccountOwner }
func (r *RevokeRequest) FeePayerKey() *types.PublicKey          { return r.feePayer }
func (r *RevokeRequest) Blockhash() *types.Hash                 { return r.rbh }
func (r *RevokeRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
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

	TokenAccount      string      `json:"token_account"`
	TokenAccountOwner string      `json:"token_account_owner"`
	Program           string      `json:"program"`
	Fee               SystemPayer `json:"fee"`
}

func NewRevokeResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, tokenAccountOwner, tokenProgram, nonceAuthority *types.PublicKey,
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
		Transaction:       codec.Base64.Encode(raw),
		Message:           codec.Base64.Encode(message),
		RecentBlockhash:   tx.Message.RecentBlockhash.Base58(),
		AccountKeys:       keys,
		Signers:           signers,
		NonceAuthority:    nonceAuth,
		TokenAccount:      tokenAccount.Base58(),
		TokenAccountOwner: tokenAccountOwner.Base58(),
		Program:           tokenProgram.Base58(),
		Fee:               newSystemPayer(feePayer, fee),
	}
}

// SetMintAuthorityReplaceRequest replaces a mint's mint authority with a new key.
type SetMintAuthorityReplaceRequest struct {
	Mint string `json:"mint" example:""`

	// MintAuthority must be Mint's current mint authority exactly.
	MintAuthority string `json:"mint_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NewMintAuthority replaces MintAuthority entirely; it is not required to
	// sign, since InitializeMint2-style authority changes only record the
	// new value rather than checking it against a signer.
	NewMintAuthority string `json:"new_mint_authority" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022. It is required rather than defaulted, since a mint
	// belongs to exactly one of the two forever.
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

	mint             *types.PublicKey
	mintAuthority    *types.PublicKey
	newMintAuthority *types.PublicKey
	feePayer         *types.PublicKey
	rbh              *types.Hash
	dna              *types.PublicKey
	tokenProgramID   *types.PublicKey
	multisigSigners  []*types.PublicKey
}

func (r *SetMintAuthorityReplaceRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.mintAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.MintAuthority)); err != nil {
		return errors.New("mint_authority: " + err.Error())
	}
	newMintAuthority := strings.TrimSpace(r.NewMintAuthority)
	if newMintAuthority == "" {
		return errors.New("new_mint_authority is required")
	}
	if r.newMintAuthority, err = types.NewPublicKeyFromBase58(newMintAuthority); err != nil {
		return errors.New("new_mint_authority: " + err.Error())
	}
	if r.mintAuthority.Equal(r.newMintAuthority) {
		return errors.New("new_mint_authority: is already the current mint authority")
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

func (r *SetMintAuthorityReplaceRequest) MintKey() *types.PublicKey          { return r.mint }
func (r *SetMintAuthorityReplaceRequest) MintAuthorityKey() *types.PublicKey { return r.mintAuthority }
func (r *SetMintAuthorityReplaceRequest) NewMintAuthorityKey() *types.PublicKey {
	return r.newMintAuthority
}
func (r *SetMintAuthorityReplaceRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *SetMintAuthorityReplaceRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *SetMintAuthorityReplaceRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *SetMintAuthorityReplaceRequest) TokenProgramID() *types.PublicKey { return r.tokenProgramID }
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

	Mint             string      `json:"mint"`
	MintAuthority    string      `json:"mint_authority"`
	NewMintAuthority string      `json:"new_mint_authority"`
	Program          string      `json:"program"`
	Fee              SystemPayer `json:"fee"`
}

func NewSetMintAuthorityReplaceResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, mintAuthority, tokenProgram, nonceAuthority, newMintAuthority *types.PublicKey,
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
		Transaction:      codec.Base64.Encode(raw),
		Message:          codec.Base64.Encode(message),
		RecentBlockhash:  tx.Message.RecentBlockhash.Base58(),
		AccountKeys:      keys,
		Signers:          signers,
		NonceAuthority:   nonceAuth,
		Mint:             mint.Base58(),
		MintAuthority:    mintAuthority.Base58(),
		NewMintAuthority: newMintAuthority.Base58(),
		Program:          tokenProgram.Base58(),
		Fee:              newSystemPayer(feePayer, fee),
	}
}

// SetMintAuthorityClearRequest removes a mint's mint authority permanently.
//
// Once cleared, no endpoint can set it again: the program stores this as a
// COption and rejects nothing here, but nothing can ever sign as an authority
// that is now None. This is how a supply is capped forever.
type SetMintAuthorityClearRequest struct {
	Mint string `json:"mint" example:""`

	// MintAuthority must be Mint's current mint authority exactly.
	MintAuthority string `json:"mint_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022. It is required rather than defaulted, since a mint
	// belongs to exactly one of the two forever.
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
	mintAuthority   *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *SetMintAuthorityClearRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.mintAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.MintAuthority)); err != nil {
		return errors.New("mint_authority: " + err.Error())
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

func (r *SetMintAuthorityClearRequest) MintKey() *types.PublicKey          { return r.mint }
func (r *SetMintAuthorityClearRequest) MintAuthorityKey() *types.PublicKey { return r.mintAuthority }
func (r *SetMintAuthorityClearRequest) FeePayerKey() *types.PublicKey      { return r.feePayer }
func (r *SetMintAuthorityClearRequest) Blockhash() *types.Hash             { return r.rbh }
func (r *SetMintAuthorityClearRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *SetMintAuthorityClearRequest) TokenProgramID() *types.PublicKey { return r.tokenProgramID }
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

	Mint          string      `json:"mint"`
	MintAuthority string      `json:"mint_authority"`
	Cleared       bool        `json:"cleared"`
	Program       string      `json:"program"`
	Fee           SystemPayer `json:"fee"`
}

func NewSetMintAuthorityClearResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, mintAuthority, tokenProgram, nonceAuthority *types.PublicKey,
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
		MintAuthority:   mintAuthority.Base58(),
		Cleared:         true,
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// SetFreezeAuthorityReplaceRequest replaces a mint's freeze authority with a new key.
type SetFreezeAuthorityReplaceRequest struct {
	Mint string `json:"mint" example:""`

	// FreezeAuthority must be Mint's current freeze authority exactly.
	FreezeAuthority string `json:"freeze_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NewFreezeAuthority replaces FreezeAuthority entirely.
	NewFreezeAuthority string `json:"new_freeze_authority" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022. It is required rather than defaulted, since a mint
	// belongs to exactly one of the two forever.
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

	mint               *types.PublicKey
	freezeAuthority    *types.PublicKey
	newFreezeAuthority *types.PublicKey
	feePayer           *types.PublicKey
	rbh                *types.Hash
	dna                *types.PublicKey
	tokenProgramID     *types.PublicKey
	multisigSigners    []*types.PublicKey
}

func (r *SetFreezeAuthorityReplaceRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.freezeAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FreezeAuthority)); err != nil {
		return errors.New("freeze_authority: " + err.Error())
	}
	newFreezeAuthority := strings.TrimSpace(r.NewFreezeAuthority)
	if newFreezeAuthority == "" {
		return errors.New("new_freeze_authority is required")
	}
	if r.newFreezeAuthority, err = types.NewPublicKeyFromBase58(newFreezeAuthority); err != nil {
		return errors.New("new_freeze_authority: " + err.Error())
	}
	if r.freezeAuthority.Equal(r.newFreezeAuthority) {
		return errors.New("new_freeze_authority: is already the current freeze authority")
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

func (r *SetFreezeAuthorityReplaceRequest) MintKey() *types.PublicKey { return r.mint }
func (r *SetFreezeAuthorityReplaceRequest) FreezeAuthorityKey() *types.PublicKey {
	return r.freezeAuthority
}
func (r *SetFreezeAuthorityReplaceRequest) NewFreezeAuthorityKey() *types.PublicKey {
	return r.newFreezeAuthority
}
func (r *SetFreezeAuthorityReplaceRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *SetFreezeAuthorityReplaceRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *SetFreezeAuthorityReplaceRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *SetFreezeAuthorityReplaceRequest) TokenProgramID() *types.PublicKey { return r.tokenProgramID }
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

	Mint               string      `json:"mint"`
	FreezeAuthority    string      `json:"freeze_authority"`
	NewFreezeAuthority string      `json:"new_freeze_authority"`
	Program            string      `json:"program"`
	Fee                SystemPayer `json:"fee"`
}

func NewSetFreezeAuthorityReplaceResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, freezeAuthority, tokenProgram, nonceAuthority, newFreezeAuthority *types.PublicKey,
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
		Transaction:        codec.Base64.Encode(raw),
		Message:            codec.Base64.Encode(message),
		RecentBlockhash:    tx.Message.RecentBlockhash.Base58(),
		AccountKeys:        keys,
		Signers:            signers,
		NonceAuthority:     nonceAuth,
		Mint:               mint.Base58(),
		FreezeAuthority:    freezeAuthority.Base58(),
		NewFreezeAuthority: newFreezeAuthority.Base58(),
		Program:            tokenProgram.Base58(),
		Fee:                newSystemPayer(feePayer, fee),
	}
}

// SetFreezeAuthorityClearRequest removes a mint's freeze authority permanently.
//
// Once cleared, no holder of this mint can ever be frozen again, and nothing
// can restore the capability: there is no authority left to sign the change.
type SetFreezeAuthorityClearRequest struct {
	Mint string `json:"mint" example:""`

	// FreezeAuthority must be Mint's current freeze authority exactly.
	FreezeAuthority string `json:"freeze_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022. It is required rather than defaulted, since a mint
	// belongs to exactly one of the two forever.
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
	freezeAuthority *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *SetFreezeAuthorityClearRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.freezeAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FreezeAuthority)); err != nil {
		return errors.New("freeze_authority: " + err.Error())
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

func (r *SetFreezeAuthorityClearRequest) MintKey() *types.PublicKey { return r.mint }
func (r *SetFreezeAuthorityClearRequest) FreezeAuthorityKey() *types.PublicKey {
	return r.freezeAuthority
}
func (r *SetFreezeAuthorityClearRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *SetFreezeAuthorityClearRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *SetFreezeAuthorityClearRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *SetFreezeAuthorityClearRequest) TokenProgramID() *types.PublicKey { return r.tokenProgramID }
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

	Mint            string      `json:"mint"`
	FreezeAuthority string      `json:"freeze_authority"`
	Cleared         bool        `json:"cleared"`
	Program         string      `json:"program"`
	Fee             SystemPayer `json:"fee"`
}

func NewSetFreezeAuthorityClearResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, freezeAuthority, tokenProgram, nonceAuthority *types.PublicKey,
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
		FreezeAuthority: freezeAuthority.Base58(),
		Cleared:         true,
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// SetAccountOwnerReplaceRequest SetAccountOwnerReplace replaces a token account's owner with a new key.
//
// There is no clear variant. The account's owner field is a plain Pubkey on
// chain, not a COption, so there is no representation for "no owner" to set
// it to; the program rejects a None authority here rather than accepting one
// it could never store.
type SetAccountOwnerReplaceRequest struct {
	// TokenAccount is handed to NewTokenAccountOwner. It must already exist.
	TokenAccount string `json:"token_account" example:""`

	// TokenAccountOwner must be TokenAccount's current owner exactly, never
	// a delegate: a delegate has no authority over the account itself, only
	// over what it was allowed to spend.
	TokenAccountOwner string `json:"token_account_owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NewTokenAccountOwner replaces TokenAccountOwner entirely.
	NewTokenAccountOwner string `json:"new_token_account_owner" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022. It is required rather than defaulted, since a token
	// account belongs to exactly one of the two forever.
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

	tokenAccount         *types.PublicKey
	tokenAccountOwner    *types.PublicKey
	newTokenAccountOwner *types.PublicKey
	feePayer             *types.PublicKey
	rbh                  *types.Hash
	dna                  *types.PublicKey
	tokenProgramID       *types.PublicKey
	multisigSigners      []*types.PublicKey
}

func (r *SetAccountOwnerReplaceRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
	}
	if r.tokenAccountOwner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccountOwner)); err != nil {
		return errors.New("token_account_owner: " + err.Error())
	}
	newTokenAccountOwner := strings.TrimSpace(r.NewTokenAccountOwner)
	if newTokenAccountOwner == "" {
		return errors.New("new_token_account_owner is required")
	}
	if r.newTokenAccountOwner, err = types.NewPublicKeyFromBase58(newTokenAccountOwner); err != nil {
		return errors.New("new_token_account_owner: " + err.Error())
	}
	if r.tokenAccountOwner.Equal(r.newTokenAccountOwner) {
		return errors.New("new_token_account_owner: is already the current owner")
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

func (r *SetAccountOwnerReplaceRequest) TokenAccountKey() *types.PublicKey { return r.tokenAccount }
func (r *SetAccountOwnerReplaceRequest) TokenAccountOwnerKey() *types.PublicKey {
	return r.tokenAccountOwner
}
func (r *SetAccountOwnerReplaceRequest) NewTokenAccountOwnerKey() *types.PublicKey {
	return r.newTokenAccountOwner
}
func (r *SetAccountOwnerReplaceRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *SetAccountOwnerReplaceRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *SetAccountOwnerReplaceRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *SetAccountOwnerReplaceRequest) TokenProgramID() *types.PublicKey { return r.tokenProgramID }
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

	TokenAccount         string      `json:"token_account"`
	TokenAccountOwner    string      `json:"token_account_owner"`
	NewTokenAccountOwner string      `json:"new_token_account_owner"`
	Program              string      `json:"program"`
	Fee                  SystemPayer `json:"fee"`
}

func NewSetAccountOwnerReplaceResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, tokenAccountOwner, tokenProgram, nonceAuthority, newTokenAccountOwner *types.PublicKey,
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
		Transaction:          codec.Base64.Encode(raw),
		Message:              codec.Base64.Encode(message),
		RecentBlockhash:      tx.Message.RecentBlockhash.Base58(),
		AccountKeys:          keys,
		Signers:              signers,
		NonceAuthority:       nonceAuth,
		TokenAccount:         tokenAccount.Base58(),
		TokenAccountOwner:    tokenAccountOwner.Base58(),
		NewTokenAccountOwner: newTokenAccountOwner.Base58(),
		Program:              tokenProgram.Base58(),
		Fee:                  newSystemPayer(feePayer, fee),
	}
}

// SetCloseAuthorityReplaceRequest replaces a token account's close authority
// with a new key.
//
// TokenAccountCloseAuthority is whichever one is already recorded: the
// account's close authority if one is set, otherwise its owner, the same
// rule close-account itself checks.
type SetCloseAuthorityReplaceRequest struct {
	// TokenAccount has its close authority replaced. It must already exist.
	TokenAccount string `json:"token_account" example:""`

	// TokenAccountCloseAuthority must be TokenAccount's current close
	// authority exactly: its owner, unless a close authority is already set,
	// in which case it must be that instead.
	TokenAccountCloseAuthority string `json:"token_account_close_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NewTokenAccountCloseAuthority replaces TokenAccountCloseAuthority
	// entirely.
	NewTokenAccountCloseAuthority string `json:"new_token_account_close_authority" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022. It is required rather than defaulted, since a token
	// account belongs to exactly one of the two forever.
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

	tokenAccount                  *types.PublicKey
	tokenAccountCloseAuthority    *types.PublicKey
	newTokenAccountCloseAuthority *types.PublicKey
	feePayer                      *types.PublicKey
	rbh                           *types.Hash
	dna                           *types.PublicKey
	tokenProgramID                *types.PublicKey
	multisigSigners               []*types.PublicKey
}

func (r *SetCloseAuthorityReplaceRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
	}
	if r.tokenAccountCloseAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccountCloseAuthority)); err != nil {
		return errors.New("token_account_close_authority: " + err.Error())
	}
	newTokenAccountCloseAuthority := strings.TrimSpace(r.NewTokenAccountCloseAuthority)
	if newTokenAccountCloseAuthority == "" {
		return errors.New("new_token_account_close_authority is required")
	}
	if r.newTokenAccountCloseAuthority, err = types.NewPublicKeyFromBase58(newTokenAccountCloseAuthority); err != nil {
		return errors.New("new_token_account_close_authority: " + err.Error())
	}
	if r.tokenAccountCloseAuthority.Equal(r.newTokenAccountCloseAuthority) {
		return errors.New("new_token_account_close_authority: is already the current close authority")
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

func (r *SetCloseAuthorityReplaceRequest) TokenAccountKey() *types.PublicKey { return r.tokenAccount }
func (r *SetCloseAuthorityReplaceRequest) TokenAccountCloseAuthorityKey() *types.PublicKey {
	return r.tokenAccountCloseAuthority
}
func (r *SetCloseAuthorityReplaceRequest) NewTokenAccountCloseAuthorityKey() *types.PublicKey {
	return r.newTokenAccountCloseAuthority
}
func (r *SetCloseAuthorityReplaceRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *SetCloseAuthorityReplaceRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *SetCloseAuthorityReplaceRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *SetCloseAuthorityReplaceRequest) TokenProgramID() *types.PublicKey { return r.tokenProgramID }
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

	TokenAccount                  string      `json:"token_account"`
	TokenAccountCloseAuthority    string      `json:"token_account_close_authority"`
	NewTokenAccountCloseAuthority string      `json:"new_token_account_close_authority"`
	Program                       string      `json:"program"`
	Fee                           SystemPayer `json:"fee"`
}

func NewSetCloseAuthorityReplaceResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, tokenAccountCloseAuthority, tokenProgram, nonceAuthority, newTokenAccountCloseAuthority *types.PublicKey,
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
		Transaction:                   codec.Base64.Encode(raw),
		Message:                       codec.Base64.Encode(message),
		RecentBlockhash:               tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                   keys,
		Signers:                       signers,
		NonceAuthority:                nonceAuth,
		TokenAccount:                  tokenAccount.Base58(),
		TokenAccountCloseAuthority:    tokenAccountCloseAuthority.Base58(),
		NewTokenAccountCloseAuthority: newTokenAccountCloseAuthority.Base58(),
		Program:                       tokenProgram.Base58(),
		Fee:                           newSystemPayer(feePayer, fee),
	}
}

// SetCloseAuthorityClearRequest removes a token account's close authority.
//
// Unlike the mint authorities, this one is recoverable: the account's owner
// never goes away, and close-account already falls back to the owner when no
// close authority is set, so clearing this only reverts to that default.
type SetCloseAuthorityClearRequest struct {
	// TokenAccount has its close authority cleared. It must already exist.
	TokenAccount string `json:"token_account" example:""`

	// TokenAccountCloseAuthority must be TokenAccount's current close
	// authority exactly: its owner, unless a close authority is already set,
	// in which case it must be that instead.
	TokenAccountCloseAuthority string `json:"token_account_close_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022. It is required rather than defaulted, since a token
	// account belongs to exactly one of the two forever.
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

	tokenAccount               *types.PublicKey
	tokenAccountCloseAuthority *types.PublicKey
	feePayer                   *types.PublicKey
	rbh                        *types.Hash
	dna                        *types.PublicKey
	tokenProgramID             *types.PublicKey
	multisigSigners            []*types.PublicKey
}

func (r *SetCloseAuthorityClearRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
	}
	if r.tokenAccountCloseAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccountCloseAuthority)); err != nil {
		return errors.New("token_account_close_authority: " + err.Error())
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

func (r *SetCloseAuthorityClearRequest) TokenAccountKey() *types.PublicKey { return r.tokenAccount }
func (r *SetCloseAuthorityClearRequest) TokenAccountCloseAuthorityKey() *types.PublicKey {
	return r.tokenAccountCloseAuthority
}
func (r *SetCloseAuthorityClearRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *SetCloseAuthorityClearRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *SetCloseAuthorityClearRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *SetCloseAuthorityClearRequest) TokenProgramID() *types.PublicKey { return r.tokenProgramID }
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

	TokenAccount               string      `json:"token_account"`
	TokenAccountCloseAuthority string      `json:"token_account_close_authority"`
	Cleared                    bool        `json:"cleared"`
	Program                    string      `json:"program"`
	Fee                        SystemPayer `json:"fee"`
}

func NewSetCloseAuthorityClearResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, tokenAccountCloseAuthority, tokenProgram, nonceAuthority *types.PublicKey,
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
		Transaction:                codec.Base64.Encode(raw),
		Message:                    codec.Base64.Encode(message),
		RecentBlockhash:            tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                keys,
		Signers:                    signers,
		NonceAuthority:             nonceAuth,
		TokenAccount:               tokenAccount.Base58(),
		TokenAccountCloseAuthority: tokenAccountCloseAuthority.Base58(),
		Cleared:                    true,
		Program:                    tokenProgram.Base58(),
		Fee:                        newSystemPayer(feePayer, fee),
	}
}

// FreezeAccountRequest names the token account to suspend.
//
// FreezeAuthority must be the mint's freeze authority, not the account's
// owner or any delegate. Freezing is a mint-level power: it exists so
// whoever controls a mint can suspend any account holding it, which is a
// different axis from who may spend an account's own balance.
type FreezeAccountRequest struct {
	// TokenAccount is suspended. It must already exist, hold Mint, and not
	// already be frozen.
	TokenAccount string `json:"token_account" example:""`

	// Mint is what TokenAccount must hold, and is the source of the freeze
	// authority checked against.
	Mint string `json:"mint" example:""`

	// FreezeAuthority must be Mint's freeze authority exactly.
	FreezeAuthority string `json:"freeze_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022. It is required rather than defaulted, since a token
	// account belongs to exactly one of the two forever.
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

	tokenAccount    *types.PublicKey
	mint            *types.PublicKey
	freezeAuthority *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *FreezeAccountRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.freezeAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FreezeAuthority)); err != nil {
		return errors.New("freeze_authority: " + err.Error())
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

func (r *FreezeAccountRequest) TokenAccountKey() *types.PublicKey    { return r.tokenAccount }
func (r *FreezeAccountRequest) MintKey() *types.PublicKey            { return r.mint }
func (r *FreezeAccountRequest) FreezeAuthorityKey() *types.PublicKey { return r.freezeAuthority }
func (r *FreezeAccountRequest) FeePayerKey() *types.PublicKey        { return r.feePayer }
func (r *FreezeAccountRequest) Blockhash() *types.Hash               { return r.rbh }
func (r *FreezeAccountRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
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

	TokenAccount    string      `json:"token_account"`
	Mint            string      `json:"mint"`
	FreezeAuthority string      `json:"freeze_authority"`
	Program         string      `json:"program"`
	Fee             SystemPayer `json:"fee"`
}

func NewFreezeAccountResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, mint, freezeAuthority, tokenProgram, nonceAuthority *types.PublicKey,
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
		TokenAccount:    tokenAccount.Base58(),
		Mint:            mint.Base58(),
		FreezeAuthority: freezeAuthority.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// ThawAccountRequest names the token account to resume.
//
// The same rule as FreezeAccountRequest applies: FreezeAuthority is the
// mint's freeze authority, since thawing is undoing a mint-level suspension
// rather than anything the account's own owner controls.
type ThawAccountRequest struct {
	// TokenAccount is resumed. It must already exist, hold Mint, and
	// currently be frozen.
	TokenAccount string `json:"token_account" example:""`

	// Mint is what TokenAccount must hold, and is the source of the freeze
	// authority checked against.
	Mint string `json:"mint" example:""`

	// FreezeAuthority must be Mint's freeze authority exactly.
	FreezeAuthority string `json:"freeze_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program names the account to send the instruction to: classic Token or
	// Token-2022. It is required rather than defaulted, since a token
	// account belongs to exactly one of the two forever.
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

	tokenAccount    *types.PublicKey
	mint            *types.PublicKey
	freezeAuthority *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *ThawAccountRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.freezeAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FreezeAuthority)); err != nil {
		return errors.New("freeze_authority: " + err.Error())
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

func (r *ThawAccountRequest) TokenAccountKey() *types.PublicKey    { return r.tokenAccount }
func (r *ThawAccountRequest) MintKey() *types.PublicKey            { return r.mint }
func (r *ThawAccountRequest) FreezeAuthorityKey() *types.PublicKey { return r.freezeAuthority }
func (r *ThawAccountRequest) FeePayerKey() *types.PublicKey        { return r.feePayer }
func (r *ThawAccountRequest) Blockhash() *types.Hash               { return r.rbh }
func (r *ThawAccountRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
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

	TokenAccount    string      `json:"token_account"`
	Mint            string      `json:"mint"`
	FreezeAuthority string      `json:"freeze_authority"`
	Program         string      `json:"program"`
	Fee             SystemPayer `json:"fee"`
}

func NewThawAccountResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, tokenAccount, mint, freezeAuthority, tokenProgram, nonceAuthority *types.PublicKey,
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
		TokenAccount:    tokenAccount.Base58(),
		Mint:            mint.Base58(),
		FreezeAuthority: freezeAuthority.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// ReallocateTransferFeeConfigRequest checks whether Account already holds
// room for TransferFeeConfig, and grows it if not.
//
// TransferFeeConfig is a mint-side extension in the interface crate's own
// numbering, not one Reallocate's own account list ever expects — that list
// is always a token account, since a mint's extension set is fixed forever
// at initialize-mint2 and Reallocate has no path back into it. Nothing here
// stops a caller from naming this type anyway; the deployed program is what
// rejects it, not this endpoint, the same as every other place in this API
// where a wrong role is a chain error rather than a 400.
//
// The instruction itself only ever needs the one new extension type being
// added: Reallocate reads Account's own existing extensions on chain and
// unions them with whatever this sends, so a caller never resends what is
// already there. Getting the resize's rent right is this handler's own
// job, not the instruction's — it reads Account's current extensions and
// actual lamports itself, asks GetAccountDataSize for the full target size
// once TransferFeeConfig is unioned in, and only then knows RentPayer's
// shortfall.
type ReallocateTransferFeeConfigRequest struct {
	// Account is the token account to check and, if needed, grow. It must
	// already exist and be owned by Program.
	Account string `json:"account" example:""`

	// RentPayer funds whatever the resize costs, a distinct role from
	// Owner: Owner authorizes the account being touched, RentPayer covers
	// what that costs, and they need not be the same key.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Owner is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. Unlike every other Token endpoint, this
	// is not the usual either-program field: a classic Token account's
	// layout is fixed at 165 bytes forever, with no TLV region to grow
	// into, so classic Token is rejected here rather than left to fail on
	// chain.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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

	account         *types.PublicKey
	rentPayer       *types.PublicKey
	owner           *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *ReallocateTransferFeeConfigRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.rentPayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
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
	// Unlike every other Token endpoint, which accepts either program
	// because the instruction genuinely works on both, an extension has
	// nowhere to live on a classic Token account: that layout is fixed at
	// 165 bytes forever, with no TLV region to grow into at all. Rejecting
	// classic Token here is a structural fact about the account, not a
	// preference, so it is checked before the request ever reaches the
	// chain rather than left to come back as an on-chain rejection.
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ReallocateTransferFeeConfigRequest) AccountKey() *types.PublicKey   { return r.account }
func (r *ReallocateTransferFeeConfigRequest) RentPayerKey() *types.PublicKey { return r.rentPayer }
func (r *ReallocateTransferFeeConfigRequest) OwnerKey() *types.PublicKey     { return r.owner }
func (r *ReallocateTransferFeeConfigRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *ReallocateTransferFeeConfigRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *ReallocateTransferFeeConfigRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ReallocateTransferFeeConfigRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ReallocateTransferFeeConfigRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ReallocateTransferFeeConfigResponse reports the built transaction
// alongside what it resizes Account for.
type ReallocateTransferFeeConfigResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Owner   string `json:"owner"`
	Program string `json:"program"`

	// TargetSize is the total account size GetAccountDataSize reported for
	// Account's existing extensions plus TransferFeeConfig, asked of the
	// deployed program rather than recomputed here.
	TargetSize string `json:"target_size"`

	// Rent reports what funds the resize: the shortfall between
	// TargetSize's rent-exemption minimum and Account's actual current
	// lamports, zero when Account already holds enough.
	Rent SystemPayer `json:"rent"`
	Fee  SystemPayer `json:"fee"`
}

func NewReallocateTransferFeeConfigResponse(
	tx *types.Transaction, raw, message []byte,
	rentPayer, feePayer, account, owner, tokenProgram, nonceAuthority *types.PublicKey,
	targetSize, rentShortfall, fee uint64,
) *ReallocateTransferFeeConfigResponse {
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

	return &ReallocateTransferFeeConfigResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Owner:           owner.Base58(),
		Program:         tokenProgram.Base58(),
		TargetSize:      strconv.FormatUint(targetSize, 10),
		Rent:            newSystemPayer(rentPayer, rentShortfall),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// ReallocateMintCloseAuthorityRequest checks whether Account already holds
// room for MintCloseAuthority, and grows it if not.
//
// MintCloseAuthority is a mint-side extension in the interface crate's own
// numbering, not one Reallocate's own account list ever expects — that list
// is always a token account, since a mint's extension set is fixed forever
// at initialize-mint2 and Reallocate has no path back into it. Nothing here
// stops a caller from naming this type anyway; the deployed program is what
// rejects it, not this endpoint, the same as every other place in this API
// where a wrong role is a chain error rather than a 400.
//
// The instruction itself only ever needs the one new extension type being
// added: Reallocate reads Account's own existing extensions on chain and
// unions them with whatever this sends, so a caller never resends what is
// already there. Getting the resize's rent right is this handler's own
// job, not the instruction's — it reads Account's current extensions and
// actual lamports itself, asks GetAccountDataSize for the full target size
// once MintCloseAuthority is unioned in, and only then knows RentPayer's
// shortfall.
type ReallocateMintCloseAuthorityRequest struct {
	// Account is the token account to check and, if needed, grow. It must
	// already exist and be owned by Program.
	Account string `json:"account" example:""`

	// RentPayer funds whatever the resize costs, a distinct role from
	// Owner: Owner authorizes the account being touched, RentPayer covers
	// what that costs, and they need not be the same key.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Owner is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. Unlike every other Token endpoint, this
	// is not the usual either-program field: a classic Token account's
	// layout is fixed at 165 bytes forever, with no TLV region to grow
	// into, so classic Token is rejected here rather than left to fail on
	// chain.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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

	account         *types.PublicKey
	rentPayer       *types.PublicKey
	owner           *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *ReallocateMintCloseAuthorityRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.rentPayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
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
	// Unlike every other Token endpoint, which accepts either program
	// because the instruction genuinely works on both, an extension has
	// nowhere to live on a classic Token account: that layout is fixed at
	// 165 bytes forever, with no TLV region to grow into at all. Rejecting
	// classic Token here is a structural fact about the account, not a
	// preference, so it is checked before the request ever reaches the
	// chain rather than left to come back as an on-chain rejection.
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ReallocateMintCloseAuthorityRequest) AccountKey() *types.PublicKey   { return r.account }
func (r *ReallocateMintCloseAuthorityRequest) RentPayerKey() *types.PublicKey { return r.rentPayer }
func (r *ReallocateMintCloseAuthorityRequest) OwnerKey() *types.PublicKey     { return r.owner }
func (r *ReallocateMintCloseAuthorityRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *ReallocateMintCloseAuthorityRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *ReallocateMintCloseAuthorityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ReallocateMintCloseAuthorityRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ReallocateMintCloseAuthorityRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ReallocateMintCloseAuthorityResponse reports the built transaction
// alongside what it resizes Account for.
type ReallocateMintCloseAuthorityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Owner   string `json:"owner"`
	Program string `json:"program"`

	// TargetSize is the total account size GetAccountDataSize reported for
	// Account's existing extensions plus MintCloseAuthority, asked of the
	// deployed program rather than recomputed here.
	TargetSize string `json:"target_size"`

	// Rent reports what funds the resize: the shortfall between
	// TargetSize's rent-exemption minimum and Account's actual current
	// lamports, zero when Account already holds enough.
	Rent SystemPayer `json:"rent"`
	Fee  SystemPayer `json:"fee"`
}

func NewReallocateMintCloseAuthorityResponse(
	tx *types.Transaction, raw, message []byte,
	rentPayer, feePayer, account, owner, tokenProgram, nonceAuthority *types.PublicKey,
	targetSize, rentShortfall, fee uint64,
) *ReallocateMintCloseAuthorityResponse {
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

	return &ReallocateMintCloseAuthorityResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Owner:           owner.Base58(),
		Program:         tokenProgram.Base58(),
		TargetSize:      strconv.FormatUint(targetSize, 10),
		Rent:            newSystemPayer(rentPayer, rentShortfall),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// ReallocateTransferFeeAmountRequest checks whether Account already holds
// room for TransferFeeAmount, and grows it if not.
//
// Unlike TransferFeeConfig, TransferFeeAmount is exactly the token-account
// extension Reallocate's own account list expects: this is the endpoint
// that actually succeeds, preparing a destination to receive a transfer
// from a fee-charging mint. Without it, any transfer that computes a
// non-zero fee fails as InvalidState the moment the program tries to
// withhold into an extension the account never reserved room for.
//
// The instruction itself only ever needs the one new extension type being
// added: Reallocate reads Account's own existing extensions on chain and
// unions them with whatever this sends, so a caller never resends what is
// already there. Getting the resize's rent right is this handler's own
// job, not the instruction's — it reads Account's current extensions and
// actual lamports itself, asks GetAccountDataSize for the full target size
// once TransferFeeAmount is unioned in, and only then knows RentPayer's
// shortfall.
type ReallocateTransferFeeAmountRequest struct {
	// Account is the token account to check and, if needed, grow. It must
	// already exist and be owned by Program.
	Account string `json:"account" example:""`

	// RentPayer funds whatever the resize costs, a distinct role from
	// Owner: Owner authorizes the account being touched, RentPayer covers
	// what that costs, and they need not be the same key.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Owner is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. Unlike every other Token endpoint, this
	// is not the usual either-program field: a classic Token account's
	// layout is fixed at 165 bytes forever, with no TLV region to grow
	// into, so classic Token is rejected here rather than left to fail on
	// chain.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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

	account         *types.PublicKey
	rentPayer       *types.PublicKey
	owner           *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *ReallocateTransferFeeAmountRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.rentPayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
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
	// Unlike every other Token endpoint, which accepts either program
	// because the instruction genuinely works on both, an extension has
	// nowhere to live on a classic Token account: that layout is fixed at
	// 165 bytes forever, with no TLV region to grow into at all. Rejecting
	// classic Token here is a structural fact about the account, not a
	// preference, so it is checked before the request ever reaches the
	// chain rather than left to come back as an on-chain rejection.
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ReallocateTransferFeeAmountRequest) AccountKey() *types.PublicKey   { return r.account }
func (r *ReallocateTransferFeeAmountRequest) RentPayerKey() *types.PublicKey { return r.rentPayer }
func (r *ReallocateTransferFeeAmountRequest) OwnerKey() *types.PublicKey     { return r.owner }
func (r *ReallocateTransferFeeAmountRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *ReallocateTransferFeeAmountRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *ReallocateTransferFeeAmountRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ReallocateTransferFeeAmountRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ReallocateTransferFeeAmountRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ReallocateTransferFeeAmountResponse reports the built transaction
// alongside what it resizes Account for.
type ReallocateTransferFeeAmountResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Owner   string `json:"owner"`
	Program string `json:"program"`

	// TargetSize is the total account size GetAccountDataSize reported for
	// Account's existing extensions plus TransferFeeAmount, asked of the
	// deployed program rather than recomputed here.
	TargetSize string `json:"target_size"`

	// Rent reports what funds the resize: the shortfall between
	// TargetSize's rent-exemption minimum and Account's actual current
	// lamports, zero when Account already holds enough.
	Rent SystemPayer `json:"rent"`
	Fee  SystemPayer `json:"fee"`
}

func NewReallocateTransferFeeAmountResponse(
	tx *types.Transaction, raw, message []byte,
	rentPayer, feePayer, account, owner, tokenProgram, nonceAuthority *types.PublicKey,
	targetSize, rentShortfall, fee uint64,
) *ReallocateTransferFeeAmountResponse {
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

	return &ReallocateTransferFeeAmountResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Owner:           owner.Base58(),
		Program:         tokenProgram.Base58(),
		TargetSize:      strconv.FormatUint(targetSize, 10),
		Rent:            newSystemPayer(rentPayer, rentShortfall),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// ReallocateConfidentialTransferMintRequest checks whether Account already
// holds room for ConfidentialTransferMint, and grows it if not.
//
// ConfidentialTransferMint is a mint-side extension in the interface
// crate's own numbering, not one Reallocate's own account list ever
// expects — that list is always a token account, since a mint's extension
// set is fixed forever at initialize-mint2 and Reallocate has no path back
// into it. Nothing here stops a caller from naming this type anyway; the
// deployed program is what rejects it, not this endpoint, the same as
// every other place in this API where a wrong role is a chain error rather
// than a 400.
//
// The instruction itself only ever needs the one new extension type being
// added: Reallocate reads Account's own existing extensions on chain and
// unions them with whatever this sends, so a caller never resends what is
// already there. Getting the resize's rent right is this handler's own
// job, not the instruction's — it reads Account's current extensions and
// actual lamports itself, asks GetAccountDataSize for the full target size
// once ConfidentialTransferMint is unioned in, and only then knows
// RentPayer's shortfall.
type ReallocateConfidentialTransferMintRequest struct {
	// Account is the token account to check and, if needed, grow. It must
	// already exist and be owned by Program.
	Account string `json:"account" example:""`

	// RentPayer funds whatever the resize costs, a distinct role from
	// Owner: Owner authorizes the account being touched, RentPayer covers
	// what that costs, and they need not be the same key.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Owner is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. Unlike every other Token endpoint, this
	// is not the usual either-program field: a classic Token account's
	// layout is fixed at 165 bytes forever, with no TLV region to grow
	// into, so classic Token is rejected here rather than left to fail on
	// chain.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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

	account         *types.PublicKey
	rentPayer       *types.PublicKey
	owner           *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *ReallocateConfidentialTransferMintRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.rentPayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
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
	// Unlike every other Token endpoint, which accepts either program
	// because the instruction genuinely works on both, an extension has
	// nowhere to live on a classic Token account: that layout is fixed at
	// 165 bytes forever, with no TLV region to grow into at all. Rejecting
	// classic Token here is a structural fact about the account, not a
	// preference, so it is checked before the request ever reaches the
	// chain rather than left to come back as an on-chain rejection.
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ReallocateConfidentialTransferMintRequest) AccountKey() *types.PublicKey {
	return r.account
}
func (r *ReallocateConfidentialTransferMintRequest) RentPayerKey() *types.PublicKey {
	return r.rentPayer
}
func (r *ReallocateConfidentialTransferMintRequest) OwnerKey() *types.PublicKey { return r.owner }
func (r *ReallocateConfidentialTransferMintRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}
func (r *ReallocateConfidentialTransferMintRequest) Blockhash() *types.Hash { return r.rbh }
func (r *ReallocateConfidentialTransferMintRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ReallocateConfidentialTransferMintRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ReallocateConfidentialTransferMintRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ReallocateConfidentialTransferMintResponse reports the built transaction
// alongside what it resizes Account for.
type ReallocateConfidentialTransferMintResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Owner   string `json:"owner"`
	Program string `json:"program"`

	// TargetSize is the total account size GetAccountDataSize reported for
	// Account's existing extensions plus ConfidentialTransferMint, asked of
	// the deployed program rather than recomputed here.
	TargetSize string `json:"target_size"`

	// Rent reports what funds the resize: the shortfall between
	// TargetSize's rent-exemption minimum and Account's actual current
	// lamports, zero when Account already holds enough.
	Rent SystemPayer `json:"rent"`
	Fee  SystemPayer `json:"fee"`
}

func NewReallocateConfidentialTransferMintResponse(
	tx *types.Transaction, raw, message []byte,
	rentPayer, feePayer, account, owner, tokenProgram, nonceAuthority *types.PublicKey,
	targetSize, rentShortfall, fee uint64,
) *ReallocateConfidentialTransferMintResponse {
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

	return &ReallocateConfidentialTransferMintResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Owner:           owner.Base58(),
		Program:         tokenProgram.Base58(),
		TargetSize:      strconv.FormatUint(targetSize, 10),
		Rent:            newSystemPayer(rentPayer, rentShortfall),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// ReallocateConfidentialTransferAccountRequest checks whether Account
// already holds room for ConfidentialTransferAccount, and grows it if not.
//
// Unlike ConfidentialTransferMint, ConfidentialTransferAccount is exactly
// the token-account extension Reallocate's own account list expects: this
// is the endpoint that actually succeeds, preparing an account for
// extensions/confidential-transfer-account/configure-account -- without
// it that call fails as InvalidAccountData the moment the program tries
// to write pending/available balance ciphertexts into an account that
// never reserved the 295 bytes those TLV fields need.
//
// The instruction itself only ever needs the one new extension type being
// added: Reallocate reads Account's own existing extensions on chain and
// unions them with whatever this sends, so a caller never resends what is
// already there. Getting the resize's rent right is this handler's own
// job, not the instruction's — it reads Account's current extensions and
// actual lamports itself, asks GetAccountDataSize for the full target size
// once ConfidentialTransferAccount is unioned in, and only then knows
// RentPayer's shortfall.
type ReallocateConfidentialTransferAccountRequest struct {
	// Account is the token account to check and, if needed, grow. It must
	// already exist and be owned by Program.
	Account string `json:"account" example:""`

	// RentPayer funds whatever the resize costs, a distinct role from
	// Owner: Owner authorizes the account being touched, RentPayer covers
	// what that costs, and they need not be the same key.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Owner is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// IncludeConfidentialTransferFeeAmount also reserves room for the
	// ConfidentialTransferFeeAmount extension, in the same Reallocate
	// instruction. Set it when Account's mint charges a transfer fee: on
	// such a mint, configure-account itself initializes
	// ConfidentialTransferFeeAmount alongside ConfidentialTransferAccount,
	// so the account needs room for both before it runs, and the two have
	// to be reserved together -- reallocating for one and then the other
	// leaves room for only one, since neither exists yet for the second
	// call to count.
	IncludeConfidentialTransferFeeAmount bool `json:"include_confidential_transfer_fee_amount" example:"false"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. Unlike every other Token endpoint, this
	// is not the usual either-program field: a classic Token account's
	// layout is fixed at 165 bytes forever, with no TLV region to grow
	// into, so classic Token is rejected here rather than left to fail on
	// chain.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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

	account         *types.PublicKey
	rentPayer       *types.PublicKey
	owner           *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *ReallocateConfidentialTransferAccountRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.rentPayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
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
	// Unlike every other Token endpoint, which accepts either program
	// because the instruction genuinely works on both, an extension has
	// nowhere to live on a classic Token account: that layout is fixed at
	// 165 bytes forever, with no TLV region to grow into at all. Rejecting
	// classic Token here is a structural fact about the account, not a
	// preference, so it is checked before the request ever reaches the
	// chain rather than left to come back as an on-chain rejection.
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ReallocateConfidentialTransferAccountRequest) AccountKey() *types.PublicKey {
	return r.account
}
func (r *ReallocateConfidentialTransferAccountRequest) RentPayerKey() *types.PublicKey {
	return r.rentPayer
}
func (r *ReallocateConfidentialTransferAccountRequest) OwnerKey() *types.PublicKey { return r.owner }
func (r *ReallocateConfidentialTransferAccountRequest) WithConfidentialTransferFeeAmount() bool {
	return r.IncludeConfidentialTransferFeeAmount
}
func (r *ReallocateConfidentialTransferAccountRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}
func (r *ReallocateConfidentialTransferAccountRequest) Blockhash() *types.Hash { return r.rbh }
func (r *ReallocateConfidentialTransferAccountRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ReallocateConfidentialTransferAccountRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ReallocateConfidentialTransferAccountRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ReallocateConfidentialTransferAccountResponse reports the built transaction
// alongside what it resizes Account for.
type ReallocateConfidentialTransferAccountResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Owner   string `json:"owner"`
	Program string `json:"program"`

	// TargetSize is the total account size GetAccountDataSize reported for
	// Account's existing extensions plus ConfidentialTransferAccount, asked of
	// the deployed program rather than recomputed here.
	TargetSize string `json:"target_size"`

	// Rent reports what funds the resize: the shortfall between
	// TargetSize's rent-exemption minimum and Account's actual current
	// lamports, zero when Account already holds enough.
	Rent SystemPayer `json:"rent"`
	Fee  SystemPayer `json:"fee"`
}

func NewReallocateConfidentialTransferAccountResponse(
	tx *types.Transaction, raw, message []byte,
	rentPayer, feePayer, account, owner, tokenProgram, nonceAuthority *types.PublicKey,
	targetSize, rentShortfall, fee uint64,
) *ReallocateConfidentialTransferAccountResponse {
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

	return &ReallocateConfidentialTransferAccountResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Owner:           owner.Base58(),
		Program:         tokenProgram.Base58(),
		TargetSize:      strconv.FormatUint(targetSize, 10),
		Rent:            newSystemPayer(rentPayer, rentShortfall),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// ConfigureAccountRequest attaches the ConfidentialTransferAccount
// extension to Account, the token-account-side counterpart to
// extensions/confidential-transfer-mint/initialize -- Mint has to already
// carry ConfidentialTransferMint, and Account has to already hold room
// for this extension (see extensions/confidential-transfer-account/
// reallocate) before this can succeed.
//
// This builds two instructions in one transaction: ConfigureAccount
// itself, and the VerifyPubkeyValidity instruction it depends on as its
// very next sibling (proof_instruction_offset = 1) -- the program has to
// be convinced ElgamalPubkey has a known secret key before letting Account
// claim it, and this is the only way that ever gets checked. PubkeyProof
// is built by tool/prove/pubkey-validity from the same secret key
// ElgamalPubkey was derived from (tool/generate/elgamal-keypair); a proof
// built against a different key fails here, before a transaction is ever
// built, via a local check equivalent to what the deployed verifier
// itself would run.
type ConfigureAccountRequest struct {
	// Account is the token account this attaches to. It must already
	// exist, be owned by Program, and already hold enough space (see
	// extensions/confidential-transfer-account/reallocate).
	Account string `json:"account" example:""`

	// Mint must already carry the ConfidentialTransferMint extension (see
	// extensions/confidential-transfer-mint/initialize).
	Mint string `json:"mint" example:""`

	// Owner is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// ElgamalPubkey is the ElGamal public key Account's confidential
	// balance will be encrypted under, base58-encoded -- a raw 32-byte
	// ristretto255 value, not a Solana address (see
	// tool/generate/elgamal-keypair).
	ElgamalPubkey string `json:"elgamal_pubkey" example:""`

	// PubkeyProof proves whoever built this request knows the secret key
	// ElgamalPubkey was derived from, base58-encoded (see
	// tool/prove/pubkey-validity).
	PubkeyProof string `json:"pubkey_proof" example:""`

	// AeKey encrypts Account's decryptable_zero_balance (always zero -- a
	// freshly configured account has no balance yet), base58-encoded --
	// a raw 16-byte AES-128-GCM-SIV key, not a Solana address. Upstream
	// derives this by signing a fixed message with the account owner's
	// real wallet key, which this API never holds; the caller derives it
	// themselves and supplies the raw bytes.
	AeKey string `json:"ae_key" example:""`

	// MaximumPendingBalanceCreditCounter caps how many deposits and
	// transfers Account can receive before apply-pending-balance (not yet
	// built) has to run before it can receive more.
	MaximumPendingBalanceCreditCounter string `json:"maximum_pending_balance_credit_counter" example:"65536"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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

	account                            *types.PublicKey
	mint                               *types.PublicKey
	owner                              *types.PublicKey
	elgamalPubkey                      []byte
	pubkeyProof                        []byte
	aeKey                              []byte
	maximumPendingBalanceCreditCounter uint64
	feePayer                           *types.PublicKey
	rbh                                *types.Hash
	dna                                *types.PublicKey
	tokenProgramID                     *types.PublicKey
	multisigSigners                    []*types.PublicKey
}

func (r *ConfigureAccountRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}

	if r.elgamalPubkey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.ElgamalPubkey), 32); err != nil {
		return errors.New("elgamal_pubkey: " + err.Error())
	}
	if r.pubkeyProof, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.PubkeyProof), core.PubkeyValidityProofLen); err != nil {
		return errors.New("pubkey_proof: " + err.Error())
	}
	if r.aeKey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.AeKey), core.AeKeyLen); err != nil {
		return errors.New("ae_key: " + err.Error())
	}

	maximumPendingBalanceCreditCounter := strings.TrimSpace(r.MaximumPendingBalanceCreditCounter)
	if maximumPendingBalanceCreditCounter == "" {
		return errors.New("maximum_pending_balance_credit_counter is required")
	}
	if r.maximumPendingBalanceCreditCounter, err = strconv.ParseUint(maximumPendingBalanceCreditCounter, 10, 64); err != nil {
		return errors.New("maximum_pending_balance_credit_counter: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ConfigureAccountRequest) AccountKey() *types.PublicKey { return r.account }
func (r *ConfigureAccountRequest) MintKey() *types.PublicKey    { return r.mint }
func (r *ConfigureAccountRequest) OwnerKey() *types.PublicKey   { return r.owner }
func (r *ConfigureAccountRequest) ToElgamalPubkey() []byte      { return r.elgamalPubkey }
func (r *ConfigureAccountRequest) ToPubkeyProof() []byte        { return r.pubkeyProof }
func (r *ConfigureAccountRequest) ToAeKey() []byte              { return r.aeKey }
func (r *ConfigureAccountRequest) ToMaximumPendingBalanceCreditCounter() uint64 {
	return r.maximumPendingBalanceCreditCounter
}
func (r *ConfigureAccountRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *ConfigureAccountRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *ConfigureAccountRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ConfigureAccountRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ConfigureAccountRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ConfigureAccountResponse reports the built transaction alongside the
// confidential transfer configuration it attaches.
type ConfigureAccountResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account                            string `json:"account"`
	Mint                               string `json:"mint"`
	Owner                              string `json:"owner"`
	ElgamalPubkey                      string `json:"elgamal_pubkey"`
	MaximumPendingBalanceCreditCounter string `json:"maximum_pending_balance_credit_counter"`
	Program                            string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewConfigureAccountResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, account, mint, owner, tokenProgram, nonceAuthority *types.PublicKey,
	elgamalPubkey []byte, maximumPendingBalanceCreditCounter, fee uint64,
) *ConfigureAccountResponse {
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

	return &ConfigureAccountResponse{
		Transaction:                        codec.Base64.Encode(raw),
		Message:                            codec.Base64.Encode(message),
		RecentBlockhash:                    tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                        keys,
		Signers:                            signers,
		NonceAuthority:                     nonceAuth,
		Account:                            account.Base58(),
		Mint:                               mint.Base58(),
		Owner:                              owner.Base58(),
		ElgamalPubkey:                      codec.Base58.Encode(elgamalPubkey),
		MaximumPendingBalanceCreditCounter: strconv.FormatUint(maximumPendingBalanceCreditCounter, 10),
		Program:                            tokenProgram.Base58(),
		Fee:                                newSystemPayer(feePayer, fee),
	}
}

// ApproveAccountRequest flips Account's ConfidentialTransferAccount.approved
// flag, authorized by Authority -- Mint's ConfidentialTransferMint
// authority (see extensions/confidential-transfer-mint/initialize or
// /update), not Account's own owner. This is only ever needed when Mint
// was set up with auto_approve_new_accounts false; against a mint set up
// with it true, configure-account already leaves a usable account and
// this call is unnecessary (though not rejected -- the deployed program
// accepts it regardless, it just has nothing left to flip).
type ApproveAccountRequest struct {
	// Account is the token account to approve. It must already carry the
	// ConfidentialTransferAccount extension (see configure-account).
	Account string `json:"account" example:""`

	// Mint must already carry the ConfidentialTransferMint extension.
	Mint string `json:"mint" example:""`

	// Authority is the authority initialize (or update) named, or its
	// multisig for a multisig-owned authority (see MultisigSigners).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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

	account         *types.PublicKey
	mint            *types.PublicKey
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *ApproveAccountRequest) ValidateRequest() error {
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ApproveAccountRequest) AccountKey() *types.PublicKey   { return r.account }
func (r *ApproveAccountRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *ApproveAccountRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *ApproveAccountRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *ApproveAccountRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *ApproveAccountRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ApproveAccountRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ApproveAccountRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ApproveAccountResponse reports the built transaction.
type ApproveAccountResponse struct {
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

	Fee SystemPayer `json:"fee"`
}

func NewApproveAccountResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, account, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *ApproveAccountResponse {
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

	return &ApproveAccountResponse{
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
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// DepositRequest moves Amount from Account's ordinary public balance into
// its ConfidentialTransferAccount pending balance -- the entry point into
// the confidential side from a plain SPL balance. Account must already
// carry the extension (see configure-account).
//
// No zero-knowledge proof is needed: the amount is still public at this
// instant (it is leaving the public balance, which anyone can already
// see), so there is nothing to prove about it yet.
type DepositRequest struct {
	// Account is debited from its public balance and credited to its own
	// confidential pending balance -- the same account both ends.
	Account string `json:"account" example:""`

	// Mint is what Account must hold, and is the source of the decimals
	// checked against.
	Mint string `json:"mint" example:""`

	// Authority is Account's owner, or its delegate for no more than what
	// was delegated -- the same role a plain transfer or burn checks,
	// since this spends from the public balance like either of those.
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Amount is the raw base-unit count to move, not a UI decimal string.
	Amount string `json:"amount" example:"1000"`

	// Decimals must equal Mint's own, the same check every other
	// *Checked-shaped instruction in this API runs rather than trusting
	// the caller's figure.
	Decimals uint8 `json:"decimals" example:"0"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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

	account         *types.PublicKey
	mint            *types.PublicKey
	authority       *types.PublicKey
	amount          uint64
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *DepositRequest) ValidateRequest() error {
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

	amount := strings.TrimSpace(r.Amount)
	if amount == "" {
		return errors.New("amount is required")
	}
	if r.amount, err = strconv.ParseUint(amount, 10, 64); err != nil {
		return errors.New("amount: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *DepositRequest) AccountKey() *types.PublicKey   { return r.account }
func (r *DepositRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *DepositRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *DepositRequest) ToAmount() uint64               { return r.amount }
func (r *DepositRequest) ToDecimals() uint8              { return r.Decimals }
func (r *DepositRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *DepositRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *DepositRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *DepositRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *DepositRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// DepositResponse reports the built transaction.
type DepositResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account   string `json:"account"`
	Mint      string `json:"mint"`
	Authority string `json:"authority"`
	Amount    string `json:"amount"`
	Decimals  uint8  `json:"decimals"`
	Program   string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewDepositResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, account, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	amount uint64, decimals uint8, fee uint64,
) *DepositResponse {
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

	return &DepositResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		Amount:          strconv.FormatUint(amount, 10),
		Decimals:        decimals,
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// ApplyPendingBalanceRequest moves whatever Deposit and incoming
// Transfers have accumulated in Account's encrypted pending balance into
// its available balance, the one Transfer and Withdraw actually spend
// from. Nothing received since Account's last apply can be spent until
// this runs.
//
// No zero-knowledge proof is needed: the program does the pending-into-
// available ElGamal addition itself. NewAvailableBalance is this
// endpoint's own bookkeeping catching up to that addition -- the total
// available balance Account should hold once this lands, AE-encrypted
// here under AeKey (EncryptAeAmount) the same way configure-account's
// decryptable_zero_balance was, so the account's cheap-to-read cache
// stays in sync with the ElGamal ciphertext the program actually
// updates. This endpoint does not track what that total should be on its
// own (it never decrypts a confidential balance); the caller supplies it.
type ApplyPendingBalanceRequest struct {
	// Account is the token account to apply. It must already carry the
	// ConfidentialTransferAccount extension (see configure-account).
	Account string `json:"account" example:""`

	// Authority is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// ExpectedPendingBalanceCreditCounter is how many pending-balance
	// credits (deposits and incoming transfers) landed on Account since
	// its last apply. The program rejects a mismatched count rather than
	// silently applying a different set of credits than the caller
	// believes it is catching up on.
	ExpectedPendingBalanceCreditCounter string `json:"expected_pending_balance_credit_counter" example:"1"`

	// NewAvailableBalance is the total available balance Account should
	// hold once this apply lands, in raw base units -- not a delta, the
	// full new total. AeKey encrypts it into the wire value this
	// instruction actually carries.
	NewAvailableBalance string `json:"new_available_balance" example:"10"`

	// AeKey encrypts NewAvailableBalance, base58-encoded -- a raw 16-byte
	// AES-128-GCM-SIV key, not a Solana address (see
	// tool/derive/ae-key-seed-message and tool/derive/ae-key), the same
	// key Account's own decryptable_zero_balance was set up under.
	AeKey string `json:"ae_key" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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

	account                             *types.PublicKey
	authority                           *types.PublicKey
	expectedPendingBalanceCreditCounter uint64
	newAvailableBalance                 uint64
	aeKey                               []byte
	feePayer                            *types.PublicKey
	rbh                                 *types.Hash
	dna                                 *types.PublicKey
	tokenProgramID                      *types.PublicKey
	multisigSigners                     []*types.PublicKey
}

func (r *ApplyPendingBalanceRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}

	counter := strings.TrimSpace(r.ExpectedPendingBalanceCreditCounter)
	if counter == "" {
		return errors.New("expected_pending_balance_credit_counter is required")
	}
	if r.expectedPendingBalanceCreditCounter, err = strconv.ParseUint(counter, 10, 64); err != nil {
		return errors.New("expected_pending_balance_credit_counter: " + err.Error())
	}

	balance := strings.TrimSpace(r.NewAvailableBalance)
	if balance == "" {
		return errors.New("new_available_balance is required")
	}
	if r.newAvailableBalance, err = strconv.ParseUint(balance, 10, 64); err != nil {
		return errors.New("new_available_balance: " + err.Error())
	}

	if r.aeKey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.AeKey), core.AeKeyLen); err != nil {
		return errors.New("ae_key: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ApplyPendingBalanceRequest) AccountKey() *types.PublicKey   { return r.account }
func (r *ApplyPendingBalanceRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *ApplyPendingBalanceRequest) ToExpectedPendingBalanceCreditCounter() uint64 {
	return r.expectedPendingBalanceCreditCounter
}
func (r *ApplyPendingBalanceRequest) ToNewAvailableBalance() uint64 { return r.newAvailableBalance }
func (r *ApplyPendingBalanceRequest) ToAeKey() []byte               { return r.aeKey }
func (r *ApplyPendingBalanceRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *ApplyPendingBalanceRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *ApplyPendingBalanceRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ApplyPendingBalanceRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ApplyPendingBalanceRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ApplyPendingBalanceResponse reports the built transaction.
type ApplyPendingBalanceResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account                             string `json:"account"`
	Authority                           string `json:"authority"`
	ExpectedPendingBalanceCreditCounter string `json:"expected_pending_balance_credit_counter"`
	NewAvailableBalance                 string `json:"new_available_balance"`
	Program                             string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewApplyPendingBalanceResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, account, authority, tokenProgram, nonceAuthority *types.PublicKey,
	expectedPendingBalanceCreditCounter, newAvailableBalance, fee uint64,
) *ApplyPendingBalanceResponse {
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

	return &ApplyPendingBalanceResponse{
		Transaction:                         codec.Base64.Encode(raw),
		Message:                             codec.Base64.Encode(message),
		RecentBlockhash:                     tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                         keys,
		Signers:                             signers,
		NonceAuthority:                      nonceAuth,
		Account:                             account.Base58(),
		Authority:                           authority.Base58(),
		ExpectedPendingBalanceCreditCounter: strconv.FormatUint(expectedPendingBalanceCreditCounter, 10),
		NewAvailableBalance:                 strconv.FormatUint(newAvailableBalance, 10),
		Program:                             tokenProgram.Base58(),
		Fee:                                 newSystemPayer(feePayer, fee),
	}
}

// ConfidentialTransferRequest moves an amount confidentially from Source
// to Destination -- neither the amount nor either account's resulting
// balance ever appears in plaintext on chain. Both accounts must already
// carry the ConfidentialTransferAccount extension (see configure-account
// and, for Destination, approve-account if Mint requires it).
//
// This builds only the Transfer instruction itself. The three
// zero-knowledge proofs it depends on (equality, ciphertext validity, and
// the batched range proof) must already be verified into context-state
// accounts of their own: build them with tool/prove/confidential-transfer,
// create their accounts with zk-elgamal-proof/context-state/create, and
// verify each with context-state/verify. Carrying them inline instead does
// not fit -- all three plus this instruction came to 3232 bytes against
// the 1232-byte transaction limit.
//
// NewSourceDecryptableAvailableBalance, AuditorCiphertextLo, and
// AuditorCiphertextHi are the values tool/prove/confidential-transfer
// returned alongside those proofs, and must come from that same call: a
// later call draws new randomness, so its values no longer match the
// proofs already verified into the context-state accounts.
type ConfidentialTransferRequest struct {
	// Source is debited. It must already carry the
	// ConfidentialTransferAccount extension.
	Source string `json:"source" example:""`

	// Mint is what both Source and Destination must hold, and must
	// already carry the ConfidentialTransferMint extension.
	Mint string `json:"mint" example:""`

	// Destination is credited. It must already carry the
	// ConfidentialTransferAccount extension.
	Destination string `json:"destination" example:""`

	// Owner is Source's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// EqualityContextStateAccount holds the verified
	// CiphertextCommitmentEquality proof's context (see
	// context-state/verify/ciphertext-commitment-equality).
	EqualityContextStateAccount string `json:"equality_context_state_account" example:""`

	// CiphertextValidityContextStateAccount holds the verified
	// BatchedGroupedCiphertext3HandlesValidity proof's context (see
	// context-state/verify/batched-grouped-ciphertext-3-handles-validity).
	CiphertextValidityContextStateAccount string `json:"ciphertext_validity_context_state_account" example:""`

	// RangeProofContextStateAccount holds the verified BatchedRangeProofU128
	// proof's context (see context-state/verify/batched-range-proof-u128).
	RangeProofContextStateAccount string `json:"range_proof_context_state_account" example:""`

	// NewSourceDecryptableAvailableBalance is tool/prove/confidential-transfer's
	// own field of the same name, base58-encoded (36 bytes).
	NewSourceDecryptableAvailableBalance string `json:"new_source_decryptable_available_balance" example:""`

	// AuditorCiphertextLo is tool/prove/confidential-transfer's own
	// auditor_ciphertext_lo, base58-encoded (64 bytes).
	AuditorCiphertextLo string `json:"auditor_ciphertext_lo" example:""`

	// AuditorCiphertextHi is tool/prove/confidential-transfer's own
	// auditor_ciphertext_hi, base58-encoded (64 bytes).
	AuditorCiphertextHi string `json:"auditor_ciphertext_hi" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty,
	// Owner itself does not sign; the named members do, in its place.
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

	source                               *types.PublicKey
	mint                                 *types.PublicKey
	destination                          *types.PublicKey
	owner                                *types.PublicKey
	equalityContext                      *types.PublicKey
	validityContext                      *types.PublicKey
	rangeContext                         *types.PublicKey
	newSourceDecryptableAvailableBalance []byte
	auditorCiphertextLo                  []byte
	auditorCiphertextHi                  []byte
	feePayer                             *types.PublicKey
	rbh                                  *types.Hash
	dna                                  *types.PublicKey
	tokenProgramID                       *types.PublicKey
	multisigSigners                      []*types.PublicKey
}

func (r *ConfidentialTransferRequest) ValidateRequest() error {
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
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}

	if r.equalityContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.EqualityContextStateAccount)); err != nil {
		return errors.New("equality_context_state_account: " + err.Error())
	}
	if r.validityContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.CiphertextValidityContextStateAccount)); err != nil {
		return errors.New("ciphertext_validity_context_state_account: " + err.Error())
	}
	if r.rangeContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RangeProofContextStateAccount)); err != nil {
		return errors.New("range_proof_context_state_account: " + err.Error())
	}

	if r.newSourceDecryptableAvailableBalance, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.NewSourceDecryptableAvailableBalance), core.AeCiphertextLen); err != nil {
		return errors.New("new_source_decryptable_available_balance: " + err.Error())
	}
	if r.auditorCiphertextLo, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.AuditorCiphertextLo), 64); err != nil {
		return errors.New("auditor_ciphertext_lo: " + err.Error())
	}
	if r.auditorCiphertextHi, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.AuditorCiphertextHi), 64); err != nil {
		return errors.New("auditor_ciphertext_hi: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ConfidentialTransferRequest) SourceKey() *types.PublicKey      { return r.source }
func (r *ConfidentialTransferRequest) MintKey() *types.PublicKey        { return r.mint }
func (r *ConfidentialTransferRequest) DestinationKey() *types.PublicKey { return r.destination }
func (r *ConfidentialTransferRequest) OwnerKey() *types.PublicKey       { return r.owner }
func (r *ConfidentialTransferRequest) EqualityContextKey() *types.PublicKey {
	return r.equalityContext
}
func (r *ConfidentialTransferRequest) ValidityContextKey() *types.PublicKey {
	return r.validityContext
}
func (r *ConfidentialTransferRequest) RangeContextKey() *types.PublicKey { return r.rangeContext }
func (r *ConfidentialTransferRequest) ToNewSourceDecryptableAvailableBalance() []byte {
	return r.newSourceDecryptableAvailableBalance
}
func (r *ConfidentialTransferRequest) ToAuditorCiphertextLo() []byte { return r.auditorCiphertextLo }
func (r *ConfidentialTransferRequest) ToAuditorCiphertextHi() []byte { return r.auditorCiphertextHi }
func (r *ConfidentialTransferRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *ConfidentialTransferRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *ConfidentialTransferRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ConfidentialTransferRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ConfidentialTransferRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ConfidentialTransferResponse reports the built transaction.
type ConfidentialTransferResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Source      string `json:"source"`
	Mint        string `json:"mint"`
	Destination string `json:"destination"`
	Owner       string `json:"owner"`
	Program     string `json:"program"`

	EqualityContextStateAccount           string `json:"equality_context_state_account"`
	CiphertextValidityContextStateAccount string `json:"ciphertext_validity_context_state_account"`
	RangeProofContextStateAccount         string `json:"range_proof_context_state_account"`

	Fee SystemPayer `json:"fee"`
}

func NewConfidentialTransferResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, source, mint, destination, owner, tokenProgram, equalityContext, validityContext, rangeContext, nonceAuthority *types.PublicKey,
	fee uint64,
) *ConfidentialTransferResponse {
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

	return &ConfidentialTransferResponse{
		Transaction:                           codec.Base64.Encode(raw),
		Message:                               codec.Base64.Encode(message),
		RecentBlockhash:                       tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                           keys,
		Signers:                               signers,
		NonceAuthority:                        nonceAuth,
		Source:                                source.Base58(),
		Mint:                                  mint.Base58(),
		Destination:                           destination.Base58(),
		Owner:                                 owner.Base58(),
		Program:                               tokenProgram.Base58(),
		EqualityContextStateAccount:           equalityContext.Base58(),
		CiphertextValidityContextStateAccount: validityContext.Base58(),
		RangeProofContextStateAccount:         rangeContext.Base58(),
		Fee:                                   newSystemPayer(feePayer, fee),
	}
}

// ConfidentialMintRequest mints an encrypted amount into Account's pending
// confidential balance and adds it to Mint's confidential supply -- the amount
// never appears in plaintext on chain. Account must already carry the
// ConfidentialTransferAccount extension (see configure-account, and
// approve-account if the mint requires it) and Mint both
// ConfidentialMintBurn and ConfidentialTransferMint. Authorized by the mint's
// mint authority.
//
// This builds only the Mint instruction. The three zero-knowledge proofs it
// depends on must already be verified into context-state accounts: build them
// with tool/prove/confidential-mint, create their accounts with
// zk-elgamal-proof/context-state/create, and verify each with
// context-state/verify (or verify-from-account with a compute_unit_limit --
// the u128 range verifier costs about as much as a transaction's default
// compute budget).
//
// NewDecryptableSupply, AuditorCiphertextLo and AuditorCiphertextHi are the
// values tool/prove/confidential-mint returned alongside those proofs, and
// must come from that same call: a later call draws new randomness, so its
// values no longer match the proofs already verified.
type ConfidentialMintRequest struct {
	// Account is credited (its pending balance). It must already carry the
	// ConfidentialTransferAccount extension.
	Account string `json:"account" example:""`

	// Mint must carry ConfidentialMintBurn and ConfidentialTransferMint, and
	// is what Account holds.
	Mint string `json:"mint" example:""`

	// Authority is the mint's mint authority, or its multisig for a
	// multisig-owned one (see MultisigSigners).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// EqualityContextStateAccount holds the verified
	// CiphertextCommitmentEquality proof's context (see
	// context-state/verify/ciphertext-commitment-equality).
	EqualityContextStateAccount string `json:"equality_context_state_account" example:""`

	// CiphertextValidityContextStateAccount holds the verified
	// BatchedGroupedCiphertext3HandlesValidity proof's context (see
	// context-state/verify/batched-grouped-ciphertext-3-handles-validity).
	CiphertextValidityContextStateAccount string `json:"ciphertext_validity_context_state_account" example:""`

	// RangeProofContextStateAccount holds the verified BatchedRangeProofU128
	// proof's context (see context-state/verify/batched-range-proof-u128).
	RangeProofContextStateAccount string `json:"range_proof_context_state_account" example:""`

	// NewDecryptableSupply is tool/prove/confidential-mint's own field of the
	// same name, base58-encoded (36 bytes).
	NewDecryptableSupply string `json:"new_decryptable_supply" example:""`

	// AuditorCiphertextLo is tool/prove/confidential-mint's own
	// auditor_ciphertext_lo, base58-encoded (64 bytes).
	AuditorCiphertextLo string `json:"auditor_ciphertext_lo" example:""`

	// AuditorCiphertextHi is tool/prove/confidential-mint's own
	// auditor_ciphertext_hi, base58-encoded (64 bytes).
	AuditorCiphertextHi string `json:"auditor_ciphertext_hi" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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

	account              *types.PublicKey
	mint                 *types.PublicKey
	authority            *types.PublicKey
	equalityContext      *types.PublicKey
	validityContext      *types.PublicKey
	rangeContext         *types.PublicKey
	newDecryptableSupply []byte
	auditorCiphertextLo  []byte
	auditorCiphertextHi  []byte
	feePayer             *types.PublicKey
	rbh                  *types.Hash
	dna                  *types.PublicKey
	tokenProgramID       *types.PublicKey
	multisigSigners      []*types.PublicKey
}

func (r *ConfidentialMintRequest) ValidateRequest() error {
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

	if r.equalityContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.EqualityContextStateAccount)); err != nil {
		return errors.New("equality_context_state_account: " + err.Error())
	}
	if r.validityContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.CiphertextValidityContextStateAccount)); err != nil {
		return errors.New("ciphertext_validity_context_state_account: " + err.Error())
	}
	if r.rangeContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RangeProofContextStateAccount)); err != nil {
		return errors.New("range_proof_context_state_account: " + err.Error())
	}

	if r.newDecryptableSupply, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.NewDecryptableSupply), core.AeCiphertextLen); err != nil {
		return errors.New("new_decryptable_supply: " + err.Error())
	}
	if r.auditorCiphertextLo, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.AuditorCiphertextLo), 64); err != nil {
		return errors.New("auditor_ciphertext_lo: " + err.Error())
	}
	if r.auditorCiphertextHi, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.AuditorCiphertextHi), 64); err != nil {
		return errors.New("auditor_ciphertext_hi: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ConfidentialMintRequest) AccountKey() *types.PublicKey   { return r.account }
func (r *ConfidentialMintRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *ConfidentialMintRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *ConfidentialMintRequest) EqualityContextKey() *types.PublicKey {
	return r.equalityContext
}
func (r *ConfidentialMintRequest) ValidityContextKey() *types.PublicKey {
	return r.validityContext
}
func (r *ConfidentialMintRequest) RangeContextKey() *types.PublicKey { return r.rangeContext }
func (r *ConfidentialMintRequest) ToNewDecryptableSupply() []byte    { return r.newDecryptableSupply }
func (r *ConfidentialMintRequest) ToAuditorCiphertextLo() []byte     { return r.auditorCiphertextLo }
func (r *ConfidentialMintRequest) ToAuditorCiphertextHi() []byte     { return r.auditorCiphertextHi }
func (r *ConfidentialMintRequest) FeePayerKey() *types.PublicKey     { return r.feePayer }
func (r *ConfidentialMintRequest) Blockhash() *types.Hash            { return r.rbh }
func (r *ConfidentialMintRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ConfidentialMintRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ConfidentialMintRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ConfidentialMintResponse reports the built transaction.
type ConfidentialMintResponse struct {
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

	EqualityContextStateAccount           string `json:"equality_context_state_account"`
	CiphertextValidityContextStateAccount string `json:"ciphertext_validity_context_state_account"`
	RangeProofContextStateAccount         string `json:"range_proof_context_state_account"`

	Fee SystemPayer `json:"fee"`
}

func NewConfidentialMintResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, account, mint, authority, tokenProgram, equalityContext, validityContext, rangeContext, nonceAuthority *types.PublicKey,
	fee uint64,
) *ConfidentialMintResponse {
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

	return &ConfidentialMintResponse{
		Transaction:                           codec.Base64.Encode(raw),
		Message:                               codec.Base64.Encode(message),
		RecentBlockhash:                       tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                           keys,
		Signers:                               signers,
		NonceAuthority:                        nonceAuth,
		Account:                               account.Base58(),
		Mint:                                  mint.Base58(),
		Authority:                             authority.Base58(),
		Program:                               tokenProgram.Base58(),
		EqualityContextStateAccount:           equalityContext.Base58(),
		CiphertextValidityContextStateAccount: validityContext.Base58(),
		RangeProofContextStateAccount:         rangeContext.Base58(),
		Fee:                                   newSystemPayer(feePayer, fee),
	}
}

// ConfidentialBurnRequest burns an encrypted amount from Account's available
// confidential balance and adds it to Mint's pending burn -- the amount never
// appears in plaintext on chain. Account must carry the
// ConfidentialTransferAccount extension and Mint both ConfidentialMintBurn and
// ConfidentialTransferMint. Authorized by the account's owner, not the mint
// authority. The burn only reaches the confidential supply once the mint
// authority runs apply-pending-burn.
//
// This builds only the Burn instruction. The three zero-knowledge proofs it
// depends on must already be verified into context-state accounts: build them
// with tool/prove/confidential-burn, create their accounts with
// zk-elgamal-proof/context-state/create, and verify each with
// context-state/verify. NewDecryptableAvailableBalance and the auditor
// ciphertexts are the values that tool returned alongside those proofs, and
// must come from that same call.
type ConfidentialBurnRequest struct {
	// Account is debited (its available balance). It must already carry the
	// ConfidentialTransferAccount extension and hold at least the amount.
	Account string `json:"account" example:""`

	// Mint must carry ConfidentialBurnBurn and ConfidentialTransferMint, and
	// is what Account holds.
	Mint string `json:"mint" example:""`

	// Authority is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners) -- not the mint authority.
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// EqualityContextStateAccount holds the verified
	// CiphertextCommitmentEquality proof's context (see
	// context-state/verify/ciphertext-commitment-equality).
	EqualityContextStateAccount string `json:"equality_context_state_account" example:""`

	// CiphertextValidityContextStateAccount holds the verified
	// BatchedGroupedCiphertext3HandlesValidity proof's context (see
	// context-state/verify/batched-grouped-ciphertext-3-handles-validity).
	CiphertextValidityContextStateAccount string `json:"ciphertext_validity_context_state_account" example:""`

	// RangeProofContextStateAccount holds the verified BatchedRangeProofU128
	// proof's context (see context-state/verify/batched-range-proof-u128).
	RangeProofContextStateAccount string `json:"range_proof_context_state_account" example:""`

	// NewDecryptableAvailableBalance is tool/prove/confidential-burn's own
	// new_decryptable_available_balance, base58-encoded (36 bytes).
	NewDecryptableAvailableBalance string `json:"new_decryptable_available_balance" example:""`

	// AuditorCiphertextLo is tool/prove/confidential-burn's own
	// auditor_ciphertext_lo, base58-encoded (64 bytes).
	AuditorCiphertextLo string `json:"auditor_ciphertext_lo" example:""`

	// AuditorCiphertextHi is tool/prove/confidential-burn's own
	// auditor_ciphertext_hi, base58-encoded (64 bytes).
	AuditorCiphertextHi string `json:"auditor_ciphertext_hi" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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

	account                        *types.PublicKey
	mint                           *types.PublicKey
	authority                      *types.PublicKey
	equalityContext                *types.PublicKey
	validityContext                *types.PublicKey
	rangeContext                   *types.PublicKey
	newDecryptableAvailableBalance []byte
	auditorCiphertextLo            []byte
	auditorCiphertextHi            []byte
	feePayer                       *types.PublicKey
	rbh                            *types.Hash
	dna                            *types.PublicKey
	tokenProgramID                 *types.PublicKey
	multisigSigners                []*types.PublicKey
}

func (r *ConfidentialBurnRequest) ValidateRequest() error {
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

	if r.equalityContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.EqualityContextStateAccount)); err != nil {
		return errors.New("equality_context_state_account: " + err.Error())
	}
	if r.validityContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.CiphertextValidityContextStateAccount)); err != nil {
		return errors.New("ciphertext_validity_context_state_account: " + err.Error())
	}
	if r.rangeContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RangeProofContextStateAccount)); err != nil {
		return errors.New("range_proof_context_state_account: " + err.Error())
	}

	if r.newDecryptableAvailableBalance, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.NewDecryptableAvailableBalance), core.AeCiphertextLen); err != nil {
		return errors.New("new_decryptable_available_balance: " + err.Error())
	}
	if r.auditorCiphertextLo, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.AuditorCiphertextLo), 64); err != nil {
		return errors.New("auditor_ciphertext_lo: " + err.Error())
	}
	if r.auditorCiphertextHi, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.AuditorCiphertextHi), 64); err != nil {
		return errors.New("auditor_ciphertext_hi: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ConfidentialBurnRequest) AccountKey() *types.PublicKey   { return r.account }
func (r *ConfidentialBurnRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *ConfidentialBurnRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *ConfidentialBurnRequest) EqualityContextKey() *types.PublicKey {
	return r.equalityContext
}
func (r *ConfidentialBurnRequest) ValidityContextKey() *types.PublicKey {
	return r.validityContext
}
func (r *ConfidentialBurnRequest) RangeContextKey() *types.PublicKey { return r.rangeContext }
func (r *ConfidentialBurnRequest) ToNewDecryptableAvailableBalance() []byte {
	return r.newDecryptableAvailableBalance
}
func (r *ConfidentialBurnRequest) ToAuditorCiphertextLo() []byte { return r.auditorCiphertextLo }
func (r *ConfidentialBurnRequest) ToAuditorCiphertextHi() []byte { return r.auditorCiphertextHi }
func (r *ConfidentialBurnRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *ConfidentialBurnRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *ConfidentialBurnRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ConfidentialBurnRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ConfidentialBurnRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ConfidentialBurnResponse reports the built transaction.
type ConfidentialBurnResponse struct {
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

	EqualityContextStateAccount           string `json:"equality_context_state_account"`
	CiphertextValidityContextStateAccount string `json:"ciphertext_validity_context_state_account"`
	RangeProofContextStateAccount         string `json:"range_proof_context_state_account"`

	Fee SystemPayer `json:"fee"`
}

func NewConfidentialBurnResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, account, mint, authority, tokenProgram, equalityContext, validityContext, rangeContext, nonceAuthority *types.PublicKey,
	fee uint64,
) *ConfidentialBurnResponse {
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

	return &ConfidentialBurnResponse{
		Transaction:                           codec.Base64.Encode(raw),
		Message:                               codec.Base64.Encode(message),
		RecentBlockhash:                       tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                           keys,
		Signers:                               signers,
		NonceAuthority:                        nonceAuth,
		Account:                               account.Base58(),
		Mint:                                  mint.Base58(),
		Authority:                             authority.Base58(),
		Program:                               tokenProgram.Base58(),
		EqualityContextStateAccount:           equalityContext.Base58(),
		CiphertextValidityContextStateAccount: validityContext.Base58(),
		RangeProofContextStateAccount:         rangeContext.Base58(),
		Fee:                                   newSystemPayer(feePayer, fee),
	}
}

// InitializeTransferFeeConfigRequest attaches the TransferFeeConfig
// extension to Mint, fixing the fee rate every transfer-checked-with-fee
// withholds and who may later change it or withdraw what accumulates.
//
// This can only ever run in the narrow window every mint extension shares:
// after create-mint has allocated the account (sized to include this
// extension) and before initialize-mint2 locks the extension list forever.
// There is no path back into an already-initialized mint -- no Reallocate
// equivalent exists for mints at all, only for token accounts.
type InitializeTransferFeeConfigRequest struct {
	// Mint is the account this attaches to. It must already exist (see
	// create-mint) and not yet be initialized -- initialize-mint2 has to
	// run after this, never before.
	Mint string `json:"mint" example:""`

	// TransferFeeConfigAuthority may call set-transfer-fee later to change
	// the rate. Left empty, this capability is given up permanently:
	// unlike a mint or freeze authority, there is no later instruction that
	// grants one where none was set.
	TransferFeeConfigAuthority string `json:"transfer_fee_config_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// WithdrawWithheldAuthority may withdraw what
	// withdraw-withheld-tokens-from-mint/from-accounts moves. Left empty,
	// whatever accumulates as withheld fees can never be withdrawn from the
	// mint again -- harvest-withheld-tokens-to-mint still works from
	// accounts into the mint, but nothing can move it out from there.
	WithdrawWithheldAuthority string `json:"withdraw_withheld_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// TransferFeeBasisPoints is the fee rate, out of 10,000 (500 = 5%). The
	// program itself rejects anything over 10,000, so this is checked here
	// too rather than left to come back as an on-chain rejection.
	TransferFeeBasisPoints uint16 `json:"transfer_fee_basis_points" example:"500"`

	// MaximumFee caps what a single transfer-checked-with-fee ever
	// withholds, in raw base units, regardless of how large the transfer
	// is or what the rate above would otherwise compute.
	MaximumFee string `json:"maximum_fee" example:"1000000"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this
	// extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint                       *types.PublicKey
	transferFeeConfigAuthority *types.PublicKey
	withdrawWithheldAuthority  *types.PublicKey
	maximumFee                 uint64
	feePayer                   *types.PublicKey
	rbh                        *types.Hash
	dna                        *types.PublicKey
	tokenProgramID             *types.PublicKey
}

func (r *InitializeTransferFeeConfigRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}

	if a := strings.TrimSpace(r.TransferFeeConfigAuthority); a != "" {
		if r.transferFeeConfigAuthority, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("transfer_fee_config_authority: " + err.Error())
		}
	}

	if a := strings.TrimSpace(r.WithdrawWithheldAuthority); a != "" {
		if r.withdrawWithheldAuthority, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("withdraw_withheld_authority: " + err.Error())
		}
	}

	if r.TransferFeeBasisPoints > 10_000 {
		return fmt.Errorf("transfer_fee_basis_points: %d is outside the valid range [0, 10000]", r.TransferFeeBasisPoints)
	}

	maximumFee := strings.TrimSpace(r.MaximumFee)
	if maximumFee == "" {
		return errors.New("maximum_fee is required")
	}
	if r.maximumFee, err = strconv.ParseUint(maximumFee, 10, 64); err != nil {
		return errors.New("maximum_fee: " + err.Error())
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
	// Unlike every other Token endpoint, which accepts either program
	// because the instruction genuinely works on both, an extension has
	// nowhere to live on a classic Token mint: that layout is fixed at 82
	// bytes forever, with no TLV region to grow into at all.
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *InitializeTransferFeeConfigRequest) MintKey() *types.PublicKey { return r.mint }
func (r *InitializeTransferFeeConfigRequest) TransferFeeConfigAuthorityKey() *types.PublicKey {
	return r.transferFeeConfigAuthority
}
func (r *InitializeTransferFeeConfigRequest) WithdrawWithheldAuthorityKey() *types.PublicKey {
	return r.withdrawWithheldAuthority
}
func (r *InitializeTransferFeeConfigRequest) ToMaximumFee() uint64          { return r.maximumFee }
func (r *InitializeTransferFeeConfigRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *InitializeTransferFeeConfigRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *InitializeTransferFeeConfigRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *InitializeTransferFeeConfigRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeTransferFeeConfigResponse reports the built transaction
// alongside the fee configuration it attaches.
type InitializeTransferFeeConfigResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint                       string `json:"mint"`
	TransferFeeConfigAuthority string `json:"transfer_fee_config_authority,omitempty"`
	WithdrawWithheldAuthority  string `json:"withdraw_withheld_authority,omitempty"`
	TransferFeeBasisPoints     uint16 `json:"transfer_fee_basis_points"`
	MaximumFee                 string `json:"maximum_fee"`
	Program                    string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializeTransferFeeConfigResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, transferFeeConfigAuthority, withdrawWithheldAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	transferFeeBasisPoints uint16, maximumFee, fee uint64,
) *InitializeTransferFeeConfigResponse {
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

	res := &InitializeTransferFeeConfigResponse{
		Transaction:            codec.Base64.Encode(raw),
		Message:                codec.Base64.Encode(message),
		RecentBlockhash:        tx.Message.RecentBlockhash.Base58(),
		AccountKeys:            keys,
		Signers:                signers,
		NonceAuthority:         nonceAuth,
		Mint:                   mint.Base58(),
		TransferFeeBasisPoints: transferFeeBasisPoints,
		MaximumFee:             strconv.FormatUint(maximumFee, 10),
		Program:                tokenProgram.Base58(),
		Fee:                    newSystemPayer(feePayer, fee),
	}
	if !transferFeeConfigAuthority.IsNil() {
		res.TransferFeeConfigAuthority = transferFeeConfigAuthority.Base58()
	}
	if !withdrawWithheldAuthority.IsNil() {
		res.WithdrawWithheldAuthority = withdrawWithheldAuthority.Base58()
	}

	return res
}

// InitializeMintCloseAuthorityRequest attaches the MintCloseAuthority
// extension to Mint, naming who may later close it via close-account --
// without this extension a mint can never be closed at all, since the base
// layout has no close-authority field of its own the way a token account
// does.
//
// This can only ever run in the narrow window every mint extension shares:
// after create-mint has allocated the account (sized to include this
// extension) and before initialize-mint2 locks the extension list forever.
// There is no path back into an already-initialized mint -- no Reallocate
// equivalent exists for mints at all, only for token accounts.
type InitializeMintCloseAuthorityRequest struct {
	// Mint is the account this attaches to. It must already exist (see
	// create-mint) and not yet be initialized -- initialize-mint2 has to
	// run after this, never before.
	Mint string `json:"mint" example:""`

	// CloseAuthority may sign close-account against Mint once initialized.
	// Left empty, the extension is not attached at all. Unlike
	// transfer_fee_config_authority, upstream also exposes
	// AuthorityType::CloseMint through the plain set-authority instruction,
	// so a close authority can still be granted or replaced later even if
	// none is set here.
	CloseAuthority string `json:"close_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this
	// extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint           *types.PublicKey
	closeAuthority *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *InitializeMintCloseAuthorityRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}

	if a := strings.TrimSpace(r.CloseAuthority); a != "" {
		if r.closeAuthority, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("close_authority: " + err.Error())
		}
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
	// Unlike every other Token endpoint, which accepts either program
	// because the instruction genuinely works on both, an extension has
	// nowhere to live on a classic Token mint: that layout is fixed at 82
	// bytes forever, with no TLV region to grow into at all.
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *InitializeMintCloseAuthorityRequest) MintKey() *types.PublicKey { return r.mint }
func (r *InitializeMintCloseAuthorityRequest) CloseAuthorityKey() *types.PublicKey {
	return r.closeAuthority
}
func (r *InitializeMintCloseAuthorityRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *InitializeMintCloseAuthorityRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *InitializeMintCloseAuthorityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *InitializeMintCloseAuthorityRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeMintCloseAuthorityResponse reports the built transaction
// alongside the close authority it attaches.
type InitializeMintCloseAuthorityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint           string `json:"mint"`
	CloseAuthority string `json:"close_authority,omitempty"`
	Program        string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializeMintCloseAuthorityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, closeAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *InitializeMintCloseAuthorityResponse {
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

	res := &InitializeMintCloseAuthorityResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
	if !closeAuthority.IsNil() {
		res.CloseAuthority = closeAuthority.Base58()
	}

	return res
}

// InitializeConfidentialTransferMintRequest attaches the
// ConfidentialTransferMint extension to Mint, naming who may later
// reconfigure it and approve new confidential accounts (Authority),
// whether new accounts need that approval before use
// (AutoApproveNewAccounts), and an optional auditor key that can decrypt
// any confidential transfer amount (AuditorElgamalPubkey).
//
// This can only ever run in the narrow window every mint extension shares:
// after create-mint has allocated the account (sized to include this
// extension) and before initialize-mint2 locks the extension list forever.
// There is no path back into an already-initialized mint -- no Reallocate
// equivalent exists for mints at all, only for token accounts.
//
// This endpoint only ever builds InitializeMint -- the one sub-instruction
// of ConfidentialTransferExtension (opcode 27) that needs no ElGamal math
// on this server's side, just raw key bytes the caller already has. The
// other 14 (ConfigureAccount, Deposit, Withdraw, Transfer, and the rest)
// need zero-knowledge proofs this package does not yet generate or verify,
// and are not built here.
type InitializeConfidentialTransferMintRequest struct {
	// Mint is the account this attaches to. It must already exist (see
	// create-mint) and not yet be initialized -- initialize-mint2 has to
	// run after this, never before.
	Mint string `json:"mint" example:""`

	// Authority may later call whatever reconfigures this extension and
	// approve new confidential accounts when AutoApproveNewAccounts is
	// false. Left empty, this capability is given up permanently.
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// AutoApproveNewAccounts determines whether a newly configured
	// confidential account may be used immediately, or needs Authority to
	// approve it first.
	AutoApproveNewAccounts bool `json:"auto_approve_new_accounts" example:"true"`

	// AuditorElgamalPubkey, left empty, means no auditor can ever decrypt a
	// confidential transfer amount on this mint. Given, it is a raw ElGamal
	// public key encoded as base58 -- a 32-byte compressed Ristretto point,
	// not a Solana address, and this API does not derive one from a
	// keypair; the caller supplies the raw bytes themselves.
	AuditorElgamalPubkey string `json:"auditor_elgamal_pubkey" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this
	// extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint                 *types.PublicKey
	authority            *types.PublicKey
	auditorElGamalPubkey []byte
	feePayer             *types.PublicKey
	rbh                  *types.Hash
	dna                  *types.PublicKey
	tokenProgramID       *types.PublicKey
}

func (r *InitializeConfidentialTransferMintRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}

	if a := strings.TrimSpace(r.Authority); a != "" {
		if r.authority, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("authority: " + err.Error())
		}
	}

	if a := strings.TrimSpace(r.AuditorElgamalPubkey); a != "" {
		if r.auditorElGamalPubkey, err = codec.Base58.DecodeFixed(a, 32); err != nil {
			return errors.New("auditor_elgamal_pubkey: " + err.Error())
		}
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *InitializeConfidentialTransferMintRequest) MintKey() *types.PublicKey { return r.mint }
func (r *InitializeConfidentialTransferMintRequest) AuthorityKey() *types.PublicKey {
	return r.authority
}
func (r *InitializeConfidentialTransferMintRequest) ToAuditorElGamalPubkey() []byte {
	return r.auditorElGamalPubkey
}
func (r *InitializeConfidentialTransferMintRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *InitializeConfidentialTransferMintRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *InitializeConfidentialTransferMintRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *InitializeConfidentialTransferMintRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeConfidentialTransferMintResponse reports the built transaction
// alongside the confidential transfer configuration it attaches.
type InitializeConfidentialTransferMintResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint                   string `json:"mint"`
	Authority              string `json:"authority,omitempty"`
	AutoApproveNewAccounts bool   `json:"auto_approve_new_accounts"`
	AuditorElgamalPubkey   string `json:"auditor_elgamal_pubkey,omitempty"`
	Program                string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializeConfidentialTransferMintResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	autoApproveNewAccounts bool, auditorElGamalPubkey []byte,
	fee uint64,
) *InitializeConfidentialTransferMintResponse {
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

	res := &InitializeConfidentialTransferMintResponse{
		Transaction:            codec.Base64.Encode(raw),
		Message:                codec.Base64.Encode(message),
		RecentBlockhash:        tx.Message.RecentBlockhash.Base58(),
		AccountKeys:            keys,
		Signers:                signers,
		NonceAuthority:         nonceAuth,
		Mint:                   mint.Base58(),
		AutoApproveNewAccounts: autoApproveNewAccounts,
		Program:                tokenProgram.Base58(),
		Fee:                    newSystemPayer(feePayer, fee),
	}
	if !authority.IsNil() {
		res.Authority = authority.Base58()
	}
	if len(auditorElGamalPubkey) > 0 {
		res.AuditorElgamalPubkey = codec.Base58.Encode(auditorElGamalPubkey)
	}

	return res
}

// InitializeConfidentialMintBurnRequest attaches the ConfidentialMintBurn
// extension to Mint, naming the ElGamal public key its confidential supply is
// encrypted under and starting that supply at zero.
//
// This can only ever run in the narrow window every mint extension shares:
// after the mint account has been allocated (sized to include this
// extension, see extensions/mint/data-size) and before initialize-mint2 locks
// the extension list forever. A mint that should also carry
// ConfidentialTransferMint -- Mint and Burn read the auditor key from it --
// needs both extensions in the allocated size.
type InitializeConfidentialMintBurnRequest struct {
	// Mint is the account this attaches to. It must already exist (see
	// create-mint) and not yet be initialized -- initialize-mint2 has to
	// run after this, never before.
	Mint string `json:"mint" example:""`

	// SupplyElgamalPubkey is the ElGamal public key the mint's confidential
	// supply is encrypted under, base58-encoded raw 32 bytes (see
	// tool/generate/elgamal-keypair). Its secret key is what later mint and
	// burn proofs are built with, and it can be rotated (see
	// rotate-supply-elgamal-pubkey).
	SupplyElgamalPubkey string `json:"supply_elgamal_pubkey" example:""`

	// SupplyAeKey encrypts the initial supply of zero into the decryptable
	// supply the instruction carries, base58-encoded raw 16 bytes -- the same
	// kind of key an account's decryptable balance uses. Keep it: every later
	// mint and burn needs it to keep the decryptable supply in step.
	SupplyAeKey string `json:"supply_ae_key" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this
	// extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint                *types.PublicKey
	supplyElGamalPubkey []byte
	decryptableSupply   []byte
	feePayer            *types.PublicKey
	rbh                 *types.Hash
	dna                 *types.PublicKey
	tokenProgramID      *types.PublicKey
}

func (r *InitializeConfidentialMintBurnRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}

	if r.supplyElGamalPubkey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.SupplyElgamalPubkey), 32); err != nil {
		return errors.New("supply_elgamal_pubkey: " + err.Error())
	}
	aeKey, err := codec.Base58.DecodeFixed(strings.TrimSpace(r.SupplyAeKey), 16)
	if err != nil {
		return errors.New("supply_ae_key: " + err.Error())
	}
	if r.decryptableSupply, err = core.EncryptAeAmount(aeKey, 0); err != nil {
		return errors.New("supply_ae_key: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *InitializeConfidentialMintBurnRequest) MintKey() *types.PublicKey { return r.mint }
func (r *InitializeConfidentialMintBurnRequest) ToSupplyElGamalPubkey() []byte {
	return r.supplyElGamalPubkey
}
func (r *InitializeConfidentialMintBurnRequest) ToDecryptableSupply() []byte {
	return r.decryptableSupply
}
func (r *InitializeConfidentialMintBurnRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *InitializeConfidentialMintBurnRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *InitializeConfidentialMintBurnRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *InitializeConfidentialMintBurnRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeConfidentialMintBurnResponse reports the built transaction
// alongside the confidential transfer configuration it attaches.
type InitializeConfidentialMintBurnResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint                string `json:"mint"`
	SupplyElgamalPubkey string `json:"supply_elgamal_pubkey"`
	DecryptableSupply   string `json:"decryptable_supply"`
	Program             string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializeConfidentialMintBurnResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, tokenProgram, nonceAuthority *types.PublicKey,
	supplyElGamalPubkey, decryptableSupply []byte,
	fee uint64,
) *InitializeConfidentialMintBurnResponse {
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

	return &InitializeConfidentialMintBurnResponse{
		Transaction:         codec.Base64.Encode(raw),
		Message:             codec.Base64.Encode(message),
		RecentBlockhash:     tx.Message.RecentBlockhash.Base58(),
		AccountKeys:         keys,
		Signers:             signers,
		NonceAuthority:      nonceAuth,
		Mint:                mint.Base58(),
		SupplyElgamalPubkey: codec.Base58.Encode(supplyElGamalPubkey),
		DecryptableSupply:   codec.Base58.Encode(decryptableSupply),
		Program:             tokenProgram.Base58(),
		Fee:                 newSystemPayer(feePayer, fee),
	}
}

// CloseMintRequest closes a Token-2022 mint that carries the
// MintCloseAuthority extension, reclaiming its rent to RecipientAccount.
//
// This cannot reuse close-account (the classic token-account endpoint):
// that handler decodes TokenAccount and checks its close_authority field,
// neither of which describes a mint at all -- a mint's close authority
// lives in the MintCloseAuthority extension's TLV data instead, read via
// core.DecodeMintCloseAuthority, not TokenAccount.CloseAuthority. The
// on-chain CloseAccount instruction itself (opcode 9) is exactly the same
// generic instruction either way -- upstream's own processor tries
// unpacking the target as a token account first, falling back to a mint --
// so this only needs its own client-side validation, not a different
// instruction.
//
// Mint's supply must already be zero: the program enforces this
// (TokenError::MintHasSupply otherwise) since closing destroys the mint
// account and any outstanding supply would become permanently unaccounted
// for. There is no burn-and-close in one instruction; supply has to already
// read zero before this is called.
type CloseMintRequest struct {
	// Mint is closed. It must already carry the MintCloseAuthority extension
	// with an authority set, and its supply must already be zero.
	Mint string `json:"mint" example:""`

	// RecipientAccount receives Mint's entire reclaimed lamport balance. It
	// must already exist; this is not a way to bring a new account into
	// existence.
	RecipientAccount string `json:"recipient_account" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// CloseAuthority must be Mint's current MintCloseAuthority close
	// authority exactly.
	CloseAuthority string `json:"close_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this
	// extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint             *types.PublicKey
	recipientAccount *types.PublicKey
	closeAuthority   *types.PublicKey
	feePayer         *types.PublicKey
	rbh              *types.Hash
	dna              *types.PublicKey
	tokenProgramID   *types.PublicKey
	multisigSigners  []*types.PublicKey
}

func (r *CloseMintRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.recipientAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RecipientAccount)); err != nil {
		return errors.New("recipient_account: " + err.Error())
	}
	if r.mint.Equal(r.recipientAccount) {
		return errors.New("mint and recipient_account are the same account")
	}
	if r.closeAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.CloseAuthority)); err != nil {
		return errors.New("close_authority: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *CloseMintRequest) MintKey() *types.PublicKey             { return r.mint }
func (r *CloseMintRequest) RecipientAccountKey() *types.PublicKey { return r.recipientAccount }
func (r *CloseMintRequest) CloseAuthorityKey() *types.PublicKey   { return r.closeAuthority }
func (r *CloseMintRequest) FeePayerKey() *types.PublicKey         { return r.feePayer }
func (r *CloseMintRequest) Blockhash() *types.Hash                { return r.rbh }
func (r *CloseMintRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *CloseMintRequest) TokenProgramID() *types.PublicKey { return r.tokenProgramID }
func (r *CloseMintRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// CloseMintResponse reports the built transaction alongside what closing
// Mint reclaims.
type CloseMintResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint             string `json:"mint"`
	RecipientAccount string `json:"recipient_account"`
	CloseAuthority   string `json:"close_authority"`
	Program          string `json:"program"`

	// Reclaimed reports Mint's balance at the moment it was read, which is
	// what closing hands to recipient_account. It can change between this
	// response and the transaction landing if anything else touches the
	// account first.
	Reclaimed SystemPayer `json:"reclaimed"`
	Fee       SystemPayer `json:"fee"`
}

func NewCloseMintResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, recipientAccount, closeAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	reclaimedLamports, fee uint64,
) *CloseMintResponse {
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

	return &CloseMintResponse{
		Transaction:      codec.Base64.Encode(raw),
		Message:          codec.Base64.Encode(message),
		RecentBlockhash:  tx.Message.RecentBlockhash.Base58(),
		AccountKeys:      keys,
		Signers:          signers,
		NonceAuthority:   nonceAuth,
		Mint:             mint.Base58(),
		RecipientAccount: recipientAccount.Base58(),
		CloseAuthority:   closeAuthority.Base58(),
		Program:          tokenProgram.Base58(),
		Reclaimed:        newSystemPayer(recipientAccount, reclaimedLamports),
		Fee:              newSystemPayer(feePayer, fee),
	}
}

// SetCloseMintAuthorityReplaceRequest replaces the MintCloseAuthority
// extension's close_authority with a new key.
//
// Unlike mint_authority or freeze_authority, this is not one of the four
// classic SetAuthority roles: upstream reuses the same SetAuthority
// instruction (opcode 6) with AuthorityType::CloseMint (6), a
// Token-2022-only value this codebase declares as TokenAuthorityCloseMint,
// non-contiguous with the classic four. Mint must already carry the
// extension (see initialize-mint-close-authority) with a close_authority
// set -- there is no granting one here where none exists, since SetAuthority
// always requires the current authority to sign.
type SetCloseMintAuthorityReplaceRequest struct {
	Mint string `json:"mint" example:""`

	// CloseAuthority must be Mint's current MintCloseAuthority close
	// authority exactly.
	CloseAuthority string `json:"close_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NewCloseAuthority replaces CloseAuthority entirely; it is not required
	// to sign, since SetAuthority-style authority changes only record the
	// new value rather than checking it against a signer.
	NewCloseAuthority string `json:"new_close_authority" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this
	// extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint              *types.PublicKey
	closeAuthority    *types.PublicKey
	newCloseAuthority *types.PublicKey
	feePayer          *types.PublicKey
	rbh               *types.Hash
	dna               *types.PublicKey
	tokenProgramID    *types.PublicKey
	multisigSigners   []*types.PublicKey
}

func (r *SetCloseMintAuthorityReplaceRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.closeAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.CloseAuthority)); err != nil {
		return errors.New("close_authority: " + err.Error())
	}
	newCloseAuthority := strings.TrimSpace(r.NewCloseAuthority)
	if newCloseAuthority == "" {
		return errors.New("new_close_authority is required")
	}
	if r.newCloseAuthority, err = types.NewPublicKeyFromBase58(newCloseAuthority); err != nil {
		return errors.New("new_close_authority: " + err.Error())
	}
	if r.closeAuthority.Equal(r.newCloseAuthority) {
		return errors.New("new_close_authority: is already the current close authority")
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *SetCloseMintAuthorityReplaceRequest) MintKey() *types.PublicKey { return r.mint }
func (r *SetCloseMintAuthorityReplaceRequest) CloseAuthorityKey() *types.PublicKey {
	return r.closeAuthority
}
func (r *SetCloseMintAuthorityReplaceRequest) NewCloseAuthorityKey() *types.PublicKey {
	return r.newCloseAuthority
}
func (r *SetCloseMintAuthorityReplaceRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *SetCloseMintAuthorityReplaceRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *SetCloseMintAuthorityReplaceRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *SetCloseMintAuthorityReplaceRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *SetCloseMintAuthorityReplaceRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// SetCloseMintAuthorityReplaceResponse reports the authority change just built.
type SetCloseMintAuthorityReplaceResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint              string      `json:"mint"`
	CloseAuthority    string      `json:"close_authority"`
	NewCloseAuthority string      `json:"new_close_authority"`
	Program           string      `json:"program"`
	Fee               SystemPayer `json:"fee"`
}

func NewSetCloseMintAuthorityReplaceResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, closeAuthority, tokenProgram, nonceAuthority, newCloseAuthority *types.PublicKey,
	fee uint64,
) *SetCloseMintAuthorityReplaceResponse {
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

	return &SetCloseMintAuthorityReplaceResponse{
		Transaction:       codec.Base64.Encode(raw),
		Message:           codec.Base64.Encode(message),
		RecentBlockhash:   tx.Message.RecentBlockhash.Base58(),
		AccountKeys:       keys,
		Signers:           signers,
		NonceAuthority:    nonceAuth,
		Mint:              mint.Base58(),
		CloseAuthority:    closeAuthority.Base58(),
		NewCloseAuthority: newCloseAuthority.Base58(),
		Program:           tokenProgram.Base58(),
		Fee:               newSystemPayer(feePayer, fee),
	}
}

// SetCloseMintAuthorityClearRequest removes the MintCloseAuthority
// extension's close_authority permanently.
//
// Once cleared, no endpoint can set it again: the program stores this as a
// MaybeNull<Address> and rejects nothing here, but nothing can ever sign as
// an authority that is now None. This is how a mint becomes permanently
// unclosable while every other extension it carries stays exactly as it is.
type SetCloseMintAuthorityClearRequest struct {
	Mint string `json:"mint" example:""`

	// CloseAuthority must be Mint's current MintCloseAuthority close
	// authority exactly.
	CloseAuthority string `json:"close_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this
	// extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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
	closeAuthority  *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *SetCloseMintAuthorityClearRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.closeAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.CloseAuthority)); err != nil {
		return errors.New("close_authority: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *SetCloseMintAuthorityClearRequest) MintKey() *types.PublicKey { return r.mint }
func (r *SetCloseMintAuthorityClearRequest) CloseAuthorityKey() *types.PublicKey {
	return r.closeAuthority
}
func (r *SetCloseMintAuthorityClearRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *SetCloseMintAuthorityClearRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *SetCloseMintAuthorityClearRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *SetCloseMintAuthorityClearRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *SetCloseMintAuthorityClearRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// SetCloseMintAuthorityClearResponse reports the authority change just built.
type SetCloseMintAuthorityClearResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint           string      `json:"mint"`
	CloseAuthority string      `json:"close_authority"`
	Cleared        bool        `json:"cleared"`
	Program        string      `json:"program"`
	Fee            SystemPayer `json:"fee"`
}

func NewSetCloseMintAuthorityClearResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, closeAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *SetCloseMintAuthorityClearResponse {
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

	return &SetCloseMintAuthorityClearResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		CloseAuthority:  closeAuthority.Base58(),
		Cleared:         true,
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// SetTransferFeeRequest changes the TransferFeeConfig rate
// InitializeTransferFeeConfig fixed, authorized by TransferFeeConfigAuthority
// rather than Mint's own mint or freeze authority.
//
// The new rate is not immediate: the program keeps an older and a newer
// rate side by side, each stamped with the epoch it takes effect at. What
// this sets becomes the newer rate, effective at the start of the next
// epoch; whatever was already active keeps applying until then. That delay
// is enforced on chain and not reported here yet -- reading the current
// epoch and estimating a wall-clock time for the next one is a small
// follow-up, not something this endpoint computes today.
type SetTransferFeeRequest struct {
	// Mint must already have the TransferFeeConfig extension (see
	// initialize-transfer-fee-config).
	Mint string `json:"mint" example:""`

	// TransferFeeConfigAuthority is the authority
	// initialize-transfer-fee-config named, or its multisig for a
	// multisig-owned authority (see MultisigSigners). Unlike that endpoint,
	// this one cannot be left empty: an authority that was never set has no
	// way to sign this instruction in the first place, permanently.
	TransferFeeConfigAuthority string `json:"transfer_fee_config_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// TransferFeeBasisPoints is the new fee rate, out of 10,000 (500 = 5%).
	// The program itself rejects anything over 10,000, so this is checked
	// here too rather than left to come back as an on-chain rejection.
	TransferFeeBasisPoints uint16 `json:"transfer_fee_basis_points" example:"500"`

	// MaximumFee caps what a single transfer-checked-with-fee ever
	// withholds, in raw base units, regardless of how large the transfer
	// is or what the rate above would otherwise compute.
	MaximumFee string `json:"maximum_fee" example:"1000000"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this
	// extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// TransferFeeConfigAuthority itself does not sign; the named members
	// do, in its place.
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

	mint                       *types.PublicKey
	transferFeeConfigAuthority *types.PublicKey
	maximumFee                 uint64
	feePayer                   *types.PublicKey
	rbh                        *types.Hash
	dna                        *types.PublicKey
	tokenProgramID             *types.PublicKey
	multisigSigners            []*types.PublicKey
}

func (r *SetTransferFeeRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.transferFeeConfigAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TransferFeeConfigAuthority)); err != nil {
		return errors.New("transfer_fee_config_authority: " + err.Error())
	}

	if r.TransferFeeBasisPoints > 10_000 {
		return fmt.Errorf("transfer_fee_basis_points: %d is outside the valid range [0, 10000]", r.TransferFeeBasisPoints)
	}

	maximumFee := strings.TrimSpace(r.MaximumFee)
	if maximumFee == "" {
		return errors.New("maximum_fee is required")
	}
	if r.maximumFee, err = strconv.ParseUint(maximumFee, 10, 64); err != nil {
		return errors.New("maximum_fee: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *SetTransferFeeRequest) MintKey() *types.PublicKey { return r.mint }
func (r *SetTransferFeeRequest) TransferFeeConfigAuthorityKey() *types.PublicKey {
	return r.transferFeeConfigAuthority
}
func (r *SetTransferFeeRequest) ToMaximumFee() uint64          { return r.maximumFee }
func (r *SetTransferFeeRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *SetTransferFeeRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *SetTransferFeeRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *SetTransferFeeRequest) TokenProgramID() *types.PublicKey { return r.tokenProgramID }
func (r *SetTransferFeeRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// SetTransferFeeResponse reports the built transaction alongside the fee
// configuration it sets.
type SetTransferFeeResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint                       string `json:"mint"`
	TransferFeeConfigAuthority string `json:"transfer_fee_config_authority"`
	TransferFeeBasisPoints     uint16 `json:"transfer_fee_basis_points"`
	MaximumFee                 string `json:"maximum_fee"`
	Program                    string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewSetTransferFeeResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, transferFeeConfigAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	transferFeeBasisPoints uint16, maximumFee, fee uint64,
) *SetTransferFeeResponse {
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

	return &SetTransferFeeResponse{
		Transaction:                codec.Base64.Encode(raw),
		Message:                    codec.Base64.Encode(message),
		RecentBlockhash:            tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                keys,
		Signers:                    signers,
		NonceAuthority:             nonceAuth,
		Mint:                       mint.Base58(),
		TransferFeeConfigAuthority: transferFeeConfigAuthority.Base58(),
		TransferFeeBasisPoints:     transferFeeBasisPoints,
		MaximumFee:                 strconv.FormatUint(maximumFee, 10),
		Program:                    tokenProgram.Base58(),
		Fee:                        newSystemPayer(feePayer, fee),
	}
}

// UpdateConfidentialTransferMintRequest changes
// InitializeConfidentialTransferMint's two adjustable fields --
// AutoApproveNewAccounts and AuditorElgamalPubkey -- authorized by
// Authority, exactly as SetTransferFeeRequest changes TransferFeeConfig
// authorized by TransferFeeConfigAuthority rather than Mint's own mint or
// freeze authority.
//
// Unlike InitializeConfidentialTransferMint, Authority is not itself
// reassignable through this endpoint: it has to sign here as proof of the
// role, and there is no field in the underlying instruction's data that
// could hand it to someone else. Both fields below overwrite whatever is
// currently set, with no way to leave one unchanged -- passing the same
// value back is how a caller keeps it as is.
type UpdateConfidentialTransferMintRequest struct {
	// Mint must already have the ConfidentialTransferMint extension (see
	// initialize).
	Mint string `json:"mint" example:""`

	// Authority is the authority initialize named, or its multisig for a
	// multisig-owned authority (see MultisigSigners). This cannot be left
	// empty: an authority that was never set has no way to sign this
	// instruction in the first place, permanently.
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// AutoApproveNewAccounts replaces whatever initialize set entirely.
	AutoApproveNewAccounts bool `json:"auto_approve_new_accounts" example:"true"`

	// AuditorElgamalPubkey replaces whatever initialize set entirely. Left
	// empty, no auditor can decrypt a confidential transfer amount on this
	// mint from this point on. Given, it is a raw ElGamal public key
	// encoded as base58 -- a 32-byte compressed Ristretto point, not a
	// Solana address.
	AuditorElgamalPubkey string `json:"auditor_elgamal_pubkey" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this
	// extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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

	mint                 *types.PublicKey
	authority            *types.PublicKey
	auditorElGamalPubkey []byte
	feePayer             *types.PublicKey
	rbh                  *types.Hash
	dna                  *types.PublicKey
	tokenProgramID       *types.PublicKey
	multisigSigners      []*types.PublicKey
}

func (r *UpdateConfidentialTransferMintRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}

	if a := strings.TrimSpace(r.AuditorElgamalPubkey); a != "" {
		if r.auditorElGamalPubkey, err = codec.Base58.DecodeFixed(a, 32); err != nil {
			return errors.New("auditor_elgamal_pubkey: " + err.Error())
		}
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *UpdateConfidentialTransferMintRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *UpdateConfidentialTransferMintRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *UpdateConfidentialTransferMintRequest) ToAuditorElGamalPubkey() []byte {
	return r.auditorElGamalPubkey
}
func (r *UpdateConfidentialTransferMintRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *UpdateConfidentialTransferMintRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *UpdateConfidentialTransferMintRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *UpdateConfidentialTransferMintRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *UpdateConfidentialTransferMintRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// UpdateConfidentialTransferMintResponse reports the built transaction
// alongside the confidential transfer configuration it sets.
type UpdateConfidentialTransferMintResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint                   string `json:"mint"`
	Authority              string `json:"authority"`
	AutoApproveNewAccounts bool   `json:"auto_approve_new_accounts"`
	AuditorElgamalPubkey   string `json:"auditor_elgamal_pubkey,omitempty"`
	Program                string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewUpdateConfidentialTransferMintResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	autoApproveNewAccounts bool, auditorElGamalPubkey []byte,
	fee uint64,
) *UpdateConfidentialTransferMintResponse {
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

	res := &UpdateConfidentialTransferMintResponse{
		Transaction:            codec.Base64.Encode(raw),
		Message:                codec.Base64.Encode(message),
		RecentBlockhash:        tx.Message.RecentBlockhash.Base58(),
		AccountKeys:            keys,
		Signers:                signers,
		NonceAuthority:         nonceAuth,
		Mint:                   mint.Base58(),
		Authority:              authority.Base58(),
		AutoApproveNewAccounts: autoApproveNewAccounts,
		Program:                tokenProgram.Base58(),
		Fee:                    newSystemPayer(feePayer, fee),
	}
	if len(auditorElGamalPubkey) > 0 {
		res.AuditorElgamalPubkey = codec.Base58.Encode(auditorElGamalPubkey)
	}

	return res
}

// TransferCheckedWithFeeRequest is TransferChecked plus a fee: everything
// SourceTokenAccountAuthority and Decimals check is identical, and the fee
// withheld into DestinationTokenAccount's TransferFeeAmount extension is
// the only addition.
//
// There is no Fee field to set: unlike Reallocate's own generous
// tolerance, the deployed program recomputes this fee itself from Mint's
// current TransferFeeConfig rate (calculate_epoch_fee) and requires
// whatever this instruction carries to match byte for byte, failing the
// entire transfer as FeeMismatch over a single base unit of difference.
// Asking the caller to reproduce that formula (ceiling-divide by 10,000,
// cap at maximum_fee, and pick the right one of two rates by comparing the
// current epoch) invites exactly the class of mistake this project's own
// rules exist to avoid, so this handler reads Mint's TransferFeeConfig and
// the cluster's current epoch itself and computes the one fee that can
// ever be correct.
type TransferCheckedWithFeeRequest struct {
	// SourceTokenAccount is debited. It must already exist, hold Mint, and
	// not be frozen.
	SourceTokenAccount string `json:"source_token_account" example:""`

	// Mint is what both token accounts must hold, and is the source of the
	// decimals checked against; it must already have the TransferFeeConfig
	// extension (see initialize-transfer-fee-config).
	Mint string `json:"mint" example:""`

	// DestinationTokenAccount is credited Amount minus Fee, and is where
	// Fee itself accumulates as withheld -- it must already have the
	// TransferFeeAmount extension (see reallocate/transfer-fee-amount).
	DestinationTokenAccount string `json:"destination_token_account" example:""`

	// SourceTokenAccountAuthority is SourceTokenAccount's owner, or its
	// delegate for no more than what was delegated.
	SourceTokenAccountAuthority string `json:"source_token_account_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Amount is the raw base-unit count to move, not a UI decimal string.
	// DestinationTokenAccount is credited Amount minus Fee.
	Amount string `json:"amount" example:"250000"`

	// Decimals is checked against Mint's own stored value rather than
	// trusted, the same catch every checked variant makes.
	Decimals uint8 `json:"decimals" example:"6"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold
	// TransferFeeConfig.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// the authority itself does not sign; the named members do, in its
	// place.
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

	source          *types.PublicKey
	mint            *types.PublicKey
	destination     *types.PublicKey
	authority       *types.PublicKey
	amount          uint64
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *TransferCheckedWithFeeRequest) ValidateRequest() error {
	var err error
	if r.source, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.SourceTokenAccount)); err != nil {
		return errors.New("source_token_account: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.destination, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.DestinationTokenAccount)); err != nil {
		return errors.New("destination_token_account: " + err.Error())
	}
	if r.source.Equal(r.destination) {
		return errors.New("source_token_account and destination_token_account are the same account")
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.SourceTokenAccountAuthority)); err != nil {
		return errors.New("source_token_account_authority: " + err.Error())
	}

	amount := strings.TrimSpace(r.Amount)
	if amount == "" {
		return errors.New("amount is required")
	}
	if r.amount, err = strconv.ParseUint(amount, 10, 64); err != nil {
		return errors.New("amount: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- TransferFeeConfig can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *TransferCheckedWithFeeRequest) SourceTokenAccountKey() *types.PublicKey { return r.source }
func (r *TransferCheckedWithFeeRequest) MintKey() *types.PublicKey               { return r.mint }
func (r *TransferCheckedWithFeeRequest) DestinationTokenAccountKey() *types.PublicKey {
	return r.destination
}
func (r *TransferCheckedWithFeeRequest) SourceTokenAccountAuthorityKey() *types.PublicKey {
	return r.authority
}
func (r *TransferCheckedWithFeeRequest) ToAmount() uint64              { return r.amount }
func (r *TransferCheckedWithFeeRequest) ToDecimals() uint8             { return r.Decimals }
func (r *TransferCheckedWithFeeRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *TransferCheckedWithFeeRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *TransferCheckedWithFeeRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *TransferCheckedWithFeeRequest) TokenProgramID() *types.PublicKey { return r.tokenProgramID }
func (r *TransferCheckedWithFeeRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// TransferCheckedWithFeeResponse reports the built transaction alongside
// what it moves. TransferFee and Epoch are what this handler computed and
// sent, not anything the request named -- exactly the value the deployed
// program will recompute for itself and compare against.
type TransferCheckedWithFeeResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	SourceTokenAccount          string `json:"source_token_account"`
	Mint                        string `json:"mint"`
	DestinationTokenAccount     string `json:"destination_token_account"`
	SourceTokenAccountAuthority string `json:"source_token_account_authority"`
	Amount                      string `json:"amount"`
	Decimals                    uint8  `json:"decimals"`

	// TransferFee is the amount withheld into DestinationTokenAccount's
	// TransferFeeAmount extension, computed from Mint's TransferFeeConfig
	// at Epoch -- not a value this request ever supplies.
	TransferFee string `json:"transfer_fee"`

	// Epoch is which epoch's rate TransferFee was computed against: Mint's
	// newer_transfer_fee if this epoch has reached the one it is stamped
	// with, its older_transfer_fee otherwise. A transaction built here and
	// sent after the epoch rolls over no longer matches what the program
	// will demand and has to be rebuilt.
	Epoch uint64 `json:"epoch"`

	Program string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewTransferCheckedWithFeeResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, source, mint, destination, authority, tokenProgram, nonceAuthority *types.PublicKey,
	amount uint64, decimals uint8, transferFee, epoch, fee uint64,
) *TransferCheckedWithFeeResponse {
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

	return &TransferCheckedWithFeeResponse{
		Transaction:                 codec.Base64.Encode(raw),
		Message:                     codec.Base64.Encode(message),
		RecentBlockhash:             tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                 keys,
		Signers:                     signers,
		NonceAuthority:              nonceAuth,
		SourceTokenAccount:          source.Base58(),
		Mint:                        mint.Base58(),
		DestinationTokenAccount:     destination.Base58(),
		SourceTokenAccountAuthority: authority.Base58(),
		Amount:                      strconv.FormatUint(amount, 10),
		Decimals:                    decimals,
		TransferFee:                 strconv.FormatUint(transferFee, 10),
		Epoch:                       epoch,
		Program:                     tokenProgram.Base58(),
		Fee:                         newSystemPayer(feePayer, fee),
	}
}

// HarvestWithheldTokensToMintRequest sweeps whatever each of
// SourceTokenAccounts has withheld in its own TransferFeeAmount extension
// into Mint's TransferFeeConfig withheld_amount.
//
// This is permissionless: no authority field exists here at all, since
// moving a balance between two places it can already only ever sit -- an
// account's own withheld fees, or the mint's -- needs nobody's permission,
// only the mint they all agree on.
type HarvestWithheldTokensToMintRequest struct {
	// Mint is what every one of SourceTokenAccounts must hold, and where
	// the harvested total ends up.
	Mint string `json:"mint" example:""`

	// SourceTokenAccounts is swept in full: this instruction always sweeps
	// each named account's own withheld_amount entirely, there is no
	// partial-amount form.
	SourceTokenAccounts []string `json:"source_token_accounts" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold
	// TransferFeeConfig.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint                *types.PublicKey
	sourceTokenAccounts []*types.PublicKey
	feePayer            *types.PublicKey
	rbh                 *types.Hash
	dna                 *types.PublicKey
	tokenProgramID      *types.PublicKey
}

func (r *HarvestWithheldTokensToMintRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}

	if len(r.SourceTokenAccounts) == 0 {
		return errors.New("source_token_accounts: at least one is required")
	}
	r.sourceTokenAccounts = make([]*types.PublicKey, len(r.SourceTokenAccounts))
	for i, s := range r.SourceTokenAccounts {
		if r.sourceTokenAccounts[i], err = types.NewPublicKeyFromBase58(strings.TrimSpace(s)); err != nil {
			return fmt.Errorf("source_token_accounts[%d]: %s", i, err)
		}
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- TransferFeeConfig can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *HarvestWithheldTokensToMintRequest) MintKey() *types.PublicKey { return r.mint }
func (r *HarvestWithheldTokensToMintRequest) ToSourceTokenAccounts() []*types.PublicKey {
	return r.sourceTokenAccounts
}
func (r *HarvestWithheldTokensToMintRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *HarvestWithheldTokensToMintRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *HarvestWithheldTokensToMintRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *HarvestWithheldTokensToMintRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// HarvestWithheldTokensToMintResponse reports the built transaction
// alongside what it sweeps.
type HarvestWithheldTokensToMintResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint                string   `json:"mint"`
	SourceTokenAccounts []string `json:"source_token_accounts"`
	Program             string   `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewHarvestWithheldTokensToMintResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, tokenProgram, nonceAuthority *types.PublicKey,
	sourceTokenAccounts []string,
	fee uint64,
) *HarvestWithheldTokensToMintResponse {
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

	return &HarvestWithheldTokensToMintResponse{
		Transaction:         codec.Base64.Encode(raw),
		Message:             codec.Base64.Encode(message),
		RecentBlockhash:     tx.Message.RecentBlockhash.Base58(),
		AccountKeys:         keys,
		Signers:             signers,
		NonceAuthority:      nonceAuth,
		Mint:                mint.Base58(),
		SourceTokenAccounts: sourceTokenAccounts,
		Program:             tokenProgram.Base58(),
		Fee:                 newSystemPayer(feePayer, fee),
	}
}

// WithdrawWithheldTokensFromMintRequest moves Mint's own TransferFeeConfig
// withheld_amount out to Destination as real tokens, authorized by
// WithdrawWithheldAuthority rather than Mint's own mint or freeze
// authority.
//
// This is the counterpart harvest-withheld-tokens-to-mint's permissionless
// sweep feeds: harvesting only ever moves a balance into the mint, never
// out of it, so getting it out from there to somewhere spendable is this
// endpoint's job alone, and it is the one step in the whole withheld-fee
// lifecycle that actually requires a signature.
type WithdrawWithheldTokensFromMintRequest struct {
	// Mint must already have the TransferFeeConfig extension, with some
	// amount already harvested into it (see harvest-withheld-tokens-to-mint).
	Mint string `json:"mint" example:""`

	// Destination receives the withdrawn tokens. It must already exist and
	// hold Mint.
	Destination string `json:"destination" example:""`

	// WithdrawWithheldAuthority is the authority
	// initialize-transfer-fee-config named, or its multisig for a
	// multisig-owned authority (see MultisigSigners). Unlike
	// TransferFeeConfigAuthority, this cannot be left empty when set up:
	// an authority that was never named has no way to sign this
	// instruction, permanently.
	WithdrawWithheldAuthority string `json:"withdraw_withheld_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold
	// TransferFeeConfig.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// WithdrawWithheldAuthority itself does not sign; the named members do,
	// in its place.
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

	mint                      *types.PublicKey
	destination               *types.PublicKey
	withdrawWithheldAuthority *types.PublicKey
	feePayer                  *types.PublicKey
	rbh                       *types.Hash
	dna                       *types.PublicKey
	tokenProgramID            *types.PublicKey
	multisigSigners           []*types.PublicKey
}

func (r *WithdrawWithheldTokensFromMintRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.destination, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Destination)); err != nil {
		return errors.New("destination: " + err.Error())
	}
	if r.withdrawWithheldAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.WithdrawWithheldAuthority)); err != nil {
		return errors.New("withdraw_withheld_authority: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- TransferFeeConfig can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *WithdrawWithheldTokensFromMintRequest) MintKey() *types.PublicKey { return r.mint }
func (r *WithdrawWithheldTokensFromMintRequest) DestinationKey() *types.PublicKey {
	return r.destination
}
func (r *WithdrawWithheldTokensFromMintRequest) WithdrawWithheldAuthorityKey() *types.PublicKey {
	return r.withdrawWithheldAuthority
}
func (r *WithdrawWithheldTokensFromMintRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *WithdrawWithheldTokensFromMintRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *WithdrawWithheldTokensFromMintRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *WithdrawWithheldTokensFromMintRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *WithdrawWithheldTokensFromMintRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// WithdrawWithheldTokensFromMintResponse reports the built transaction
// alongside what it moves.
type WithdrawWithheldTokensFromMintResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint                      string `json:"mint"`
	Destination               string `json:"destination"`
	WithdrawWithheldAuthority string `json:"withdraw_withheld_authority"`
	Program                   string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewWithdrawWithheldTokensFromMintResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, destination, withdrawWithheldAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *WithdrawWithheldTokensFromMintResponse {
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

	return &WithdrawWithheldTokensFromMintResponse{
		Transaction:               codec.Base64.Encode(raw),
		Message:                   codec.Base64.Encode(message),
		RecentBlockhash:           tx.Message.RecentBlockhash.Base58(),
		AccountKeys:               keys,
		Signers:                   signers,
		NonceAuthority:            nonceAuth,
		Mint:                      mint.Base58(),
		Destination:               destination.Base58(),
		WithdrawWithheldAuthority: withdrawWithheldAuthority.Base58(),
		Program:                   tokenProgram.Base58(),
		Fee:                       newSystemPayer(feePayer, fee),
	}
}

// WithdrawWithheldTokensFromAccountsRequest moves whatever each of
// SourceTokenAccounts has withheld in its own TransferFeeAmount extension
// straight to Destination, bypassing Mint's own TransferFeeConfig
// withheld_amount entirely -- the shortcut harvest-withheld-tokens-to-mint
// does not take.
//
// Mint itself is read-only: it is named only so the program can confirm
// every source actually belongs to it, never written to. Unlike
// harvest-withheld-tokens-to-mint this does require WithdrawWithheldAuthority
// to sign, the same authority withdraw-withheld-tokens-from-mint answers
// to, since real tokens are leaving the accounts entirely rather than
// settling into a shared pool anyone could later account for.
type WithdrawWithheldTokensFromAccountsRequest struct {
	// Mint is what every one of SourceTokenAccounts must hold. It is never
	// written to by this instruction.
	Mint string `json:"mint" example:""`

	// Destination receives everything withdrawn, summed across every
	// source. It must already exist and hold Mint.
	Destination string `json:"destination" example:""`

	// WithdrawWithheldAuthority is the authority
	// initialize-transfer-fee-config named, or its multisig for a
	// multisig-owned authority (see MultisigSigners).
	WithdrawWithheldAuthority string `json:"withdraw_withheld_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// SourceTokenAccounts is swept in full: this instruction always
	// withdraws each named account's own withheld_amount entirely, there
	// is no partial-amount form. At most 255, since the count travels the
	// wire as a single byte.
	SourceTokenAccounts []string `json:"source_token_accounts" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold
	// TransferFeeConfig.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// WithdrawWithheldAuthority itself does not sign; the named members do,
	// in its place.
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

	mint                      *types.PublicKey
	destination               *types.PublicKey
	withdrawWithheldAuthority *types.PublicKey
	sourceTokenAccounts       []*types.PublicKey
	feePayer                  *types.PublicKey
	rbh                       *types.Hash
	dna                       *types.PublicKey
	tokenProgramID            *types.PublicKey
	multisigSigners           []*types.PublicKey
}

func (r *WithdrawWithheldTokensFromAccountsRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.destination, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Destination)); err != nil {
		return errors.New("destination: " + err.Error())
	}
	if r.withdrawWithheldAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.WithdrawWithheldAuthority)); err != nil {
		return errors.New("withdraw_withheld_authority: " + err.Error())
	}

	if len(r.SourceTokenAccounts) == 0 {
		return errors.New("source_token_accounts: at least one is required")
	}
	if len(r.SourceTokenAccounts) > 255 {
		return fmt.Errorf("source_token_accounts: %d exceeds the 255 a single byte count can carry", len(r.SourceTokenAccounts))
	}
	r.sourceTokenAccounts = make([]*types.PublicKey, len(r.SourceTokenAccounts))
	for i, s := range r.SourceTokenAccounts {
		if r.sourceTokenAccounts[i], err = types.NewPublicKeyFromBase58(strings.TrimSpace(s)); err != nil {
			return fmt.Errorf("source_token_accounts[%d]: %s", i, err)
		}
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- TransferFeeConfig can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *WithdrawWithheldTokensFromAccountsRequest) MintKey() *types.PublicKey { return r.mint }
func (r *WithdrawWithheldTokensFromAccountsRequest) DestinationKey() *types.PublicKey {
	return r.destination
}
func (r *WithdrawWithheldTokensFromAccountsRequest) WithdrawWithheldAuthorityKey() *types.PublicKey {
	return r.withdrawWithheldAuthority
}
func (r *WithdrawWithheldTokensFromAccountsRequest) ToSourceTokenAccounts() []*types.PublicKey {
	return r.sourceTokenAccounts
}
func (r *WithdrawWithheldTokensFromAccountsRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}
func (r *WithdrawWithheldTokensFromAccountsRequest) Blockhash() *types.Hash { return r.rbh }
func (r *WithdrawWithheldTokensFromAccountsRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *WithdrawWithheldTokensFromAccountsRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *WithdrawWithheldTokensFromAccountsRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// WithdrawWithheldTokensFromAccountsResponse reports the built transaction
// alongside what it moves.
type WithdrawWithheldTokensFromAccountsResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint                      string   `json:"mint"`
	Destination               string   `json:"destination"`
	WithdrawWithheldAuthority string   `json:"withdraw_withheld_authority"`
	SourceTokenAccounts       []string `json:"source_token_accounts"`
	Program                   string   `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewWithdrawWithheldTokensFromAccountsResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, destination, withdrawWithheldAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	sourceTokenAccounts []string,
	fee uint64,
) *WithdrawWithheldTokensFromAccountsResponse {
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

	return &WithdrawWithheldTokensFromAccountsResponse{
		Transaction:               codec.Base64.Encode(raw),
		Message:                   codec.Base64.Encode(message),
		RecentBlockhash:           tx.Message.RecentBlockhash.Base58(),
		AccountKeys:               keys,
		Signers:                   signers,
		NonceAuthority:            nonceAuth,
		Mint:                      mint.Base58(),
		Destination:               destination.Base58(),
		WithdrawWithheldAuthority: withdrawWithheldAuthority.Base58(),
		SourceTokenAccounts:       sourceTokenAccounts,
		Program:                   tokenProgram.Base58(),
		Fee:                       newSystemPayer(feePayer, fee),
	}
}

// DisableNonConfidentialCreditsRequest makes Account reject any ordinary
// (non-confidential) transfer into it -- clears its
// ConfidentialTransferAccount.allow_non_confidential_credits flag. Paired
// with the account still accepting confidential credits (the default),
// this makes it a confidential-only receiver. No zero-knowledge proof is
// needed, and the instruction carries no data beyond its discriminant.
type DisableNonConfidentialCreditsRequest struct {
	// Account must already carry the ConfidentialTransferAccount extension
	// (see configure-account).
	Account string `json:"account" example:""`

	// Owner is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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

	account         *types.PublicKey
	owner           *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *DisableNonConfidentialCreditsRequest) ValidateRequest() error {
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *DisableNonConfidentialCreditsRequest) AccountKey() *types.PublicKey  { return r.account }
func (r *DisableNonConfidentialCreditsRequest) OwnerKey() *types.PublicKey    { return r.owner }
func (r *DisableNonConfidentialCreditsRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *DisableNonConfidentialCreditsRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *DisableNonConfidentialCreditsRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *DisableNonConfidentialCreditsRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *DisableNonConfidentialCreditsRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// DisableNonConfidentialCreditsResponse reports the built transaction.
type DisableNonConfidentialCreditsResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Owner   string `json:"owner"`
	Program string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewDisableNonConfidentialCreditsResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, account, owner, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *DisableNonConfidentialCreditsResponse {
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

	return &DisableNonConfidentialCreditsResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Owner:           owner.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// EnableConfidentialCreditsRequest makes Account accept incoming confidential transfers -- sets its
// ConfidentialTransferAccount.allow_confidential_credits flag. No zero-knowledge proof is
// needed, and the instruction carries no data beyond its discriminant.
type EnableConfidentialCreditsRequest struct {
	// Account must already carry the ConfidentialTransferAccount extension
	// (see configure-account).
	Account string `json:"account" example:""`

	// Owner is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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

	account         *types.PublicKey
	owner           *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *EnableConfidentialCreditsRequest) ValidateRequest() error {
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *EnableConfidentialCreditsRequest) AccountKey() *types.PublicKey  { return r.account }
func (r *EnableConfidentialCreditsRequest) OwnerKey() *types.PublicKey    { return r.owner }
func (r *EnableConfidentialCreditsRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *EnableConfidentialCreditsRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *EnableConfidentialCreditsRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *EnableConfidentialCreditsRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *EnableConfidentialCreditsRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// EnableConfidentialCreditsResponse reports the built transaction.
type EnableConfidentialCreditsResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Owner   string `json:"owner"`
	Program string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewEnableConfidentialCreditsResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, account, owner, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *EnableConfidentialCreditsResponse {
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

	return &EnableConfidentialCreditsResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Owner:           owner.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// DisableConfidentialCreditsRequest makes Account reject any incoming confidential transfer -- clears its
// ConfidentialTransferAccount.allow_confidential_credits flag. Ordinary
// transfers are still governed by allow_non_confidential_credits. No zero-knowledge proof is
// needed, and the instruction carries no data beyond its discriminant.
type DisableConfidentialCreditsRequest struct {
	// Account must already carry the ConfidentialTransferAccount extension
	// (see configure-account).
	Account string `json:"account" example:""`

	// Owner is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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

	account         *types.PublicKey
	owner           *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *DisableConfidentialCreditsRequest) ValidateRequest() error {
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *DisableConfidentialCreditsRequest) AccountKey() *types.PublicKey  { return r.account }
func (r *DisableConfidentialCreditsRequest) OwnerKey() *types.PublicKey    { return r.owner }
func (r *DisableConfidentialCreditsRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *DisableConfidentialCreditsRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *DisableConfidentialCreditsRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *DisableConfidentialCreditsRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *DisableConfidentialCreditsRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// DisableConfidentialCreditsResponse reports the built transaction.
type DisableConfidentialCreditsResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Owner   string `json:"owner"`
	Program string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewDisableConfidentialCreditsResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, account, owner, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *DisableConfidentialCreditsResponse {
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

	return &DisableConfidentialCreditsResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Owner:           owner.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// EnableNonConfidentialCreditsRequest makes Account accept ordinary (non-confidential) transfers -- sets its
// ConfidentialTransferAccount.allow_non_confidential_credits flag. No zero-knowledge proof is
// needed, and the instruction carries no data beyond its discriminant.
type EnableNonConfidentialCreditsRequest struct {
	// Account must already carry the ConfidentialTransferAccount extension
	// (see configure-account).
	Account string `json:"account" example:""`

	// Owner is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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

	account         *types.PublicKey
	owner           *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *EnableNonConfidentialCreditsRequest) ValidateRequest() error {
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *EnableNonConfidentialCreditsRequest) AccountKey() *types.PublicKey  { return r.account }
func (r *EnableNonConfidentialCreditsRequest) OwnerKey() *types.PublicKey    { return r.owner }
func (r *EnableNonConfidentialCreditsRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *EnableNonConfidentialCreditsRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *EnableNonConfidentialCreditsRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *EnableNonConfidentialCreditsRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *EnableNonConfidentialCreditsRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// EnableNonConfidentialCreditsResponse reports the built transaction.
type EnableNonConfidentialCreditsResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Owner   string `json:"owner"`
	Program string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewEnableNonConfidentialCreditsResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, account, owner, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *EnableNonConfidentialCreditsResponse {
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

	return &EnableNonConfidentialCreditsResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Owner:           owner.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// ConfidentialWithdrawRequest moves Amount out of Account's confidential
// available balance back into its ordinary public balance -- the reverse
// of deposit. Amount is public (it is leaving the confidential side), but
// the remaining encrypted balance is not, so the program needs two proofs
// that it is what it should be: an equality proof and a 64-bit range proof.
//
// This builds only the Withdraw instruction itself. Both proofs must
// already be verified into context-state accounts of their own: build
// them with tool/prove/confidential-withdraw, create their accounts with
// zk-elgamal-proof/context-state/create, and verify each with
// context-state/verify.
//
// NewDecryptableAvailableBalance is the value
// tool/prove/confidential-withdraw returned alongside those proofs, and
// must come from that same call: a later call draws new randomness, so its
// value no longer matches the proofs already verified. Account's balance
// must not change between building the proofs and this withdrawal landing.
type ConfidentialWithdrawRequest struct {
	// Account is debited from its confidential available balance and
	// credited to its public balance. It must already carry the
	// ConfidentialTransferAccount extension.
	Account string `json:"account" example:""`

	// Mint is what Account must hold, and is the source of the decimals
	// checked against.
	Mint string `json:"mint" example:""`

	// Owner is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Amount is the raw base-unit count to withdraw, not a UI decimal
	// string. It must be the same amount tool/prove/confidential-withdraw
	// built its proofs for.
	Amount string `json:"amount" example:"5"`

	// Decimals must equal Mint's own, the same check every other
	// *Checked-shaped instruction in this API runs rather than trusting
	// the caller's figure.
	Decimals uint8 `json:"decimals" example:"0"`

	// EqualityContextStateAccount holds the verified
	// CiphertextCommitmentEquality proof's context (see
	// context-state/verify/ciphertext-commitment-equality).
	EqualityContextStateAccount string `json:"equality_context_state_account" example:""`

	// RangeProofContextStateAccount holds the verified BatchedRangeProofU64
	// proof's context (see context-state/verify/batched-range-proof-u64).
	RangeProofContextStateAccount string `json:"range_proof_context_state_account" example:""`

	// NewDecryptableAvailableBalance is tool/prove/confidential-withdraw's
	// own new_decryptable_available_balance, base58-encoded (36 bytes).
	NewDecryptableAvailableBalance string `json:"new_decryptable_available_balance" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty,
	// Owner itself does not sign; the named members do, in its place.
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

	account                        *types.PublicKey
	mint                           *types.PublicKey
	owner                          *types.PublicKey
	amount                         uint64
	equalityContext                *types.PublicKey
	rangeContext                   *types.PublicKey
	newDecryptableAvailableBalance []byte
	feePayer                       *types.PublicKey
	rbh                            *types.Hash
	dna                            *types.PublicKey
	tokenProgramID                 *types.PublicKey
	multisigSigners                []*types.PublicKey
}

func (r *ConfidentialWithdrawRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}

	amount := strings.TrimSpace(r.Amount)
	if amount == "" {
		return errors.New("amount is required")
	}
	if r.amount, err = strconv.ParseUint(amount, 10, 64); err != nil {
		return errors.New("amount: " + err.Error())
	}
	if r.amount == 0 {
		return errors.New("amount must be greater than zero")
	}

	if r.equalityContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.EqualityContextStateAccount)); err != nil {
		return errors.New("equality_context_state_account: " + err.Error())
	}
	if r.rangeContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RangeProofContextStateAccount)); err != nil {
		return errors.New("range_proof_context_state_account: " + err.Error())
	}
	if r.newDecryptableAvailableBalance, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.NewDecryptableAvailableBalance), core.AeCiphertextLen); err != nil {
		return errors.New("new_decryptable_available_balance: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ConfidentialWithdrawRequest) AccountKey() *types.PublicKey { return r.account }
func (r *ConfidentialWithdrawRequest) MintKey() *types.PublicKey    { return r.mint }
func (r *ConfidentialWithdrawRequest) OwnerKey() *types.PublicKey   { return r.owner }
func (r *ConfidentialWithdrawRequest) ToAmount() uint64             { return r.amount }
func (r *ConfidentialWithdrawRequest) ToDecimals() uint8            { return r.Decimals }
func (r *ConfidentialWithdrawRequest) EqualityContextKey() *types.PublicKey {
	return r.equalityContext
}
func (r *ConfidentialWithdrawRequest) RangeContextKey() *types.PublicKey { return r.rangeContext }
func (r *ConfidentialWithdrawRequest) ToNewDecryptableAvailableBalance() []byte {
	return r.newDecryptableAvailableBalance
}
func (r *ConfidentialWithdrawRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *ConfidentialWithdrawRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *ConfidentialWithdrawRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ConfidentialWithdrawRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ConfidentialWithdrawRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ConfidentialWithdrawResponse reports the built transaction.
type ConfidentialWithdrawResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Mint    string `json:"mint"`
	Owner   string `json:"owner"`
	Amount  string `json:"amount"`
	Program string `json:"program"`

	EqualityContextStateAccount   string `json:"equality_context_state_account"`
	RangeProofContextStateAccount string `json:"range_proof_context_state_account"`

	Fee SystemPayer `json:"fee"`
}

func NewConfidentialWithdrawResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, account, mint, owner, tokenProgram, equalityContext, rangeContext, nonceAuthority *types.PublicKey,
	amount, fee uint64,
) *ConfidentialWithdrawResponse {
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

	return &ConfidentialWithdrawResponse{
		Transaction:                   codec.Base64.Encode(raw),
		Message:                       codec.Base64.Encode(message),
		RecentBlockhash:               tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                   keys,
		Signers:                       signers,
		NonceAuthority:                nonceAuth,
		Account:                       account.Base58(),
		Mint:                          mint.Base58(),
		Owner:                         owner.Base58(),
		Amount:                        strconv.FormatUint(amount, 10),
		Program:                       tokenProgram.Base58(),
		EqualityContextStateAccount:   equalityContext.Base58(),
		RangeProofContextStateAccount: rangeContext.Base58(),
		Fee:                           newSystemPayer(feePayer, fee),
	}
}

// ConfidentialEmptyAccountRequest resets Account's confidential available
// balance to all-zero bytes so the token account can be closed. A
// confidential account only closes once its pending and available balance
// ciphertexts are literally all zero bytes; after a withdraw empties the
// available balance it still holds a randomized encryption of zero, which
// is not that. This takes a proof that the stored ciphertext encrypts
// zero, then overwrites it. It fails if the available balance is already
// empty, so it only applies to an account that once held a balance.
//
// This builds only the EmptyAccount instruction. The zero-ciphertext proof
// must already be verified into a context-state account: build it with
// tool/prove/confidential-empty-account, create the account with
// zk-elgamal-proof/context-state/create/zero-ciphertext, and verify it
// with context-state/verify/zero-ciphertext.
type ConfidentialEmptyAccountRequest struct {
	// Account must already carry the ConfidentialTransferAccount extension
	// (see configure-account).
	Account string `json:"account" example:""`

	// Owner is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// ZeroCiphertextContextStateAccount holds the verified ZeroCiphertext
	// proof's context (see context-state/verify/zero-ciphertext).
	ZeroCiphertextContextStateAccount string `json:"zero_ciphertext_context_state_account" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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

	account         *types.PublicKey
	zeroContext     *types.PublicKey
	owner           *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *ConfidentialEmptyAccountRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}
	if r.zeroContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.ZeroCiphertextContextStateAccount)); err != nil {
		return errors.New("zero_ciphertext_context_state_account: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ConfidentialEmptyAccountRequest) AccountKey() *types.PublicKey     { return r.account }
func (r *ConfidentialEmptyAccountRequest) OwnerKey() *types.PublicKey       { return r.owner }
func (r *ConfidentialEmptyAccountRequest) ZeroContextKey() *types.PublicKey { return r.zeroContext }
func (r *ConfidentialEmptyAccountRequest) FeePayerKey() *types.PublicKey    { return r.feePayer }
func (r *ConfidentialEmptyAccountRequest) Blockhash() *types.Hash           { return r.rbh }
func (r *ConfidentialEmptyAccountRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ConfidentialEmptyAccountRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ConfidentialEmptyAccountRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ConfidentialEmptyAccountResponse reports the built transaction.
type ConfidentialEmptyAccountResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Owner   string `json:"owner"`
	Program string `json:"program"`

	ZeroCiphertextContextStateAccount string `json:"zero_ciphertext_context_state_account"`

	Fee SystemPayer `json:"fee"`
}

func NewConfidentialEmptyAccountResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, account, owner, tokenProgram, zeroContext, nonceAuthority *types.PublicKey,
	fee uint64,
) *ConfidentialEmptyAccountResponse {
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

	return &ConfidentialEmptyAccountResponse{
		Transaction:                       codec.Base64.Encode(raw),
		Message:                           codec.Base64.Encode(message),
		RecentBlockhash:                   tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                       keys,
		Signers:                           signers,
		NonceAuthority:                    nonceAuth,
		Account:                           account.Base58(),
		Owner:                             owner.Base58(),
		Program:                           tokenProgram.Base58(),
		ZeroCiphertextContextStateAccount: zeroContext.Base58(),
		Fee:                               newSystemPayer(feePayer, fee),
	}
}

// ConfidentialWithdrawWithheldTokensFromMintRequest moves the confidential
// fees gathered on Mint (see harvest-withheld-tokens-to-mint) into
// Destination's available balance, without revealing the amount. It is
// the encrypted counterpart of the plain withdraw-withheld-tokens-from-mint:
// a CiphertextCiphertextEquality proof ties the mint's withheld ciphertext
// to the same amount re-encrypted for Destination.
//
// This builds only the instruction. Build the proof and the new decryptable
// balance with tool/prove/confidential-withdraw-withheld-from-mint, create
// the account with zk-elgamal-proof/context-state/create/ciphertext-ciphertext-equality,
// and verify it with context-state/verify/ciphertext-ciphertext-equality.
type ConfidentialWithdrawWithheldTokensFromMintRequest struct {
	// Mint must carry the TransferFeeConfig and ConfidentialTransferFeeConfig
	// extensions.
	Mint string `json:"mint" example:""`

	// Destination is the token account credited, which must hold Mint and
	// carry the ConfidentialTransferAccount extension. It may be any such
	// account, including the sender's own.
	Destination string `json:"destination" example:""`

	// EqualityContextStateAccount holds the verified
	// CiphertextCiphertextEquality proof's context (see
	// context-state/verify/ciphertext-ciphertext-equality).
	EqualityContextStateAccount string `json:"equality_context_state_account" example:""`

	// Authority is the TransferFeeConfig's withdraw withheld authority, or
	// its multisig for a multisig-owned one (see MultisigSigners).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NewDecryptableAvailableBalance is the destination's available balance
	// after the credit, base58-encoded raw 36-byte AE ciphertext -- the
	// tool/prove endpoint's new_decryptable_available_balance.
	NewDecryptableAvailableBalance string `json:"new_decryptable_available_balance" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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
	destination     *types.PublicKey
	eqContext       *types.PublicKey
	authority       *types.PublicKey
	newDecryptable  []byte
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *ConfidentialWithdrawWithheldTokensFromMintRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.destination, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Destination)); err != nil {
		return errors.New("destination: " + err.Error())
	}
	if r.eqContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.EqualityContextStateAccount)); err != nil {
		return errors.New("equality_context_state_account: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.newDecryptable, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.NewDecryptableAvailableBalance), 36); err != nil {
		return errors.New("new_decryptable_available_balance: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ConfidentialWithdrawWithheldTokensFromMintRequest) MintKey() *types.PublicKey { return r.mint }
func (r *ConfidentialWithdrawWithheldTokensFromMintRequest) DestinationKey() *types.PublicKey {
	return r.destination
}
func (r *ConfidentialWithdrawWithheldTokensFromMintRequest) EqualityContextKey() *types.PublicKey {
	return r.eqContext
}
func (r *ConfidentialWithdrawWithheldTokensFromMintRequest) AuthorityKey() *types.PublicKey {
	return r.authority
}
func (r *ConfidentialWithdrawWithheldTokensFromMintRequest) ToNewDecryptableAvailableBalance() []byte {
	return r.newDecryptable
}
func (r *ConfidentialWithdrawWithheldTokensFromMintRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}
func (r *ConfidentialWithdrawWithheldTokensFromMintRequest) Blockhash() *types.Hash { return r.rbh }
func (r *ConfidentialWithdrawWithheldTokensFromMintRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ConfidentialWithdrawWithheldTokensFromMintRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ConfidentialWithdrawWithheldTokensFromMintRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ConfidentialWithdrawWithheldTokensFromMintResponse reports the built transaction.
type ConfidentialWithdrawWithheldTokensFromMintResponse struct {
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

	EqualityContextStateAccount string `json:"equality_context_state_account"`

	Fee SystemPayer `json:"fee"`
}

func NewConfidentialWithdrawWithheldTokensFromMintResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, destination, authority, tokenProgram, eqContext, nonceAuthority *types.PublicKey,
	fee uint64,
) *ConfidentialWithdrawWithheldTokensFromMintResponse {
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

	return &ConfidentialWithdrawWithheldTokensFromMintResponse{
		Transaction:                 codec.Base64.Encode(raw),
		Message:                     codec.Base64.Encode(message),
		RecentBlockhash:             tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                 keys,
		Signers:                     signers,
		NonceAuthority:              nonceAuth,
		Mint:                        mint.Base58(),
		Destination:                 destination.Base58(),
		Authority:                   authority.Base58(),
		Program:                     tokenProgram.Base58(),
		EqualityContextStateAccount: eqContext.Base58(),
		Fee:                         newSystemPayer(feePayer, fee),
	}
}

// ConfidentialWithdrawWithheldTokensFromAccountsRequest moves the confidential
// fees withheld on each of SourceAccounts straight into Destination's
// available balance, without revealing the amount and without going through
// the mint (see withdraw-withheld-tokens-from-mint for that route). A
// CiphertextCiphertextEquality proof ties the sum of the sources' withheld
// ciphertexts to the same amount re-encrypted for Destination.
//
// This builds only the instruction. Build the proof and the new decryptable
// balance with tool/prove/confidential-withdraw-withheld-from-accounts, create
// the account with zk-elgamal-proof/context-state/create/ciphertext-ciphertext-equality,
// and verify it with context-state/verify/ciphertext-ciphertext-equality.
type ConfidentialWithdrawWithheldTokensFromAccountsRequest struct {
	// Mint must carry the TransferFeeConfig and ConfidentialTransferFeeConfig
	// extensions.
	Mint string `json:"mint" example:""`

	// Destination is the token account credited, which must hold Mint and
	// carry the ConfidentialTransferAccount extension. It may be any such
	// account, including the sender's own.
	Destination string `json:"destination" example:""`

	// SourceAccounts are the token accounts to withdraw from, each holding
	// Mint and carrying ConfidentialTransferFeeAmount. Their order does not
	// matter, but the proof was built from exactly this set, so it must be
	// the same one given to the prove tool.
	SourceAccounts []string `json:"source_accounts"`

	// EqualityContextStateAccount holds the verified
	// CiphertextCiphertextEquality proof's context (see
	// context-state/verify/ciphertext-ciphertext-equality).
	EqualityContextStateAccount string `json:"equality_context_state_account" example:""`

	// Authority is the TransferFeeConfig's withdraw withheld authority, or
	// its multisig for a multisig-owned one (see MultisigSigners).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NewDecryptableAvailableBalance is the destination's available balance
	// after the credit, base58-encoded raw 36-byte AE ciphertext -- the
	// tool/prove endpoint's new_decryptable_available_balance.
	NewDecryptableAvailableBalance string `json:"new_decryptable_available_balance" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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
	destination     *types.PublicKey
	eqContext       *types.PublicKey
	authority       *types.PublicKey
	newDecryptable  []byte
	sources         []*types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *ConfidentialWithdrawWithheldTokensFromAccountsRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.destination, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Destination)); err != nil {
		return errors.New("destination: " + err.Error())
	}
	if len(r.SourceAccounts) == 0 {
		return errors.New("source_accounts: at least one is required")
	}
	seen := make(map[string]bool, len(r.SourceAccounts))
	r.sources = make([]*types.PublicKey, len(r.SourceAccounts))
	for i, a := range r.SourceAccounts {
		if r.sources[i], err = types.NewPublicKeyFromBase58(strings.TrimSpace(a)); err != nil {
			return fmt.Errorf("source_accounts[%d]: %s", i, err)
		}
		if seen[r.sources[i].Base58()] {
			return fmt.Errorf("source_accounts[%d]: %s is listed twice", i, r.sources[i])
		}
		seen[r.sources[i].Base58()] = true
	}
	if r.eqContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.EqualityContextStateAccount)); err != nil {
		return errors.New("equality_context_state_account: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.newDecryptable, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.NewDecryptableAvailableBalance), 36); err != nil {
		return errors.New("new_decryptable_available_balance: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ConfidentialWithdrawWithheldTokensFromAccountsRequest) MintKey() *types.PublicKey {
	return r.mint
}
func (r *ConfidentialWithdrawWithheldTokensFromAccountsRequest) DestinationKey() *types.PublicKey {
	return r.destination
}
func (r *ConfidentialWithdrawWithheldTokensFromAccountsRequest) EqualityContextKey() *types.PublicKey {
	return r.eqContext
}
func (r *ConfidentialWithdrawWithheldTokensFromAccountsRequest) AuthorityKey() *types.PublicKey {
	return r.authority
}
func (r *ConfidentialWithdrawWithheldTokensFromAccountsRequest) SourceKeys() []*types.PublicKey {
	return r.sources
}
func (r *ConfidentialWithdrawWithheldTokensFromAccountsRequest) ToNewDecryptableAvailableBalance() []byte {
	return r.newDecryptable
}
func (r *ConfidentialWithdrawWithheldTokensFromAccountsRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}
func (r *ConfidentialWithdrawWithheldTokensFromAccountsRequest) Blockhash() *types.Hash { return r.rbh }
func (r *ConfidentialWithdrawWithheldTokensFromAccountsRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ConfidentialWithdrawWithheldTokensFromAccountsRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ConfidentialWithdrawWithheldTokensFromAccountsRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ConfidentialWithdrawWithheldTokensFromAccountsResponse reports the built transaction.
type ConfidentialWithdrawWithheldTokensFromAccountsResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint           string   `json:"mint"`
	Destination    string   `json:"destination"`
	Authority      string   `json:"authority"`
	SourceAccounts []string `json:"source_accounts"`
	Program        string   `json:"program"`

	EqualityContextStateAccount string `json:"equality_context_state_account"`

	Fee SystemPayer `json:"fee"`
}

func NewConfidentialWithdrawWithheldTokensFromAccountsResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, destination, authority, tokenProgram, eqContext, nonceAuthority *types.PublicKey,
	sources []*types.PublicKey,
	fee uint64,
) *ConfidentialWithdrawWithheldTokensFromAccountsResponse {
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

	return &ConfidentialWithdrawWithheldTokensFromAccountsResponse{
		Transaction:                 codec.Base64.Encode(raw),
		Message:                     codec.Base64.Encode(message),
		RecentBlockhash:             tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                 keys,
		Signers:                     signers,
		NonceAuthority:              nonceAuth,
		Mint:                        mint.Base58(),
		Destination:                 destination.Base58(),
		Authority:                   authority.Base58(),
		Program:                     tokenProgram.Base58(),
		EqualityContextStateAccount: eqContext.Base58(),
		Fee:                         newSystemPayer(feePayer, fee),
	}
}

func sourceList(keys []*types.PublicKey) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.Base58()
	}
	return out
}

// ConfidentialConfigureAccountWithRegistryRequest sets a token account up for
// confidential transfers using the ElGamal public key in its owner's registry
// (see elgamal-registry/create) instead of a PubkeyValidity proof. No
// signature from the account's owner is needed -- the program only checks that
// the registry's owner is the account's owner -- so anyone can pay for it.
// The registry account is not a field: it is the PDA derived from the token
// account's owner, read from the account.
//
// The account starts with an all-zero decryptable balance and the default
// pending-credit limit. An all-zero AE ciphertext is not a valid encryption
// of zero, so the owner's first apply-pending-balance is what makes the
// decryptable balance real.
type ConfidentialConfigureAccountWithRegistryRequest struct {
	// Account must be a Token-2022 token account of a mint that carries the
	// ConfidentialTransferMint extension, and must not already carry
	// ConfidentialTransferAccount.
	Account string `json:"account" example:""`

	// RentPayer is optional. Named, it signs and lets the program resize Account
	// itself to fit the confidential extension (and the confidential fee
	// extension on a fee mint), paying any rent shortfall. Left empty, Account
	// must already have room for them (see reallocate).
	RentPayer string `json:"rent_payer" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	account        *types.PublicKey
	rentPayer      *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *ConfidentialConfigureAccountWithRegistryRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if p := strings.TrimSpace(r.RentPayer); p != "" {
		if r.rentPayer, err = types.NewPublicKeyFromBase58(p); err != nil {
			return errors.New("rent_payer: " + err.Error())
		}
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ConfidentialConfigureAccountWithRegistryRequest) AccountKey() *types.PublicKey {
	return r.account
}
func (r *ConfidentialConfigureAccountWithRegistryRequest) RentPayerKey() *types.PublicKey {
	return r.rentPayer
}
func (r *ConfidentialConfigureAccountWithRegistryRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}
func (r *ConfidentialConfigureAccountWithRegistryRequest) Blockhash() *types.Hash { return r.rbh }
func (r *ConfidentialConfigureAccountWithRegistryRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ConfidentialConfigureAccountWithRegistryRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// ConfidentialConfigureAccountWithRegistryResponse reports the built transaction.
type ConfidentialConfigureAccountWithRegistryResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account         string `json:"account"`
	Mint            string `json:"mint"`
	RegistryAccount string `json:"registry_account"`
	RentPayer       string `json:"rent_payer,omitempty"`
	Program         string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewConfidentialConfigureAccountWithRegistryResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, account, mint, registry, payer, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *ConfidentialConfigureAccountWithRegistryResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	payerStr := ""
	if !payer.IsNil() {
		payerStr = payer.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &ConfidentialConfigureAccountWithRegistryResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Mint:            mint.Base58(),
		RegistryAccount: registry.Base58(),
		RentPayer:       payerStr,
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// InitializeConfidentialTransferFeeConfigRequest attaches the
// ConfidentialTransferFeeConfig extension to Mint, naming who may later
// change it (Authority) and the ElGamal public key withheld confidential
// transfer fees are encrypted under (WithdrawWithheldAuthorityElgamalPubkey).
// A mint that already charges an ordinary transfer fee (TransferFeeConfig)
// refuses the plain confidential transfer and accepts only
// transfer-with-fee, which needs this extension to know whom the fee is
// encrypted for.
//
// This can only ever run in the narrow window every mint extension shares:
// after create-mint has allocated the account (sized to include this
// extension) and before initialize-mint2 locks the extension list forever.
// There is no path back into an already-initialized mint -- no Reallocate
// equivalent exists for mints at all, only for token accounts.
type InitializeConfidentialTransferFeeConfigRequest struct {
	// Mint is the account this attaches to. It must already exist (see
	// create-mint) and not yet be initialized -- initialize-mint2 has to
	// run after this, never before.
	Mint string `json:"mint" example:""`

	// Authority may later reconfigure this extension. Left empty, it can
	// never be reconfigured.
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// WithdrawWithheldAuthorityElgamalPubkey is required: the ElGamal
	// public key withheld fees are encrypted under, base58-encoded (a
	// 32-byte compressed Ristretto point, not a Solana address -- see
	// tool/generate/elgamal-keypair). Whoever holds its secret key can
	// decrypt every withheld fee, and with the fee parameters that can
	// reveal information about transfer amounts.
	WithdrawWithheldAuthorityElgamalPubkey string `json:"withdraw_withheld_authority_elgamal_pubkey" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this
	// extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint                  *types.PublicKey
	authority             *types.PublicKey
	withdrawElGamalPubkey []byte
	feePayer              *types.PublicKey
	rbh                   *types.Hash
	dna                   *types.PublicKey
	tokenProgramID        *types.PublicKey
}

func (r *InitializeConfidentialTransferFeeConfigRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}

	if a := strings.TrimSpace(r.Authority); a != "" {
		if r.authority, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("authority: " + err.Error())
		}
	}

	if r.withdrawElGamalPubkey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.WithdrawWithheldAuthorityElgamalPubkey), 32); err != nil {
		return errors.New("withdraw_withheld_authority_elgamal_pubkey: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *InitializeConfidentialTransferFeeConfigRequest) MintKey() *types.PublicKey { return r.mint }
func (r *InitializeConfidentialTransferFeeConfigRequest) AuthorityKey() *types.PublicKey {
	return r.authority
}
func (r *InitializeConfidentialTransferFeeConfigRequest) ToWithdrawWithheldAuthorityElGamalPubkey() []byte {
	return r.withdrawElGamalPubkey
}
func (r *InitializeConfidentialTransferFeeConfigRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}
func (r *InitializeConfidentialTransferFeeConfigRequest) Blockhash() *types.Hash { return r.rbh }
func (r *InitializeConfidentialTransferFeeConfigRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *InitializeConfidentialTransferFeeConfigRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeConfidentialTransferFeeConfigResponse reports the built transaction
// alongside the confidential transfer configuration it attaches.
type InitializeConfidentialTransferFeeConfigResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint                                   string `json:"mint"`
	Authority                              string `json:"authority,omitempty"`
	WithdrawWithheldAuthorityElgamalPubkey string `json:"withdraw_withheld_authority_elgamal_pubkey"`
	Program                                string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializeConfidentialTransferFeeConfigResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	withdrawElGamalPubkey []byte,
	fee uint64,
) *InitializeConfidentialTransferFeeConfigResponse {
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

	res := &InitializeConfidentialTransferFeeConfigResponse{
		Transaction:                            codec.Base64.Encode(raw),
		Message:                                codec.Base64.Encode(message),
		RecentBlockhash:                        tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                            keys,
		Signers:                                signers,
		NonceAuthority:                         nonceAuth,
		Mint:                                   mint.Base58(),
		WithdrawWithheldAuthorityElgamalPubkey: codec.Base58.Encode(withdrawElGamalPubkey),
		Program:                                tokenProgram.Base58(),
		Fee:                                    newSystemPayer(feePayer, fee),
	}
	if !authority.IsNil() {
		res.Authority = authority.Base58()
	}

	return res
}

// ConfidentialTransferWithFeeRequest moves an amount confidentially from
// Source to Destination on a mint that charges a transfer fee -- neither
// the amount, the fee, nor either account's resulting balance ever appears
// in plaintext on chain. Once a mint carries TransferFeeConfig the plain
// confidential transfer is refused and only this instruction is accepted.
// Both accounts must already carry the ConfidentialTransferAccount
// extension, and Destination must also carry ConfidentialTransferFeeAmount
// (the withheld fee accumulates there).
//
// This builds only the TransferWithFee instruction itself. The five
// zero-knowledge proofs it depends on (equality, transfer amount validity,
// fee percentage-with-cap, fee validity, and a 256-bit range proof) must
// already be verified into context-state accounts of their own: build them
// with tool/prove/confidential-transfer-with-fee, create their accounts
// with zk-elgamal-proof/context-state/create, and verify each with
// context-state/verify.
//
// NewSourceDecryptableAvailableBalance, AuditorCiphertextLo, and
// AuditorCiphertextHi are the values tool/prove/confidential-transfer-with-fee
// returned alongside those proofs, and must come from that same call.
type ConfidentialTransferWithFeeRequest struct {
	// Source is debited. It must already carry the
	// ConfidentialTransferAccount extension.
	Source string `json:"source" example:""`

	// Mint is what both Source and Destination must hold, and must
	// already carry the ConfidentialTransferMint extension.
	Mint string `json:"mint" example:""`

	// Destination is credited. It must already carry the
	// ConfidentialTransferAccount extension.
	Destination string `json:"destination" example:""`

	// Owner is Source's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// EqualityContextStateAccount holds the verified
	// CiphertextCommitmentEquality proof's context (see
	// context-state/verify/ciphertext-commitment-equality).
	EqualityContextStateAccount string `json:"equality_context_state_account" example:""`

	// TransferAmountValidityContextStateAccount holds the verified
	// BatchedGroupedCiphertext3HandlesValidity proof's context for the
	// transfer amount (see
	// context-state/verify/batched-grouped-ciphertext-3-handles-validity).
	TransferAmountValidityContextStateAccount string `json:"transfer_amount_validity_context_state_account" example:""`

	// FeeSigmaContextStateAccount holds the verified PercentageWithCap
	// proof's context (see context-state/verify/percentage-with-cap).
	FeeSigmaContextStateAccount string `json:"fee_sigma_context_state_account" example:""`

	// FeeValidityContextStateAccount holds the verified
	// BatchedGroupedCiphertext2HandlesValidity proof's context for the fee
	// (see context-state/verify/batched-grouped-ciphertext-2-handles-validity).
	FeeValidityContextStateAccount string `json:"fee_validity_context_state_account" example:""`

	// RangeProofContextStateAccount holds the verified BatchedRangeProofU256
	// proof's context (see context-state/verify/batched-range-proof-u256).
	RangeProofContextStateAccount string `json:"range_proof_context_state_account" example:""`

	// NewSourceDecryptableAvailableBalance is tool/prove/confidential-transfer's
	// own field of the same name, base58-encoded (36 bytes).
	NewSourceDecryptableAvailableBalance string `json:"new_source_decryptable_available_balance" example:""`

	// AuditorCiphertextLo is tool/prove/confidential-transfer's own
	// auditor_ciphertext_lo, base58-encoded (64 bytes).
	AuditorCiphertextLo string `json:"auditor_ciphertext_lo" example:""`

	// AuditorCiphertextHi is tool/prove/confidential-transfer's own
	// auditor_ciphertext_hi, base58-encoded (64 bytes).
	AuditorCiphertextHi string `json:"auditor_ciphertext_hi" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty,
	// Owner itself does not sign; the named members do, in its place.
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

	source                               *types.PublicKey
	mint                                 *types.PublicKey
	destination                          *types.PublicKey
	owner                                *types.PublicKey
	equalityContext                      *types.PublicKey
	validityContext                      *types.PublicKey
	feeSigmaContext                      *types.PublicKey
	feeValidityContext                   *types.PublicKey
	rangeContext                         *types.PublicKey
	newSourceDecryptableAvailableBalance []byte
	auditorCiphertextLo                  []byte
	auditorCiphertextHi                  []byte
	feePayer                             *types.PublicKey
	rbh                                  *types.Hash
	dna                                  *types.PublicKey
	tokenProgramID                       *types.PublicKey
	multisigSigners                      []*types.PublicKey
}

func (r *ConfidentialTransferWithFeeRequest) ValidateRequest() error {
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
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}

	if r.equalityContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.EqualityContextStateAccount)); err != nil {
		return errors.New("equality_context_state_account: " + err.Error())
	}
	if r.validityContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TransferAmountValidityContextStateAccount)); err != nil {
		return errors.New("transfer_amount_validity_context_state_account: " + err.Error())
	}
	if r.feeSigmaContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeeSigmaContextStateAccount)); err != nil {
		return errors.New("fee_sigma_context_state_account: " + err.Error())
	}
	if r.feeValidityContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeeValidityContextStateAccount)); err != nil {
		return errors.New("fee_validity_context_state_account: " + err.Error())
	}
	if r.rangeContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RangeProofContextStateAccount)); err != nil {
		return errors.New("range_proof_context_state_account: " + err.Error())
	}

	if r.newSourceDecryptableAvailableBalance, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.NewSourceDecryptableAvailableBalance), core.AeCiphertextLen); err != nil {
		return errors.New("new_source_decryptable_available_balance: " + err.Error())
	}
	if r.auditorCiphertextLo, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.AuditorCiphertextLo), 64); err != nil {
		return errors.New("auditor_ciphertext_lo: " + err.Error())
	}
	if r.auditorCiphertextHi, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.AuditorCiphertextHi), 64); err != nil {
		return errors.New("auditor_ciphertext_hi: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ConfidentialTransferWithFeeRequest) SourceKey() *types.PublicKey      { return r.source }
func (r *ConfidentialTransferWithFeeRequest) MintKey() *types.PublicKey        { return r.mint }
func (r *ConfidentialTransferWithFeeRequest) DestinationKey() *types.PublicKey { return r.destination }
func (r *ConfidentialTransferWithFeeRequest) OwnerKey() *types.PublicKey       { return r.owner }
func (r *ConfidentialTransferWithFeeRequest) EqualityContextKey() *types.PublicKey {
	return r.equalityContext
}
func (r *ConfidentialTransferWithFeeRequest) ValidityContextKey() *types.PublicKey {
	return r.validityContext
}
func (r *ConfidentialTransferWithFeeRequest) FeeSigmaContextKey() *types.PublicKey {
	return r.feeSigmaContext
}
func (r *ConfidentialTransferWithFeeRequest) FeeValidityContextKey() *types.PublicKey {
	return r.feeValidityContext
}
func (r *ConfidentialTransferWithFeeRequest) RangeContextKey() *types.PublicKey {
	return r.rangeContext
}
func (r *ConfidentialTransferWithFeeRequest) ToNewSourceDecryptableAvailableBalance() []byte {
	return r.newSourceDecryptableAvailableBalance
}
func (r *ConfidentialTransferWithFeeRequest) ToAuditorCiphertextLo() []byte {
	return r.auditorCiphertextLo
}
func (r *ConfidentialTransferWithFeeRequest) ToAuditorCiphertextHi() []byte {
	return r.auditorCiphertextHi
}
func (r *ConfidentialTransferWithFeeRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *ConfidentialTransferWithFeeRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *ConfidentialTransferWithFeeRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ConfidentialTransferWithFeeRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ConfidentialTransferWithFeeRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ConfidentialTransferWithFeeResponse reports the built transaction.
type ConfidentialTransferWithFeeResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Source      string `json:"source"`
	Mint        string `json:"mint"`
	Destination string `json:"destination"`
	Owner       string `json:"owner"`
	Program     string `json:"program"`

	EqualityContextStateAccount               string `json:"equality_context_state_account"`
	TransferAmountValidityContextStateAccount string `json:"transfer_amount_validity_context_state_account"`
	FeeSigmaContextStateAccount               string `json:"fee_sigma_context_state_account"`
	FeeValidityContextStateAccount            string `json:"fee_validity_context_state_account"`
	RangeProofContextStateAccount             string `json:"range_proof_context_state_account"`

	Fee SystemPayer `json:"fee"`
}

func NewConfidentialTransferWithFeeResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, source, mint, destination, owner, tokenProgram, equalityContext, validityContext, feeSigmaContext, feeValidityContext, rangeContext, nonceAuthority *types.PublicKey,
	fee uint64,
) *ConfidentialTransferWithFeeResponse {
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

	return &ConfidentialTransferWithFeeResponse{
		Transaction:                 codec.Base64.Encode(raw),
		Message:                     codec.Base64.Encode(message),
		RecentBlockhash:             tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                 keys,
		Signers:                     signers,
		NonceAuthority:              nonceAuth,
		Source:                      source.Base58(),
		Mint:                        mint.Base58(),
		Destination:                 destination.Base58(),
		Owner:                       owner.Base58(),
		Program:                     tokenProgram.Base58(),
		EqualityContextStateAccount: equalityContext.Base58(),
		TransferAmountValidityContextStateAccount: validityContext.Base58(),
		FeeSigmaContextStateAccount:               feeSigmaContext.Base58(),
		FeeValidityContextStateAccount:            feeValidityContext.Base58(),
		RangeProofContextStateAccount:             rangeContext.Base58(),
		Fee:                                       newSystemPayer(feePayer, fee),
	}
}

// EnableHarvestToMintRequest makes the mint accept harvested confidential fees -- sets its
// ConfidentialTransferFeeConfig.harvest_to_mint_enabled flag. No zero-knowledge
// proof is needed, and the instruction carries no data beyond its
// discriminant.
type EnableHarvestToMintRequest struct {
	// Mint must already carry the ConfidentialTransferFeeConfig extension
	// (see confidential-transfer-fee-config/initialize).
	Mint string `json:"mint" example:""`

	// Authority is the authority the ConfidentialTransferFeeConfig names
	// (its authority field, not the TransferFeeConfig's withdraw withheld
	// authority), or its multisig for a multisig-owned one (see
	// MultisigSigners).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this
	// extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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
	// builds the message against the value that mint stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the mint, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	mint            *types.PublicKey
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *EnableHarvestToMintRequest) ValidateRequest() error {
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *EnableHarvestToMintRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *EnableHarvestToMintRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *EnableHarvestToMintRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *EnableHarvestToMintRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *EnableHarvestToMintRequest) DurableNonceMintKey() *types.PublicKey {
	return r.dna
}
func (r *EnableHarvestToMintRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *EnableHarvestToMintRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// EnableHarvestToMintResponse reports the built transaction.
type EnableHarvestToMintResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint      string `json:"mint"`
	Authority string `json:"authority"`
	Program   string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewEnableHarvestToMintResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *EnableHarvestToMintResponse {
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

	return &EnableHarvestToMintResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// ConfidentialApplyPendingBurnRequest folds the mint's pending burn (what Burn
// accumulated) into its confidential supply and resets the pending burn to
// zero. Authorized by the mint authority. No zero-knowledge proof is needed,
// and the instruction carries no data beyond its discriminant.
type ConfidentialApplyPendingBurnRequest struct {
	// Mint must carry the ConfidentialMintBurn extension.
	Mint string `json:"mint" example:""`

	// Authority is the mint's mint authority, or its multisig for a
	// multisig-owned one (see MultisigSigners).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this
	// extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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
	// builds the message against the value that mint stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the mint, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	mint            *types.PublicKey
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *ConfidentialApplyPendingBurnRequest) ValidateRequest() error {
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *ConfidentialApplyPendingBurnRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *ConfidentialApplyPendingBurnRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *ConfidentialApplyPendingBurnRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *ConfidentialApplyPendingBurnRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *ConfidentialApplyPendingBurnRequest) DurableNonceMintKey() *types.PublicKey {
	return r.dna
}
func (r *ConfidentialApplyPendingBurnRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ConfidentialApplyPendingBurnRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ConfidentialApplyPendingBurnResponse reports the built transaction.
type ConfidentialApplyPendingBurnResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint      string `json:"mint"`
	Authority string `json:"authority"`
	Program   string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewConfidentialApplyPendingBurnResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *ConfidentialApplyPendingBurnResponse {
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

	return &ConfidentialApplyPendingBurnResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// ConfidentialRotateSupplyElGamalPubkeyRequest replaces the ElGamal key the
// mint's confidential supply is encrypted under -- and the ciphertext itself --
// with a new one. Authorized by the mint authority. The mint's pending burn
// must be zero (run apply-pending-burn first).
//
// This builds only the instruction. The CiphertextCiphertextEquality proof
// must already be verified into a context-state account: build it with
// tool/prove/confidential-rotate-supply-elgamal-pubkey, create the account with
// zk-elgamal-proof/context-state/create/ciphertext-ciphertext-equality, and
// verify it with context-state/verify/ciphertext-ciphertext-equality.
type ConfidentialRotateSupplyElGamalPubkeyRequest struct {
	// Mint must carry the ConfidentialMintBurn extension.
	Mint string `json:"mint" example:""`

	// NewSupplyElgamalPubkey is the key the supply moves to, base58-encoded raw
	// 32 bytes -- the same one the prove tool was given.
	NewSupplyElgamalPubkey string `json:"new_supply_elgamal_pubkey" example:""`

	// EqualityContextStateAccount holds the verified
	// CiphertextCiphertextEquality proof's context.
	EqualityContextStateAccount string `json:"equality_context_state_account" example:""`

	// Authority is the mint's mint authority, or its multisig for a
	// multisig-owned one (see MultisigSigners).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this
	// extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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
	// builds the message against the value that mint stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the mint, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	mint            *types.PublicKey
	newPubkey       []byte
	eqContext       *types.PublicKey
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *ConfidentialRotateSupplyElGamalPubkeyRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.newPubkey, err = codec.Base58.DecodeFixed(strings.TrimSpace(r.NewSupplyElgamalPubkey), 32); err != nil {
		return errors.New("new_supply_elgamal_pubkey: " + err.Error())
	}
	if r.eqContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.EqualityContextStateAccount)); err != nil {
		return errors.New("equality_context_state_account: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *ConfidentialRotateSupplyElGamalPubkeyRequest) ToNewSupplyElgamalPubkey() []byte {
	return r.newPubkey
}
func (r *ConfidentialRotateSupplyElGamalPubkeyRequest) EqualityContextKey() *types.PublicKey {
	return r.eqContext
}
func (r *ConfidentialRotateSupplyElGamalPubkeyRequest) MintKey() *types.PublicKey { return r.mint }
func (r *ConfidentialRotateSupplyElGamalPubkeyRequest) AuthorityKey() *types.PublicKey {
	return r.authority
}
func (r *ConfidentialRotateSupplyElGamalPubkeyRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}
func (r *ConfidentialRotateSupplyElGamalPubkeyRequest) Blockhash() *types.Hash { return r.rbh }
func (r *ConfidentialRotateSupplyElGamalPubkeyRequest) DurableNonceMintKey() *types.PublicKey {
	return r.dna
}
func (r *ConfidentialRotateSupplyElGamalPubkeyRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ConfidentialRotateSupplyElGamalPubkeyRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ConfidentialRotateSupplyElGamalPubkeyResponse reports the built transaction.
type ConfidentialRotateSupplyElGamalPubkeyResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint                        string `json:"mint"`
	Authority                   string `json:"authority"`
	NewSupplyElgamalPubkey      string `json:"new_supply_elgamal_pubkey"`
	EqualityContextStateAccount string `json:"equality_context_state_account"`
	Program                     string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewConfidentialRotateSupplyElGamalPubkeyResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, eqContext, nonceAuthority *types.PublicKey,
	newPubkey []byte,
	fee uint64,
) *ConfidentialRotateSupplyElGamalPubkeyResponse {
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

	return &ConfidentialRotateSupplyElGamalPubkeyResponse{
		Transaction:                 codec.Base64.Encode(raw),
		Message:                     codec.Base64.Encode(message),
		RecentBlockhash:             tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                 keys,
		Signers:                     signers,
		NonceAuthority:              nonceAuth,
		Mint:                        mint.Base58(),
		Authority:                   authority.Base58(),
		NewSupplyElgamalPubkey:      codec.Base58.Encode(newPubkey),
		EqualityContextStateAccount: eqContext.Base58(),
		Program:                     tokenProgram.Base58(),
		Fee:                         newSystemPayer(feePayer, fee),
	}
}

// ConfidentialUpdateDecryptableSupplyRequest overwrites the mint's
// decryptable supply -- the cheap AE cache of its confidential supply. The
// program cannot check the value against the confidential supply, so the
// caller is trusted to keep the two in step. Authorized by the mint authority.
type ConfidentialUpdateDecryptableSupplyRequest struct {
	// Mint must carry the ConfidentialMintBurn extension.
	Mint string `json:"mint" example:""`

	// Authority is the mint's mint authority, or its multisig for a
	// multisig-owned one (see MultisigSigners).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// SupplyAeKey encrypts NewSupply into the decryptable supply the
	// instruction carries, base58-encoded raw 16 bytes -- the key the mint was
	// initialized with.
	SupplyAeKey string `json:"supply_ae_key" example:""`

	// NewSupply is the confidential supply the decryptable supply should now
	// equal, in raw base units. The program cannot check it against the
	// confidential supply, so it has to be the value the caller knows the
	// supply to be (see the ElGamal decryption of the mint's
	// confidential_supply).
	NewSupply string `json:"new_supply" example:"600"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this
	// extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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
	// builds the message against the value that mint stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the mint, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	mint            *types.PublicKey
	newDecryptable  []byte
	newSupply       uint64
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *ConfidentialUpdateDecryptableSupplyRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	aeKey, err := codec.Base58.DecodeFixed(strings.TrimSpace(r.SupplyAeKey), 16)
	if err != nil {
		return errors.New("supply_ae_key: " + err.Error())
	}
	if r.newSupply, err = strconv.ParseUint(strings.TrimSpace(r.NewSupply), 10, 64); err != nil {
		return errors.New("new_supply: " + err.Error())
	}
	if r.newDecryptable, err = core.EncryptAeAmount(aeKey, r.newSupply); err != nil {
		return errors.New("supply_ae_key: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *ConfidentialUpdateDecryptableSupplyRequest) ToNewDecryptableSupply() []byte {
	return r.newDecryptable
}
func (r *ConfidentialUpdateDecryptableSupplyRequest) MintKey() *types.PublicKey { return r.mint }
func (r *ConfidentialUpdateDecryptableSupplyRequest) AuthorityKey() *types.PublicKey {
	return r.authority
}
func (r *ConfidentialUpdateDecryptableSupplyRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}
func (r *ConfidentialUpdateDecryptableSupplyRequest) Blockhash() *types.Hash { return r.rbh }
func (r *ConfidentialUpdateDecryptableSupplyRequest) DurableNonceMintKey() *types.PublicKey {
	return r.dna
}
func (r *ConfidentialUpdateDecryptableSupplyRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ConfidentialUpdateDecryptableSupplyRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ConfidentialUpdateDecryptableSupplyResponse reports the built transaction.
type ConfidentialUpdateDecryptableSupplyResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint                 string `json:"mint"`
	Authority            string `json:"authority"`
	NewDecryptableSupply string `json:"new_decryptable_supply"`
	Program              string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewConfidentialUpdateDecryptableSupplyResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	newDecryptableSupply []byte,
	fee uint64,
) *ConfidentialUpdateDecryptableSupplyResponse {
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

	return &ConfidentialUpdateDecryptableSupplyResponse{
		Transaction:          codec.Base64.Encode(raw),
		Message:              codec.Base64.Encode(message),
		RecentBlockhash:      tx.Message.RecentBlockhash.Base58(),
		AccountKeys:          keys,
		Signers:              signers,
		NonceAuthority:       nonceAuth,
		Mint:                 mint.Base58(),
		Authority:            authority.Base58(),
		NewDecryptableSupply: codec.Base58.Encode(newDecryptableSupply),
		Program:              tokenProgram.Base58(),
		Fee:                  newSystemPayer(feePayer, fee),
	}
}

// DisableHarvestToMintRequest makes the mint reject harvested confidential fees -- clears its
// ConfidentialTransferFeeConfig.harvest_to_mint_enabled flag. No zero-knowledge
// proof is needed, and the instruction carries no data beyond its
// discriminant.
type DisableHarvestToMintRequest struct {
	// Mint must already carry the ConfidentialTransferFeeConfig extension
	// (see confidential-transfer-fee-config/initialize).
	Mint string `json:"mint" example:""`

	// Authority is the authority the ConfidentialTransferFeeConfig names
	// (its authority field, not the TransferFeeConfig's withdraw withheld
	// authority), or its multisig for a multisig-owned one (see
	// MultisigSigners).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this
	// extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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
	// builds the message against the value that mint stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction. The authority is not a
	// field: it is read from the mint, since it is a fact about it rather
	// than a choice.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	mint            *types.PublicKey
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *DisableHarvestToMintRequest) ValidateRequest() error {
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *DisableHarvestToMintRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *DisableHarvestToMintRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *DisableHarvestToMintRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *DisableHarvestToMintRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *DisableHarvestToMintRequest) DurableNonceMintKey() *types.PublicKey {
	return r.dna
}
func (r *DisableHarvestToMintRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *DisableHarvestToMintRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// DisableHarvestToMintResponse reports the built transaction.
type DisableHarvestToMintResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint      string `json:"mint"`
	Authority string `json:"authority"`
	Program   string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewDisableHarvestToMintResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *DisableHarvestToMintResponse {
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

	return &DisableHarvestToMintResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// ConfidentialHarvestWithheldTokensToMintRequest moves the confidential fees withheld on
// each of SourceAccounts into Mint's own withheld amount, where the withdraw
// authority can then collect them all at once. It is permissionless -- no
// account signs -- and no zero-knowledge proof is needed. A source account
// that does not carry both TransferFeeAmount and ConfidentialTransferAccount
// is skipped by the program rather than rejected, so the response reports
// which sources were actually eligible.
type ConfidentialHarvestWithheldTokensToMintRequest struct {
	// Mint must carry the ConfidentialTransferFeeConfig extension with
	// harvest_to_mint_enabled set (see enable-harvest-to-mint).
	Mint string `json:"mint" example:""`

	// SourceAccounts are the token accounts to harvest from, each holding
	// Mint. There is no limit here beyond what fits in one transaction, which
	// this endpoint checks.
	SourceAccounts []string `json:"source_accounts"`

	// FeePayer signs and pays the transaction fee. Nothing else signs.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this
	// extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	mint           *types.PublicKey
	sources        []*types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *ConfidentialHarvestWithheldTokensToMintRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}

	if len(r.SourceAccounts) == 0 {
		return errors.New("source_accounts: at least one is required")
	}
	seen := make(map[string]bool, len(r.SourceAccounts))
	r.sources = make([]*types.PublicKey, len(r.SourceAccounts))
	for i, a := range r.SourceAccounts {
		if r.sources[i], err = types.NewPublicKeyFromBase58(strings.TrimSpace(a)); err != nil {
			return fmt.Errorf("source_accounts[%d]: %s", i, err)
		}
		if seen[r.sources[i].Base58()] {
			return fmt.Errorf("source_accounts[%d]: %s is listed twice", i, r.sources[i])
		}
		seen[r.sources[i].Base58()] = true
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ConfidentialHarvestWithheldTokensToMintRequest) MintKey() *types.PublicKey { return r.mint }
func (r *ConfidentialHarvestWithheldTokensToMintRequest) SourceKeys() []*types.PublicKey {
	return r.sources
}
func (r *ConfidentialHarvestWithheldTokensToMintRequest) FeePayerKey() *types.PublicKey {
	return r.feePayer
}
func (r *ConfidentialHarvestWithheldTokensToMintRequest) Blockhash() *types.Hash { return r.rbh }
func (r *ConfidentialHarvestWithheldTokensToMintRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ConfidentialHarvestWithheldTokensToMintRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// ConfidentialHarvestWithheldTokensToMintResponse reports the built transaction.
type ConfidentialHarvestWithheldTokensToMintResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint    string `json:"mint"`
	Program string `json:"program"`

	// HarvestedSources are the source accounts that carry both
	// TransferFeeAmount and ConfidentialTransferAccount, so the program
	// actually moves their withheld fees. SkippedSources do not, and the
	// program passes over them silently.
	HarvestedSources []string `json:"harvested_sources"`
	SkippedSources   []string `json:"skipped_sources"`

	Fee SystemPayer `json:"fee"`
}

func NewConfidentialHarvestWithheldTokensToMintResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, tokenProgram, nonceAuthority *types.PublicKey,
	harvested, skipped []*types.PublicKey,
	fee uint64,
) *ConfidentialHarvestWithheldTokensToMintResponse {
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

	list := func(ks []*types.PublicKey) []string {
		out := make([]string, len(ks))
		for i, k := range ks {
			out[i] = k.Base58()
		}
		return out
	}

	return &ConfidentialHarvestWithheldTokensToMintResponse{
		Transaction:      codec.Base64.Encode(raw),
		Message:          codec.Base64.Encode(message),
		RecentBlockhash:  tx.Message.RecentBlockhash.Base58(),
		AccountKeys:      keys,
		Signers:          signers,
		NonceAuthority:   nonceAuth,
		Mint:             mint.Base58(),
		Program:          tokenProgram.Base58(),
		HarvestedSources: list(harvested),
		SkippedSources:   list(skipped),
		Fee:              newSystemPayer(feePayer, fee),
	}
}

// InitializeNonTransferableMintRequest marks Mint as non-transferable: its
// tokens can be minted and burned but never moved between accounts, and no
// instruction ever makes the mint transferable again. Every token account of
// such a mint gets the NonTransferableAccount extension automatically and needs
// ImmutableOwner.
//
// This can only ever run in the narrow window every mint extension shares:
// after the mint account has been allocated (sized to include this extension)
// and before initialize-mint2 locks the extension list forever.
type InitializeNonTransferableMintRequest struct {
	// Mint is the account this attaches to. It must already exist (see
	// create-mint) and not yet be initialized -- initialize-mint2 has to
	// run after this, never before.
	Mint string `json:"mint" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint           *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *InitializeNonTransferableMintRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *InitializeNonTransferableMintRequest) MintKey() *types.PublicKey     { return r.mint }
func (r *InitializeNonTransferableMintRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *InitializeNonTransferableMintRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *InitializeNonTransferableMintRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *InitializeNonTransferableMintRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeNonTransferableMintResponse reports the built transaction.
type InitializeNonTransferableMintResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint    string `json:"mint"`
	Program string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializeNonTransferableMintResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *InitializeNonTransferableMintResponse {
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

	res := &InitializeNonTransferableMintResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}

	return res
}

// InitializePermanentDelegateRequest names a permanent delegate for Mint -- an
// authority that can transfer or burn any holder's tokens of this mint,
// without approval and for as long as the mint exists. A mint that should not
// have one simply does not carry this extension.
//
// This can only ever run in the narrow window every mint extension shares:
// after the mint account has been allocated (sized to include this extension)
// and before initialize-mint2 locks the extension list forever.
type InitializePermanentDelegateRequest struct {
	// Mint is the account this attaches to. It must already exist (see
	// create-mint) and not yet be initialized -- initialize-mint2 has to
	// run after this, never before.
	Mint string `json:"mint" example:""`

	// Delegate may transfer or burn any holder's tokens of Mint, with no approval,
	// for as long as the mint exists. Required: there is no such thing as a
	// permanent delegate that is nobody.
	Delegate string `json:"delegate" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint           *types.PublicKey
	delegate       *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *InitializePermanentDelegateRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.delegate, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Delegate)); err != nil {
		return errors.New("delegate: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *InitializePermanentDelegateRequest) MintKey() *types.PublicKey     { return r.mint }
func (r *InitializePermanentDelegateRequest) DelegateKey() *types.PublicKey { return r.delegate }
func (r *InitializePermanentDelegateRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *InitializePermanentDelegateRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *InitializePermanentDelegateRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *InitializePermanentDelegateRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializePermanentDelegateResponse reports the built transaction.
type InitializePermanentDelegateResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint     string `json:"mint"`
	Delegate string `json:"delegate"`
	Program  string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializePermanentDelegateResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, delegate, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *InitializePermanentDelegateResponse {
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

	res := &InitializePermanentDelegateResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Delegate:        delegate.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}

	return res
}

// CreateNativeMintRequest creates and initializes Token-2022's own native mint
// -- the mint that stands in for wrapped SOL under that program -- at the
// address the program derives. It exists only on Token-2022 and fails if the
// account already exists, which is the case on every public cluster, so this
// is only useful on a fresh one.
type CreateNativeMintRequest struct {
	// RentPayer signs and pays the native mint's rent, which the program takes
	// from it.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. Classic Token has no CreateNativeMint.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *CreateNativeMintRequest) ValidateRequest() error {
	var err error
	if r.rentPayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *CreateNativeMintRequest) RentPayerKey() *types.PublicKey { return r.rentPayer }
func (r *CreateNativeMintRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *CreateNativeMintRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *CreateNativeMintRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *CreateNativeMintRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// CreateNativeMintResponse reports the built transaction.
type CreateNativeMintResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint      string `json:"mint"`
	RentPayer string `json:"rent_payer"`
	Program   string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewCreateNativeMintResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, rentPayer, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *CreateNativeMintResponse {
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

	res := &CreateNativeMintResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		RentPayer:       rentPayer.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}

	return res
}

// EnableRequiredMemoTransfersRequest makes Account require a Memo instruction
// ahead of every transfer into it -- sets its MemoTransfer.require_incoming_transfer_memos
// flag. No zero-knowledge proof is needed, and the instruction carries no data
// beyond its discriminants.
type EnableRequiredMemoTransfersRequest struct {
	// Account is a Token-2022 token account. If it does not carry the
	// MemoTransfer extension yet, the instruction adds it, which needs room for it
	// already in the account (see memo-transfer/reallocate).
	Account string `json:"account" example:""`

	// Owner is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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

	account         *types.PublicKey
	owner           *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *EnableRequiredMemoTransfersRequest) ValidateRequest() error {
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *EnableRequiredMemoTransfersRequest) AccountKey() *types.PublicKey  { return r.account }
func (r *EnableRequiredMemoTransfersRequest) OwnerKey() *types.PublicKey    { return r.owner }
func (r *EnableRequiredMemoTransfersRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *EnableRequiredMemoTransfersRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *EnableRequiredMemoTransfersRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *EnableRequiredMemoTransfersRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *EnableRequiredMemoTransfersRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// EnableRequiredMemoTransfersResponse reports the built transaction.
type EnableRequiredMemoTransfersResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Owner   string `json:"owner"`
	Program string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewEnableRequiredMemoTransfersResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, account, owner, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *EnableRequiredMemoTransfersResponse {
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

	return &EnableRequiredMemoTransfersResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Owner:           owner.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// DisableRequiredMemoTransfersRequest stops Account requiring memos on incoming
// transfers -- clears its MemoTransfer.require_incoming_transfer_memos flag.
type DisableRequiredMemoTransfersRequest struct {
	// Account is a Token-2022 token account. If it does not carry the
	// MemoTransfer extension yet, the instruction adds it, which needs room for it
	// already in the account (see memo-transfer/reallocate).
	Account string `json:"account" example:""`

	// Owner is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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

	account         *types.PublicKey
	owner           *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *DisableRequiredMemoTransfersRequest) ValidateRequest() error {
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *DisableRequiredMemoTransfersRequest) AccountKey() *types.PublicKey  { return r.account }
func (r *DisableRequiredMemoTransfersRequest) OwnerKey() *types.PublicKey    { return r.owner }
func (r *DisableRequiredMemoTransfersRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *DisableRequiredMemoTransfersRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *DisableRequiredMemoTransfersRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *DisableRequiredMemoTransfersRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *DisableRequiredMemoTransfersRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// DisableRequiredMemoTransfersResponse reports the built transaction.
type DisableRequiredMemoTransfersResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Owner   string `json:"owner"`
	Program string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewDisableRequiredMemoTransfersResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, account, owner, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *DisableRequiredMemoTransfersResponse {
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

	return &DisableRequiredMemoTransfersResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Owner:           owner.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// EnableCpiGuardRequest turns the CPI guard on for Account -- sets its
// CpiGuard.lock_cpi flag. Within a cross-program invocation, Transfer and Burn
// must then go through a delegate, CloseAccount can only return lamports to
// the owner, SetAuthority can only remove a close authority, and Approve is
// disallowed. It cannot itself be enabled or disabled via CPI.
type EnableCpiGuardRequest struct {
	// Account is a Token-2022 token account. If it does not carry the
	// CpiGuard extension yet, the instruction adds it, which needs room for it
	// already in the account (see cpi-guard/reallocate).
	Account string `json:"account" example:""`

	// Owner is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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

	account         *types.PublicKey
	owner           *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *EnableCpiGuardRequest) ValidateRequest() error {
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *EnableCpiGuardRequest) AccountKey() *types.PublicKey  { return r.account }
func (r *EnableCpiGuardRequest) OwnerKey() *types.PublicKey    { return r.owner }
func (r *EnableCpiGuardRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *EnableCpiGuardRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *EnableCpiGuardRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *EnableCpiGuardRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *EnableCpiGuardRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// EnableCpiGuardResponse reports the built transaction.
type EnableCpiGuardResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Owner   string `json:"owner"`
	Program string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewEnableCpiGuardResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, account, owner, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *EnableCpiGuardResponse {
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

	return &EnableCpiGuardResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Owner:           owner.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// DisableCpiGuardRequest turns the CPI guard off for Account -- clears its
// CpiGuard.lock_cpi flag, so all token operations may happen via CPI as normal.
type DisableCpiGuardRequest struct {
	// Account is a Token-2022 token account. If it does not carry the
	// CpiGuard extension yet, the instruction adds it, which needs room for it
	// already in the account (see cpi-guard/reallocate).
	Account string `json:"account" example:""`

	// Owner is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token account can never hold
	// this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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

	account         *types.PublicKey
	owner           *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *DisableCpiGuardRequest) ValidateRequest() error {
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *DisableCpiGuardRequest) AccountKey() *types.PublicKey  { return r.account }
func (r *DisableCpiGuardRequest) OwnerKey() *types.PublicKey    { return r.owner }
func (r *DisableCpiGuardRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *DisableCpiGuardRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *DisableCpiGuardRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *DisableCpiGuardRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *DisableCpiGuardRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// DisableCpiGuardResponse reports the built transaction.
type DisableCpiGuardResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Owner   string `json:"owner"`
	Program string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewDisableCpiGuardResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, account, owner, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *DisableCpiGuardResponse {
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

	return &DisableCpiGuardResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Owner:           owner.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// ReallocateMemoTransferRequest checks whether Account already holds room for
// MemoTransfer, and grows it if not -- the step before memo-transfer/enable
// or /disable on an account that does not carry the extension yet.
//
// The instruction itself only ever needs the one new extension type being
// added: Reallocate reads Account's own existing extensions on chain and
// unions them with whatever this sends. Getting the resize's rent right is
// this handler's own job, not the instruction's -- it reads Account's current
// extensions and actual lamports itself, asks GetAccountDataSize for the full
// target size, and only then knows RentPayer's shortfall.
type ReallocateMemoTransferRequest struct {
	// Account is the token account to check and, if needed, grow. It must
	// already exist and be owned by Program.
	Account string `json:"account" example:""`

	// RentPayer funds whatever the resize costs, a distinct role from
	// Owner: Owner authorizes the account being touched, RentPayer covers
	// what that costs, and they need not be the same key.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Owner is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. Unlike every other Token endpoint, this
	// is not the usual either-program field: a classic Token account's
	// layout is fixed at 165 bytes forever, with no TLV region to grow
	// into, so classic Token is rejected here rather than left to fail on
	// chain.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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

	account         *types.PublicKey
	rentPayer       *types.PublicKey
	owner           *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *ReallocateMemoTransferRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.rentPayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
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
	// Unlike every other Token endpoint, which accepts either program
	// because the instruction genuinely works on both, an extension has
	// nowhere to live on a classic Token account: that layout is fixed at
	// 165 bytes forever, with no TLV region to grow into at all. Rejecting
	// classic Token here is a structural fact about the account, not a
	// preference, so it is checked before the request ever reaches the
	// chain rather than left to come back as an on-chain rejection.
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ReallocateMemoTransferRequest) AccountKey() *types.PublicKey   { return r.account }
func (r *ReallocateMemoTransferRequest) RentPayerKey() *types.PublicKey { return r.rentPayer }
func (r *ReallocateMemoTransferRequest) OwnerKey() *types.PublicKey     { return r.owner }
func (r *ReallocateMemoTransferRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *ReallocateMemoTransferRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *ReallocateMemoTransferRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ReallocateMemoTransferRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ReallocateMemoTransferRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ReallocateMemoTransferResponse reports the built transaction
// alongside what it resizes Account for.
type ReallocateMemoTransferResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Owner   string `json:"owner"`
	Program string `json:"program"`

	// TargetSize is the total account size GetAccountDataSize reported for
	// Account's existing extensions plus MemoTransfer, asked of the
	// deployed program rather than recomputed here.
	TargetSize string `json:"target_size"`

	// Rent reports what funds the resize: the shortfall between
	// TargetSize's rent-exemption minimum and Account's actual current
	// lamports, zero when Account already holds enough.
	Rent SystemPayer `json:"rent"`
	Fee  SystemPayer `json:"fee"`
}

func NewReallocateMemoTransferResponse(
	tx *types.Transaction, raw, message []byte,
	rentPayer, feePayer, account, owner, tokenProgram, nonceAuthority *types.PublicKey,
	targetSize, rentShortfall, fee uint64,
) *ReallocateMemoTransferResponse {
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

	return &ReallocateMemoTransferResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Owner:           owner.Base58(),
		Program:         tokenProgram.Base58(),
		TargetSize:      strconv.FormatUint(targetSize, 10),
		Rent:            newSystemPayer(rentPayer, rentShortfall),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// ReallocateCpiGuardRequest checks whether Account already holds room for
// CpiGuard, and grows it if not -- the step before cpi-guard/enable or
// /disable on an account that does not carry the extension yet.
//
// The instruction itself only ever needs the one new extension type being
// added: Reallocate reads Account's own existing extensions on chain and
// unions them with whatever this sends. Getting the resize's rent right is
// this handler's own job, not the instruction's -- it reads Account's current
// extensions and actual lamports itself, asks GetAccountDataSize for the full
// target size, and only then knows RentPayer's shortfall.
type ReallocateCpiGuardRequest struct {
	// Account is the token account to check and, if needed, grow. It must
	// already exist and be owned by Program.
	Account string `json:"account" example:""`

	// RentPayer funds whatever the resize costs, a distinct role from
	// Owner: Owner authorizes the account being touched, RentPayer covers
	// what that costs, and they need not be the same key.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Owner is Account's owner, or its multisig for a multisig-owned
	// account (see MultisigSigners).
	Owner string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. Unlike every other Token endpoint, this
	// is not the usual either-program field: a classic Token account's
	// layout is fixed at 165 bytes forever, with no TLV region to grow
	// into, so classic Token is rejected here rather than left to fail on
	// chain.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer owner. Non-empty, Owner
	// itself does not sign; the named members do, in its place.
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

	account         *types.PublicKey
	rentPayer       *types.PublicKey
	owner           *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *ReallocateCpiGuardRequest) ValidateRequest() error {
	var err error
	if r.account, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Account)); err != nil {
		return errors.New("account: " + err.Error())
	}
	if r.rentPayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
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
	// Unlike every other Token endpoint, which accepts either program
	// because the instruction genuinely works on both, an extension has
	// nowhere to live on a classic Token account: that layout is fixed at
	// 165 bytes forever, with no TLV region to grow into at all. Rejecting
	// classic Token here is a structural fact about the account, not a
	// preference, so it is checked before the request ever reaches the
	// chain rather than left to come back as an on-chain rejection.
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 account", r.tokenProgramID)
	}

	return nil
}

func (r *ReallocateCpiGuardRequest) AccountKey() *types.PublicKey   { return r.account }
func (r *ReallocateCpiGuardRequest) RentPayerKey() *types.PublicKey { return r.rentPayer }
func (r *ReallocateCpiGuardRequest) OwnerKey() *types.PublicKey     { return r.owner }
func (r *ReallocateCpiGuardRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *ReallocateCpiGuardRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *ReallocateCpiGuardRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ReallocateCpiGuardRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ReallocateCpiGuardRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ReallocateCpiGuardResponse reports the built transaction
// alongside what it resizes Account for.
type ReallocateCpiGuardResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Account string `json:"account"`
	Owner   string `json:"owner"`
	Program string `json:"program"`

	// TargetSize is the total account size GetAccountDataSize reported for
	// Account's existing extensions plus CpiGuard, asked of the
	// deployed program rather than recomputed here.
	TargetSize string `json:"target_size"`

	// Rent reports what funds the resize: the shortfall between
	// TargetSize's rent-exemption minimum and Account's actual current
	// lamports, zero when Account already holds enough.
	Rent SystemPayer `json:"rent"`
	Fee  SystemPayer `json:"fee"`
}

func NewReallocateCpiGuardResponse(
	tx *types.Transaction, raw, message []byte,
	rentPayer, feePayer, account, owner, tokenProgram, nonceAuthority *types.PublicKey,
	targetSize, rentShortfall, fee uint64,
) *ReallocateCpiGuardResponse {
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

	return &ReallocateCpiGuardResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Account:         account.Base58(),
		Owner:           owner.Base58(),
		Program:         tokenProgram.Base58(),
		TargetSize:      strconv.FormatUint(targetSize, 10),
		Rent:            newSystemPayer(rentPayer, rentShortfall),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// InitializeDefaultAccountStateRequest attaches the DefaultAccountState
// extension to Mint: every token account created for it from then on starts in
// State, which is how a mint makes new accounts start frozen until its freeze
// authority thaws them.
//
// This can only ever run in the narrow window every mint extension shares:
// after the mint account has been allocated (sized to include this extension)
// and before initialize-mint2 locks the extension list forever.
type InitializeDefaultAccountStateRequest struct {
	// Mint is the account this attaches to. It must already exist (see
	// create-mint) and not yet be initialized -- initialize-mint2 has to
	// run after this, never before.
	Mint string `json:"mint" example:""`

	// State is what every new token account of this mint starts in: "initialized"
	// (usable at once) or "frozen" (unusable until the freeze authority thaws it). A
	// frozen default needs the mint to have a freeze authority.
	State string `json:"state" example:"frozen"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint           *types.PublicKey
	state          uint8
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *InitializeDefaultAccountStateRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	switch strings.ToLower(strings.TrimSpace(r.State)) {
	case "initialized":
		r.state = core.TokenAccountStateInitialized
	case "frozen":
		r.state = core.TokenAccountStateFrozen
	default:
		return errors.New(`state: must be "initialized" or "frozen"`)
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *InitializeDefaultAccountStateRequest) MintKey() *types.PublicKey     { return r.mint }
func (r *InitializeDefaultAccountStateRequest) ToState() uint8                { return r.state }
func (r *InitializeDefaultAccountStateRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *InitializeDefaultAccountStateRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *InitializeDefaultAccountStateRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *InitializeDefaultAccountStateRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeDefaultAccountStateResponse reports the built transaction.
type InitializeDefaultAccountStateResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint    string `json:"mint"`
	State   string `json:"state"`
	Program string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializeDefaultAccountStateResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, tokenProgram, nonceAuthority *types.PublicKey,
	stateName string,
	fee uint64,
) *InitializeDefaultAccountStateResponse {
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

	res := &InitializeDefaultAccountStateResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		State:           stateName,
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}

	return res
}

// InitializeInterestBearingMintRequest attaches the InterestBearingConfig
// extension to Mint, naming who may later change the rate and the initial rate.
// The extension only changes how amounts are displayed (see amount-to-ui); it
// never mints tokens.
//
// This can only ever run in the narrow window every mint extension shares:
// after the mint account has been allocated (sized to include this extension)
// and before initialize-mint2 locks the extension list forever.
type InitializeInterestBearingMintRequest struct {
	// Mint is the account this attaches to. It must already exist (see
	// create-mint) and not yet be initialized -- initialize-mint2 has to
	// run after this, never before.
	Mint string `json:"mint" example:""`

	// RateAuthority may change the rate later. Left empty, the rate is fixed for
	// good.
	RateAuthority string `json:"rate_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Rate is the initial interest rate in basis points, as a signed 16-bit
	// number (500 = 5% a year; negative rates are allowed).
	Rate string `json:"rate" example:"500"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint           *types.PublicKey
	rateAuthority  *types.PublicKey
	rate           int16
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *InitializeInterestBearingMintRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if a := strings.TrimSpace(r.RateAuthority); a != "" {
		if r.rateAuthority, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("rate_authority: " + err.Error())
		}
	}
	rate, err := strconv.ParseInt(strings.TrimSpace(r.Rate), 10, 16)
	if err != nil {
		return errors.New("rate: " + err.Error())
	}
	r.rate = int16(rate)
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *InitializeInterestBearingMintRequest) MintKey() *types.PublicKey { return r.mint }
func (r *InitializeInterestBearingMintRequest) RateAuthorityKey() *types.PublicKey {
	return r.rateAuthority
}
func (r *InitializeInterestBearingMintRequest) ToRate() int16                 { return r.rate }
func (r *InitializeInterestBearingMintRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *InitializeInterestBearingMintRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *InitializeInterestBearingMintRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *InitializeInterestBearingMintRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeInterestBearingMintResponse reports the built transaction.
type InitializeInterestBearingMintResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint          string `json:"mint"`
	RateAuthority string `json:"rate_authority,omitempty"`
	Rate          string `json:"rate"`
	Program       string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializeInterestBearingMintResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, rateAuthority, tokenProgram, nonceAuthority *types.PublicKey,
	rate int16,
	fee uint64,
) *InitializeInterestBearingMintResponse {
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

	res := &InitializeInterestBearingMintResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Rate:            strconv.Itoa(int(rate)),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
	if !rateAuthority.IsNil() {
		res.RateAuthority = rateAuthority.Base58()
	}

	return res
}

// InitializeScaledUiAmountRequest attaches the ScaledUiAmount extension to Mint,
// naming who may later change the multiplier and the initial multiplier. Like
// the interest-bearing extension it only changes how amounts are displayed.
//
// This can only ever run in the narrow window every mint extension shares:
// after the mint account has been allocated (sized to include this extension)
// and before initialize-mint2 locks the extension list forever.
type InitializeScaledUiAmountRequest struct {
	// Mint is the account this attaches to. It must already exist (see
	// create-mint) and not yet be initialized -- initialize-mint2 has to
	// run after this, never before.
	Mint string `json:"mint" example:""`

	// Authority may change the multiplier later. Left empty, the multiplier is fixed
	// for good.
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Multiplier is the initial display multiplier: a positive decimal, not
	// subnormal (1.5 shows 100 base units as 150).
	Multiplier string `json:"multiplier" example:"1.5"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint           *types.PublicKey
	authority      *types.PublicKey
	multiplier     float64
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *InitializeScaledUiAmountRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if a := strings.TrimSpace(r.Authority); a != "" {
		if r.authority, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("authority: " + err.Error())
		}
	}
	multiplier, err := strconv.ParseFloat(strings.TrimSpace(r.Multiplier), 64)
	if err != nil {
		return errors.New("multiplier: " + err.Error())
	}
	if math.IsNaN(multiplier) || math.IsInf(multiplier, 0) || multiplier <= 0 {
		return errors.New("multiplier: must be a positive finite number")
	}
	r.multiplier = multiplier
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *InitializeScaledUiAmountRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *InitializeScaledUiAmountRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *InitializeScaledUiAmountRequest) ToMultiplier() float64          { return r.multiplier }
func (r *InitializeScaledUiAmountRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *InitializeScaledUiAmountRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *InitializeScaledUiAmountRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *InitializeScaledUiAmountRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeScaledUiAmountResponse reports the built transaction.
type InitializeScaledUiAmountResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint       string `json:"mint"`
	Authority  string `json:"authority,omitempty"`
	Multiplier string `json:"multiplier"`
	Program    string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializeScaledUiAmountResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	multiplier float64,
	fee uint64,
) *InitializeScaledUiAmountResponse {
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

	res := &InitializeScaledUiAmountResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Multiplier:      strconv.FormatFloat(multiplier, 'g', -1, 64),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
	if !authority.IsNil() {
		res.Authority = authority.Base58()
	}

	return res
}

// InitializePausableRequest attaches the Pausable extension to Mint, naming the
// pause authority, who can stop and resume all minting, burning and
// transferring of the mint.
//
// This can only ever run in the narrow window every mint extension shares:
// after the mint account has been allocated (sized to include this extension)
// and before initialize-mint2 locks the extension list forever.
type InitializePausableRequest struct {
	// Mint is the account this attaches to. It must already exist (see
	// create-mint) and not yet be initialized -- initialize-mint2 has to
	// run after this, never before.
	Mint string `json:"mint" example:""`

	// Authority may pause and resume all minting, burning and transferring of the
	// mint. Required: there is no pausable mint that nobody can pause.
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint           *types.PublicKey
	authority      *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *InitializePausableRequest) ValidateRequest() error {
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *InitializePausableRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *InitializePausableRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *InitializePausableRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *InitializePausableRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *InitializePausableRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *InitializePausableRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializePausableResponse reports the built transaction.
type InitializePausableResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint      string `json:"mint"`
	Authority string `json:"authority"`
	Program   string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializePausableResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *InitializePausableResponse {
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

	res := &InitializePausableResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}

	return res
}

// UpdateDefaultAccountStateRequest changes the state new token accounts of Mint
// start in. Authorized by the mint's freeze authority.

type UpdateDefaultAccountStateRequest struct {
	// Mint must already carry the extension and be initialized.
	Mint string `json:"mint" example:""`

	// Authority is the mint's freeze authority, or its multisig for a multisig-owned one
	// (see MultisigSigners).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// State is what every new token account of this mint starts in: "initialized"
	// (usable at once) or "frozen" (unusable until the freeze authority thaws it). A
	// frozen default needs the mint to have a freeze authority.
	State string `json:"state" example:"frozen"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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
	authority       *types.PublicKey
	state           uint8
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *UpdateDefaultAccountStateRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	switch strings.ToLower(strings.TrimSpace(r.State)) {
	case "initialized":
		r.state = core.TokenAccountStateInitialized
	case "frozen":
		r.state = core.TokenAccountStateFrozen
	default:
		return errors.New(`state: must be "initialized" or "frozen"`)
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *UpdateDefaultAccountStateRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *UpdateDefaultAccountStateRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *UpdateDefaultAccountStateRequest) ToState() uint8                 { return r.state }
func (r *UpdateDefaultAccountStateRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *UpdateDefaultAccountStateRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *UpdateDefaultAccountStateRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *UpdateDefaultAccountStateRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *UpdateDefaultAccountStateRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// UpdateDefaultAccountStateResponse reports the built transaction.
type UpdateDefaultAccountStateResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint      string `json:"mint"`
	Authority string `json:"authority"`
	State     string `json:"state"`
	Program   string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewUpdateDefaultAccountStateResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	stateName string,
	fee uint64,
) *UpdateDefaultAccountStateResponse {
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

	return &UpdateDefaultAccountStateResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		State:           stateName,
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// UpdateInterestBearingRateRequest changes the interest rate of Mint.
// Authorized by the extension's rate authority.

type UpdateInterestBearingRateRequest struct {
	// Mint must already carry the extension and be initialized.
	Mint string `json:"mint" example:""`

	// Authority is the extension's rate authority, or its multisig for a multisig-owned one
	// (see MultisigSigners).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Rate is the initial interest rate in basis points, as a signed 16-bit
	// number (500 = 5% a year; negative rates are allowed).
	Rate string `json:"rate" example:"500"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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
	authority       *types.PublicKey
	rate            int16
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *UpdateInterestBearingRateRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	rate, err := strconv.ParseInt(strings.TrimSpace(r.Rate), 10, 16)
	if err != nil {
		return errors.New("rate: " + err.Error())
	}
	r.rate = int16(rate)
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *UpdateInterestBearingRateRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *UpdateInterestBearingRateRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *UpdateInterestBearingRateRequest) ToRate() int16                  { return r.rate }
func (r *UpdateInterestBearingRateRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *UpdateInterestBearingRateRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *UpdateInterestBearingRateRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *UpdateInterestBearingRateRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *UpdateInterestBearingRateRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// UpdateInterestBearingRateResponse reports the built transaction.
type UpdateInterestBearingRateResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint      string `json:"mint"`
	Authority string `json:"authority"`
	Rate      string `json:"rate"`
	Program   string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewUpdateInterestBearingRateResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	rate int16,
	fee uint64,
) *UpdateInterestBearingRateResponse {
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

	return &UpdateInterestBearingRateResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		Rate:            strconv.Itoa(int(rate)),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// UpdateScaledUiAmountMultiplierRequest sets a new display multiplier on Mint,
// taking effect at EffectiveTimestamp. Authorized by the extension's multiplier
// authority.

type UpdateScaledUiAmountMultiplierRequest struct {
	// Mint must already carry the extension and be initialized.
	Mint string `json:"mint" example:""`

	// Authority is the extension's multiplier authority, or its multisig for a multisig-owned one
	// (see MultisigSigners).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Multiplier is the initial display multiplier: a positive decimal, not
	// subnormal (1.5 shows 100 base units as 150).
	Multiplier string `json:"multiplier" example:"1.5"`

	// EffectiveTimestamp is the unix time (seconds) the new multiplier takes
	// effect. A time already past applies it immediately; 0 is such a time.
	EffectiveTimestamp string `json:"effective_timestamp" example:"0"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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

	mint               *types.PublicKey
	authority          *types.PublicKey
	multiplier         float64
	effectiveTimestamp int64
	feePayer           *types.PublicKey
	rbh                *types.Hash
	dna                *types.PublicKey
	tokenProgramID     *types.PublicKey
	multisigSigners    []*types.PublicKey
}

func (r *UpdateScaledUiAmountMultiplierRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	multiplier, err := strconv.ParseFloat(strings.TrimSpace(r.Multiplier), 64)
	if err != nil {
		return errors.New("multiplier: " + err.Error())
	}
	if math.IsNaN(multiplier) || math.IsInf(multiplier, 0) || multiplier <= 0 {
		return errors.New("multiplier: must be a positive finite number")
	}
	r.multiplier = multiplier
	effective, err := strconv.ParseInt(strings.TrimSpace(r.EffectiveTimestamp), 10, 64)
	if err != nil {
		return errors.New("effective_timestamp: " + err.Error())
	}
	r.effectiveTimestamp = effective
	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *UpdateScaledUiAmountMultiplierRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *UpdateScaledUiAmountMultiplierRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *UpdateScaledUiAmountMultiplierRequest) ToMultiplier() float64          { return r.multiplier }
func (r *UpdateScaledUiAmountMultiplierRequest) ToEffectiveTimestamp() int64 {
	return r.effectiveTimestamp
}
func (r *UpdateScaledUiAmountMultiplierRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *UpdateScaledUiAmountMultiplierRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *UpdateScaledUiAmountMultiplierRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *UpdateScaledUiAmountMultiplierRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *UpdateScaledUiAmountMultiplierRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// UpdateScaledUiAmountMultiplierResponse reports the built transaction.
type UpdateScaledUiAmountMultiplierResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint               string `json:"mint"`
	Authority          string `json:"authority"`
	Multiplier         string `json:"multiplier"`
	EffectiveTimestamp string `json:"effective_timestamp"`
	Program            string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewUpdateScaledUiAmountMultiplierResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	multiplier float64,
	effectiveTimestamp int64,
	fee uint64,
) *UpdateScaledUiAmountMultiplierResponse {
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

	return &UpdateScaledUiAmountMultiplierResponse{
		Transaction:        codec.Base64.Encode(raw),
		Message:            codec.Base64.Encode(message),
		RecentBlockhash:    tx.Message.RecentBlockhash.Base58(),
		AccountKeys:        keys,
		Signers:            signers,
		NonceAuthority:     nonceAuth,
		Mint:               mint.Base58(),
		Authority:          authority.Base58(),
		Multiplier:         strconv.FormatFloat(multiplier, 'g', -1, 64),
		EffectiveTimestamp: strconv.FormatInt(effectiveTimestamp, 10),
		Program:            tokenProgram.Base58(),
		Fee:                newSystemPayer(feePayer, fee),
	}
}

// PauseMintRequest stops all minting, burning and transferring of Mint until it
// is resumed. Authorized by the pause authority.

type PauseMintRequest struct {
	// Mint must already carry the extension and be initialized.
	Mint string `json:"mint" example:""`

	// Authority is the pause authority, or its multisig for a multisig-owned one
	// (see MultisigSigners).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *PauseMintRequest) ValidateRequest() error {
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *PauseMintRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *PauseMintRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *PauseMintRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *PauseMintRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *PauseMintRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *PauseMintRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *PauseMintRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// PauseMintResponse reports the built transaction.
type PauseMintResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint      string `json:"mint"`
	Authority string `json:"authority"`
	Program   string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewPauseMintResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *PauseMintResponse {
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

	return &PauseMintResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// ResumeMintRequest lifts a pause on Mint, so minting, burning and transferring
// work again. Authorized by the pause authority.

type ResumeMintRequest struct {
	// Mint must already carry the extension and be initialized.
	Mint string `json:"mint" example:""`

	// Authority is the pause authority, or its multisig for a multisig-owned one
	// (see MultisigSigners).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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
	authority       *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *ResumeMintRequest) ValidateRequest() error {
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *ResumeMintRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *ResumeMintRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *ResumeMintRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *ResumeMintRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *ResumeMintRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *ResumeMintRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *ResumeMintRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// ResumeMintResponse reports the built transaction.
type ResumeMintResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint      string `json:"mint"`
	Authority string `json:"authority"`
	Program   string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewResumeMintResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *ResumeMintResponse {
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

	return &ResumeMintResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// stateNameOf is the request-facing name of a token account state.
func stateNameOf(state uint8) string {
	if state == core.TokenAccountStateFrozen {
		return "frozen"
	}
	return "initialized"
}

// InitializeMetadataPointerRequest attaches the MetadataPointer extension to Mint,
// naming who may later change the pointer and the address it points to. The
// pointer only records where the metadata lives.
//
// This can only ever run in the narrow window every mint extension shares:
// after the mint account has been allocated (sized to include this extension)
// and before initialize-mint2 locks the extension list forever.
type InitializeMetadataPointerRequest struct {
	// Mint is the account this attaches to. It must already exist (see
	// create-mint) and not yet be initialized -- initialize-mint2 has to
	// run after this, never before.
	Mint string `json:"mint" example:""`

	// Authority may change the pointer later. Left empty, the pointer is fixed for
	// good.
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// MetadataAddress is the account that holds the mint's metadata (the mint itself when the metadata lives in the TokenMetadata extension).
	// Left empty, the pointer starts out pointing nowhere.
	MetadataAddress string `json:"metadata_address" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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
	authority       *types.PublicKey
	metadataAddress *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
}

func (r *InitializeMetadataPointerRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if a := strings.TrimSpace(r.Authority); a != "" {
		if r.authority, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("authority: " + err.Error())
		}
	}
	if a := strings.TrimSpace(r.MetadataAddress); a != "" {
		if r.metadataAddress, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("metadata_address: " + err.Error())
		}
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *InitializeMetadataPointerRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *InitializeMetadataPointerRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *InitializeMetadataPointerRequest) MetadataAddressKey() *types.PublicKey {
	return r.metadataAddress
}
func (r *InitializeMetadataPointerRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *InitializeMetadataPointerRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *InitializeMetadataPointerRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *InitializeMetadataPointerRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeMetadataPointerResponse reports the built transaction.
type InitializeMetadataPointerResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint            string `json:"mint"`
	Authority       string `json:"authority,omitempty"`
	MetadataAddress string `json:"metadata_address,omitempty"`
	Program         string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializeMetadataPointerResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, metadataAddress, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *InitializeMetadataPointerResponse {
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

	res := &InitializeMetadataPointerResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
	if !authority.IsNil() {
		res.Authority = authority.Base58()
	}
	if !metadataAddress.IsNil() {
		res.MetadataAddress = metadataAddress.Base58()
	}

	return res
}

// UpdateMetadataPointerRequest changes the address Mint's MetadataPointer extension
// points to. Authorized by the pointer's authority.

type UpdateMetadataPointerRequest struct {
	// Mint must already carry the extension and be initialized.
	Mint string `json:"mint" example:""`

	// Authority is the metadata pointer's authority, or its multisig for a multisig-owned one
	// (see MultisigSigners).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// MetadataAddress is the new address the pointer points to: the account that holds the mint's metadata (the mint itself when the metadata lives in the TokenMetadata extension).
	// Left empty, the pointer is cleared.
	MetadataAddress string `json:"metadata_address" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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
	authority       *types.PublicKey
	metadataAddress *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *UpdateMetadataPointerRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if a := strings.TrimSpace(r.MetadataAddress); a != "" {
		if r.metadataAddress, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("metadata_address: " + err.Error())
		}
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *UpdateMetadataPointerRequest) MintKey() *types.PublicKey           { return r.mint }
func (r *UpdateMetadataPointerRequest) AuthorityKey() *types.PublicKey      { return r.authority }
func (r *UpdateMetadataPointerRequest) ToMetadataAddress() *types.PublicKey { return r.metadataAddress }
func (r *UpdateMetadataPointerRequest) FeePayerKey() *types.PublicKey       { return r.feePayer }
func (r *UpdateMetadataPointerRequest) Blockhash() *types.Hash              { return r.rbh }
func (r *UpdateMetadataPointerRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *UpdateMetadataPointerRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *UpdateMetadataPointerRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// UpdateMetadataPointerResponse reports the built transaction.
type UpdateMetadataPointerResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint            string `json:"mint"`
	Authority       string `json:"authority"`
	MetadataAddress string `json:"metadata_address,omitempty"`
	Program         string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewUpdateMetadataPointerResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	metadataAddress *types.PublicKey,
	fee uint64,
) *UpdateMetadataPointerResponse {
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

	return &UpdateMetadataPointerResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		MetadataAddress: optionalKeyString(metadataAddress),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// InitializeGroupPointerRequest attaches the GroupPointer extension to Mint,
// naming who may later change the pointer and the address it points to. The
// pointer only records where the group lives.
//
// This can only ever run in the narrow window every mint extension shares:
// after the mint account has been allocated (sized to include this extension)
// and before initialize-mint2 locks the extension list forever.
type InitializeGroupPointerRequest struct {
	// Mint is the account this attaches to. It must already exist (see
	// create-mint) and not yet be initialized -- initialize-mint2 has to
	// run after this, never before.
	Mint string `json:"mint" example:""`

	// Authority may change the pointer later. Left empty, the pointer is fixed for
	// good.
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// GroupAddress is the account that holds the mint's group configuration (the mint itself when it lives in the TokenGroup extension).
	// Left empty, the pointer starts out pointing nowhere.
	GroupAddress string `json:"group_address" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint           *types.PublicKey
	authority      *types.PublicKey
	groupAddress   *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *InitializeGroupPointerRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if a := strings.TrimSpace(r.Authority); a != "" {
		if r.authority, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("authority: " + err.Error())
		}
	}
	if a := strings.TrimSpace(r.GroupAddress); a != "" {
		if r.groupAddress, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("group_address: " + err.Error())
		}
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *InitializeGroupPointerRequest) MintKey() *types.PublicKey         { return r.mint }
func (r *InitializeGroupPointerRequest) AuthorityKey() *types.PublicKey    { return r.authority }
func (r *InitializeGroupPointerRequest) GroupAddressKey() *types.PublicKey { return r.groupAddress }
func (r *InitializeGroupPointerRequest) FeePayerKey() *types.PublicKey     { return r.feePayer }
func (r *InitializeGroupPointerRequest) Blockhash() *types.Hash            { return r.rbh }
func (r *InitializeGroupPointerRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *InitializeGroupPointerRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeGroupPointerResponse reports the built transaction.
type InitializeGroupPointerResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint         string `json:"mint"`
	Authority    string `json:"authority,omitempty"`
	GroupAddress string `json:"group_address,omitempty"`
	Program      string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializeGroupPointerResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, groupAddress, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *InitializeGroupPointerResponse {
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

	res := &InitializeGroupPointerResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
	if !authority.IsNil() {
		res.Authority = authority.Base58()
	}
	if !groupAddress.IsNil() {
		res.GroupAddress = groupAddress.Base58()
	}

	return res
}

// UpdateGroupPointerRequest changes the address Mint's GroupPointer extension
// points to. Authorized by the pointer's authority.

type UpdateGroupPointerRequest struct {
	// Mint must already carry the extension and be initialized.
	Mint string `json:"mint" example:""`

	// Authority is the group pointer's authority, or its multisig for a multisig-owned one
	// (see MultisigSigners).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// GroupAddress is the new address the pointer points to: the account that holds the mint's group configuration (the mint itself when it lives in the TokenGroup extension).
	// Left empty, the pointer is cleared.
	GroupAddress string `json:"group_address" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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
	authority       *types.PublicKey
	groupAddress    *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *UpdateGroupPointerRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if a := strings.TrimSpace(r.GroupAddress); a != "" {
		if r.groupAddress, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("group_address: " + err.Error())
		}
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *UpdateGroupPointerRequest) MintKey() *types.PublicKey        { return r.mint }
func (r *UpdateGroupPointerRequest) AuthorityKey() *types.PublicKey   { return r.authority }
func (r *UpdateGroupPointerRequest) ToGroupAddress() *types.PublicKey { return r.groupAddress }
func (r *UpdateGroupPointerRequest) FeePayerKey() *types.PublicKey    { return r.feePayer }
func (r *UpdateGroupPointerRequest) Blockhash() *types.Hash           { return r.rbh }
func (r *UpdateGroupPointerRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *UpdateGroupPointerRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *UpdateGroupPointerRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// UpdateGroupPointerResponse reports the built transaction.
type UpdateGroupPointerResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint         string `json:"mint"`
	Authority    string `json:"authority"`
	GroupAddress string `json:"group_address,omitempty"`
	Program      string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewUpdateGroupPointerResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	groupAddress *types.PublicKey,
	fee uint64,
) *UpdateGroupPointerResponse {
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

	return &UpdateGroupPointerResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		GroupAddress:    optionalKeyString(groupAddress),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// InitializeGroupMemberPointerRequest attaches the GroupMemberPointer extension to Mint,
// naming who may later change the pointer and the address it points to. The
// pointer only records where the group member lives.
//
// This can only ever run in the narrow window every mint extension shares:
// after the mint account has been allocated (sized to include this extension)
// and before initialize-mint2 locks the extension list forever.
type InitializeGroupMemberPointerRequest struct {
	// Mint is the account this attaches to. It must already exist (see
	// create-mint) and not yet be initialized -- initialize-mint2 has to
	// run after this, never before.
	Mint string `json:"mint" example:""`

	// Authority may change the pointer later. Left empty, the pointer is fixed for
	// good.
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// MemberAddress is the account that holds the mint's group membership (the mint itself when it lives in the TokenGroupMember extension).
	// Left empty, the pointer starts out pointing nowhere.
	MemberAddress string `json:"member_address" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint           *types.PublicKey
	authority      *types.PublicKey
	memberAddress  *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *InitializeGroupMemberPointerRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if a := strings.TrimSpace(r.Authority); a != "" {
		if r.authority, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("authority: " + err.Error())
		}
	}
	if a := strings.TrimSpace(r.MemberAddress); a != "" {
		if r.memberAddress, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("member_address: " + err.Error())
		}
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *InitializeGroupMemberPointerRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *InitializeGroupMemberPointerRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *InitializeGroupMemberPointerRequest) MemberAddressKey() *types.PublicKey {
	return r.memberAddress
}
func (r *InitializeGroupMemberPointerRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *InitializeGroupMemberPointerRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *InitializeGroupMemberPointerRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *InitializeGroupMemberPointerRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeGroupMemberPointerResponse reports the built transaction.
type InitializeGroupMemberPointerResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint          string `json:"mint"`
	Authority     string `json:"authority,omitempty"`
	MemberAddress string `json:"member_address,omitempty"`
	Program       string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializeGroupMemberPointerResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, memberAddress, tokenProgram, nonceAuthority *types.PublicKey,
	fee uint64,
) *InitializeGroupMemberPointerResponse {
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

	res := &InitializeGroupMemberPointerResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
	if !authority.IsNil() {
		res.Authority = authority.Base58()
	}
	if !memberAddress.IsNil() {
		res.MemberAddress = memberAddress.Base58()
	}

	return res
}

// UpdateGroupMemberPointerRequest changes the address Mint's GroupMemberPointer extension
// points to. Authorized by the pointer's authority.

type UpdateGroupMemberPointerRequest struct {
	// Mint must already carry the extension and be initialized.
	Mint string `json:"mint" example:""`

	// Authority is the group member pointer's authority, or its multisig for a multisig-owned one
	// (see MultisigSigners).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// MemberAddress is the new address the pointer points to: the account that holds the mint's group membership (the mint itself when it lives in the TokenGroupMember extension).
	// Left empty, the pointer is cleared.
	MemberAddress string `json:"member_address" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	// MultisigSigners is empty for a single-signer authority. Non-empty,
	// Authority itself does not sign; the named members do, in its place.
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
	authority       *types.PublicKey
	memberAddress   *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
	multisigSigners []*types.PublicKey
}

func (r *UpdateGroupMemberPointerRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if a := strings.TrimSpace(r.MemberAddress); a != "" {
		if r.memberAddress, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("member_address: " + err.Error())
		}
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *UpdateGroupMemberPointerRequest) MintKey() *types.PublicKey         { return r.mint }
func (r *UpdateGroupMemberPointerRequest) AuthorityKey() *types.PublicKey    { return r.authority }
func (r *UpdateGroupMemberPointerRequest) ToMemberAddress() *types.PublicKey { return r.memberAddress }
func (r *UpdateGroupMemberPointerRequest) FeePayerKey() *types.PublicKey     { return r.feePayer }
func (r *UpdateGroupMemberPointerRequest) Blockhash() *types.Hash            { return r.rbh }
func (r *UpdateGroupMemberPointerRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *UpdateGroupMemberPointerRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}
func (r *UpdateGroupMemberPointerRequest) ToMultisigSigners() []*types.PublicKey {
	return r.multisigSigners
}

// UpdateGroupMemberPointerResponse reports the built transaction.
type UpdateGroupMemberPointerResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint          string `json:"mint"`
	Authority     string `json:"authority"`
	MemberAddress string `json:"member_address,omitempty"`
	Program       string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewUpdateGroupMemberPointerResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	memberAddress *types.PublicKey,
	fee uint64,
) *UpdateGroupMemberPointerResponse {
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

	return &UpdateGroupMemberPointerResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		MemberAddress:   optionalKeyString(memberAddress),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// optionalKeyString is a key's base58 form, or the empty string when there is
// none.
func optionalKeyString(k *types.PublicKey) string {
	if k.IsNil() {
		return ""
	}
	return k.Base58()
}

// InitializeTokenMetadataRequest writes the TokenMetadata extension into Mint --
// name, symbol and uri. The uri points at a JSON document, which is where the
// token's image lives. Token-2022 keeps the metadata in the mint itself, so the
// mint must already be initialized and carry a MetadataPointer pointing at
// itself (see metadata-pointer/initialize); the account grows to hold it, and
// the rent for the growth is transferred in first from RentPayer. Authorized by
// the mint authority. Token-2022 only: a classic Token mint has no extensions
// (its name and image live in a Metaplex Token Metadata account instead).

type InitializeTokenMetadataRequest struct {
	// Mint must already carry the extension and be initialized.
	Mint string `json:"mint" example:""`

	// Authority is the mint's mint authority (signs).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// UpdateAuthority may change the metadata later. Left empty, the metadata is
	// fixed for good.
	UpdateAuthority string `json:"update_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Name is the token's name.
	Name string `json:"name" example:"My Token"`

	// Symbol is the token's short ticker.
	Symbol string `json:"symbol" example:"MTK"`

	// Uri points at a JSON document with the token's image and other off-chain
	// details.
	Uri string `json:"uri" example:"https://example.com/token.json"`

	// RentPayer pays for the account growing. The program resizes the account
	// but does not fund the growth, so any rent the mint is missing at its new
	// size is transferred in from here first, in the same transaction. It signs when
	// named and may be left empty only when the mint already holds enough.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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
	authority       *types.PublicKey
	updateAuthority *types.PublicKey
	name            string
	symbol          string
	uri             string
	rentPayer       *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
}

func (r *InitializeTokenMetadataRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if a := strings.TrimSpace(r.UpdateAuthority); a != "" {
		if r.updateAuthority, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("update_authority: " + err.Error())
		}
	}
	r.name = r.Name
	r.symbol = r.Symbol
	r.uri = r.Uri
	if a := strings.TrimSpace(r.RentPayer); a != "" {
		if r.rentPayer, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("rent_payer: " + err.Error())
		}
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *InitializeTokenMetadataRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *InitializeTokenMetadataRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *InitializeTokenMetadataRequest) ToUpdateAuthority() *types.PublicKey {
	return r.updateAuthority
}
func (r *InitializeTokenMetadataRequest) ToName() string                { return r.name }
func (r *InitializeTokenMetadataRequest) ToSymbol() string              { return r.symbol }
func (r *InitializeTokenMetadataRequest) ToUri() string                 { return r.uri }
func (r *InitializeTokenMetadataRequest) ToRentPayer() *types.PublicKey { return r.rentPayer }
func (r *InitializeTokenMetadataRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *InitializeTokenMetadataRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *InitializeTokenMetadataRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *InitializeTokenMetadataRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeTokenMetadataResponse reports the built transaction.
type InitializeTokenMetadataResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint            string `json:"mint"`
	Authority       string `json:"authority"`
	UpdateAuthority string `json:"update_authority,omitempty"`
	Name            string `json:"name"`
	Symbol          string `json:"symbol"`
	Uri             string `json:"uri"`
	RentPayer       string `json:"rent_payer,omitempty"`
	Program         string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializeTokenMetadataResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	updateAuthority *types.PublicKey,
	name string,
	symbol string,
	uri string,
	rentPayer *types.PublicKey,
	fee uint64,
) *InitializeTokenMetadataResponse {
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

	return &InitializeTokenMetadataResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		UpdateAuthority: optionalKeyString(updateAuthority),
		Name:            name,
		Symbol:          symbol,
		Uri:             uri,
		RentPayer:       optionalKeyString(rentPayer),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// UpdateTokenMetadataFieldRequest sets one field of Mint's TokenMetadata: name,
// symbol, uri, or an additional key. A new key is created and an existing one
// overwritten; the account is resized to fit, and growing it costs rent that is
// transferred in first from RentPayer. Authorized by the metadata's update
// authority.

type UpdateTokenMetadataFieldRequest struct {
	// Mint must already carry the extension and be initialized.
	Mint string `json:"mint" example:""`

	// Authority is the metadata's update authority (signs).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Field is what to set: "name", "symbol", "uri", or "key" for an additional
	// field named by Key.
	Field string `json:"field" example:"uri"`

	// Key names the additional field when field is "key"; ignored for name, symbol
	// and uri.
	Key string `json:"key" example:"website"`

	// Value is what the field is set to.
	Value string `json:"value" example:"https://example.com/new.json"`

	// RentPayer pays for the account growing. The program resizes the account
	// but does not fund the growth, so any rent the mint is missing at its new
	// size is transferred in from here first, in the same transaction. It signs when
	// named and may be left empty only when the mint already holds enough.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint           *types.PublicKey
	authority      *types.PublicKey
	field          uint8
	key            string
	value          string
	rentPayer      *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *UpdateTokenMetadataFieldRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	switch strings.ToLower(strings.TrimSpace(r.Field)) {
	case "name":
		r.field = core.TokenMetadataFieldName
	case "symbol":
		r.field = core.TokenMetadataFieldSymbol
	case "uri":
		r.field = core.TokenMetadataFieldUri
	case "key":
		r.field = core.TokenMetadataFieldKey
	default:
		return errors.New(`field: must be "name", "symbol", "uri" or "key"`)
	}
	r.key = strings.TrimSpace(r.Key)
	if r.field == core.TokenMetadataFieldKey && r.key == "" {
		return errors.New("key is required when field is \"key\"")
	}
	r.value = r.Value
	if a := strings.TrimSpace(r.RentPayer); a != "" {
		if r.rentPayer, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("rent_payer: " + err.Error())
		}
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *UpdateTokenMetadataFieldRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *UpdateTokenMetadataFieldRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *UpdateTokenMetadataFieldRequest) ToField() uint8                 { return r.field }
func (r *UpdateTokenMetadataFieldRequest) ToKey() string                  { return r.key }
func (r *UpdateTokenMetadataFieldRequest) ToValue() string                { return r.value }
func (r *UpdateTokenMetadataFieldRequest) ToRentPayer() *types.PublicKey  { return r.rentPayer }
func (r *UpdateTokenMetadataFieldRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *UpdateTokenMetadataFieldRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *UpdateTokenMetadataFieldRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *UpdateTokenMetadataFieldRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// UpdateTokenMetadataFieldResponse reports the built transaction.
type UpdateTokenMetadataFieldResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint      string `json:"mint"`
	Authority string `json:"authority"`
	Field     string `json:"field"`
	Key       string `json:"key"`
	Value     string `json:"value"`
	RentPayer string `json:"rent_payer,omitempty"`
	Program   string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewUpdateTokenMetadataFieldResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	fieldName string,
	key string,
	value string,
	rentPayer *types.PublicKey,
	fee uint64,
) *UpdateTokenMetadataFieldResponse {
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

	return &UpdateTokenMetadataFieldResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		Field:           strings.ToLower(strings.TrimSpace(fieldName)),
		Key:             key,
		Value:           value,
		RentPayer:       optionalKeyString(rentPayer),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// RemoveTokenMetadataKeyRequest deletes an additional key from Mint's
// TokenMetadata (never name, symbol or uri). Authorized by the metadata's update
// authority.

type RemoveTokenMetadataKeyRequest struct {
	// Mint must already carry the extension and be initialized.
	Mint string `json:"mint" example:""`

	// Authority is the metadata's update authority (signs).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Key is the additional field to delete.
	Key string `json:"key" example:"website"`

	// Idempotent set to true makes a key that is not there a no-op instead of an
	// error.
	Idempotent bool `json:"idempotent" example:"true"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint           *types.PublicKey
	authority      *types.PublicKey
	key            string
	idempotent     bool
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *RemoveTokenMetadataKeyRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if strings.TrimSpace(r.Key) == "" {
		return errors.New("key is required")
	}
	r.key = r.Key
	r.idempotent = r.Idempotent
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *RemoveTokenMetadataKeyRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *RemoveTokenMetadataKeyRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *RemoveTokenMetadataKeyRequest) ToKey() string                  { return r.key }
func (r *RemoveTokenMetadataKeyRequest) ToIdempotent() bool             { return r.idempotent }
func (r *RemoveTokenMetadataKeyRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *RemoveTokenMetadataKeyRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *RemoveTokenMetadataKeyRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *RemoveTokenMetadataKeyRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// RemoveTokenMetadataKeyResponse reports the built transaction.
type RemoveTokenMetadataKeyResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint       string `json:"mint"`
	Authority  string `json:"authority"`
	Key        string `json:"key"`
	Idempotent bool   `json:"idempotent"`
	Program    string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewRemoveTokenMetadataKeyResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	key string,
	idempotent bool,
	fee uint64,
) *RemoveTokenMetadataKeyResponse {
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

	return &RemoveTokenMetadataKeyResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		Key:             key,
		Idempotent:      idempotent,
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// UpdateTokenMetadataAuthorityRequest hands Mint's TokenMetadata update authority
// to NewAuthority, or clears it when empty -- permanently, since with none
// nobody can sign for it again. Authorized by the current update authority.

type UpdateTokenMetadataAuthorityRequest struct {
	// Mint must already carry the extension and be initialized.
	Mint string `json:"mint" example:""`

	// Authority is the metadata's current update authority (signs).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NewAuthority is the new update authority. Left empty, the authority is
	// cleared for good.
	NewAuthority string `json:"new_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint           *types.PublicKey
	authority      *types.PublicKey
	newAuthority   *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *UpdateTokenMetadataAuthorityRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if a := strings.TrimSpace(r.NewAuthority); a != "" {
		if r.newAuthority, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("new_authority: " + err.Error())
		}
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *UpdateTokenMetadataAuthorityRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *UpdateTokenMetadataAuthorityRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *UpdateTokenMetadataAuthorityRequest) ToNewAuthority() *types.PublicKey {
	return r.newAuthority
}
func (r *UpdateTokenMetadataAuthorityRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *UpdateTokenMetadataAuthorityRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *UpdateTokenMetadataAuthorityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *UpdateTokenMetadataAuthorityRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// UpdateTokenMetadataAuthorityResponse reports the built transaction.
type UpdateTokenMetadataAuthorityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint         string `json:"mint"`
	Authority    string `json:"authority"`
	NewAuthority string `json:"new_authority,omitempty"`
	Program      string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewUpdateTokenMetadataAuthorityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	newAuthority *types.PublicKey,
	fee uint64,
) *UpdateTokenMetadataAuthorityResponse {
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

	return &UpdateTokenMetadataAuthorityResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		NewAuthority:    optionalKeyString(newAuthority),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// InitializeTokenGroupRequest makes Mint a group -- for example an NFT
// collection: UpdateAuthority may change it later and it holds at most MaxSize
// members. Token-2022 keeps the group in the mint itself, so the mint must
// already be initialized and carry a GroupPointer pointing at itself; the
// account grows to hold it and the rent for the growth is transferred in first
// from RentPayer. Authorized by the mint authority.

type InitializeTokenGroupRequest struct {
	// Mint must already carry the extension and be initialized.
	Mint string `json:"mint" example:""`

	// Authority is the mint's mint authority (signs).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// UpdateAuthority may change the group later. Left empty, it is fixed for good.
	UpdateAuthority string `json:"update_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// MaxSize is the most members the group may hold.
	MaxSize string `json:"max_size" example:"100"`

	// RentPayer pays for the account growing. The program resizes the account
	// but does not fund the growth, so any rent the mint is missing at its new
	// size is transferred in from here first, in the same transaction. It signs when
	// named and may be left empty only when the mint already holds enough.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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
	authority       *types.PublicKey
	updateAuthority *types.PublicKey
	maxSize         uint64
	rentPayer       *types.PublicKey
	feePayer        *types.PublicKey
	rbh             *types.Hash
	dna             *types.PublicKey
	tokenProgramID  *types.PublicKey
}

func (r *InitializeTokenGroupRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if a := strings.TrimSpace(r.UpdateAuthority); a != "" {
		if r.updateAuthority, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("update_authority: " + err.Error())
		}
	}
	maxSize, err := strconv.ParseUint(strings.TrimSpace(r.MaxSize), 10, 64)
	if err != nil {
		return errors.New("max_size: " + err.Error())
	}
	r.maxSize = maxSize
	if a := strings.TrimSpace(r.RentPayer); a != "" {
		if r.rentPayer, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("rent_payer: " + err.Error())
		}
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *InitializeTokenGroupRequest) MintKey() *types.PublicKey           { return r.mint }
func (r *InitializeTokenGroupRequest) AuthorityKey() *types.PublicKey      { return r.authority }
func (r *InitializeTokenGroupRequest) ToUpdateAuthority() *types.PublicKey { return r.updateAuthority }
func (r *InitializeTokenGroupRequest) ToMaxSize() uint64                   { return r.maxSize }
func (r *InitializeTokenGroupRequest) ToRentPayer() *types.PublicKey       { return r.rentPayer }
func (r *InitializeTokenGroupRequest) FeePayerKey() *types.PublicKey       { return r.feePayer }
func (r *InitializeTokenGroupRequest) Blockhash() *types.Hash              { return r.rbh }
func (r *InitializeTokenGroupRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *InitializeTokenGroupRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeTokenGroupResponse reports the built transaction.
type InitializeTokenGroupResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint            string `json:"mint"`
	Authority       string `json:"authority"`
	UpdateAuthority string `json:"update_authority,omitempty"`
	MaxSize         string `json:"max_size"`
	RentPayer       string `json:"rent_payer,omitempty"`
	Program         string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializeTokenGroupResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	updateAuthority *types.PublicKey,
	maxSize uint64,
	rentPayer *types.PublicKey,
	fee uint64,
) *InitializeTokenGroupResponse {
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

	return &InitializeTokenGroupResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		UpdateAuthority: optionalKeyString(updateAuthority),
		MaxSize:         strconv.FormatUint(maxSize, 10),
		RentPayer:       optionalKeyString(rentPayer),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// UpdateTokenGroupMaxSizeRequest changes how many members Mint's group may
// hold; it cannot go below the current size. Authorized by the group's update
// authority.

type UpdateTokenGroupMaxSizeRequest struct {
	// Mint must already carry the extension and be initialized.
	Mint string `json:"mint" example:""`

	// Authority is the group's update authority (signs).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// MaxSize is the new member limit.
	MaxSize string `json:"max_size" example:"200"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint           *types.PublicKey
	authority      *types.PublicKey
	maxSize        uint64
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *UpdateTokenGroupMaxSizeRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	maxSize, err := strconv.ParseUint(strings.TrimSpace(r.MaxSize), 10, 64)
	if err != nil {
		return errors.New("max_size: " + err.Error())
	}
	r.maxSize = maxSize
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *UpdateTokenGroupMaxSizeRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *UpdateTokenGroupMaxSizeRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *UpdateTokenGroupMaxSizeRequest) ToMaxSize() uint64              { return r.maxSize }
func (r *UpdateTokenGroupMaxSizeRequest) FeePayerKey() *types.PublicKey  { return r.feePayer }
func (r *UpdateTokenGroupMaxSizeRequest) Blockhash() *types.Hash         { return r.rbh }
func (r *UpdateTokenGroupMaxSizeRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *UpdateTokenGroupMaxSizeRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// UpdateTokenGroupMaxSizeResponse reports the built transaction.
type UpdateTokenGroupMaxSizeResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint      string `json:"mint"`
	Authority string `json:"authority"`
	MaxSize   string `json:"max_size"`
	Program   string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewUpdateTokenGroupMaxSizeResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	maxSize uint64,
	fee uint64,
) *UpdateTokenGroupMaxSizeResponse {
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

	return &UpdateTokenGroupMaxSizeResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		MaxSize:         strconv.FormatUint(maxSize, 10),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// UpdateTokenGroupAuthorityRequest hands Mint's group update authority to
// NewAuthority, or clears it when empty -- permanently. Authorized by the
// current update authority.

type UpdateTokenGroupAuthorityRequest struct {
	// Mint must already carry the extension and be initialized.
	Mint string `json:"mint" example:""`

	// Authority is the group's current update authority (signs).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// NewAuthority is the new update authority. Left empty, the authority is
	// cleared for good.
	NewAuthority string `json:"new_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint           *types.PublicKey
	authority      *types.PublicKey
	newAuthority   *types.PublicKey
	feePayer       *types.PublicKey
	rbh            *types.Hash
	dna            *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *UpdateTokenGroupAuthorityRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if a := strings.TrimSpace(r.NewAuthority); a != "" {
		if r.newAuthority, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("new_authority: " + err.Error())
		}
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *UpdateTokenGroupAuthorityRequest) MintKey() *types.PublicKey        { return r.mint }
func (r *UpdateTokenGroupAuthorityRequest) AuthorityKey() *types.PublicKey   { return r.authority }
func (r *UpdateTokenGroupAuthorityRequest) ToNewAuthority() *types.PublicKey { return r.newAuthority }
func (r *UpdateTokenGroupAuthorityRequest) FeePayerKey() *types.PublicKey    { return r.feePayer }
func (r *UpdateTokenGroupAuthorityRequest) Blockhash() *types.Hash           { return r.rbh }
func (r *UpdateTokenGroupAuthorityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *UpdateTokenGroupAuthorityRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// UpdateTokenGroupAuthorityResponse reports the built transaction.
type UpdateTokenGroupAuthorityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint         string `json:"mint"`
	Authority    string `json:"authority"`
	NewAuthority string `json:"new_authority,omitempty"`
	Program      string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewUpdateTokenGroupAuthorityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	newAuthority *types.PublicKey,
	fee uint64,
) *UpdateTokenGroupAuthorityResponse {
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

	return &UpdateTokenGroupAuthorityResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		Mint:            mint.Base58(),
		Authority:       authority.Base58(),
		NewAuthority:    optionalKeyString(newAuthority),
		Program:         tokenProgram.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// InitializeTokenGroupMemberRequest makes Mint a member of the group held by
// Group, numbering it and counting it in the group's size. Token-2022 keeps the
// membership in the member mint itself, so it must already be initialized and
// carry a GroupMemberPointer pointing at itself; the account grows to hold it
// and the rent for the growth is transferred in first from RentPayer. Both the
// member mint's mint authority and the group's update authority sign.

type InitializeTokenGroupMemberRequest struct {
	// Mint must already carry the extension and be initialized.
	Mint string `json:"mint" example:""`

	// Authority is the member mint's mint authority (signs).
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Group is the group's mint, the mint that carries the TokenGroup extension.
	Group string `json:"group" example:""`

	// GroupUpdateAuthority is the group's update authority, who has to approve new
	// members (signs).
	GroupUpdateAuthority string `json:"group_update_authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RentPayer pays for the account growing. The program resizes the account
	// but does not fund the growth, so any rent the mint is missing at its new
	// size is transferred in from here first, in the same transaction. It signs when
	// named and may be left empty only when the mint already holds enough.
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// Program must be Token-2022. A classic Token mint can never hold this extension.
	Program string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

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

	mint                 *types.PublicKey
	authority            *types.PublicKey
	group                *types.PublicKey
	groupUpdateAuthority *types.PublicKey
	rentPayer            *types.PublicKey
	feePayer             *types.PublicKey
	rbh                  *types.Hash
	dna                  *types.PublicKey
	tokenProgramID       *types.PublicKey
}

func (r *InitializeTokenGroupMemberRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.group, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Group)); err != nil {
		return errors.New("group: " + err.Error())
	}
	if r.groupUpdateAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.GroupUpdateAuthority)); err != nil {
		return errors.New("group_update_authority: " + err.Error())
	}
	if a := strings.TrimSpace(r.RentPayer); a != "" {
		if r.rentPayer, err = types.NewPublicKeyFromBase58(a); err != nil {
			return errors.New("rent_payer: " + err.Error())
		}
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
	if !r.tokenProgramID.Equal(core.Token2022ProgramID) {
		return fmt.Errorf("program: %s is not Token-2022 -- extensions can only ever exist on a Token-2022 mint", r.tokenProgramID)
	}

	return nil
}

func (r *InitializeTokenGroupMemberRequest) MintKey() *types.PublicKey      { return r.mint }
func (r *InitializeTokenGroupMemberRequest) AuthorityKey() *types.PublicKey { return r.authority }
func (r *InitializeTokenGroupMemberRequest) ToGroup() *types.PublicKey      { return r.group }
func (r *InitializeTokenGroupMemberRequest) ToGroupUpdateAuthority() *types.PublicKey {
	return r.groupUpdateAuthority
}
func (r *InitializeTokenGroupMemberRequest) ToRentPayer() *types.PublicKey { return r.rentPayer }
func (r *InitializeTokenGroupMemberRequest) FeePayerKey() *types.PublicKey { return r.feePayer }
func (r *InitializeTokenGroupMemberRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *InitializeTokenGroupMemberRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}
func (r *InitializeTokenGroupMemberRequest) TokenProgramID() *types.PublicKey {
	return r.tokenProgramID
}

// InitializeTokenGroupMemberResponse reports the built transaction.
type InitializeTokenGroupMemberResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Mint                 string `json:"mint"`
	Authority            string `json:"authority"`
	Group                string `json:"group"`
	GroupUpdateAuthority string `json:"group_update_authority"`
	RentPayer            string `json:"rent_payer,omitempty"`
	Program              string `json:"program"`

	Fee SystemPayer `json:"fee"`
}

func NewInitializeTokenGroupMemberResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, mint, authority, tokenProgram, nonceAuthority *types.PublicKey,
	group *types.PublicKey,
	groupUpdateAuthority *types.PublicKey,
	rentPayer *types.PublicKey,
	fee uint64,
) *InitializeTokenGroupMemberResponse {
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

	return &InitializeTokenGroupMemberResponse{
		Transaction:          codec.Base64.Encode(raw),
		Message:              codec.Base64.Encode(message),
		RecentBlockhash:      tx.Message.RecentBlockhash.Base58(),
		AccountKeys:          keys,
		Signers:              signers,
		NonceAuthority:       nonceAuth,
		Mint:                 mint.Base58(),
		Authority:            authority.Base58(),
		Group:                group.Base58(),
		GroupUpdateAuthority: groupUpdateAuthority.Base58(),
		RentPayer:            optionalKeyString(rentPayer),
		Program:              tokenProgram.Base58(),
		Fee:                  newSystemPayer(feePayer, fee),
	}
}

// tokenMetadataFieldName is the request-facing name of an UpdateField selector.
func tokenMetadataFieldName(field uint8) string {
	switch field {
	case core.TokenMetadataFieldName:
		return "name"
	case core.TokenMetadataFieldSymbol:
		return "symbol"
	case core.TokenMetadataFieldUri:
		return "uri"
	}
	return "key"
}
