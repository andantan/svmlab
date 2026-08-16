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
