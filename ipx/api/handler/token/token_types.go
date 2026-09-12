package token

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/types"
)

// MintRequest names the mint to read.
type MintRequest struct {
	MintAccount string `json:"mint_account" example:"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"`

	mintAccount *types.PublicKey
}

func (r *MintRequest) ValidateRequest() error {
	var err error
	if r.mintAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.MintAccount)); err != nil {
		return errors.New("mint_account: " + err.Error())
	}

	return nil
}

func (r *MintRequest) MintAccountKey() *types.PublicKey {
	return r.mintAccount
}

// MintResponse reports what a mint account holds.
//
// This is the closest thing Solana has to an ERC-20 contract, and the fields it
// does not have are the point: no balances and no allowances, because those
// live in separate accounts owned by each holder. Supply is the only thing a
// mint knows about who holds what.
//
// MintAuthority and FreezeAuthority are empty when absent, which is different
// from being the zero address. Removing the mint authority is how a supply is
// capped and cannot be undone; a mint that was initialized without a freeze
// authority can never gain one.
type MintResponse struct {
	PublicKey       string `json:"public_key"`
	Exists          bool   `json:"exists"`
	Program         string `json:"program"`
	Initialized     bool   `json:"initialized"`
	Decimals        uint8  `json:"decimals"`
	Supply          string `json:"supply"`
	SupplyUI        string `json:"supply_ui"`
	MintAuthority   string `json:"mint_authority,omitempty"`
	FreezeAuthority string `json:"freeze_authority,omitempty"`
	Mintable        bool   `json:"mintable"`
	Freezable       bool   `json:"freezable"`
}

func NewMintResponse(k *types.PublicKey, program string, m *core.Mint) *MintResponse {
	res := &MintResponse{
		PublicKey:   k.Base58(),
		Exists:      true,
		Program:     program,
		Initialized: m.IsInitialized,
		Decimals:    m.Decimals,
		Supply:      strconv.FormatUint(m.Supply, 10),
		SupplyUI:    types.BaseUnitsToUI(m.Supply, m.Decimals),
		Mintable:    m.Mintable(),
		Freezable:   m.Freezable(),
	}
	if !m.MintAuthority.IsNil() {
		res.MintAuthority = m.MintAuthority.Base58()
	}
	if !m.FreezeAuthority.IsNil() {
		res.FreezeAuthority = m.FreezeAuthority.Base58()
	}

	return res
}

// AccountRequest names the token account to read.
type AccountRequest struct {
	TokenAccount string `json:"token_account" example:"4qRgcVrSqs43Jy9n8w7H5EJh8FnRiTFnABjE37Dd3Ae5"`

	tokenAccount *types.PublicKey
}

func (r *AccountRequest) ValidateRequest() error {
	var err error
	if r.tokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.TokenAccount)); err != nil {
		return errors.New("token_account: " + err.Error())
	}

	return nil
}

func (r *AccountRequest) TokenAccountKey() *types.PublicKey {
	return r.tokenAccount
}

// AccountResponse reports what a holder account holds.
//
// Owner is not the runtime owner. That is the token program, which is what may
// write the data; Owner here is the wallet whose signature the program accepts.
//
// Amount has no decimals of its own. It is base units, and AmountUI is it
// placed against the mint's decimals, which is why reading an account means
// reading its mint too.
type AccountResponse struct {
	PublicKey       string `json:"public_key"`
	Exists          bool   `json:"exists"`
	Program         string `json:"program"`
	Mint            string `json:"mint"`
	Owner           string `json:"owner"`
	Amount          string `json:"amount"`
	AmountUI        string `json:"amount_ui,omitempty"`
	Decimals        *uint8 `json:"decimals,omitempty"`
	State           string `json:"state"`
	Frozen          bool   `json:"frozen"`
	Native          bool   `json:"native"`
	RentReserve     string `json:"rent_reserve,omitempty"`
	Delegate        string `json:"delegate,omitempty"`
	DelegatedAmount string `json:"delegated_amount,omitempty"`
	CloseAuthority  string `json:"close_authority,omitempty"`
}

// accountStateName names the state rather than reporting the byte, since
// frozen is the one a caller has to act on and 2 does not say so.
func accountStateName(state uint8) string {
	switch state {
	case core.TokenAccountStateUninitialized:
		return "uninitialized"
	case core.TokenAccountStateInitialized:
		return "initialized"
	case core.TokenAccountStateFrozen:
		return "frozen"
	default:
		return "unknown"
	}
}

// NewAccountResponse fills the UI amount only when the mint was read.
//
// decimals is nil when it could not be, which happens when the mint is on a
// different program or has gone. Reporting the base units alone is honest;
// guessing a scale would misstate a balance by orders of magnitude.
func NewAccountResponse(k *types.PublicKey, program string, a *core.TokenAccount, decimals *uint8) *AccountResponse {
	res := &AccountResponse{
		PublicKey: k.Base58(),
		Exists:    true,
		Program:   program,
		Mint:      a.Mint.Base58(),
		Owner:     a.Owner.Base58(),
		Amount:    strconv.FormatUint(a.Amount, 10),
		Decimals:  decimals,
		State:     accountStateName(a.State),
		Frozen:    a.Frozen(),
		Native:    a.IsNative,
	}
	if decimals != nil {
		res.AmountUI = types.BaseUnitsToUI(a.Amount, *decimals)
	}
	if a.IsNative {
		res.RentReserve = strconv.FormatUint(a.RentReserve, 10)
	}
	if !a.Delegate.IsNil() {
		res.Delegate = a.Delegate.Base58()
		res.DelegatedAmount = strconv.FormatUint(a.Delegated(), 10)
	}
	if !a.CloseAuthority.IsNil() {
		res.CloseAuthority = a.CloseAuthority.Base58()
	}

	return res
}

// ATADeriveRequest names the wallet, mint, and program to derive the
// associated token address for.
type ATADeriveRequest struct {
	Owner   string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Mint    string `json:"mint" example:""`
	Program string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	owner          *types.PublicKey
	mint           *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *ATADeriveRequest) ValidateRequest() error {
	var err error
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
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

func (r *ATADeriveRequest) OwnerKey() *types.PublicKey       { return r.owner }
func (r *ATADeriveRequest) MintKey() *types.PublicKey        { return r.mint }
func (r *ATADeriveRequest) TokenProgramID() *types.PublicKey { return r.tokenProgramID }

// ATADeriveResponse reports the derived address and the bump that produced
// it. Bump is always the canonical one: PDA.Find searches from 255 downward
// and stops at the first off-curve point, which is not a choice this
// endpoint or the caller makes — the Associated Token Account program
// recomputes and validates the canonical bump internally and accepts no
// other.
type ATADeriveResponse struct {
	Owner                  string `json:"owner"`
	Mint                   string `json:"mint"`
	Program                string `json:"program"`
	AssociatedTokenAccount string `json:"associated_token_account"`
	Bump                   uint8  `json:"bump"`
}

func NewATADeriveResponse(owner, mint, program, account *types.PublicKey, bump uint8) *ATADeriveResponse {
	return &ATADeriveResponse{
		Owner:                  owner.Base58(),
		Mint:                   mint.Base58(),
		Program:                program.Base58(),
		AssociatedTokenAccount: account.Base58(),
		Bump:                   bump,
	}
}

// ATAValidateRequest names the same wallet, mint, and program ATADeriveRequest
// does, plus the address to check against what they derive.
type ATAValidateRequest struct {
	Owner                  string `json:"owner" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Mint                   string `json:"mint" example:""`
	Program                string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`
	AssociatedTokenAccount string `json:"associated_token_account" example:""`

	owner                  *types.PublicKey
	mint                   *types.PublicKey
	tokenProgramID         *types.PublicKey
	associatedTokenAccount *types.PublicKey
}

func (r *ATAValidateRequest) ValidateRequest() error {
	var err error
	if r.owner, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Owner)); err != nil {
		return errors.New("owner: " + err.Error())
	}
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}
	if r.associatedTokenAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.AssociatedTokenAccount)); err != nil {
		return errors.New("associated_token_account: " + err.Error())
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

func (r *ATAValidateRequest) OwnerKey() *types.PublicKey       { return r.owner }
func (r *ATAValidateRequest) MintKey() *types.PublicKey        { return r.mint }
func (r *ATAValidateRequest) TokenProgramID() *types.PublicKey { return r.tokenProgramID }
func (r *ATAValidateRequest) AssociatedTokenAccountKey() *types.PublicKey {
	return r.associatedTokenAccount
}

// ATAValidateResponse reports whether the named address is genuinely the
// canonical associated token account for owner, mint, and program — not
// merely a plausible-looking address, since only the one PDA.Find derives is
// the one the Associated Token Account program will ever create or accept.
type ATAValidateResponse struct {
	Owner                  string `json:"owner"`
	Mint                   string `json:"mint"`
	Program                string `json:"program"`
	AssociatedTokenAccount string `json:"associated_token_account"`
	Valid                  bool   `json:"valid"`
	Derived                string `json:"derived"`
	Bump                   uint8  `json:"bump"`
}

func NewATAValidateResponse(owner, mint, program, candidate, derived *types.PublicKey, bump uint8) *ATAValidateResponse {
	return &ATAValidateResponse{
		Owner:                  owner.Base58(),
		Mint:                   mint.Base58(),
		Program:                program.Base58(),
		AssociatedTokenAccount: candidate.Base58(),
		Valid:                  candidate.Equal(derived),
		Derived:                derived.Base58(),
		Bump:                   bump,
	}
}

// AmountToUiRequest names the mint whose decimals (and, for a
// Token-2022 interest-bearing mint, accrued rate) format Amount into a UI
// string. FeePayer is required even though nothing here is ever sent: the
// node still checks the simulated fee payer can afford the transaction fee
// before running the instruction, the same way it would for real.
type AmountToUiRequest struct {
	Mint     string `json:"mint" example:""`
	Amount   string `json:"amount" example:"1000000"`
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program  string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	mint           *types.PublicKey
	amount         uint64
	feePayer       *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *AmountToUiRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
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

func (r *AmountToUiRequest) MintKey() *types.PublicKey        { return r.mint }
func (r *AmountToUiRequest) ToAmount() uint64                 { return r.amount }
func (r *AmountToUiRequest) FeePayerKey() *types.PublicKey    { return r.feePayer }
func (r *AmountToUiRequest) TokenProgramID() *types.PublicKey { return r.tokenProgramID }

// AmountToUiResponse reports the string the program itself formatted, not
// one computed here: against an interest-bearing Token-2022 mint that string
// can differ from a plain decimals division by whatever interest has
// accrued since the mint's last update.
type AmountToUiResponse struct {
	Mint     string `json:"mint"`
	Amount   string `json:"amount"`
	Program  string `json:"program"`
	UIAmount string `json:"ui_amount"`
}

func NewAmountToUiResponse(mint, program *types.PublicKey, amount uint64, uiAmount string) *AmountToUiResponse {
	return &AmountToUiResponse{
		Mint:     mint.Base58(),
		Amount:   strconv.FormatUint(amount, 10),
		Program:  program.Base58(),
		UIAmount: uiAmount,
	}
}

// UiToAmountRequest is AmountToUiRequest's inverse: UIAmount is the string
// to parse rather than the base-unit count to format. FeePayer is required
// for the same reason it is there: simulation still checks the named payer
// can afford the fee, even though nothing is ever sent.
type UiToAmountRequest struct {
	Mint     string `json:"mint" example:""`
	UIAmount string `json:"ui_amount" example:"1.5"`
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program  string `json:"program" example:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"`

	mint           *types.PublicKey
	uiAmount       string
	feePayer       *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *UiToAmountRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}

	r.uiAmount = strings.TrimSpace(r.UIAmount)
	if r.uiAmount == "" {
		return errors.New("ui_amount is required")
	}

	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
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

func (r *UiToAmountRequest) MintKey() *types.PublicKey        { return r.mint }
func (r *UiToAmountRequest) ToUIAmount() string               { return r.uiAmount }
func (r *UiToAmountRequest) FeePayerKey() *types.PublicKey    { return r.feePayer }
func (r *UiToAmountRequest) TokenProgramID() *types.PublicKey { return r.tokenProgramID }

// UiToAmountResponse reports the raw base-unit count the program itself
// parsed uiAmount into.
type UiToAmountResponse struct {
	Mint     string `json:"mint"`
	UIAmount string `json:"ui_amount"`
	Program  string `json:"program"`
	Amount   string `json:"amount"`
}

func NewUiToAmountResponse(mint, program *types.PublicKey, uiAmount string, amount uint64) *UiToAmountResponse {
	return &UiToAmountResponse{
		Mint:     mint.Base58(),
		UIAmount: uiAmount,
		Program:  program.Base58(),
		Amount:   strconv.FormatUint(amount, 10),
	}
}

// GetAccountDataSizeRequest names the mint and every extension type an
// account should have room for, and asks the program for the exact byte
// size that combination needs — the same authority Reallocate itself
// defers to. FeePayer is required even though nothing is ever sent:
// simulating is still processing a transaction, and every transaction
// message requires a loadable fee payer in account_keys[0] regardless of
// what its instructions do.
type GetAccountDataSizeRequest struct {
	Mint string `json:"mint" example:""`

	// ExtensionTypes may be empty, in which case the response is the bare
	// size a Token-2022 account with no extensions needs. Each name is the
	// same lowercase-with-underscores form reallocate takes (e.g.
	// "immutable_owner", "cpi_guard").
	ExtensionTypes []string `json:"extension_types" example:"immutable_owner"`

	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	Program  string `json:"program" example:"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"`

	mint           *types.PublicKey
	extensionTypes []core.ExtensionType
	feePayer       *types.PublicKey
	tokenProgramID *types.PublicKey
}

func (r *GetAccountDataSizeRequest) ValidateRequest() error {
	var err error
	if r.mint, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Mint)); err != nil {
		return errors.New("mint: " + err.Error())
	}

	r.extensionTypes = make([]core.ExtensionType, len(r.ExtensionTypes))
	for i, name := range r.ExtensionTypes {
		if r.extensionTypes[i], err = core.ParseExtensionType(strings.TrimSpace(name)); err != nil {
			return fmt.Errorf("extension_types[%d]: %s", i, err)
		}
	}

	if r.feePayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
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

func (r *GetAccountDataSizeRequest) MintKey() *types.PublicKey              { return r.mint }
func (r *GetAccountDataSizeRequest) ToExtensionTypes() []core.ExtensionType { return r.extensionTypes }
func (r *GetAccountDataSizeRequest) FeePayerKey() *types.PublicKey          { return r.feePayer }
func (r *GetAccountDataSizeRequest) TokenProgramID() *types.PublicKey       { return r.tokenProgramID }

// GetAccountDataSizeResponse reports the size the program itself computed,
// not one recomputed here.
type GetAccountDataSizeResponse struct {
	Mint           string   `json:"mint"`
	ExtensionTypes []string `json:"extension_types"`
	Program        string   `json:"program"`
	Size           string   `json:"size"`
}

func NewGetAccountDataSizeResponse(mint, program *types.PublicKey, extensionTypeNames []string, size uint64) *GetAccountDataSizeResponse {
	return &GetAccountDataSizeResponse{
		Mint:           mint.Base58(),
		ExtensionTypes: extensionTypeNames,
		Program:        program.Base58(),
		Size:           strconv.FormatUint(size, 10),
	}
}
