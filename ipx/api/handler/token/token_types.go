package token

import (
	"errors"
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
