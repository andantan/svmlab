package account

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
	"github.com/andantan/svmlab/internal/rpc"
)

// AccountRequest names one account to read.
type AccountRequest struct {
	PublicKey string `json:"public_key" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	publicKey *types.PublicKey
}

func (r *AccountRequest) ValidateRequest() error {
	var err error
	if r.publicKey, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.PublicKey)); err != nil {
		return errors.New("public_key: " + err.Error())
	}

	return nil
}

func (r *AccountRequest) ToPublicKey() *types.PublicKey {
	return r.publicKey
}

type BalanceResponse struct {
	PublicKey string `json:"public_key"`
	Lamports  string `json:"lamports"`
	SOL       string `json:"sol"`
}

func NewBalanceResponse(k *types.PublicKey, lamports uint64) *BalanceResponse {
	return &BalanceResponse{
		PublicKey: k.Base58(),
		Lamports:  strconv.FormatUint(lamports, 10),
		SOL:       types.LamportsToSol(lamports),
	}
}

// AccountResponse is an account's on-chain state.
//
// Exists is separate from the rest because a missing account is an ordinary
// answer rather than an error: most 32-byte values name an account nobody has
// created.
type AccountResponse struct {
	PublicKey  string `json:"public_key"`
	Exists     bool   `json:"exists"`
	Lamports   string `json:"lamports"`
	SOL        string `json:"sol"`
	Owner      string `json:"owner"`
	Executable bool   `json:"executable"`
	Space      uint64 `json:"space"`
	Data       string `json:"data"`

	// Initialized is true for anything without an uninitialized state of its
	// own to report — a plain wallet, a program, an account this endpoint has
	// no parser for. It is only ever false for the handful of layouts that
	// actually carry an initialization flag: a durable nonce account, a mint,
	// or a token account allocated and assigned to a token program but not
	// yet initialized by InitializeMint*/InitializeAccount*.
	Initialized bool `json:"initialized"`
}

func NewAccountResponse(k *types.PublicKey, info *rpc.AccountInfo) *AccountResponse {
	if info == nil {
		return &AccountResponse{PublicKey: k.Base58(), Lamports: "0", SOL: "0"}
	}

	data, _ := info.Bytes()

	resp := &AccountResponse{
		PublicKey:   k.Base58(),
		Exists:      true,
		Lamports:    strconv.FormatUint(info.Lamports, 10),
		SOL:         types.LamportsToSol(info.Lamports),
		Owner:       info.Owner,
		Executable:  info.Executable,
		Space:       info.Space,
		Data:        codec.Base64.Encode(data),
		Initialized: true,
	}

	owner, err := types.NewPublicKeyFromBase58(info.Owner)
	if err != nil {
		return resp
	}

	if owner.Equal(core.System.ID()) {
		if info.Space == core.NonceAccountSpace {
			if nonce, nErr := core.DeserializeNonceAccount(data); nErr == nil {
				resp.Initialized = nonce.Initialized()
			}
		}
		return resp
	}

	if _, err := core.TokenProgram(owner); err == nil {
		if mint, mErr := core.DecodeMint(owner, data); mErr == nil {
			resp.Initialized = mint.IsInitialized
			return resp
		}
		if account, aErr := core.DecodeTokenAccount(owner, data); aErr == nil {
			resp.Initialized = account.Initialized()
			return resp
		}
	}

	return resp
}

// TokensRequest names the wallet whose token accounts should be listed.
type TokensRequest struct {
	PublicKey string `json:"public_key" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	publicKey *types.PublicKey
}

func (r *TokensRequest) ValidateRequest() error {
	var err error
	if r.publicKey, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.PublicKey)); err != nil {
		return errors.New("public_key: " + err.Error())
	}

	return nil
}

func (r *TokensRequest) ToPublicKey() *types.PublicKey {
	return r.publicKey
}

// TokensResponse lists the token accounts owned by a wallet.
//
// The listing covers both the classic Token Program and Token-2022. Each
// account still reports its program, because the two programs own separate
// accounts and no single token instruction can touch both at once.
type TokensResponse struct {
	PublicKey string                  `json:"public_key"`
	Count     int                     `json:"count"`
	Accounts  []*TokenAccountResponse `json:"accounts"`
}

type TokenEntry struct {
	PublicKey *types.PublicKey
	Program   string
	Account   *core.TokenAccount
	Decimals  *uint8
}

// TokenAccountResponse reports what a holder account holds.
//
// Owner is not the runtime owner. That is the token program, which is what may
// write the data; Owner here is the wallet whose signature the program accepts.
//
// Amount has no decimals of its own. It is base units, and Decimals is reported
// only when the mint could be read.
type TokenAccountResponse struct {
	PublicKey       string `json:"public_key"`
	Exists          bool   `json:"exists"`
	Program         string `json:"program"`
	Mint            string `json:"mint"`
	Owner           string `json:"owner"`
	Amount          string `json:"amount"`
	Decimals        *uint8 `json:"decimals,omitempty"`
	State           string `json:"state"`
	Native          bool   `json:"native"`
	RentReserve     string `json:"rent_reserve,omitempty"`
	Delegate        string `json:"delegate,omitempty"`
	DelegatedAmount string `json:"delegated_amount,omitempty"`
	CloseAuthority  string `json:"close_authority,omitempty"`
}

// tokenAccountStateName names the state rather than reporting the byte, since
// frozen is the one a caller has to act on and 2 does not say so.
func tokenAccountStateName(state uint8) string {
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

// NewTokenAccountResponse fills the UI amount only when the mint was read.
//
// decimals is nil when it could not be, which happens when the mint is on a
// different program or has gone. Reporting the base units alone is honest;
// guessing a scale would misstate a balance by orders of magnitude.
func NewTokenAccountResponse(k *types.PublicKey, program string, a *core.TokenAccount, decimals *uint8) *TokenAccountResponse {
	res := &TokenAccountResponse{
		PublicKey: k.Base58(),
		Exists:    true,
		Program:   program,
		Mint:      a.Mint.Base58(),
		Owner:     a.Owner.Base58(),
		Amount:    strconv.FormatUint(a.Amount, 10),
		Decimals:  decimals,
		State:     tokenAccountStateName(a.State),
		Native:    a.IsNative,
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

func NewTokensResponse(k *types.PublicKey, entries []*TokenEntry) *TokensResponse {
	accounts := make([]*TokenAccountResponse, 0, len(entries))
	for _, entry := range entries {
		accounts = append(accounts, NewTokenAccountResponse(entry.PublicKey, entry.Program, entry.Account, entry.Decimals))
	}

	return &TokensResponse{
		PublicKey: k.Base58(),
		Count:     len(accounts),
		Accounts:  accounts,
	}
}

// AccountOwnerRequest names the account whose owner to read.
type AccountOwnerRequest struct {
	PublicKey string `json:"public_key" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	publicKey *types.PublicKey
}

func (r *AccountOwnerRequest) ValidateRequest() error {
	var err error
	if r.publicKey, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.PublicKey)); err != nil {
		return errors.New("public_key: " + err.Error())
	}

	return nil
}

func (r *AccountOwnerRequest) ToPublicKey() *types.PublicKey {
	return r.publicKey
}

type AccountAuthorityRequest struct {
	PublicKey string `json:"public_key" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	publicKey *types.PublicKey
}

func (r *AccountAuthorityRequest) ValidateRequest() error {
	var err error
	if r.publicKey, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.PublicKey)); err != nil {
		return errors.New("public_key: " + err.Error())
	}

	return nil
}

func (r *AccountAuthorityRequest) ToPublicKey() *types.PublicKey {
	return r.publicKey
}

// AccountOwnerResponse reports who owns an account, and whether that leaves it
// spendable.
//
// SystemOwned is the part worth asking for on its own. Only the owning program
// may debit an account, so an account owned by anything else cannot be moved
// with a System Program transfer, and an account owned by a non-executable
// address cannot be moved at all.
type AccountOwnerResponse struct {
	PublicKey   string `json:"public_key"`
	Exists      bool   `json:"exists"`
	Owner       string `json:"owner"`
	SystemOwned bool   `json:"system_owned"`
}

func NewAccountOwnerResponse(k *types.PublicKey, info *rpc.AccountInfo) *AccountOwnerResponse {
	if info == nil {
		return &AccountOwnerResponse{PublicKey: k.Base58()}
	}

	return &AccountOwnerResponse{
		PublicKey:   k.Base58(),
		Exists:      true,
		Owner:       info.Owner,
		SystemOwned: info.Owner == core.System.ID().Base58(),
	}
}

// AirdropAmount is what every airdrop requests.
//
// It is fixed rather than taken from the body because the faucet decides the
// real limit anyway, and asking for more than it allows fails the whole call
// rather than giving less. Half a SOL sits well inside what devnet and testnet
// hand out, so the amount was never a useful choice to offer.
const AirdropAmount = types.LamportsPerSol / 2

// AirdropRequest funds an account on devnet or testnet. Mainnet refuses it.
type AirdropRequest struct {
	PublicKey string `json:"public_key"`

	publicKey *types.PublicKey
}

func (r *AirdropRequest) ValidateRequest() error {
	var err error
	if r.publicKey, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.PublicKey)); err != nil {
		return errors.New("public_key: " + err.Error())
	}

	return nil
}

func (r *AirdropRequest) ToPublicKey() *types.PublicKey {
	return r.publicKey
}

type AirdropResponse struct {
	Signature string `json:"signature"`
	Lamports  string `json:"lamports"`
	SOL       string `json:"sol"`
}

func NewAirdropResponse(sig *types.Signature) *AirdropResponse {
	return &AirdropResponse{
		Signature: sig.Base58(),
		Lamports:  strconv.FormatUint(AirdropAmount, 10),
		SOL:       types.LamportsToSol(AirdropAmount),
	}
}

// NonceRequest names the nonce account to read.
type NonceRequest struct {
	PublicKey string `json:"public_key" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	publicKey *types.PublicKey
}

func (r *NonceRequest) ValidateRequest() error {
	var err error
	if r.publicKey, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.PublicKey)); err != nil {
		return errors.New("public_key: " + err.Error())
	}

	return nil
}

func (r *NonceRequest) ToPublicKey() *types.PublicKey {
	return r.publicKey
}

// NonceResponse reports what a durable nonce account holds.
//
// Initialized is separate from the rest because an account sized for a nonce
// but never initialized is an ordinary intermediate state: create-account
// allocates the 80 bytes, and they stay zero until the initializer writes
// them. Such an account reports the Legacy version and the uninitialized
// state, which is what all-zero bytes decode to.
//
// Nonce is the stored blockhash. A transaction carrying it in place of a
// recent one never expires, which is the whole point of the feature.
type NonceResponse struct {
	PublicKey            string `json:"public_key"`
	Exists               bool   `json:"exists"`
	Initialized          bool   `json:"initialized"`
	Version              uint32 `json:"version"`
	State                uint32 `json:"state"`
	Authority            string `json:"authority"`
	Nonce                string `json:"nonce"`
	LamportsPerSignature string `json:"lamports_per_signature"`
}

func NewNonceResponse(k *types.PublicKey, n *core.NonceAccount) *NonceResponse {
	return &NonceResponse{
		PublicKey:            k.Base58(),
		Exists:               true,
		Initialized:          n.Initialized(),
		Version:              n.Version,
		State:                n.State,
		Authority:            n.Authority.Base58(),
		Nonce:                n.Nonce.Base58(),
		LamportsPerSignature: strconv.FormatUint(n.LamportsPerSignature, 10),
	}
}

// AccountAuthorityResponse reports the authority-bearing fields for whichever
// kind of account public_key names. Where that authority lives is entirely
// different by kind — a nonce account, a mint, a token account, and a
// multisig each keep it somewhere else, and a plain System account has none
// at all — so Type says what was actually decoded before any of the
// type-specific fields are read: system_account, nonce_account, mint,
// token_account, multisig, or unknown for a program-owned account this
// endpoint has no parser for.
type AccountAuthorityResponse struct {
	PublicKey string `json:"public_key"`
	Exists    bool   `json:"exists"`
	Owner     string `json:"owner"`
	Type      string `json:"type"`

	// NonceAuthority is relevant only when Type is nonce_account, and even
	// then only once initialized — it is always present in the response
	// (empty when it does not apply) rather than silently omitted, so an
	// empty string is never ambiguous between "not this kind of account" and
	// "this account has none".
	NonceAuthority string `json:"nonce_authority"`

	// MintAuthority and FreezeAuthority are relevant only when Type is mint.
	// Either can be permanently removed on a real mint, and empty here means
	// exactly that: gone for good, not merely unset.
	MintAuthority   string `json:"mint_authority"`
	FreezeAuthority string `json:"freeze_authority"`

	// TokenOwner and Delegate are relevant only when Type is token_account.
	// Delegate empty means no delegate is currently approved.
	TokenOwner string `json:"token_owner"`
	Delegate   string `json:"delegate"`

	// CloseAuthority reports who can actually close this token account,
	// which is never blank once Type is token_account: the program checks
	// close_authority.unwrap_or(owner), so this is TokenOwner whenever the
	// account carries no close authority of its own, and the stored value
	// otherwise. It is never left for the caller to resolve that fallback.
	CloseAuthority string `json:"close_authority"`

	// M, N, and Signers are set only when Type is multisig.
	M       uint8    `json:"m,omitempty"`
	N       uint8    `json:"n,omitempty"`
	Signers []string `json:"signers,omitempty"`
}

func NewAccountAuthorityResponse(k *types.PublicKey, info *rpc.AccountInfo) (*AccountAuthorityResponse, error) {
	if !info.Exists() {
		return &AccountAuthorityResponse{PublicKey: k.Base58()}, nil
	}

	resp := &AccountAuthorityResponse{
		PublicKey: k.Base58(),
		Exists:    true,
		Owner:     info.Owner,
	}

	owner, err := types.NewPublicKeyFromBase58(info.Owner)
	if err != nil {
		return nil, fmt.Errorf("owner: %w", err)
	}

	if owner.Equal(core.System.ID()) {
		resp.Type = "system_account"
		if info.Space != core.NonceAccountSpace {
			return resp, nil
		}

		data, err := info.Bytes()
		if err != nil {
			return nil, fmt.Errorf("failed to decode account data: %w", err)
		}
		nonce, err := core.DeserializeNonceAccount(data)
		if err != nil {
			return nil, err
		}

		resp.Type = "nonce_account"
		if nonce.Initialized() {
			resp.NonceAuthority = nonce.Authority.Base58()
		}
		return resp, nil
	}

	if _, err := core.TokenProgram(owner); err == nil {
		data, err := info.Bytes()
		if err != nil {
			return nil, fmt.Errorf("failed to decode account data: %w", err)
		}

		if mint, mErr := core.DecodeMint(owner, data); mErr == nil {
			resp.Type = "mint"
			if !mint.MintAuthority.IsNil() {
				resp.MintAuthority = mint.MintAuthority.Base58()
			}
			if !mint.FreezeAuthority.IsNil() {
				resp.FreezeAuthority = mint.FreezeAuthority.Base58()
			}
			return resp, nil
		}

		if account, aErr := core.DecodeTokenAccount(owner, data); aErr == nil {
			resp.Type = "token_account"
			resp.TokenOwner = account.Owner.Base58()
			if !account.Delegate.IsNil() {
				resp.Delegate = account.Delegate.Base58()
			}

			// The program checks close_authority.unwrap_or(owner): a token
			// account is never actually closable by nobody, so the effective
			// closer is reported directly rather than leaving the caller to
			// apply this fallback themselves.
			resp.CloseAuthority = resp.TokenOwner
			if !account.CloseAuthority.IsNil() {
				resp.CloseAuthority = account.CloseAuthority.Base58()
			}
			return resp, nil
		}

		if multisig, msErr := core.DecodeMultisig(owner, data); msErr == nil {
			resp.Type = "multisig"
			resp.M = multisig.M
			resp.N = multisig.N
			signers := make([]string, len(multisig.Signers))
			for i, s := range multisig.Signers {
				signers[i] = s.Base58()
			}
			resp.Signers = signers
			return resp, nil
		}
	}

	resp.Type = "unknown"
	return resp, nil
}
