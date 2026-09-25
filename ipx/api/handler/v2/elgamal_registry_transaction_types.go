package v2

import (
	"errors"
	"strings"

	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
)

// ElGamalRegistryCreateRequest creates a wallet's ElGamal registry account
// and records the ElGamal public key a verified PubkeyValidity proof
// certifies.
type ElGamalRegistryCreateRequest struct {
	// Wallet owns the registry and signs. The registry account itself is not
	// a field: it is the PDA derived from the wallet (seeds
	// ["elgamal-registry", wallet]) and the response reports it.
	Wallet string `json:"wallet" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// PubkeyValidityContextStateAccount holds the verified PubkeyValidity
	// proof for the ElGamal public key being registered (see
	// tool/prove/pubkey-validity and
	// zk-elgamal-proof/context-state/{create,verify}/pubkey-validity).
	PubkeyValidityContextStateAccount string `json:"pubkey_validity_context_state_account" example:""`

	// RentPayer funds the registry account's rent-exempt minimum. The
	// registry program does not fund the account it creates -- it only
	// allocates and assigns it, and refuses to if the address does not
	// already hold enough lamports -- so this transaction first transfers
	// the shortfall from RentPayer to the registry address. It may be left
	// empty only when the address is already funded. It signs when named
	// and is not the wallet's business: anyone can fund the address.
	RentPayer string `json:"rent_payer" example:""`

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
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	wallet        *types.PublicKey
	rentPayer     *types.PublicKey
	registry      *types.PublicKey
	pubkeyContext *types.PublicKey
	fp            *types.PublicKey
	rbh           *types.Hash
	dna           *types.PublicKey
}

func (r *ElGamalRegistryCreateRequest) ValidateRequest() error {
	var err error

	if r.wallet, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Wallet)); err != nil {
		return errors.New("wallet: " + err.Error())
	}
	if r.registry, _, err = core.ElGamalRegistry.Address(r.wallet); err != nil {
		return errors.New("wallet: " + err.Error())
	}
	if rp := strings.TrimSpace(r.RentPayer); rp != "" {
		if r.rentPayer, err = types.NewPublicKeyFromBase58(rp); err != nil {
			return errors.New("rent_payer: " + err.Error())
		}
	}
	if r.pubkeyContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.PubkeyValidityContextStateAccount)); err != nil {
		return errors.New("pubkey_validity_context_state_account: " + err.Error())
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

func (r *ElGamalRegistryCreateRequest) WalletKey() *types.PublicKey    { return r.wallet }
func (r *ElGamalRegistryCreateRequest) RentPayerKey() *types.PublicKey { return r.rentPayer }
func (r *ElGamalRegistryCreateRequest) RegistryKey() *types.PublicKey  { return r.registry }
func (r *ElGamalRegistryCreateRequest) PubkeyContextKey() *types.PublicKey {
	return r.pubkeyContext
}
func (r *ElGamalRegistryCreateRequest) FeePayerKey() *types.PublicKey { return r.fp }
func (r *ElGamalRegistryCreateRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *ElGamalRegistryCreateRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ElGamalRegistryCreateResponse reports the built transaction.
type ElGamalRegistryCreateResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Wallet                            string `json:"wallet"`
	RegistryAccount                   string `json:"registry_account"`
	PubkeyValidityContextStateAccount string `json:"pubkey_validity_context_state_account"`

	Fee SystemPayer `json:"fee"`
}

func NewElGamalRegistryCreateResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	wallet, registry, pubkeyContext *types.PublicKey,
	fee uint64,
) *ElGamalRegistryCreateResponse {
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

	return &ElGamalRegistryCreateResponse{
		Transaction:                       codec.Base64.Encode(raw),
		Message:                           codec.Base64.Encode(message),
		RecentBlockhash:                   tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                       keys,
		Signers:                           signers,
		NonceAuthority:                    nonceAuth,
		Wallet:                            wallet.Base58(),
		RegistryAccount:                   registry.Base58(),
		PubkeyValidityContextStateAccount: pubkeyContext.Base58(),
		Fee:                               newSystemPayer(feePayer, fee),
	}
}

// ElGamalRegistryUpdateRequest replaces the ElGamal public key in a wallet's
// existing registry account.
type ElGamalRegistryUpdateRequest struct {
	// Wallet owns the registry and signs. The registry account itself is not
	// a field: it is the PDA derived from the wallet (seeds
	// ["elgamal-registry", wallet]) and the response reports it.
	Wallet string `json:"wallet" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// PubkeyValidityContextStateAccount holds the verified PubkeyValidity
	// proof for the ElGamal public key being registered (see
	// tool/prove/pubkey-validity and
	// zk-elgamal-proof/context-state/{create,verify}/pubkey-validity).
	PubkeyValidityContextStateAccount string `json:"pubkey_validity_context_state_account" example:""`

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
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	wallet        *types.PublicKey
	registry      *types.PublicKey
	pubkeyContext *types.PublicKey
	fp            *types.PublicKey
	rbh           *types.Hash
	dna           *types.PublicKey
}

func (r *ElGamalRegistryUpdateRequest) ValidateRequest() error {
	var err error

	if r.wallet, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Wallet)); err != nil {
		return errors.New("wallet: " + err.Error())
	}
	if r.registry, _, err = core.ElGamalRegistry.Address(r.wallet); err != nil {
		return errors.New("wallet: " + err.Error())
	}
	if r.pubkeyContext, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.PubkeyValidityContextStateAccount)); err != nil {
		return errors.New("pubkey_validity_context_state_account: " + err.Error())
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

func (r *ElGamalRegistryUpdateRequest) WalletKey() *types.PublicKey   { return r.wallet }
func (r *ElGamalRegistryUpdateRequest) RegistryKey() *types.PublicKey { return r.registry }
func (r *ElGamalRegistryUpdateRequest) PubkeyContextKey() *types.PublicKey {
	return r.pubkeyContext
}
func (r *ElGamalRegistryUpdateRequest) FeePayerKey() *types.PublicKey { return r.fp }
func (r *ElGamalRegistryUpdateRequest) Blockhash() *types.Hash        { return r.rbh }
func (r *ElGamalRegistryUpdateRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// ElGamalRegistryUpdateResponse reports the built transaction.
type ElGamalRegistryUpdateResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	Wallet                            string `json:"wallet"`
	RegistryAccount                   string `json:"registry_account"`
	PubkeyValidityContextStateAccount string `json:"pubkey_validity_context_state_account"`

	Fee SystemPayer `json:"fee"`
}

func NewElGamalRegistryUpdateResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	wallet, registry, pubkeyContext *types.PublicKey,
	fee uint64,
) *ElGamalRegistryUpdateResponse {
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

	return &ElGamalRegistryUpdateResponse{
		Transaction:                       codec.Base64.Encode(raw),
		Message:                           codec.Base64.Encode(message),
		RecentBlockhash:                   tx.Message.RecentBlockhash.Base58(),
		AccountKeys:                       keys,
		Signers:                           signers,
		NonceAuthority:                    nonceAuth,
		Wallet:                            wallet.Base58(),
		RegistryAccount:                   registry.Base58(),
		PubkeyValidityContextStateAccount: pubkeyContext.Base58(),
		Fee:                               newSystemPayer(feePayer, fee),
	}
}
