package v2

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/types"
	"github.com/andantan/svmlab/internal/config"
	"github.com/andantan/svmlab/internal/rpc"
)

// ElGamalRegistryTransactionHandler builds instructions against the ElGamal
// registry program (regVYJW7tcT8zipN5YiBvHsvR5jXW1uLFxaHSbugABg): one PDA per
// wallet holding that wallet's ElGamal public key, so a token account of that
// wallet can be set up for confidential transfers without a proof or the
// owner's signature each time. It is a program of its own, so it gets its
// own top-level route group.
type ElGamalRegistryTransactionHandler struct {
	cfg *config.Config
}

func NewElGamalRegistryTransactionHandler(cfg *config.Config) *ElGamalRegistryTransactionHandler {
	return &ElGamalRegistryTransactionHandler{cfg: cfg}
}

// ElGamalRegistryCreate godoc
// @Summary      Create a wallet's ElGamal registry
// @Description  ElGamal registry CreateRegistry: creates the wallet's registry account -- a 64-byte PDA of the registry program with seeds [\"elgamal-registry\", wallet], created by the program itself -- and records the ElGamal public key that a PubkeyValidity proof certifies. The proof must already be verified into a context-state account (see tool/prove/pubkey-validity and zk-elgamal-proof/context-state/{create,verify}/pubkey-validity). The wallet signs, and one wallet has exactly one registry. With it, any of the wallet's token accounts can be set up for confidential transfers without a proof or the owner's signature (see confidential-transfer-account/configure-account-with-registry), and they all share this one ElGamal key. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-elgamal-registry
// @Accept       json
// @Produce      json
// @Param        request body ElGamalRegistryCreateRequest true "Registry request"
// @Success      200 {object} ElGamalRegistryCreateResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/elgamal-registry/create [post]
func (h *ElGamalRegistryTransactionHandler) ElGamalRegistryCreate(w http.ResponseWriter, r *http.Request) {
	req := new(ElGamalRegistryCreateRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	chain, err := rpc.ChainFromContext(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	lookups := []*types.PublicKey{
		req.RegistryKey(),
		req.PubkeyContextKey(),
		req.FeePayerKey(),
	}
	if !req.RentPayerKey().IsNil() {
		lookups = append(lookups, req.RentPayerKey())
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	var registryLamports uint64
	if regInfo := accounts[req.RegistryKey().Base58()]; regInfo.Exists() {
		if regInfo.Owner == core.ElGamalRegistry.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("wallet: %s already has a registry at %s -- use elgamal-registry/update", req.WalletKey(), req.RegistryKey()))
			return
		}
		if regInfo.Owner != core.SystemProgramID.Base58() || regInfo.Space != 0 {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("registry: %s already exists as a %d-byte account owned by %s", req.RegistryKey(), regInfo.Space, regInfo.Owner))
			return
		}
		registryLamports = regInfo.Lamports
	}
	registryRent, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), core.ElGamalRegistryAccountLen, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	ctxInfo := accounts[req.PubkeyContextKey().Base58()]
	if !ctxInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("pubkey_validity_context_state_account: %s does not exist -- create and verify it first via zk-elgamal-proof/context-state", req.PubkeyContextKey()))
		return
	}
	if ctxInfo.Owner != core.ZkElgamalProof.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("pubkey_validity_context_state_account: %s is not owned by %s", req.PubkeyContextKey(), core.ZkElgamalProof.ID()))
		return
	}
	if ctxInfo.Space != core.PubkeyValidityContextStateSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("pubkey_validity_context_state_account: %s is %d bytes, expected %d", req.PubkeyContextKey(), ctxInfo.Space, core.PubkeyValidityContextStateSpace))
		return
	}

	ix, err := core.ElGamalRegistry.Create(req.WalletKey(), req.PubkeyContextKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// The program allocates and assigns the registry address but never funds
	// it, and refuses when it holds less than the rent-exempt minimum, so the
	// shortfall has to be transferred in first.
	instructions := types.NewInstructions(ix)
	if registryLamports < registryRent {
		if req.RentPayerKey().IsNil() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: required -- the registry address %s holds %d of the %d lamports its rent-exempt minimum needs, and the program does not fund it", req.RegistryKey(), registryLamports, registryRent))
			return
		}
		if info := accounts[req.RentPayerKey().Base58()]; !info.Exists() || info.Lamports < registryRent-registryLamports {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s cannot cover %d lamports", req.RentPayerKey(), registryRent-registryLamports))
			return
		}
		fund, err := core.System.Transfer(req.RentPayerKey(), req.RegistryKey(), registryRent-registryLamports)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		instructions = types.NewInstructions(fund, ix)
	}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	txRaw, err := tx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode message: %s", err))
		return
	}

	handler.WriteOK(w, NewElGamalRegistryCreateResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), nonceAuthority,
		req.WalletKey(), req.RegistryKey(), req.PubkeyContextKey(),
		fee,
	))
}

// ElGamalRegistryUpdate godoc
// @Summary      Replace the ElGamal public key in a wallet's registry
// @Description  ElGamal registry UpdateRegistry: replaces the ElGamal public key in the wallet's existing registry account with the one a verified PubkeyValidity proof certifies. Token accounts already configured keep the key they were configured with; only later configure-account-with-registry calls see the new one. The wallet signs. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-elgamal-registry
// @Accept       json
// @Produce      json
// @Param        request body ElGamalRegistryUpdateRequest true "Registry request"
// @Success      200 {object} ElGamalRegistryUpdateResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/elgamal-registry/update [post]
func (h *ElGamalRegistryTransactionHandler) ElGamalRegistryUpdate(w http.ResponseWriter, r *http.Request) {
	req := new(ElGamalRegistryUpdateRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	chain, err := rpc.ChainFromContext(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	lookups := []*types.PublicKey{
		req.RegistryKey(),
		req.PubkeyContextKey(),
		req.FeePayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	regInfo := accounts[req.RegistryKey().Base58()]
	if !regInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("wallet: %s has no registry at %s -- use elgamal-registry/create", req.WalletKey(), req.RegistryKey()))
		return
	}
	if regInfo.Owner != core.ElGamalRegistry.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("registry: %s is not owned by %s", req.RegistryKey(), core.ElGamalRegistry.ID()))
		return
	}

	ctxInfo := accounts[req.PubkeyContextKey().Base58()]
	if !ctxInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("pubkey_validity_context_state_account: %s does not exist -- create and verify it first via zk-elgamal-proof/context-state", req.PubkeyContextKey()))
		return
	}
	if ctxInfo.Owner != core.ZkElgamalProof.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("pubkey_validity_context_state_account: %s is not owned by %s", req.PubkeyContextKey(), core.ZkElgamalProof.ID()))
		return
	}
	if ctxInfo.Space != core.PubkeyValidityContextStateSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("pubkey_validity_context_state_account: %s is %d bytes, expected %d", req.PubkeyContextKey(), ctxInfo.Space, core.PubkeyValidityContextStateSpace))
		return
	}

	ix, err := core.ElGamalRegistry.Update(req.WalletKey(), req.PubkeyContextKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	instructions := types.NewInstructions(ix)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	txRaw, err := tx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode message: %s", err))
		return
	}

	handler.WriteOK(w, NewElGamalRegistryUpdateResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), nonceAuthority,
		req.WalletKey(), req.RegistryKey(), req.PubkeyContextKey(),
		fee,
	))
}
