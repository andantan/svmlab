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

// ZkElgamalProofTransactionHandler builds instructions against the
// ZkElgamalProof program (ZkE1Gama1Proof11111111111111111111111111111).
// Token-2022's ConfidentialTransfer family depends on it to check the
// zero-knowledge proofs a caller supplies rather than checking them
// itself; this is a program of its own, not part of Token-2022, so it
// gets its own top-level route group the same way compute-budget does.
type ZkElgamalProofTransactionHandler struct {
	cfg *config.Config
}

func NewZkElgamalProofTransactionHandler(cfg *config.Config) *ZkElgamalProofTransactionHandler {
	return &ZkElgamalProofTransactionHandler{cfg: cfg}
}

// ContextStateCreateAccountPubkeyValidity godoc
// @Summary      Fund a new account, sized and owned for a PubkeyValidity proof context-state
// @Description  System CreateAccount only, sized (65 bytes) and owned (by the ZkElgamalProof program) for a PubkeyValidity proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-pubkey-validity instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-pubkey-validity and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateAccountPubkeyValidityRequest true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateAccountPubkeyValidityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create-account/pubkey-validity [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateAccountPubkeyValidity(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateAccountPubkeyValidityRequest)
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

	const space = core.PubkeyValidityContextStateSpace

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	rentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), space, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.ContextStateAccountKey(),
		req.RentPayerKey(),
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

	if accounts[req.ContextStateAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s already exists", req.ContextStateAccountKey()))
		return
	}
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	createIx, err := core.System.CreateAccount(req.RentPayerKey(), req.ContextStateAccountKey(), core.ZkElgamalProof.ID(), rentExempt, space)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(createIx)

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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	needed := fee
	if req.FeePayerKey().Equal(req.RentPayerKey()) {
		needed += rentExempt
	}
	if feePayerBalance < needed {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, needed))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, needed, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-needed, minRent))
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewContextStateCreateAccountPubkeyValidityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateAccountCiphertextCommitmentEquality godoc
// @Summary      Fund a new account, sized and owned for a CiphertextCommitmentEquality proof context-state
// @Description  System CreateAccount only, sized (161 bytes) and owned (by the ZkElgamalProof program) for a CiphertextCommitmentEquality proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-ciphertext-commitment-equality instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-ciphertext-commitment-equality and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateAccountCiphertextCommitmentEqualityRequest true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateAccountCiphertextCommitmentEqualityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create-account/ciphertext-commitment-equality [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateAccountCiphertextCommitmentEquality(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateAccountCiphertextCommitmentEqualityRequest)
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

	const space = core.CiphertextCommitmentEqualityContextStateSpace

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	rentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), space, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.ContextStateAccountKey(),
		req.RentPayerKey(),
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

	if accounts[req.ContextStateAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s already exists", req.ContextStateAccountKey()))
		return
	}
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	createIx, err := core.System.CreateAccount(req.RentPayerKey(), req.ContextStateAccountKey(), core.ZkElgamalProof.ID(), rentExempt, space)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(createIx)

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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	needed := fee
	if req.FeePayerKey().Equal(req.RentPayerKey()) {
		needed += rentExempt
	}
	if feePayerBalance < needed {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, needed))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, needed, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-needed, minRent))
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

	handler.WriteOK(w, NewContextStateCreateAccountCiphertextCommitmentEqualityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidity godoc
// @Summary      Fund a new account, sized and owned for a BatchedGroupedCiphertext3HandlesValidity proof context-state
// @Description  System CreateAccount only, sized (385 bytes) and owned (by the ZkElgamalProof program) for a BatchedGroupedCiphertext3HandlesValidity proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-batched-grouped-ciphertext-3-handles-validity instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-batched-grouped-ciphertext-3-handles-validity and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidityRequest true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create-account/batched-grouped-ciphertext-3-handles-validity [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidity(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidityRequest)
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

	const space = core.BatchedGroupedCiphertext3HandlesValidityContextStateSpace

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	rentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), space, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.ContextStateAccountKey(),
		req.RentPayerKey(),
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

	if accounts[req.ContextStateAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s already exists", req.ContextStateAccountKey()))
		return
	}
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	createIx, err := core.System.CreateAccount(req.RentPayerKey(), req.ContextStateAccountKey(), core.ZkElgamalProof.ID(), rentExempt, space)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(createIx)

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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	needed := fee
	if req.FeePayerKey().Equal(req.RentPayerKey()) {
		needed += rentExempt
	}
	if feePayerBalance < needed {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, needed))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, needed, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-needed, minRent))
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

	handler.WriteOK(w, NewContextStateCreateAccountBatchedGroupedCiphertext3HandlesValidityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateAccountBatchedRangeProofU128 godoc
// @Summary      Fund a new account, sized and owned for a BatchedRangeProofU128 proof context-state
// @Description  System CreateAccount only, sized (297 bytes) and owned (by the ZkElgamalProof program) for a BatchedRangeProofU128 proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-batched-range-proof-u128 instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-batched-range-proof-u128 and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateAccountBatchedRangeProofU128Request true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateAccountBatchedRangeProofU128Response
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create-account/batched-range-proof-u128 [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateAccountBatchedRangeProofU128(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateAccountBatchedRangeProofU128Request)
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

	const space = core.BatchedRangeProofU128ContextStateSpace

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	rentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), space, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.ContextStateAccountKey(),
		req.RentPayerKey(),
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

	if accounts[req.ContextStateAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s already exists", req.ContextStateAccountKey()))
		return
	}
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	createIx, err := core.System.CreateAccount(req.RentPayerKey(), req.ContextStateAccountKey(), core.ZkElgamalProof.ID(), rentExempt, space)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(createIx)

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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	needed := fee
	if req.FeePayerKey().Equal(req.RentPayerKey()) {
		needed += rentExempt
	}
	if feePayerBalance < needed {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, needed))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, needed, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-needed, minRent))
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

	handler.WriteOK(w, NewContextStateCreateAccountBatchedRangeProofU128Response(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateAccountZeroCiphertext godoc
// @Summary      Fund a new account, sized and owned for a ZeroCiphertext proof context-state
// @Description  System CreateAccount only, sized (129 bytes) and owned (by the ZkElgamalProof program) for a ZeroCiphertext proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-zero-ciphertext instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-zero-ciphertext and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateAccountZeroCiphertextRequest true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateAccountZeroCiphertextResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create-account/zero-ciphertext [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateAccountZeroCiphertext(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateAccountZeroCiphertextRequest)
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

	const space = core.ZeroCiphertextContextStateSpace

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	rentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), space, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.ContextStateAccountKey(),
		req.RentPayerKey(),
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

	if accounts[req.ContextStateAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s already exists", req.ContextStateAccountKey()))
		return
	}
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	createIx, err := core.System.CreateAccount(req.RentPayerKey(), req.ContextStateAccountKey(), core.ZkElgamalProof.ID(), rentExempt, space)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(createIx)

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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	needed := fee
	if req.FeePayerKey().Equal(req.RentPayerKey()) {
		needed += rentExempt
	}
	if feePayerBalance < needed {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, needed))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, needed, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-needed, minRent))
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

	handler.WriteOK(w, NewContextStateCreateAccountZeroCiphertextResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateAccountCiphertextCiphertextEquality godoc
// @Summary      Fund a new account, sized and owned for a CiphertextCiphertextEquality proof context-state
// @Description  System CreateAccount only, sized (225 bytes) and owned (by the ZkElgamalProof program) for a CiphertextCiphertextEquality proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-ciphertext-ciphertext-equality instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-ciphertext-ciphertext-equality and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateAccountCiphertextCiphertextEqualityRequest true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateAccountCiphertextCiphertextEqualityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create-account/ciphertext-ciphertext-equality [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateAccountCiphertextCiphertextEquality(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateAccountCiphertextCiphertextEqualityRequest)
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

	const space = core.CiphertextCiphertextEqualityContextStateSpace

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	rentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), space, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.ContextStateAccountKey(),
		req.RentPayerKey(),
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

	if accounts[req.ContextStateAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s already exists", req.ContextStateAccountKey()))
		return
	}
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	createIx, err := core.System.CreateAccount(req.RentPayerKey(), req.ContextStateAccountKey(), core.ZkElgamalProof.ID(), rentExempt, space)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(createIx)

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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	needed := fee
	if req.FeePayerKey().Equal(req.RentPayerKey()) {
		needed += rentExempt
	}
	if feePayerBalance < needed {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, needed))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, needed, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-needed, minRent))
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

	handler.WriteOK(w, NewContextStateCreateAccountCiphertextCiphertextEqualityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateAccountPercentageWithCap godoc
// @Summary      Fund a new account, sized and owned for a PercentageWithCap proof context-state
// @Description  System CreateAccount only, sized (137 bytes) and owned (by the ZkElgamalProof program) for a PercentageWithCap proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-percentage-with-cap instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-percentage-with-cap and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateAccountPercentageWithCapRequest true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateAccountPercentageWithCapResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create-account/percentage-with-cap [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateAccountPercentageWithCap(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateAccountPercentageWithCapRequest)
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

	const space = core.PercentageWithCapContextStateSpace

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	rentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), space, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.ContextStateAccountKey(),
		req.RentPayerKey(),
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

	if accounts[req.ContextStateAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s already exists", req.ContextStateAccountKey()))
		return
	}
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	createIx, err := core.System.CreateAccount(req.RentPayerKey(), req.ContextStateAccountKey(), core.ZkElgamalProof.ID(), rentExempt, space)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(createIx)

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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	needed := fee
	if req.FeePayerKey().Equal(req.RentPayerKey()) {
		needed += rentExempt
	}
	if feePayerBalance < needed {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, needed))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, needed, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-needed, minRent))
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

	handler.WriteOK(w, NewContextStateCreateAccountPercentageWithCapResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateAccountBatchedRangeProofU64 godoc
// @Summary      Fund a new account, sized and owned for a BatchedRangeProofU64 proof context-state
// @Description  System CreateAccount only, sized (297 bytes) and owned (by the ZkElgamalProof program) for a BatchedRangeProofU64 proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-batched-range-proof-u64 instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-batched-range-proof-u64 and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateAccountBatchedRangeProofU64Request true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateAccountBatchedRangeProofU64Response
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create-account/batched-range-proof-u64 [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateAccountBatchedRangeProofU64(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateAccountBatchedRangeProofU64Request)
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

	const space = core.BatchedRangeProofU64ContextStateSpace

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	rentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), space, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.ContextStateAccountKey(),
		req.RentPayerKey(),
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

	if accounts[req.ContextStateAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s already exists", req.ContextStateAccountKey()))
		return
	}
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	createIx, err := core.System.CreateAccount(req.RentPayerKey(), req.ContextStateAccountKey(), core.ZkElgamalProof.ID(), rentExempt, space)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(createIx)

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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	needed := fee
	if req.FeePayerKey().Equal(req.RentPayerKey()) {
		needed += rentExempt
	}
	if feePayerBalance < needed {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, needed))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, needed, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-needed, minRent))
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

	handler.WriteOK(w, NewContextStateCreateAccountBatchedRangeProofU64Response(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateAccountBatchedRangeProofU256 godoc
// @Summary      Fund a new account, sized and owned for a BatchedRangeProofU256 proof context-state
// @Description  System CreateAccount only, sized (297 bytes) and owned (by the ZkElgamalProof program) for a BatchedRangeProofU256 proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-batched-range-proof-u256 instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-batched-range-proof-u256 and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateAccountBatchedRangeProofU256Request true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateAccountBatchedRangeProofU256Response
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create-account/batched-range-proof-u256 [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateAccountBatchedRangeProofU256(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateAccountBatchedRangeProofU256Request)
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

	const space = core.BatchedRangeProofU256ContextStateSpace

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	rentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), space, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.ContextStateAccountKey(),
		req.RentPayerKey(),
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

	if accounts[req.ContextStateAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s already exists", req.ContextStateAccountKey()))
		return
	}
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	createIx, err := core.System.CreateAccount(req.RentPayerKey(), req.ContextStateAccountKey(), core.ZkElgamalProof.ID(), rentExempt, space)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(createIx)

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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	needed := fee
	if req.FeePayerKey().Equal(req.RentPayerKey()) {
		needed += rentExempt
	}
	if feePayerBalance < needed {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, needed))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, needed, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-needed, minRent))
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

	handler.WriteOK(w, NewContextStateCreateAccountBatchedRangeProofU256Response(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateAccountGroupedCiphertext2HandlesValidity godoc
// @Summary      Fund a new account, sized and owned for a GroupedCiphertext2HandlesValidity proof context-state
// @Description  System CreateAccount only, sized (193 bytes) and owned (by the ZkElgamalProof program) for a GroupedCiphertext2HandlesValidity proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-grouped-ciphertext-2-handles-validity instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-grouped-ciphertext-2-handles-validity and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateAccountGroupedCiphertext2HandlesValidityRequest true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateAccountGroupedCiphertext2HandlesValidityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create-account/grouped-ciphertext-2-handles-validity [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateAccountGroupedCiphertext2HandlesValidity(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateAccountGroupedCiphertext2HandlesValidityRequest)
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

	const space = core.GroupedCiphertext2HandlesValidityContextStateSpace

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	rentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), space, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.ContextStateAccountKey(),
		req.RentPayerKey(),
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

	if accounts[req.ContextStateAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s already exists", req.ContextStateAccountKey()))
		return
	}
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	createIx, err := core.System.CreateAccount(req.RentPayerKey(), req.ContextStateAccountKey(), core.ZkElgamalProof.ID(), rentExempt, space)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(createIx)

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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	needed := fee
	if req.FeePayerKey().Equal(req.RentPayerKey()) {
		needed += rentExempt
	}
	if feePayerBalance < needed {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, needed))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, needed, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-needed, minRent))
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

	handler.WriteOK(w, NewContextStateCreateAccountGroupedCiphertext2HandlesValidityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidity godoc
// @Summary      Fund a new account, sized and owned for a BatchedGroupedCiphertext2HandlesValidity proof context-state
// @Description  System CreateAccount only, sized (289 bytes) and owned (by the ZkElgamalProof program) for a BatchedGroupedCiphertext2HandlesValidity proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-batched-grouped-ciphertext-2-handles-validity instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-batched-grouped-ciphertext-2-handles-validity and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidityRequest true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create-account/batched-grouped-ciphertext-2-handles-validity [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidity(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidityRequest)
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

	const space = core.BatchedGroupedCiphertext2HandlesValidityContextStateSpace

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	rentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), space, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.ContextStateAccountKey(),
		req.RentPayerKey(),
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

	if accounts[req.ContextStateAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s already exists", req.ContextStateAccountKey()))
		return
	}
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	createIx, err := core.System.CreateAccount(req.RentPayerKey(), req.ContextStateAccountKey(), core.ZkElgamalProof.ID(), rentExempt, space)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(createIx)

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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	needed := fee
	if req.FeePayerKey().Equal(req.RentPayerKey()) {
		needed += rentExempt
	}
	if feePayerBalance < needed {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, needed))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, needed, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-needed, minRent))
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

	handler.WriteOK(w, NewContextStateCreateAccountBatchedGroupedCiphertext2HandlesValidityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateAccountGroupedCiphertext3HandlesValidity godoc
// @Summary      Fund a new account, sized and owned for a GroupedCiphertext3HandlesValidity proof context-state
// @Description  System CreateAccount only, sized (257 bytes) and owned (by the ZkElgamalProof program) for a GroupedCiphertext3HandlesValidity proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-grouped-ciphertext-3-handles-validity instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-grouped-ciphertext-3-handles-validity and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateAccountGroupedCiphertext3HandlesValidityRequest true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateAccountGroupedCiphertext3HandlesValidityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create-account/grouped-ciphertext-3-handles-validity [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateAccountGroupedCiphertext3HandlesValidity(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateAccountGroupedCiphertext3HandlesValidityRequest)
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

	const space = core.GroupedCiphertext3HandlesValidityContextStateSpace

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	rentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), space, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.ContextStateAccountKey(),
		req.RentPayerKey(),
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

	if accounts[req.ContextStateAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s already exists", req.ContextStateAccountKey()))
		return
	}
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	createIx, err := core.System.CreateAccount(req.RentPayerKey(), req.ContextStateAccountKey(), core.ZkElgamalProof.ID(), rentExempt, space)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(createIx)

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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	needed := fee
	if req.FeePayerKey().Equal(req.RentPayerKey()) {
		needed += rentExempt
	}
	if feePayerBalance < needed {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, needed))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, needed, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-needed, minRent))
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

	handler.WriteOK(w, NewContextStateCreateAccountGroupedCiphertext3HandlesValidityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}
