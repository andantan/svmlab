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

// ContextStateCreatePubkeyValidity godoc
// @Summary      Fund a new account, sized and owned for a PubkeyValidity proof context-state
// @Description  System CreateAccount only, sized (65 bytes) and owned (by the ZkElgamalProof program) for a PubkeyValidity proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-pubkey-validity instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-pubkey-validity and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreatePubkeyValidityRequest true "Context-state create-account request"
// @Success      200 {object} ContextStateCreatePubkeyValidityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create/pubkey-validity [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreatePubkeyValidity(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreatePubkeyValidityRequest)
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
	handler.WriteOK(w, NewContextStateCreatePubkeyValidityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateCiphertextCommitmentEquality godoc
// @Summary      Fund a new account, sized and owned for a CiphertextCommitmentEquality proof context-state
// @Description  System CreateAccount only, sized (161 bytes) and owned (by the ZkElgamalProof program) for a CiphertextCommitmentEquality proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-ciphertext-commitment-equality instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-ciphertext-commitment-equality and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateCiphertextCommitmentEqualityRequest true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateCiphertextCommitmentEqualityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create/ciphertext-commitment-equality [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateCiphertextCommitmentEquality(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateCiphertextCommitmentEqualityRequest)
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

	handler.WriteOK(w, NewContextStateCreateCiphertextCommitmentEqualityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateBatchedGroupedCiphertext3HandlesValidity godoc
// @Summary      Fund a new account, sized and owned for a BatchedGroupedCiphertext3HandlesValidity proof context-state
// @Description  System CreateAccount only, sized (385 bytes) and owned (by the ZkElgamalProof program) for a BatchedGroupedCiphertext3HandlesValidity proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-batched-grouped-ciphertext-3-handles-validity instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-batched-grouped-ciphertext-3-handles-validity and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateBatchedGroupedCiphertext3HandlesValidityRequest true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateBatchedGroupedCiphertext3HandlesValidityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create/batched-grouped-ciphertext-3-handles-validity [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateBatchedGroupedCiphertext3HandlesValidity(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateBatchedGroupedCiphertext3HandlesValidityRequest)
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

	handler.WriteOK(w, NewContextStateCreateBatchedGroupedCiphertext3HandlesValidityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateBatchedRangeProofU128 godoc
// @Summary      Fund a new account, sized and owned for a BatchedRangeProofU128 proof context-state
// @Description  System CreateAccount only, sized (297 bytes) and owned (by the ZkElgamalProof program) for a BatchedRangeProofU128 proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-batched-range-proof-u128 instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-batched-range-proof-u128 and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateBatchedRangeProofU128Request true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateBatchedRangeProofU128Response
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create/batched-range-proof-u128 [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateBatchedRangeProofU128(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateBatchedRangeProofU128Request)
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

	handler.WriteOK(w, NewContextStateCreateBatchedRangeProofU128Response(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateZeroCiphertext godoc
// @Summary      Fund a new account, sized and owned for a ZeroCiphertext proof context-state
// @Description  System CreateAccount only, sized (129 bytes) and owned (by the ZkElgamalProof program) for a ZeroCiphertext proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-zero-ciphertext instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-zero-ciphertext and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateZeroCiphertextRequest true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateZeroCiphertextResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create/zero-ciphertext [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateZeroCiphertext(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateZeroCiphertextRequest)
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

	handler.WriteOK(w, NewContextStateCreateZeroCiphertextResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateCiphertextCiphertextEquality godoc
// @Summary      Fund a new account, sized and owned for a CiphertextCiphertextEquality proof context-state
// @Description  System CreateAccount only, sized (225 bytes) and owned (by the ZkElgamalProof program) for a CiphertextCiphertextEquality proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-ciphertext-ciphertext-equality instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-ciphertext-ciphertext-equality and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateCiphertextCiphertextEqualityRequest true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateCiphertextCiphertextEqualityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create/ciphertext-ciphertext-equality [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateCiphertextCiphertextEquality(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateCiphertextCiphertextEqualityRequest)
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

	handler.WriteOK(w, NewContextStateCreateCiphertextCiphertextEqualityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreatePercentageWithCap godoc
// @Summary      Fund a new account, sized and owned for a PercentageWithCap proof context-state
// @Description  System CreateAccount only, sized (137 bytes) and owned (by the ZkElgamalProof program) for a PercentageWithCap proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-percentage-with-cap instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-percentage-with-cap and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreatePercentageWithCapRequest true "Context-state create-account request"
// @Success      200 {object} ContextStateCreatePercentageWithCapResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create/percentage-with-cap [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreatePercentageWithCap(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreatePercentageWithCapRequest)
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

	handler.WriteOK(w, NewContextStateCreatePercentageWithCapResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateBatchedRangeProofU64 godoc
// @Summary      Fund a new account, sized and owned for a BatchedRangeProofU64 proof context-state
// @Description  System CreateAccount only, sized (297 bytes) and owned (by the ZkElgamalProof program) for a BatchedRangeProofU64 proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-batched-range-proof-u64 instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-batched-range-proof-u64 and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateBatchedRangeProofU64Request true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateBatchedRangeProofU64Response
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create/batched-range-proof-u64 [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateBatchedRangeProofU64(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateBatchedRangeProofU64Request)
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

	handler.WriteOK(w, NewContextStateCreateBatchedRangeProofU64Response(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateBatchedRangeProofU256 godoc
// @Summary      Fund a new account, sized and owned for a BatchedRangeProofU256 proof context-state
// @Description  System CreateAccount only, sized (297 bytes) and owned (by the ZkElgamalProof program) for a BatchedRangeProofU256 proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-batched-range-proof-u256 instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-batched-range-proof-u256 and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateBatchedRangeProofU256Request true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateBatchedRangeProofU256Response
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create/batched-range-proof-u256 [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateBatchedRangeProofU256(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateBatchedRangeProofU256Request)
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

	handler.WriteOK(w, NewContextStateCreateBatchedRangeProofU256Response(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateGroupedCiphertext2HandlesValidity godoc
// @Summary      Fund a new account, sized and owned for a GroupedCiphertext2HandlesValidity proof context-state
// @Description  System CreateAccount only, sized (193 bytes) and owned (by the ZkElgamalProof program) for a GroupedCiphertext2HandlesValidity proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-grouped-ciphertext-2-handles-validity instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-grouped-ciphertext-2-handles-validity and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateGroupedCiphertext2HandlesValidityRequest true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateGroupedCiphertext2HandlesValidityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create/grouped-ciphertext-2-handles-validity [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateGroupedCiphertext2HandlesValidity(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateGroupedCiphertext2HandlesValidityRequest)
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

	handler.WriteOK(w, NewContextStateCreateGroupedCiphertext2HandlesValidityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateBatchedGroupedCiphertext2HandlesValidity godoc
// @Summary      Fund a new account, sized and owned for a BatchedGroupedCiphertext2HandlesValidity proof context-state
// @Description  System CreateAccount only, sized (289 bytes) and owned (by the ZkElgamalProof program) for a BatchedGroupedCiphertext2HandlesValidity proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-batched-grouped-ciphertext-2-handles-validity instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-batched-grouped-ciphertext-2-handles-validity and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateBatchedGroupedCiphertext2HandlesValidityRequest true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateBatchedGroupedCiphertext2HandlesValidityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create/batched-grouped-ciphertext-2-handles-validity [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateBatchedGroupedCiphertext2HandlesValidity(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateBatchedGroupedCiphertext2HandlesValidityRequest)
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

	handler.WriteOK(w, NewContextStateCreateBatchedGroupedCiphertext2HandlesValidityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateCreateGroupedCiphertext3HandlesValidity godoc
// @Summary      Fund a new account, sized and owned for a GroupedCiphertext3HandlesValidity proof context-state
// @Description  System CreateAccount only, sized (257 bytes) and owned (by the ZkElgamalProof program) for a GroupedCiphertext3HandlesValidity proof's context, but not yet written to. This is deliberately the low-level half: the account must be created in the same transaction as (and strictly before) the matching context-state/verify-grouped-ciphertext-3-handles-validity instruction, or another party can claim it first -- build create+verify as two instructions in one transaction, calling this endpoint and context-state/verify-grouped-ciphertext-3-handles-validity and merging their instructions yourself. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateCreateGroupedCiphertext3HandlesValidityRequest true "Context-state create-account request"
// @Success      200 {object} ContextStateCreateGroupedCiphertext3HandlesValidityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/create/grouped-ciphertext-3-handles-validity [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateCreateGroupedCiphertext3HandlesValidity(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateCreateGroupedCiphertext3HandlesValidityRequest)
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

	handler.WriteOK(w, NewContextStateCreateGroupedCiphertext3HandlesValidityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), space, rentExempt,
		nonceAuthority,
		fee,
	))
}

// ContextStateVerifyPubkeyValidity godoc
// @Summary      Verify a PubkeyValidity proof and persist its context
// @Description  ZkElgamalProof VerifyPubkeyValidity, context-state form: verifies pubkey_proof against elgamal_pubkey and, because context_state_account and context_state_account_owner are given, writes the proof's context (the ElGamal pubkey alone) into that account instead of only checking it. context_state_account must already exist, sized and owned for this proof type (see context-state/create/pubkey-validity) -- created in an earlier transaction, or (to close the front-running window the interface crate's own docs describe) merged into this same transaction by combining this endpoint's instruction with that create endpoint's. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateVerifyPubkeyValidityRequest true "Context-state verify request"
// @Success      200 {object} ContextStateVerifyPubkeyValidityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/verify/pubkey-validity [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateVerifyPubkeyValidity(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateVerifyPubkeyValidityRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Checked before any account is read or any transaction is built: a
	// proof that does not verify against its own public key is guaranteed
	// to fail the deployed verifier too, so there is no reason to spend a
	// round trip or a fee finding that out on chain.
	if ok, err := core.VerifyPubkeyValidity(req.ToElgamalPubkey(), req.ToPubkeyProof()); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("pubkey_proof: %s", err))
		return
	} else if !ok {
		handler.WriteError(w, http.StatusBadRequest, "pubkey_proof: does not verify against elgamal_pubkey")
		return
	}

	chain, err := rpc.ChainFromContext(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	lookups := []*types.PublicKey{
		req.ContextStateAccountKey(),
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

	contextInfo := accounts[req.ContextStateAccountKey().Base58()]
	if !contextInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s does not exist -- create it first via context-state/create/pubkey-validity", req.ContextStateAccountKey()))
		return
	}
	if contextInfo.Owner != core.ZkElgamalProof.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is not owned by %s", req.ContextStateAccountKey(), core.ZkElgamalProof.ID()))
		return
	}
	if contextInfo.Space != core.PubkeyValidityContextStateSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is %d bytes, expected %d for a PubkeyValidity context", req.ContextStateAccountKey(), contextInfo.Space, core.PubkeyValidityContextStateSpace))
		return
	}

	verifyIx, err := core.ZkElgamalProof.VerifyPubkeyValidityContextState(req.ToElgamalPubkey(), req.ToPubkeyProof(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(verifyIx)

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

	handler.WriteOK(w, NewContextStateVerifyPubkeyValidityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey(),
		nonceAuthority,
		fee,
	))
}

// ContextStateVerifyCiphertextCommitmentEquality godoc
// @Summary      Verify a CiphertextCommitmentEquality proof and persist its context
// @Description  ZkElgamalProof VerifyCiphertextCommitmentEquality, context-state form: verifies proof_data and, because context_state_account and context_state_account_owner are given, writes the proof's context into that account instead of only checking it. context_state_account must already exist, sized and owned for this proof type (see context-state/create/ciphertext-commitment-equality) -- created in an earlier transaction, or (to close the front-running window the interface crate's own docs describe) merged into this same transaction by combining this endpoint's instruction with that create endpoint's. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateVerifyCiphertextCommitmentEqualityRequest true "Context-state verify request"
// @Success      200 {object} ContextStateVerifyCiphertextCommitmentEqualityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/verify/ciphertext-commitment-equality [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateVerifyCiphertextCommitmentEquality(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateVerifyCiphertextCommitmentEqualityRequest)
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
		req.ContextStateAccountKey(),
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

	contextInfo := accounts[req.ContextStateAccountKey().Base58()]
	if !contextInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s does not exist -- create it first via context-state/create/ciphertext-commitment-equality", req.ContextStateAccountKey()))
		return
	}
	if contextInfo.Owner != core.ZkElgamalProof.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is not owned by %s", req.ContextStateAccountKey(), core.ZkElgamalProof.ID()))
		return
	}
	if contextInfo.Space != core.CiphertextCommitmentEqualityContextStateSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is %d bytes, expected %d for a CiphertextCommitmentEquality context", req.ContextStateAccountKey(), contextInfo.Space, core.CiphertextCommitmentEqualityContextStateSpace))
		return
	}

	verifyIx, err := core.ZkElgamalProof.VerifyCiphertextCommitmentEqualityContextState(req.ToProofData(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(verifyIx)

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

	handler.WriteOK(w, NewContextStateVerifyCiphertextCommitmentEqualityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey(),
		nonceAuthority,
		fee,
	))
}

// ContextStateVerifyBatchedGroupedCiphertext3HandlesValidity godoc
// @Summary      Verify a BatchedGroupedCiphertext3HandlesValidity proof and persist its context
// @Description  ZkElgamalProof VerifyBatchedGroupedCiphertext3HandlesValidity, context-state form: verifies proof_data and, because context_state_account and context_state_account_owner are given, writes the proof's context into that account instead of only checking it. context_state_account must already exist, sized and owned for this proof type (see context-state/create/batched-grouped-ciphertext-3-handles-validity) -- created in an earlier transaction, or (to close the front-running window the interface crate's own docs describe) merged into this same transaction by combining this endpoint's instruction with that create endpoint's. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateVerifyBatchedGroupedCiphertext3HandlesValidityRequest true "Context-state verify request"
// @Success      200 {object} ContextStateVerifyBatchedGroupedCiphertext3HandlesValidityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/verify/batched-grouped-ciphertext-3-handles-validity [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateVerifyBatchedGroupedCiphertext3HandlesValidity(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateVerifyBatchedGroupedCiphertext3HandlesValidityRequest)
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
		req.ContextStateAccountKey(),
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

	contextInfo := accounts[req.ContextStateAccountKey().Base58()]
	if !contextInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s does not exist -- create it first via context-state/create/batched-grouped-ciphertext-3-handles-validity", req.ContextStateAccountKey()))
		return
	}
	if contextInfo.Owner != core.ZkElgamalProof.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is not owned by %s", req.ContextStateAccountKey(), core.ZkElgamalProof.ID()))
		return
	}
	if contextInfo.Space != core.BatchedGroupedCiphertext3HandlesValidityContextStateSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is %d bytes, expected %d for a BatchedGroupedCiphertext3HandlesValidity context", req.ContextStateAccountKey(), contextInfo.Space, core.BatchedGroupedCiphertext3HandlesValidityContextStateSpace))
		return
	}

	verifyIx, err := core.ZkElgamalProof.VerifyBatchedGroupedCiphertext3HandlesValidityContextState(req.ToProofData(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(verifyIx)

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

	handler.WriteOK(w, NewContextStateVerifyBatchedGroupedCiphertext3HandlesValidityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey(),
		nonceAuthority,
		fee,
	))
}

// ContextStateVerifyBatchedRangeProofU128 godoc
// @Summary      Verify a BatchedRangeProofU128 proof and persist its context
// @Description  ZkElgamalProof VerifyBatchedRangeProofU128, context-state form: verifies proof_data and, because context_state_account and context_state_account_owner are given, writes the proof's context into that account instead of only checking it. context_state_account must already exist, sized and owned for this proof type (see context-state/create/batched-range-proof-u128) -- created in an earlier transaction, or (to close the front-running window the interface crate's own docs describe) merged into this same transaction by combining this endpoint's instruction with that create endpoint's. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateVerifyBatchedRangeProofU128Request true "Context-state verify request"
// @Success      200 {object} ContextStateVerifyBatchedRangeProofU128Response
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/verify/batched-range-proof-u128 [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateVerifyBatchedRangeProofU128(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateVerifyBatchedRangeProofU128Request)
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
		req.ContextStateAccountKey(),
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

	contextInfo := accounts[req.ContextStateAccountKey().Base58()]
	if !contextInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s does not exist -- create it first via context-state/create/batched-range-proof-u128", req.ContextStateAccountKey()))
		return
	}
	if contextInfo.Owner != core.ZkElgamalProof.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is not owned by %s", req.ContextStateAccountKey(), core.ZkElgamalProof.ID()))
		return
	}
	if contextInfo.Space != core.BatchedRangeProofU128ContextStateSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is %d bytes, expected %d for a BatchedRangeProofU128 context", req.ContextStateAccountKey(), contextInfo.Space, core.BatchedRangeProofU128ContextStateSpace))
		return
	}

	verifyIx, err := core.ZkElgamalProof.VerifyBatchedRangeProofU128ContextState(req.ToProofData(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(verifyIx)

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

	handler.WriteOK(w, NewContextStateVerifyBatchedRangeProofU128Response(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey(),
		nonceAuthority,
		fee,
	))
}

// ContextStateVerifyZeroCiphertext godoc
// @Summary      Verify a ZeroCiphertext proof and persist its context
// @Description  ZkElgamalProof VerifyZeroCiphertext, context-state form: verifies proof_data and, because context_state_account and context_state_account_owner are given, writes the proof's context into that account instead of only checking it. context_state_account must already exist, sized and owned for this proof type (see context-state/create/zero-ciphertext) -- created in an earlier transaction, or (to close the front-running window the interface crate's own docs describe) merged into this same transaction by combining this endpoint's instruction with that create endpoint's. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateVerifyZeroCiphertextRequest true "Context-state verify request"
// @Success      200 {object} ContextStateVerifyZeroCiphertextResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/verify/zero-ciphertext [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateVerifyZeroCiphertext(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateVerifyZeroCiphertextRequest)
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
		req.ContextStateAccountKey(),
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

	contextInfo := accounts[req.ContextStateAccountKey().Base58()]
	if !contextInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s does not exist -- create it first via context-state/create/zero-ciphertext", req.ContextStateAccountKey()))
		return
	}
	if contextInfo.Owner != core.ZkElgamalProof.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is not owned by %s", req.ContextStateAccountKey(), core.ZkElgamalProof.ID()))
		return
	}
	if contextInfo.Space != core.ZeroCiphertextContextStateSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is %d bytes, expected %d for a ZeroCiphertext context", req.ContextStateAccountKey(), contextInfo.Space, core.ZeroCiphertextContextStateSpace))
		return
	}

	verifyIx, err := core.ZkElgamalProof.VerifyZeroCiphertextContextState(req.ToProofData(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(verifyIx)

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

	handler.WriteOK(w, NewContextStateVerifyZeroCiphertextResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey(),
		nonceAuthority,
		fee,
	))
}

// ContextStateVerifyCiphertextCiphertextEquality godoc
// @Summary      Verify a CiphertextCiphertextEquality proof and persist its context
// @Description  ZkElgamalProof VerifyCiphertextCiphertextEquality, context-state form: verifies proof_data and, because context_state_account and context_state_account_owner are given, writes the proof's context into that account instead of only checking it. context_state_account must already exist, sized and owned for this proof type (see context-state/create/ciphertext-ciphertext-equality) -- created in an earlier transaction, or (to close the front-running window the interface crate's own docs describe) merged into this same transaction by combining this endpoint's instruction with that create endpoint's. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateVerifyCiphertextCiphertextEqualityRequest true "Context-state verify request"
// @Success      200 {object} ContextStateVerifyCiphertextCiphertextEqualityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/verify/ciphertext-ciphertext-equality [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateVerifyCiphertextCiphertextEquality(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateVerifyCiphertextCiphertextEqualityRequest)
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
		req.ContextStateAccountKey(),
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

	contextInfo := accounts[req.ContextStateAccountKey().Base58()]
	if !contextInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s does not exist -- create it first via context-state/create/ciphertext-ciphertext-equality", req.ContextStateAccountKey()))
		return
	}
	if contextInfo.Owner != core.ZkElgamalProof.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is not owned by %s", req.ContextStateAccountKey(), core.ZkElgamalProof.ID()))
		return
	}
	if contextInfo.Space != core.CiphertextCiphertextEqualityContextStateSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is %d bytes, expected %d for a CiphertextCiphertextEquality context", req.ContextStateAccountKey(), contextInfo.Space, core.CiphertextCiphertextEqualityContextStateSpace))
		return
	}

	verifyIx, err := core.ZkElgamalProof.VerifyCiphertextCiphertextEqualityContextState(req.ToProofData(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(verifyIx)

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

	handler.WriteOK(w, NewContextStateVerifyCiphertextCiphertextEqualityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey(),
		nonceAuthority,
		fee,
	))
}

// ContextStateVerifyPercentageWithCap godoc
// @Summary      Verify a PercentageWithCap proof and persist its context
// @Description  ZkElgamalProof VerifyPercentageWithCap, context-state form: verifies proof_data and, because context_state_account and context_state_account_owner are given, writes the proof's context into that account instead of only checking it. context_state_account must already exist, sized and owned for this proof type (see context-state/create/percentage-with-cap) -- created in an earlier transaction, or (to close the front-running window the interface crate's own docs describe) merged into this same transaction by combining this endpoint's instruction with that create endpoint's. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateVerifyPercentageWithCapRequest true "Context-state verify request"
// @Success      200 {object} ContextStateVerifyPercentageWithCapResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/verify/percentage-with-cap [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateVerifyPercentageWithCap(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateVerifyPercentageWithCapRequest)
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
		req.ContextStateAccountKey(),
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

	contextInfo := accounts[req.ContextStateAccountKey().Base58()]
	if !contextInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s does not exist -- create it first via context-state/create/percentage-with-cap", req.ContextStateAccountKey()))
		return
	}
	if contextInfo.Owner != core.ZkElgamalProof.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is not owned by %s", req.ContextStateAccountKey(), core.ZkElgamalProof.ID()))
		return
	}
	if contextInfo.Space != core.PercentageWithCapContextStateSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is %d bytes, expected %d for a PercentageWithCap context", req.ContextStateAccountKey(), contextInfo.Space, core.PercentageWithCapContextStateSpace))
		return
	}

	verifyIx, err := core.ZkElgamalProof.VerifyPercentageWithCapContextState(req.ToProofData(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(verifyIx)

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

	handler.WriteOK(w, NewContextStateVerifyPercentageWithCapResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey(),
		nonceAuthority,
		fee,
	))
}

// ContextStateVerifyBatchedRangeProofU64 godoc
// @Summary      Verify a BatchedRangeProofU64 proof and persist its context
// @Description  ZkElgamalProof VerifyBatchedRangeProofU64, context-state form: verifies proof_data and, because context_state_account and context_state_account_owner are given, writes the proof's context into that account instead of only checking it. context_state_account must already exist, sized and owned for this proof type (see context-state/create/batched-range-proof-u64) -- created in an earlier transaction, or (to close the front-running window the interface crate's own docs describe) merged into this same transaction by combining this endpoint's instruction with that create endpoint's. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateVerifyBatchedRangeProofU64Request true "Context-state verify request"
// @Success      200 {object} ContextStateVerifyBatchedRangeProofU64Response
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/verify/batched-range-proof-u64 [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateVerifyBatchedRangeProofU64(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateVerifyBatchedRangeProofU64Request)
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
		req.ContextStateAccountKey(),
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

	contextInfo := accounts[req.ContextStateAccountKey().Base58()]
	if !contextInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s does not exist -- create it first via context-state/create/batched-range-proof-u64", req.ContextStateAccountKey()))
		return
	}
	if contextInfo.Owner != core.ZkElgamalProof.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is not owned by %s", req.ContextStateAccountKey(), core.ZkElgamalProof.ID()))
		return
	}
	if contextInfo.Space != core.BatchedRangeProofU64ContextStateSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is %d bytes, expected %d for a BatchedRangeProofU64 context", req.ContextStateAccountKey(), contextInfo.Space, core.BatchedRangeProofU64ContextStateSpace))
		return
	}

	verifyIx, err := core.ZkElgamalProof.VerifyBatchedRangeProofU64ContextState(req.ToProofData(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(verifyIx)

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

	handler.WriteOK(w, NewContextStateVerifyBatchedRangeProofU64Response(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey(),
		nonceAuthority,
		fee,
	))
}

// ContextStateVerifyBatchedRangeProofU256 godoc
// @Summary      Verify a BatchedRangeProofU256 proof and persist its context
// @Description  ZkElgamalProof VerifyBatchedRangeProofU256, context-state form: verifies proof_data and, because context_state_account and context_state_account_owner are given, writes the proof's context into that account instead of only checking it. context_state_account must already exist, sized and owned for this proof type (see context-state/create/batched-range-proof-u256) -- created in an earlier transaction, or (to close the front-running window the interface crate's own docs describe) merged into this same transaction by combining this endpoint's instruction with that create endpoint's. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateVerifyBatchedRangeProofU256Request true "Context-state verify request"
// @Success      200 {object} ContextStateVerifyBatchedRangeProofU256Response
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/verify/batched-range-proof-u256 [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateVerifyBatchedRangeProofU256(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateVerifyBatchedRangeProofU256Request)
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
		req.ContextStateAccountKey(),
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

	contextInfo := accounts[req.ContextStateAccountKey().Base58()]
	if !contextInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s does not exist -- create it first via context-state/create/batched-range-proof-u256", req.ContextStateAccountKey()))
		return
	}
	if contextInfo.Owner != core.ZkElgamalProof.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is not owned by %s", req.ContextStateAccountKey(), core.ZkElgamalProof.ID()))
		return
	}
	if contextInfo.Space != core.BatchedRangeProofU256ContextStateSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is %d bytes, expected %d for a BatchedRangeProofU256 context", req.ContextStateAccountKey(), contextInfo.Space, core.BatchedRangeProofU256ContextStateSpace))
		return
	}

	verifyIx, err := core.ZkElgamalProof.VerifyBatchedRangeProofU256ContextState(req.ToProofData(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(verifyIx)

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

	handler.WriteOK(w, NewContextStateVerifyBatchedRangeProofU256Response(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey(),
		nonceAuthority,
		fee,
	))
}

// ContextStateVerifyGroupedCiphertext2HandlesValidity godoc
// @Summary      Verify a GroupedCiphertext2HandlesValidity proof and persist its context
// @Description  ZkElgamalProof VerifyGroupedCiphertext2HandlesValidity, context-state form: verifies proof_data and, because context_state_account and context_state_account_owner are given, writes the proof's context into that account instead of only checking it. context_state_account must already exist, sized and owned for this proof type (see context-state/create/grouped-ciphertext-2-handles-validity) -- created in an earlier transaction, or (to close the front-running window the interface crate's own docs describe) merged into this same transaction by combining this endpoint's instruction with that create endpoint's. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateVerifyGroupedCiphertext2HandlesValidityRequest true "Context-state verify request"
// @Success      200 {object} ContextStateVerifyGroupedCiphertext2HandlesValidityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/verify/grouped-ciphertext-2-handles-validity [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateVerifyGroupedCiphertext2HandlesValidity(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateVerifyGroupedCiphertext2HandlesValidityRequest)
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
		req.ContextStateAccountKey(),
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

	contextInfo := accounts[req.ContextStateAccountKey().Base58()]
	if !contextInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s does not exist -- create it first via context-state/create/grouped-ciphertext-2-handles-validity", req.ContextStateAccountKey()))
		return
	}
	if contextInfo.Owner != core.ZkElgamalProof.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is not owned by %s", req.ContextStateAccountKey(), core.ZkElgamalProof.ID()))
		return
	}
	if contextInfo.Space != core.GroupedCiphertext2HandlesValidityContextStateSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is %d bytes, expected %d for a GroupedCiphertext2HandlesValidity context", req.ContextStateAccountKey(), contextInfo.Space, core.GroupedCiphertext2HandlesValidityContextStateSpace))
		return
	}

	verifyIx, err := core.ZkElgamalProof.VerifyGroupedCiphertext2HandlesValidityContextState(req.ToProofData(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(verifyIx)

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

	handler.WriteOK(w, NewContextStateVerifyGroupedCiphertext2HandlesValidityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey(),
		nonceAuthority,
		fee,
	))
}

// ContextStateVerifyBatchedGroupedCiphertext2HandlesValidity godoc
// @Summary      Verify a BatchedGroupedCiphertext2HandlesValidity proof and persist its context
// @Description  ZkElgamalProof VerifyBatchedGroupedCiphertext2HandlesValidity, context-state form: verifies proof_data and, because context_state_account and context_state_account_owner are given, writes the proof's context into that account instead of only checking it. context_state_account must already exist, sized and owned for this proof type (see context-state/create/batched-grouped-ciphertext-2-handles-validity) -- created in an earlier transaction, or (to close the front-running window the interface crate's own docs describe) merged into this same transaction by combining this endpoint's instruction with that create endpoint's. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateVerifyBatchedGroupedCiphertext2HandlesValidityRequest true "Context-state verify request"
// @Success      200 {object} ContextStateVerifyBatchedGroupedCiphertext2HandlesValidityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/verify/batched-grouped-ciphertext-2-handles-validity [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateVerifyBatchedGroupedCiphertext2HandlesValidity(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateVerifyBatchedGroupedCiphertext2HandlesValidityRequest)
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
		req.ContextStateAccountKey(),
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

	contextInfo := accounts[req.ContextStateAccountKey().Base58()]
	if !contextInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s does not exist -- create it first via context-state/create/batched-grouped-ciphertext-2-handles-validity", req.ContextStateAccountKey()))
		return
	}
	if contextInfo.Owner != core.ZkElgamalProof.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is not owned by %s", req.ContextStateAccountKey(), core.ZkElgamalProof.ID()))
		return
	}
	if contextInfo.Space != core.BatchedGroupedCiphertext2HandlesValidityContextStateSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is %d bytes, expected %d for a BatchedGroupedCiphertext2HandlesValidity context", req.ContextStateAccountKey(), contextInfo.Space, core.BatchedGroupedCiphertext2HandlesValidityContextStateSpace))
		return
	}

	verifyIx, err := core.ZkElgamalProof.VerifyBatchedGroupedCiphertext2HandlesValidityContextState(req.ToProofData(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(verifyIx)

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

	handler.WriteOK(w, NewContextStateVerifyBatchedGroupedCiphertext2HandlesValidityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey(),
		nonceAuthority,
		fee,
	))
}

// ContextStateVerifyGroupedCiphertext3HandlesValidity godoc
// @Summary      Verify a GroupedCiphertext3HandlesValidity proof and persist its context
// @Description  ZkElgamalProof VerifyGroupedCiphertext3HandlesValidity, context-state form: verifies proof_data and, because context_state_account and context_state_account_owner are given, writes the proof's context into that account instead of only checking it. context_state_account must already exist, sized and owned for this proof type (see context-state/create/grouped-ciphertext-3-handles-validity) -- created in an earlier transaction, or (to close the front-running window the interface crate's own docs describe) merged into this same transaction by combining this endpoint's instruction with that create endpoint's. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-zk-elgamal-proof-context-state
// @Accept       json
// @Produce      json
// @Param        request body ContextStateVerifyGroupedCiphertext3HandlesValidityRequest true "Context-state verify request"
// @Success      200 {object} ContextStateVerifyGroupedCiphertext3HandlesValidityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/zk-elgamal-proof/context-state/verify/grouped-ciphertext-3-handles-validity [post]
func (h *ZkElgamalProofTransactionHandler) ContextStateVerifyGroupedCiphertext3HandlesValidity(w http.ResponseWriter, r *http.Request) {
	req := new(ContextStateVerifyGroupedCiphertext3HandlesValidityRequest)
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
		req.ContextStateAccountKey(),
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

	contextInfo := accounts[req.ContextStateAccountKey().Base58()]
	if !contextInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s does not exist -- create it first via context-state/create/grouped-ciphertext-3-handles-validity", req.ContextStateAccountKey()))
		return
	}
	if contextInfo.Owner != core.ZkElgamalProof.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is not owned by %s", req.ContextStateAccountKey(), core.ZkElgamalProof.ID()))
		return
	}
	if contextInfo.Space != core.GroupedCiphertext3HandlesValidityContextStateSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("context_state_account: %s is %d bytes, expected %d for a GroupedCiphertext3HandlesValidity context", req.ContextStateAccountKey(), contextInfo.Space, core.GroupedCiphertext3HandlesValidityContextStateSpace))
		return
	}

	verifyIx, err := core.ZkElgamalProof.VerifyGroupedCiphertext3HandlesValidityContextState(req.ToProofData(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(verifyIx)

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

	handler.WriteOK(w, NewContextStateVerifyGroupedCiphertext3HandlesValidityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.ContextStateAccountKey(), req.ContextStateAccountOwnerKey(),
		nonceAuthority,
		fee,
	))
}
