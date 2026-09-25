package v2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/types"
	"github.com/andantan/svmlab/internal/config"
	"github.com/andantan/svmlab/internal/rpc"
)

// RecordTransactionHandler builds instructions against the SPL Record
// program (recr1L3PCGKLbckBqMNcJhuuyU1zgo8nBhfLVsJNwr5): a general-purpose
// account that holds arbitrary bytes behind an authority, writable in
// pieces across several transactions. It is here because a zero-knowledge
// proof too large for one transaction can be written into a record account
// and then verified from there (see
// zk-elgamal-proof/context-state/verify-from-account). It is a program of
// its own, not part of the ZkElgamalProof or Token-2022, so it gets its own
// top-level route group.
type RecordTransactionHandler struct {
	cfg *config.Config
}

func NewRecordTransactionHandler(cfg *config.Config) *RecordTransactionHandler {
	return &RecordTransactionHandler{cfg: cfg}
}

// RecordCreateAccount godoc
// @Summary      Fund a new account, sized and owned for the SPL Record program
// @Description  System CreateAccount only, owned by the Record program and sized for a header plus data_length bytes of data (33 + data_length), but not yet initialized. Initialize it in the same transaction as this (see record/initialize): an uninitialized record account can be initialized by anyone, with any authority they like. This is what holds a proof too large to carry in one transaction, such as a 256-bit range proof (1064 bytes, so data_length 1064). recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-record
// @Accept       json
// @Produce      json
// @Param        request body RecordCreateAccountRequest true "Record create-account request"
// @Success      200 {object} RecordCreateAccountResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/record/create-account [post]
func (h *RecordTransactionHandler) RecordCreateAccount(w http.ResponseWriter, r *http.Request) {
	req := new(RecordCreateAccountRequest)
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

	space := core.Record.AccountSpace(req.ToDataLength())

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
		req.RecordAccountKey(),
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

	if accounts[req.RecordAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s already exists", req.RecordAccountKey()))
		return
	}
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	createIx, err := core.System.CreateAccount(req.RentPayerKey(), req.RecordAccountKey(), core.Record.ID(), rentExempt, space)
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
	handler.WriteOK(w, NewRecordCreateAccountResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), nonceAuthority,
		req.RecordAccountKey(), req.ToDataLength(), space, rentExempt,
		fee,
	))
}

// RecordInitialize godoc
// @Summary      Initialize a record account
// @Description  SPL Record Initialize: marks record_account as a record and names its authority. record_account must already exist, owned by the Record program (see record/create-account), and not yet be initialized. The authority does not sign here, which is why this should land in the same transaction as record/create-account -- an uninitialized record account can be initialized by anyone, with any authority they like. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-record
// @Accept       json
// @Produce      json
// @Param        request body RecordInitializeRequest true "Record request"
// @Success      200 {object} RecordInitializeResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/record/initialize [post]
func (h *RecordTransactionHandler) RecordInitialize(w http.ResponseWriter, r *http.Request) {
	req := new(RecordInitializeRequest)
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
		req.RecordAccountKey(),
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

	recInfo := accounts[req.RecordAccountKey().Base58()]
	if !recInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s does not exist", req.RecordAccountKey()))
		return
	}
	if recInfo.Owner != core.Record.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s is not owned by %s", req.RecordAccountKey(), core.Record.ID()))
		return
	}
	recData, err := recInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read record_account data: %s", err))
		return
	}
	if len(recData) < core.RecordAccountHeaderLen {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s is %d bytes, smaller than the %d-byte record header", req.RecordAccountKey(), len(recData), core.RecordAccountHeaderLen))
		return
	}
	if recData[0] == 1 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s is already initialized", req.RecordAccountKey()))
		return
	}

	ix, err := core.Record.Initialize(req.RecordAccountKey(), req.AuthorityKey())
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

	handler.WriteOK(w, NewRecordInitializeResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), nonceAuthority,
		req.RecordAccountKey(), req.AuthorityKey(),
		fee,
	))
}

// RecordWrite godoc
// @Summary      Write bytes into a record account
// @Description  SPL Record Write: copies data into record_account at offset (counted from the end of the 33-byte header). It fails if that would run past the end of the account, so create or reallocate the record large enough first. data is base58-encoded and has to fit in one transaction: about 1000 bytes without a durable nonce, about 900 with one, so a larger proof is written in several calls, each at its own offset. authority signs. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-record
// @Accept       json
// @Produce      json
// @Param        request body RecordWriteRequest true "Record request"
// @Success      200 {object} RecordWriteResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/record/write [post]
func (h *RecordTransactionHandler) RecordWrite(w http.ResponseWriter, r *http.Request) {
	req := new(RecordWriteRequest)
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
		req.RecordAccountKey(),
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

	recInfo := accounts[req.RecordAccountKey().Base58()]
	if !recInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s does not exist", req.RecordAccountKey()))
		return
	}
	if recInfo.Owner != core.Record.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s is not owned by %s", req.RecordAccountKey(), core.Record.ID()))
		return
	}
	recData, err := recInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read record_account data: %s", err))
		return
	}
	if len(recData) < core.RecordAccountHeaderLen {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s is %d bytes, smaller than the %d-byte record header", req.RecordAccountKey(), len(recData), core.RecordAccountHeaderLen))
		return
	}
	if recData[0] != 1 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s is not initialized -- run record/initialize first", req.RecordAccountKey()))
		return
	}
	if !bytes.Equal(recData[1:core.RecordAccountHeaderLen], req.AuthorityKey().Bytes()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s is not the authority recorded in %s", req.AuthorityKey(), req.RecordAccountKey()))
		return
	}
	if uint64(len(recData)-core.RecordAccountHeaderLen) < req.ToOffset()+uint64(len(req.ToData())) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("offset %d + %d bytes runs past the end of record_account %s, which holds %d bytes after its header", req.ToOffset(), len(req.ToData()), req.RecordAccountKey(), len(recData)-core.RecordAccountHeaderLen))
		return
	}

	ix, err := core.Record.Write(req.RecordAccountKey(), req.AuthorityKey(), req.ToOffset(), req.ToData())
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

	handler.WriteOK(w, NewRecordWriteResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), nonceAuthority,
		req.RecordAccountKey(), req.AuthorityKey(), req.ToOffset(), len(req.ToData()),
		fee,
	))
}

// RecordSetAuthority godoc
// @Summary      Hand a record account to a new authority
// @Description  SPL Record SetAuthority: makes new_authority the record's authority. authority, the current one, signs. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-record
// @Accept       json
// @Produce      json
// @Param        request body RecordSetAuthorityRequest true "Record request"
// @Success      200 {object} RecordSetAuthorityResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/record/set-authority [post]
func (h *RecordTransactionHandler) RecordSetAuthority(w http.ResponseWriter, r *http.Request) {
	req := new(RecordSetAuthorityRequest)
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
		req.RecordAccountKey(),
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

	recInfo := accounts[req.RecordAccountKey().Base58()]
	if !recInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s does not exist", req.RecordAccountKey()))
		return
	}
	if recInfo.Owner != core.Record.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s is not owned by %s", req.RecordAccountKey(), core.Record.ID()))
		return
	}
	recData, err := recInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read record_account data: %s", err))
		return
	}
	if len(recData) < core.RecordAccountHeaderLen {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s is %d bytes, smaller than the %d-byte record header", req.RecordAccountKey(), len(recData), core.RecordAccountHeaderLen))
		return
	}
	if recData[0] != 1 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s is not initialized -- run record/initialize first", req.RecordAccountKey()))
		return
	}
	if !bytes.Equal(recData[1:core.RecordAccountHeaderLen], req.AuthorityKey().Bytes()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s is not the authority recorded in %s", req.AuthorityKey(), req.RecordAccountKey()))
		return
	}

	ix, err := core.Record.SetAuthority(req.RecordAccountKey(), req.AuthorityKey(), req.NewAuthorityKey())
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

	handler.WriteOK(w, NewRecordSetAuthorityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), nonceAuthority,
		req.RecordAccountKey(), req.AuthorityKey(), req.NewAuthorityKey(),
		fee,
	))
}

// RecordClose godoc
// @Summary      Close a record account and reclaim its rent
// @Description  SPL Record CloseAccount: drains record_account's lamports into receiver, which removes the account once the transaction ends. authority signs. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-record
// @Accept       json
// @Produce      json
// @Param        request body RecordCloseRequest true "Record request"
// @Success      200 {object} RecordCloseResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/record/close [post]
func (h *RecordTransactionHandler) RecordClose(w http.ResponseWriter, r *http.Request) {
	req := new(RecordCloseRequest)
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
		req.RecordAccountKey(),
		req.ReceiverKey(),
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

	recInfo := accounts[req.RecordAccountKey().Base58()]
	if !recInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s does not exist", req.RecordAccountKey()))
		return
	}
	if recInfo.Owner != core.Record.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s is not owned by %s", req.RecordAccountKey(), core.Record.ID()))
		return
	}
	recData, err := recInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read record_account data: %s", err))
		return
	}
	if len(recData) < core.RecordAccountHeaderLen {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s is %d bytes, smaller than the %d-byte record header", req.RecordAccountKey(), len(recData), core.RecordAccountHeaderLen))
		return
	}
	if recData[0] != 1 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s is not initialized -- run record/initialize first", req.RecordAccountKey()))
		return
	}
	if !bytes.Equal(recData[1:core.RecordAccountHeaderLen], req.AuthorityKey().Bytes()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s is not the authority recorded in %s", req.AuthorityKey(), req.RecordAccountKey()))
		return
	}

	ix, err := core.Record.CloseAccount(req.RecordAccountKey(), req.AuthorityKey(), req.ReceiverKey())
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

	handler.WriteOK(w, NewRecordCloseResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), nonceAuthority,
		req.RecordAccountKey(), req.AuthorityKey(), req.ReceiverKey(), recInfo.Lamports,
		fee,
	))
}

// RecordReallocate godoc
// @Summary      Grow a record account
// @Description  SPL Record Reallocate: grows record_account to hold data_length bytes (excluding the 33-byte header); it does nothing if the account is already that large. The account must already hold enough lamports for the larger size, since this instruction does not fund it -- top it up with a system transfer first. authority signs. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-record
// @Accept       json
// @Produce      json
// @Param        request body RecordReallocateRequest true "Record request"
// @Success      200 {object} RecordReallocateResponse
// @Failure      400 {object} map[string]string
// @Failure      502 {object} map[string]string
// @Router       /svm/v2/transaction/record/reallocate [post]
func (h *RecordTransactionHandler) RecordReallocate(w http.ResponseWriter, r *http.Request) {
	req := new(RecordReallocateRequest)
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
		req.RecordAccountKey(),
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

	recInfo := accounts[req.RecordAccountKey().Base58()]
	if !recInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s does not exist", req.RecordAccountKey()))
		return
	}
	if recInfo.Owner != core.Record.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s is not owned by %s", req.RecordAccountKey(), core.Record.ID()))
		return
	}
	recData, err := recInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read record_account data: %s", err))
		return
	}
	if len(recData) < core.RecordAccountHeaderLen {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s is %d bytes, smaller than the %d-byte record header", req.RecordAccountKey(), len(recData), core.RecordAccountHeaderLen))
		return
	}
	if recData[0] != 1 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("record_account: %s is not initialized -- run record/initialize first", req.RecordAccountKey()))
		return
	}
	if !bytes.Equal(recData[1:core.RecordAccountHeaderLen], req.AuthorityKey().Bytes()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s is not the authority recorded in %s", req.AuthorityKey(), req.RecordAccountKey()))
		return
	}

	ix, err := core.Record.Reallocate(req.RecordAccountKey(), req.AuthorityKey(), req.ToDataLength())
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

	handler.WriteOK(w, NewRecordReallocateResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), nonceAuthority,
		req.RecordAccountKey(), req.AuthorityKey(), req.ToDataLength(),
		fee,
	))
}
