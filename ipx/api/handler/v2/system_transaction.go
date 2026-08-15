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

type SystemTransactionHandler struct {
	cfg *config.Config
}

func NewSystemTransactionHandler(cfg *config.Config) *SystemTransactionHandler {
	return &SystemTransactionHandler{cfg: cfg}
}

// SystemTransfer godoc
// @Summary      Build a native SOL transfer
// @Description  Assembles a System Program transfer between two existing accounts and returns the same shape as a v1 build, so sign and send accept it unchanged. recipient_account must already exist: this is a plain balance transfer, not a way to bring a new account into existence. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it as the first instruction; recent_blockhash then only prices the transaction, since a nonce is never among the cluster's recent blockhashes. The response reports nonce_authority in that case, which has to sign as well. To send the sender's entire balance, use transfer/max instead.
// @Tags         v2-transaction-system-transfer
// @Accept       json
// @Produce      json
// @Param        body  body      SystemTransferRequest  true  "Funding payer, recipient, and lamports"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemTransferResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/transfer [post]
func (h *SystemTransactionHandler) SystemTransfer(w http.ResponseWriter, r *http.Request) {
	req := new(SystemTransferRequest)
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

	// Every account this handler ever needs is read in one round trip.
	// funding_payer and fee_payer are frequently the same key under
	// different roles, and batching rather than fetching each alone is what
	// makes that overlap cheap instead of redundant reads.
	lookups := []*types.PublicKey{
		req.FundingPayerKey(),
		req.FeePayerKey(),
		req.RecipientAccountKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	// This is a plain balance transfer, not a way to create an account: the
	// recipient has to already be there.
	if !accounts[req.RecipientAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("recipient_account: %s does not exist", req.RecipientAccountKey()))
		return
	}

	// Transfer's `from` is rejected by the runtime outright if it carries any
	// data, regardless of who owns it — a restriction with nothing to do with
	// existence or ownership, so it is checked on its own.
	if accounts[req.FundingPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("funding_payer: %s carries data and cannot be the source of a transfer", req.FundingPayerKey()))
		return
	}

	ix, err := core.System.Transfer(req.FundingPayerKey(), req.RecipientAccountKey(), req.ToLamports())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	ixs := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), ixs); err != nil {
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
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, ixs); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, ixs); err != nil {
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

	// A resulting balance below this must be zero, or the runtime rejects the
	// transfer: an account cannot be left underfunded, only fully closed.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	// funding_payer and fee_payer may be the same account wearing two hats,
	// so what each distinct key owes is summed by address rather than
	// checked once per role.
	spent := map[string]uint64{
		req.FundingPayerKey().Base58(): 0,
		req.FeePayerKey().Base58():     0,
	}
	spent[req.FundingPayerKey().Base58()] += req.ToLamports()
	spent[req.FeePayerKey().Base58()] += fee

	for payer, amount := range spent {
		var balance uint64
		if info := accounts[payer]; info.Exists() {
			balance = info.Lamports
		}
		if balance < amount {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: balance %d does not cover %d", payer, balance, amount))
			return
		}
		if !types.RentExemptAfter(balance, amount, minRent) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: would leave %d lamports, below the %d lamport rent-exemption minimum", payer, balance-amount, minRent))
			return
		}
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	raw, err := tx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode message: %s", err))
		return
	}

	handler.WriteOK(w, NewSystemTransferResponse(tx, raw, messageBytes, req.FundingPayerKey(), req.FeePayerKey(), nonceAuthority, req.ToLamports(), fee))
}

// SystemTransferMax godoc
// @Summary      Build a native SOL transfer of the sender's entire balance
// @Description  Assembles a System Program transfer moving everything the sender can send, between two existing accounts. Resolving that amount needs the sender's balance and the fee, both fetched from the chain. The fee only comes out of the sender's balance when the sender is also the fee payer; with a separate fee payer the whole balance can go, which empties the account and lets the runtime reclaim it. recipient_account must already exist: this is a plain balance transfer, not a way to bring a new account into existence. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it as the first instruction; recent_blockhash then only prices the transaction, since a nonce is never among the cluster's recent blockhashes. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-system-transfer
// @Accept       json
// @Produce      json
// @Param        body  body      SystemTransferMaxRequest  true  "Funding payer and recipient"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemTransferMaxResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/transfer/max [post]
func (h *SystemTransactionHandler) SystemTransferMax(w http.ResponseWriter, r *http.Request) {
	req := new(SystemTransferMaxRequest)
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

	// Every account this handler ever needs is read in one round trip.
	// funding_payer and fee_payer are frequently the same key under
	// different roles, and batching rather than fetching each alone is what
	// makes that overlap cheap instead of redundant reads.
	lookups := []*types.PublicKey{
		req.FundingPayerKey(),
		req.FeePayerKey(),
		req.RecipientAccountKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	// This is a plain balance transfer, not a way to create an account: the
	// recipient has to already be there.
	if !accounts[req.RecipientAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("recipient_account: %s does not exist", req.RecipientAccountKey()))
		return
	}

	// Transfer's `from` is rejected by the runtime outright if it carries any
	// data, regardless of who owns it — a restriction with nothing to do with
	// existence or ownership, so it is checked on its own.
	if accounts[req.FundingPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("funding_payer: %s carries data and cannot be the source of a transfer", req.FundingPayerKey()))
		return
	}

	// Resolving the nonce comes before pricing rather than after, unlike every
	// endpoint that knows its amount up front. Advancing the nonce is an extra
	// instruction whose authority signs, so leaving it out of the probe would
	// price a transaction with one signature too few.
	var (
		advance        *types.Instruction
		nonceAccount   *core.NonceAccount
		nonceAuthority *types.PublicKey
	)
	if !req.DurableNonceAccountKey().IsNil() {
		if nonceAccount, err = accounts[req.DurableNonceAccountKey().Base58()].NonceAccount(); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		if advance, err = core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonceAccount.Authority); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		nonceAuthority = nonceAccount.Authority
	}

	// The fee is priced from a message, and a message needs an amount, so a
	// zero-amount probe stands in. Nothing is lost by it: a fee depends on the
	// signature count and compute budget instructions, never on the lamports
	// being moved, so the probe prices the real transfer exactly.
	probeIx, err := core.System.Transfer(req.FundingPayerKey(), req.RecipientAccountKey(), 0)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	probeInstructions := types.NewInstructions(probeIx)

	var priced *types.Message
	if req.DurableNonceAccountKey().IsNil() {
		if priced, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), probeInstructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, probeInstructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
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

	// A resulting balance below this must be zero, or the runtime rejects the
	// transfer: an account cannot be left underfunded, only fully closed.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	var balance uint64
	if info := accounts[req.FundingPayerKey().Base58()]; info.Exists() {
		balance = info.Lamports
	}
	if balance == 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("funding_payer: %s has no balance", req.FundingPayerKey()))
		return
	}

	lamports := balance
	if req.FundingPayerKey().Equal(req.FeePayerKey()) {
		if balance <= fee {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("funding_payer: balance %d does not cover the %d lamport fee", balance, fee))
			return
		}
		lamports = balance - fee
	} else {
		var feePayerBalance uint64
		if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
			feePayerBalance = info.Lamports
		}
		if feePayerBalance < fee {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
			return
		}
		if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
			return
		}
	}

	ix, err := core.System.Transfer(req.FundingPayerKey(), req.RecipientAccountKey(), lamports)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// The real message is the one that carries the nonce, which is the whole
	// point of naming one: it holds a value the cluster does not consider
	// recent, so it never expires. nonceAccount and advance were already
	// resolved above, so this does not fetch the nonce account again.
	var message *types.Message
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonceAccount.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	raw, err := tx.Serialize()
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
	handler.WriteOK(w, NewSystemTransferMaxResponse(tx, raw, messageBytes, req.FundingPayerKey(), req.FeePayerKey(), nonceAuthority, lamports, fee))
}

// SystemTransferSpread godoc
// @Summary      Build one transaction paying several recipients
// @Description  Assembles one Transfer instruction per recipient, all leaving the same account and all landing on accounts that already exist, in a single transaction. This is the first endpoint to carry an arbitrary number of instructions, so it is the first bounded by transaction size rather than by anything it checks: a transaction travels in one 1232-byte packet and cannot be split, which caps the list somewhere around twenty and is reported as size and size_limit. The account keys show fewer entries than instructions, since the sender and the System Program appear in every one and a compiled message lists each key once. There is no max variant, because sending everything one account holds does not say how to divide it. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it as the first instruction; recent_blockhash then only prices the transaction, since a nonce is never among the cluster's recent blockhashes. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-system-transfer
// @Accept       json
// @Produce      json
// @Param        body  body      SystemTransferSpreadRequest  true  "Funding payer, recipients with amounts, and fee payer"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemTransferSpreadResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/transfer/spread [post]
func (h *SystemTransactionHandler) SystemTransferSpread(w http.ResponseWriter, r *http.Request) {
	req := new(SystemTransferSpreadRequest)
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

	// Every account this handler ever needs is read in one round trip.
	// funding_payer and fee_payer are frequently the same key under
	// different roles, and batching rather than fetching each alone is what
	// makes that overlap cheap instead of redundant reads.
	targets := req.Targets()
	lookups := make([]*types.PublicKey, 0, len(targets)+3)
	lookups = append(lookups, req.FundingPayerKey(), req.FeePayerKey())
	for i := range targets {
		lookups = append(lookups, targets[i].RecipientAccountKey())
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	// This is a plain balance transfer, not a way to create an account: every
	// recipient has to already be there.
	for i := range targets {
		if !accounts[targets[i].RecipientAccountKey().Base58()].Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("transfers[%d].recipient_account: %s does not exist", i, targets[i].RecipientAccountKey()))
			return
		}
	}

	// Transfer's `from` is rejected by the runtime outright if it carries any
	// data, regardless of who owns it — a restriction with nothing to do with
	// existence or ownership, so it is checked on its own.
	if accounts[req.FundingPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("funding_payer: %s carries data and cannot be the source of a transfer", req.FundingPayerKey()))
		return
	}

	// One instruction per recipient, in the order they were given. The order
	// is kept rather than sorted because it is what the caller will read back
	// in the response, and the runtime executes them in it.
	ixs := make([]*types.Instruction, 0, len(targets))
	for i := range targets {
		ix, err := core.System.Transfer(req.FundingPayerKey(), targets[i].RecipientAccountKey(), targets[i].ToLamports())
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("transfers[%d]: %s", i, err))
			return
		}
		ixs = append(ixs, ix)
	}
	instructions := types.NewInstructions(ixs...)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
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

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Serializing here rather than at the end, which is where every other
	// endpoint does it, because this is where the size limit is enforced and
	// this is the only endpoint that can reach it. A request naming too many
	// recipients is refused before it costs a fee lookup.
	raw, err := tx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
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

	// A resulting balance below this must be zero, or the runtime rejects the
	// transfer: an account cannot be left underfunded, only fully closed.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	// funding_payer and fee_payer may be the same account wearing two hats,
	// so what each distinct key owes is summed by address rather than
	// checked once per role.
	spent := map[string]uint64{
		req.FundingPayerKey().Base58(): 0,
		req.FeePayerKey().Base58():     0,
	}
	spent[req.FundingPayerKey().Base58()] += req.Total()
	spent[req.FeePayerKey().Base58()] += fee

	for payer, amount := range spent {
		var balance uint64
		if info := accounts[payer]; info.Exists() {
			balance = info.Lamports
		}
		if balance < amount {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: balance %d does not cover %d", payer, balance, amount))
			return
		}
		if !types.RentExemptAfter(balance, amount, minRent) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: would leave %d lamports, below the %d lamport rent-exemption minimum", payer, balance-amount, minRent))
			return
		}
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode message: %s", err))
		return
	}

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewSystemTransferSpreadResponse(tx, raw, messageBytes, req.FundingPayerKey(), req.FeePayerKey(), nonceAuthority, targets, req.Total(), fee))
}

// SystemCreateAccount godoc
// @Summary      Build a System Program account creation
// @Description  Funds a new, zero-byte account owned by the System Program itself. The new account signs alongside rent_payer, which is what has no EVM counterpart: an address does not exist until whoever holds its private key authorizes its creation, and it must not already exist. rent_payer funds the creation for exactly the rent-exemption minimum for zero bytes — always, and only that amount. This endpoint only ever brings a plain account into existence, empty; reserving space is a separate call to allocate, which requires the account to already exist, handing it to another program is a separate call to assign, and funding it further is a separate transfer. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-system-account
// @Accept       json
// @Produce      json
// @Param        body  body      SystemCreateAccountRequest  true  "New account, fee payer, and rent payer"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemCreateAccountResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/create-account [post]
func (h *SystemTransactionHandler) SystemCreateAccount(w http.ResponseWriter, r *http.Request) {
	req := new(SystemCreateAccountRequest)
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

	// This endpoint only ever brings a zero-byte account into existence;
	// reserving space is a separate call to allocate. That floor is the same
	// one an ordinary wallet must clear, since both are zero-byte System
	// accounts, so this single value serves as both NewAccount's funding
	// requirement below and rent_payer/fee_payer's own floor later.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	// Every account this handler ever needs is read in one round trip.
	// rent_payer and fee_payer are frequently the same key under different
	// roles, and batching rather than fetching each alone is what makes that
	// overlap cheap instead of redundant reads.
	lookups := []*types.PublicKey{
		req.RentPayerKey(),
		req.FeePayerKey(),
		req.NewAccountKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	// Creating an account that already exists fails, and unlike a transfer to
	// an unfunded address there is no reading of it as intent.
	newAccountInfo := accounts[req.NewAccountKey().Base58()]
	if newAccountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("new_account: %s already exists", req.NewAccountKey()))
		return
	}

	// CreateAccount moves rent_payer's lamports the same way Transfer does
	// internally, and the runtime rejects that source outright if it carries
	// any data, regardless of who owns it.
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	// CreateAccount is funded entirely by rent_payer, for exactly the
	// rent-exemption minimum: this endpoint only ever brings an account into
	// existence, empty, and owned by the System Program itself, never adds to
	// it beyond that. Handing it to another program is a separate call to
	// assign.
	createIx, err := core.System.CreateAccount(req.RentPayerKey(), req.NewAccountKey(), core.System.ID(), minRent, 0)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	ixs := types.NewInstructions(createIx)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), ixs); err != nil {
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
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, ixs); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, ixs); err != nil {
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

	// rent_payer and fee_payer may be the same account wearing two hats, so
	// what each distinct key owes is summed by address rather than checked
	// once per role.
	spent := map[string]uint64{
		req.RentPayerKey().Base58(): 0,
		req.FeePayerKey().Base58():  0,
	}
	spent[req.RentPayerKey().Base58()] += minRent
	spent[req.FeePayerKey().Base58()] += fee

	for payer, amount := range spent {
		var balance uint64
		if info := accounts[payer]; info.Exists() {
			balance = info.Lamports
		}
		if balance < amount {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: balance %d does not cover %d", payer, balance, amount))
			return
		}
		if !types.RentExemptAfter(balance, amount, minRent) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: would leave %d lamports, below the %d lamport rent-exemption minimum", payer, balance-amount, minRent))
			return
		}
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	raw, err := tx.Serialize()
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
	handler.WriteOK(w, NewSystemCreateAccountResponse(tx, raw, messageBytes, req.RentPayerKey(), req.FeePayerKey(), nonceAuthority, minRent, fee))
}

// SystemAllocate godoc
// @Summary      Build a System Program allocation
// @Description  Reserves data space on an existing System-owned account that is not already sized: Allocate only ever sets a size once, so an account already allocated is rejected regardless of the new size requested, and one that does not exist yet is rejected too — this endpoint sizes an account, it does not create one. Growing an account raises its rent-exemption floor, so the balance is checked against the minimum for the new size rather than the old one; rent_payer is always required and covers exactly that shortfall with a transfer prepended ahead of the allocation, even though nothing is built and rent reports zero when Account already holds enough. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-system-account
// @Accept       json
// @Produce      json
// @Param        body  body      SystemAllocateRequest  true  "Account, space, fee payer, and rent payer"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemAllocateResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/allocate [post]
func (h *SystemTransactionHandler) SystemAllocate(w http.ResponseWriter, r *http.Request) {
	req := new(SystemAllocateRequest)
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

	// Growing an account raises its rent-exemption floor, so this is worked
	// out before anything else: it decides whether rent_payer's transfer is
	// needed at all.
	rentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), req.ToSpace(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	// Every account this handler ever needs is read in one round trip.
	// account and fee_payer are frequently distinct, but rent_payer and
	// fee_payer are frequently the same key, and batching rather than
	// fetching each alone is what makes that overlap cheap instead of
	// redundant reads.
	lookups := []*types.PublicKey{
		req.AccountKey(),
		req.FeePayerKey(),
		req.RentPayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	// One lookup answers everything the runtime will check: whether the
	// account exists, who owns it, whether it is already sized, and what it
	// holds.
	accountInfo := accounts[req.AccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s does not exist", req.AccountKey()))
		return
	}
	if accountInfo.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s is owned by %s, and only the owning program may size an account", req.AccountKey(), accountInfo.Owner))
		return
	}
	if accountInfo.Space != 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s is already allocated %d bytes", req.AccountKey(), accountInfo.Space))
		return
	}

	// Allocate itself moves no lamports, so whatever Account is short of the
	// new floor has to come from rent_payer, named for exactly that shortfall
	// ahead of the allocation. If Account already holds enough, rent_payer has
	// nothing to do here even though it is always named.
	var shortfall uint64
	if accountInfo.Lamports < rentExempt {
		shortfall = rentExempt - accountInfo.Lamports
	}

	// A shortfall has nowhere to come from when rent_payer names Account
	// itself: it would have to fund the gap out of the very balance that is
	// already short of it.
	if shortfall > 0 && req.RentPayerKey().Equal(req.AccountKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s holds %d lamports, below the %d lamport rent-exemption minimum for %d bytes; rent_payer is the same account and cannot cover its own shortfall", req.AccountKey(), accountInfo.Lamports, rentExempt, req.ToSpace()))
		return
	}

	var ixs []*types.Instruction
	if shortfall > 0 {
		// Transfer's `from` is rejected by the runtime outright if it carries
		// any data, regardless of who owns it — checked here rather than
		// unconditionally, since rent_payer is only ever this transfer's
		// source when there is a shortfall to cover.
		if accounts[req.RentPayerKey().Base58()].CarriesData() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot be the source of a transfer", req.RentPayerKey()))
			return
		}

		rentIx, err := core.System.Transfer(req.RentPayerKey(), req.AccountKey(), shortfall)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		ixs = append(ixs, rentIx)
	}
	allocateIx, err := core.System.Allocate(req.AccountKey(), req.ToSpace())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	ixs = append(ixs, allocateIx)
	instructions := types.NewInstructions(ixs...)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
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

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
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

	// This is the floor an ordinary wallet must hold, a different number from
	// rentExempt: it is what rent_payer and fee_payer must each keep above
	// zero in their own accounts, not what Account needs.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	// rent_payer and fee_payer may be the same account wearing two hats, so
	// what each distinct key owes is summed by address rather than checked
	// once per role.
	spent := map[string]uint64{
		req.RentPayerKey().Base58(): 0,
		req.FeePayerKey().Base58():  0,
	}
	spent[req.RentPayerKey().Base58()] += shortfall
	spent[req.FeePayerKey().Base58()] += fee

	for payer, amount := range spent {
		var balance uint64
		if info := accounts[payer]; info.Exists() {
			balance = info.Lamports
		}
		if balance < amount {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: balance %d does not cover %d", payer, balance, amount))
			return
		}
		if !types.RentExemptAfter(balance, amount, minRent) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: would leave %d lamports, below the %d lamport rent-exemption minimum", payer, balance-amount, minRent))
			return
		}
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	raw, err := tx.Serialize()
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
	handler.WriteOK(w, NewSystemAllocateResponse(tx, raw, messageBytes, req.RentPayerKey(), req.FeePayerKey(), nonceAuthority, req.ToSpace(), shortfall, fee))
}

// SystemAssign godoc
// @Summary      Build a System Program ownership assignment
// @Description  Hands a System-owned account to another program, which is the step that puts an account under a program's control. Ownership is a field on the account rather than a mapping the program keeps, which is the inverse of an EVM contract holding balances for its users in its own storage. Account must already exist and already be owned by the System Program: only the current owner may reassign an account. The owner must be executable: only the owning program may debit an account or write its data, so assigning to a plain address locks the account and its lamports permanently. Assign itself has no notion of size: whether account's byte count matches what the new owner expects is that program's own concern, checked only when its initialization instruction runs, not here. Assign moves no lamports of its own, so fee_payer is the only role this endpoint charges. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-system-account
// @Accept       json
// @Produce      json
// @Param        body  body      SystemAssignRequest  true  "Account, new owner, and fee payer"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemAssignResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/assign [post]
func (h *SystemTransactionHandler) SystemAssign(w http.ResponseWriter, r *http.Request) {
	req := new(SystemAssignRequest)
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

	// Every account this handler ever needs is read in one round trip.
	// account and fee_payer are frequently distinct, but batching rather than
	// fetching each alone is what makes any overlap cheap instead of
	// redundant reads.
	lookups := []*types.PublicKey{
		req.AccountKey(),
		req.OwnerKey(),
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

	// Assign requires the account to already be owned by the System Program:
	// only the current owner may reassign it, and the System Program is the
	// only owner that exposes this as a callable instruction.
	accountInfo := accounts[req.AccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s does not exist", req.AccountKey()))
		return
	}
	if accountInfo.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s is owned by %s, and only the owning program may reassign an account", req.AccountKey(), accountInfo.Owner))
		return
	}

	// Assigning to something that cannot be invoked is unrecoverable: the new
	// owner can never debit the account, and the System Program can no longer
	// assign it back because assignment requires the current owner. The
	// System Program itself is executable, so assigning back to it passes.
	ownerInfo := accounts[req.OwnerKey().Base58()]
	if !ownerInfo.Exists() || !ownerInfo.Executable {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("owner: %s is not an executable program, and assigning to it would lock the account permanently", req.OwnerKey()))
		return
	}

	ix, err := core.System.Assign(req.AccountKey(), req.OwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
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

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
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

	// This is the floor an ordinary wallet must hold: what fee_payer must
	// keep above zero in its own account. Assign moves no lamports of its
	// own, so fee_payer is the only role checked here.
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d does not cover %d", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %d lamports, below the %d lamport rent-exemption minimum", feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	raw, err := tx.Serialize()
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
	handler.WriteOK(w, NewSystemAssignResponse(tx, raw, messageBytes, req.OwnerKey(), req.FeePayerKey(), nonceAuthority, fee))
}

// SystemSeedCreateAccount godoc
// @Summary      Build an account creation at a seed-derived address
// @Description  Creates a zero-byte account at SHA256(base || seed || System Program) and funds it for exactly the rent-exemption minimum, the same split as create-account, allocate, and assign for a keypair account: this endpoint only ever brings the derived account into existence, empty; reserving space is a separate call to seed/allocate, and handing it to another program is a separate call to seed/assign. The derived account never signs, which is the difference from create-account: nobody holds a secret for it, so base signs in its place and whoever controls base controls every address derived from it. The address is derived rather than accepted, since the runtime recomputes it and rejects a mismatch. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-system-seed
// @Accept       json
// @Produce      json
// @Param        body  body      SystemSeedCreateAccountRequest  true  "Base, seed, fee payer, and rent payer"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemSeedCreateAccountResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/seed/create-account [post]
func (h *SystemTransactionHandler) SystemSeedCreateAccount(w http.ResponseWriter, r *http.Request) {
	req := new(SystemSeedCreateAccountRequest)
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

	// This endpoint only ever brings a zero-byte account into existence at
	// the derived address; reserving space is a separate call to
	// seed/allocate. That floor is the same one an ordinary wallet must
	// clear, since both are zero-byte System accounts, so this single value
	// serves as both the derived account's funding requirement below and
	// rent_payer/fee_payer's own floor later.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	// Every account this handler ever needs is read in one round trip.
	// rent_payer and fee_payer are frequently the same key under different
	// roles, and batching rather than fetching each alone is what makes that
	// overlap cheap instead of redundant reads.
	lookups := []*types.PublicKey{
		req.RentPayerKey(),
		req.FeePayerKey(),
		req.DerivedKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	// Creating an account that already exists fails, and unlike a transfer to
	// an unfunded address there is no reading of it as intent.
	if accounts[req.DerivedKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("seed: %s already exists, so base and seed together name an account that has been created", req.DerivedKey()))
		return
	}

	// CreateAccountWithSeed moves rent_payer's lamports the same way Transfer
	// does internally, and the runtime rejects that source outright if it
	// carries any data, regardless of who owns it.
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	// CreateAccountWithSeed is funded entirely by rent_payer, for exactly the
	// rent-exemption minimum: this endpoint only ever brings the derived
	// account into existence, empty and owned by the System Program itself,
	// never adds to it beyond that.
	createIx, err := core.System.CreateAccountWithSeed(req.RentPayerKey(), req.BaseKey(), req.Seed, core.System.ID(), minRent, 0)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	ixs := types.NewInstructions(createIx)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), ixs); err != nil {
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
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, ixs); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, ixs); err != nil {
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

	// rent_payer and fee_payer may be the same account wearing two hats, so
	// what each distinct key owes is summed by address rather than checked
	// once per role.
	spent := map[string]uint64{
		req.RentPayerKey().Base58(): 0,
		req.FeePayerKey().Base58():  0,
	}
	spent[req.RentPayerKey().Base58()] += minRent
	spent[req.FeePayerKey().Base58()] += fee

	for payer, amount := range spent {
		var balance uint64
		if info := accounts[payer]; info.Exists() {
			balance = info.Lamports
		}
		if balance < amount {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: balance %d does not cover %d", payer, balance, amount))
			return
		}
		if !types.RentExemptAfter(balance, amount, minRent) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: would leave %d lamports, below the %d lamport rent-exemption minimum", payer, balance-amount, minRent))
			return
		}
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	raw, err := tx.Serialize()
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
	handler.WriteOK(w, NewSystemSeedCreateAccountResponse(tx, raw, messageBytes, req.DerivedKey(), req.RentPayerKey(), req.FeePayerKey(), nonceAuthority, minRent, fee))
}

// SystemSeedTransfer godoc
// @Summary      Build a transfer out of a seed-derived address
// @Description  Debits SHA256(base || seed || System Program) without that account signing, since base signs for it. That is what makes a derived address usable as a holding account: anyone can fund it, and only the holder of base can spend it. The account must still be System-owned for a system transfer to debit it, and recipient_account must already exist: this is a plain transfer between two accounts, not a way to bring a new one into existence. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-system-seed
// @Accept       json
// @Produce      json
// @Param        body  body      SystemSeedTransferRequest  true  "Base, seed, recipient, lamports, and fee payer"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemSeedTransferResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/seed/transfer [post]
func (h *SystemTransactionHandler) SystemSeedTransfer(w http.ResponseWriter, r *http.Request) {
	req := new(SystemSeedTransferRequest)
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

	// Every account this handler ever needs is read in one round trip.
	lookups := []*types.PublicKey{
		req.DerivedKey(),
		req.FeePayerKey(),
		req.RecipientAccountKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	// This is a plain balance transfer, not a way to create an account: the
	// recipient has to already be there.
	if !accounts[req.RecipientAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("recipient_account: %s does not exist", req.RecipientAccountKey()))
		return
	}

	// The derived account has to already exist and still be System-owned:
	// only the owning program may debit an account, and seed/assign may have
	// since handed it to another one.
	derivedInfo := accounts[req.DerivedKey().Base58()]
	if !derivedInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("seed: %s does not exist", req.DerivedKey()))
		return
	}
	if derivedInfo.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("seed: %s is owned by %s, and only the owning program may debit an account", req.DerivedKey(), derivedInfo.Owner))
		return
	}

	// Transfer's `from` is rejected by the runtime outright if it carries any
	// data, regardless of who owns it — a restriction with nothing to do with
	// existence or ownership, so it is checked on its own.
	if derivedInfo.CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("seed: %s carries data and cannot be the source of a transfer", req.DerivedKey()))
		return
	}

	ix, err := core.System.TransferWithSeed(req.BaseKey(), req.Seed, core.System.ID(), req.RecipientAccountKey(), req.ToLamports())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
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

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
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

	// A resulting balance below this must be zero, or the runtime rejects the
	// transfer: an account cannot be left underfunded, only fully closed.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	// The derived account and fee_payer are distinct by construction — the
	// derived address can never sign as fee_payer — so what each owes is
	// never summed onto the same key the way funding_payer and fee_payer
	// sometimes are elsewhere.
	spent := map[string]uint64{
		req.DerivedKey().Base58():  req.ToLamports(),
		req.FeePayerKey().Base58(): 0,
	}
	spent[req.FeePayerKey().Base58()] += fee

	for payer, amount := range spent {
		var balance uint64
		if info := accounts[payer]; info.Exists() {
			balance = info.Lamports
		}
		if balance < amount {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: balance %d does not cover %d", payer, balance, amount))
			return
		}
		if !types.RentExemptAfter(balance, amount, minRent) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: would leave %d lamports, below the %d lamport rent-exemption minimum", payer, balance-amount, minRent))
			return
		}
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	raw, err := tx.Serialize()
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
	handler.WriteOK(w, NewSystemSeedTransferResponse(tx, raw, messageBytes, req.DerivedKey(), req.FeePayerKey(), nonceAuthority, req.ToLamports(), fee))
}

// SystemSeedAllocate godoc
// @Summary      Build an allocation on a seed-derived address
// @Description  Reserves data space on SHA256(base || seed || System Program) with base signing in the account's place. The account must already exist, be System-owned, and not already be allocated space — Allocate only ever sets a size once. Growing an account raises its rent-exemption floor, so the balance is checked against the minimum for the new size rather than the old one; rent_payer is always required and covers exactly that shortfall with a transfer prepended ahead of the allocation, even though nothing is built and rent reports zero when the derived account already holds enough. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-system-seed
// @Accept       json
// @Produce      json
// @Param        body  body      SystemSeedAllocateRequest  true  "Base, seed, space, fee payer, and rent payer"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemSeedAllocateResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/seed/allocate [post]
func (h *SystemTransactionHandler) SystemSeedAllocate(w http.ResponseWriter, r *http.Request) {
	req := new(SystemSeedAllocateRequest)
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

	// Growing an account raises its rent-exemption floor, so this is worked
	// out before anything else: it decides whether rent_payer's transfer is
	// needed at all.
	rentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), req.ToSpace(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	// Every account this handler ever needs is read in one round trip.
	lookups := []*types.PublicKey{
		req.DerivedKey(),
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

	// One lookup answers everything the runtime will check: whether the
	// derived account exists, who owns it, whether it is already sized, and
	// what it holds.
	derivedInfo := accounts[req.DerivedKey().Base58()]
	if !derivedInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("seed: %s does not exist", req.DerivedKey()))
		return
	}
	if derivedInfo.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("seed: %s is owned by %s, and only the owning program may size an account", req.DerivedKey(), derivedInfo.Owner))
		return
	}
	if derivedInfo.Space != 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("seed: %s is already allocated %d bytes", req.DerivedKey(), derivedInfo.Space))
		return
	}

	// Allocate itself moves no lamports, so whatever the derived account is
	// short of the new floor has to come from rent_payer, named for exactly
	// that shortfall ahead of the allocation.
	var shortfall uint64
	if derivedInfo.Lamports < rentExempt {
		shortfall = rentExempt - derivedInfo.Lamports
	}

	// A shortfall has nowhere to come from when rent_payer names the derived
	// account itself: it would have to fund the gap out of the very balance
	// that is already short of it.
	if shortfall > 0 && req.RentPayerKey().Equal(req.DerivedKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("seed: %s holds %d lamports, below the %d lamport rent-exemption minimum for %d bytes; rent_payer is the same account and cannot cover its own shortfall", req.DerivedKey(), derivedInfo.Lamports, rentExempt, req.ToSpace()))
		return
	}

	var ixs []*types.Instruction
	if shortfall > 0 {
		// Transfer's `from` is rejected by the runtime outright if it carries
		// any data, regardless of who owns it — checked here rather than
		// unconditionally, since rent_payer is only ever this transfer's
		// source when there is a shortfall to cover.
		if accounts[req.RentPayerKey().Base58()].CarriesData() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot be the source of a transfer", req.RentPayerKey()))
			return
		}

		rentIx, err := core.System.Transfer(req.RentPayerKey(), req.DerivedKey(), shortfall)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		ixs = append(ixs, rentIx)
	}
	allocateIx, err := core.System.AllocateWithSeed(req.BaseKey(), req.Seed, core.System.ID(), req.ToSpace())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	ixs = append(ixs, allocateIx)
	instructions := types.NewInstructions(ixs...)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
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

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
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

	// This is the floor an ordinary wallet must hold, a different number from
	// rentExempt: it is what rent_payer and fee_payer must each keep above
	// zero in their own accounts, not what the derived account needs.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	// rent_payer and fee_payer may be the same account wearing two hats, so
	// what each distinct key owes is summed by address rather than checked
	// once per role.
	spent := map[string]uint64{
		req.RentPayerKey().Base58(): 0,
		req.FeePayerKey().Base58():  0,
	}
	spent[req.RentPayerKey().Base58()] += shortfall
	spent[req.FeePayerKey().Base58()] += fee

	for payer, amount := range spent {
		var balance uint64
		if info := accounts[payer]; info.Exists() {
			balance = info.Lamports
		}
		if balance < amount {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: balance %d does not cover %d", payer, balance, amount))
			return
		}
		if !types.RentExemptAfter(balance, amount, minRent) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: would leave %d lamports, below the %d lamport rent-exemption minimum", payer, balance-amount, minRent))
			return
		}
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	raw, err := tx.Serialize()
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
	handler.WriteOK(w, NewSystemSeedAllocateResponse(tx, raw, messageBytes, req.DerivedKey(), req.RentPayerKey(), req.FeePayerKey(), nonceAuthority, req.ToSpace(), shortfall, fee))
}

// SystemSeedAssign godoc
// @Summary      Build an ownership assignment on a seed-derived address
// @Description  Hands SHA256(base || seed || owner) to that same owner. There is no separate new-owner field, because one owner does both jobs: it is what the address is derived from and what the account is assigned to, so an account can only be handed to the program its own address already encodes. This is a narrow, rarely-needed tool: it only works on a derived account whose address was chosen for owner from the very start, brought into existence some other way — an account made through seed/create-account never qualifies, since that always derives against the System Program, and naming that here is either a no-op or a mismatch pointing at an unrelated address. The account must already exist and already be owned by the System Program: only the current owner may reassign an account. owner must be executable, since assigning to a plain address locks the account and its lamports permanently. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-system-seed
// @Accept       json
// @Produce      json
// @Param        body  body      SystemSeedAssignRequest  true  "Base, seed, owner, and fee payer"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemSeedAssignResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/seed/assign [post]
func (h *SystemTransactionHandler) SystemSeedAssign(w http.ResponseWriter, r *http.Request) {
	req := new(SystemSeedAssignRequest)
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

	// Every account this handler ever needs is read in one round trip.
	lookups := []*types.PublicKey{
		req.DerivedKey(),
		req.OwnerKey(),
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

	// Assign requires the account to already be owned by the System Program:
	// only the current owner may reassign it, and the System Program is the
	// only owner that exposes this as a callable instruction.
	derivedInfo := accounts[req.DerivedKey().Base58()]
	if !derivedInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("seed: %s does not exist", req.DerivedKey()))
		return
	}
	if derivedInfo.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("seed: %s is owned by %s, and only the owning program may reassign an account", req.DerivedKey(), derivedInfo.Owner))
		return
	}

	// Assigning to something that cannot be invoked is unrecoverable: the new
	// owner can never debit the account, and the System Program can no longer
	// assign it back because assignment requires the current owner.
	ownerInfo := accounts[req.OwnerKey().Base58()]
	if !ownerInfo.Exists() || !ownerInfo.Executable {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("owner: %s is not an executable program, and assigning to it would lock the account permanently", req.OwnerKey()))
		return
	}

	ix, err := core.System.AssignWithSeed(req.BaseKey(), req.Seed, req.OwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
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

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
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

	// This is the floor an ordinary wallet must hold: what fee_payer must
	// keep above zero in its own account. Assign moves no lamports of its
	// own, so fee_payer is the only role checked here.
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d does not cover %d", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %d lamports, below the %d lamport rent-exemption minimum", feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	raw, err := tx.Serialize()
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
	handler.WriteOK(w, NewSystemSeedAssignResponse(tx, raw, messageBytes, req.DerivedKey(), req.OwnerKey(), req.FeePayerKey(), nonceAuthority, fee))
}

// SystemSeedTransferMax godoc
// @Summary      Build a transfer of a seed-derived address's entire balance
// @Description  Sends everything SHA256(base || seed || System Program) holds. The amount is the whole balance with nothing held back, because a derived address can never pay the fee: a fee payer has to sign, and this account cannot. That also means no probe is needed to price the message first, since the amount does not depend on the fee here the way it does for a plain transfer. Emptying the account lets the runtime reclaim it. recipient_account must already exist: this is a plain transfer between two accounts, not a way to bring a new one into existence. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-system-seed
// @Accept       json
// @Produce      json
// @Param        body  body      SystemSeedTransferMaxRequest  true  "Base, seed, recipient, and fee payer"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemSeedTransferMaxResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/seed/transfer/max [post]
func (h *SystemTransactionHandler) SystemSeedTransferMax(w http.ResponseWriter, r *http.Request) {
	req := new(SystemSeedTransferMaxRequest)
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

	// Every account this handler ever needs is read in one round trip.
	lookups := []*types.PublicKey{
		req.DerivedKey(),
		req.FeePayerKey(),
		req.RecipientAccountKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	// This is a plain balance transfer, not a way to create an account: the
	// recipient has to already be there.
	if !accounts[req.RecipientAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("recipient_account: %s does not exist", req.RecipientAccountKey()))
		return
	}

	// The derived account has to already exist and still be System-owned:
	// only the owning program may debit an account, and seed/assign may have
	// since handed it to another one.
	derivedInfo := accounts[req.DerivedKey().Base58()]
	if !derivedInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("seed: %s does not exist", req.DerivedKey()))
		return
	}
	if derivedInfo.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("seed: %s is owned by %s, and only the owning program may debit an account", req.DerivedKey(), derivedInfo.Owner))
		return
	}
	if derivedInfo.Lamports == 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("seed: %s has no balance", req.DerivedKey()))
		return
	}

	// Transfer's `from` is rejected by the runtime outright if it carries any
	// data, regardless of who owns it — a restriction with nothing to do with
	// existence or ownership, so it is checked on its own.
	if derivedInfo.CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("seed: %s carries data and cannot be the source of a transfer", req.DerivedKey()))
		return
	}

	// The whole balance goes, with no fee subtracted, because the fee comes
	// from fee_payer and the derived account can never be that: it cannot
	// sign.
	lamports := derivedInfo.Lamports

	ix, err := core.System.TransferWithSeed(req.BaseKey(), req.Seed, core.System.ID(), req.RecipientAccountKey(), lamports)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	//
	// Unlike the other max endpoints this needs no probe. The amount is the
	// derived account's whole balance with nothing subtracted, since that
	// account cannot sign and the fee comes from elsewhere, so it does not
	// depend on the fee and the real message can be priced directly.
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

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d does not cover %d", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %d lamports, below the %d lamport rent-exemption minimum", feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	raw, err := tx.Serialize()
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
	handler.WriteOK(w, NewSystemSeedTransferMaxResponse(tx, raw, messageBytes, req.DerivedKey(), req.FeePayerKey(), nonceAuthority, lamports, fee))
}

// SystemNonceCreate godoc
// @Summary      Build a durable nonce account creation
// @Description  Creates the account and initializes it as a durable nonce in one transaction, which is the first v2 endpoint to carry more than one instruction. The nonce account appears twice: it signs for the creation, since an address does not exist until its key authorizes it, and is only writable for the initialization, which needs no authority. Message compilation lists it once with the union of both, which is why it shows up among the signers. Size and funding are not fields, since a nonce account is always the same size and has to hold exactly the rent-exempt minimum for it. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well. It has to be an account other than the one this endpoint acts on.
// @Tags         v2-transaction-system-nonce
// @Accept       json
// @Produce      json
// @Param        body  body      SystemNonceCreateRequest  true  "Funder, new nonce account, and authority"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemNonceCreateResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/nonce/create-account [post]
func (h *SystemTransactionHandler) SystemNonceCreate(w http.ResponseWriter, r *http.Request) {
	req := new(SystemNonceCreateRequest)
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

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	// A nonce account has to stay rent exempt to keep holding the nonce, so
	// the funding is the minimum for its size rather than anything chosen.
	lamports, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), core.NonceAccountSpace, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	create, err := core.System.CreateAccount(req.FromKey(), req.NewNonceAccountKey(), core.System.ID(), lamports, core.NonceAccountSpace)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	initialize, err := core.System.InitializeNonceAccount(req.NewNonceAccountKey(), req.AuthorityKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(create, initialize)

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two. The nonce being borrowed here is a different
	// account from the one being created, which is what the request refuses to
	// let coincide.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
			return
		}

		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account data: %s", err))
			return
		}
		nonce, err := core.DeserializeNonceAccount(data)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
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

	exists, err := chain.Cli.Exists(r.Context(), req.NewNonceAccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to check nonce account: %s", err))
		return
	}
	if exists {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("new_nonce_account: %s already exists", req.NewNonceAccountKey()))
		return
	}

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	balance, err := chain.Cli.Balance(r.Context(), req.FromKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read balance: %s", err))
		return
	}

	spent := lamports
	if req.FromKey().Equal(req.FeePayerKey()) {
		spent += fee
	}
	if balance < spent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("from: balance %d lamports does not cover %d lamports", balance, spent))
		return
	}
	if remaining := balance - spent; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("from: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FromKey(), remaining, minRent))
		return
	}

	if !req.FromKey().Equal(req.FeePayerKey()) {
		feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
			return
		}
		if feePayerBalance < fee {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
			return
		}
		if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
			return
		}
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	raw, err := tx.Serialize()
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
	handler.WriteOK(w, NewSystemNonceCreateResponse(tx, raw, messageBytes, req.NewNonceAccountKey(), req.AuthorityKey(), nonceAuthority, lamports, fee))
}

// SystemNonceInitialize godoc
// @Summary      Build a durable nonce initialization on an existing account
// @Description  Initializes an account that already exists and is already the right size. nonce/create-account does this and the creation together, so this is for an address that can no longer be created: CreateAccount refuses one that already holds lamports, which is what happens when someone funds the address first. The account is writable but does not sign, since initializing it needs no authority of its own; it gains the authority named here. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well. It has to be an account other than the one this endpoint acts on.
// @Tags         v2-transaction-system-nonce
// @Accept       json
// @Produce      json
// @Param        body  body      SystemNonceInitializeRequest  true  "New nonce account and authority"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemNonceInitializeResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/nonce/initialize [post]
func (h *SystemTransactionHandler) SystemNonceInitialize(w http.ResponseWriter, r *http.Request) {
	req := new(SystemNonceInitializeRequest)
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

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	ix, err := core.System.InitializeNonceAccount(req.NewNonceAccountKey(), req.AuthorityKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two. Both accounts here are nonce accounts, so
	// the names say which is which: buildNonce is the one being borrowed, and
	// the one being initialized is read further down.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonceInfo, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if nonceInfo == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if nonceInfo.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), nonceInfo.Owner))
			return
		}
		if nonceInfo.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), nonceInfo.Space, core.NonceAccountSpace))
			return
		}

		data, err := nonceInfo.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account data: %s", err))
			return
		}
		buildNonce, err := core.DeserializeNonceAccount(data)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !buildNonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), buildNonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), buildNonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = buildNonce.Authority
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

	// One lookup covers everything the instruction will check: the account
	// exists, the System Program owns it, it is the right size, and it holds
	// enough to stay rent exempt at that size.
	info, err := chain.Cli.AccountInfo(r.Context(), req.NewNonceAccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
		return
	}
	if info == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"new_nonce_account: %s does not exist, so create it with nonce/create-account instead", req.NewNonceAccountKey()))
		return
	}
	if info.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"new_nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
			req.NewNonceAccountKey(), info.Owner))
		return
	}
	if info.Space != core.NonceAccountSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"new_nonce_account: %s is %d bytes, and a nonce account is %d",
			req.NewNonceAccountKey(), info.Space, core.NonceAccountSpace))
		return
	}

	data, err := info.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account data: %s", err))
		return
	}
	nonce, err := core.DeserializeNonceAccount(data)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if nonce.Initialized() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"new_nonce_account: %s is already initialized, with %s as its authority",
			req.NewNonceAccountKey(), nonce.Authority))
		return
	}

	nonceRent, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), core.NonceAccountSpace, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	if info.Lamports < nonceRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"new_nonce_account: %s holds %d lamports, below the %d lamport rent-exemption minimum for %d bytes",
			req.NewNonceAccountKey(), info.Lamports, nonceRent, core.NonceAccountSpace))
		return
	}

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	raw, err := tx.Serialize()
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
	handler.WriteOK(w, NewSystemNonceInitializeResponse(tx, raw, messageBytes, req.NewNonceAccountKey(), req.AuthorityKey(), nonceAuthority, fee))
}

// SystemNonceAdvance godoc
// @Summary      Build a durable nonce advance
// @Description  Replaces the stored nonce with the current blockhash. Advancing is what consumes a nonce: a transaction built against one carries it in place of a recent blockhash and runs this as its first instruction, so the value it was built for is gone by the time it finishes and it cannot land twice. Run on its own, this simply invalidates anything already built against the account. The authority signs, and the stored authority is checked here rather than left to fail on chain. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well. It has to be an account other than the one this endpoint acts on.
// @Tags         v2-transaction-system-nonce
// @Accept       json
// @Produce      json
// @Param        body  body      SystemNonceAdvanceRequest  true  "Target nonce account and authority"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemNonceAdvanceResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/nonce/advance [post]
func (h *SystemTransactionHandler) SystemNonceAdvance(w http.ResponseWriter, r *http.Request) {
	req := new(SystemNonceAdvanceRequest)
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

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	ix, err := core.System.AdvanceNonceAccount(req.TargetNonceAccountKey(), req.AuthorityKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two. Both accounts here are nonce accounts and
	// both get advanced, which is exactly why the request refuses to let them
	// coincide: a transaction may advance a nonce only once.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonceInfo, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if nonceInfo == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if nonceInfo.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), nonceInfo.Owner))
			return
		}
		if nonceInfo.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), nonceInfo.Space, core.NonceAccountSpace))
			return
		}

		data, err := nonceInfo.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account data: %s", err))
			return
		}
		buildNonce, err := core.DeserializeNonceAccount(data)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !buildNonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), buildNonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), buildNonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = buildNonce.Authority
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

	info, err := chain.Cli.AccountInfo(r.Context(), req.TargetNonceAccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
		return
	}
	if info == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("target_nonce_account: %s does not exist", req.TargetNonceAccountKey()))
		return
	}
	if info.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"target_nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
			req.TargetNonceAccountKey(), info.Owner))
		return
	}
	if info.Space != core.NonceAccountSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"target_nonce_account: %s is %d bytes, and a nonce account is %d",
			req.TargetNonceAccountKey(), info.Space, core.NonceAccountSpace))
		return
	}

	data, err := info.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account data: %s", err))
		return
	}
	nonce, err := core.DeserializeNonceAccount(data)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !nonce.Initialized() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("target_nonce_account: %s is not initialized", req.TargetNonceAccountKey()))
		return
	}
	if !nonce.Authority.Equal(req.AuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is not the authority of %s, which is %s",
			req.AuthorityKey(), req.TargetNonceAccountKey(), nonce.Authority))
		return
	}

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	raw, err := tx.Serialize()
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
	handler.WriteOK(w, NewSystemNonceAdvanceResponse(tx, raw, messageBytes, req.TargetNonceAccountKey(), req.AuthorityKey(), nonceAuthority, nonce.Nonce, fee))
}

// SystemNonceWithdraw godoc
// @Summary      Build a partial withdrawal from a durable nonce account
// @Description  Moves part of a nonce account's balance out. What stays has to keep the account rent exempt at its size, since an account below that floor is subject to removal while still holding a nonce something may have been built against. Taking the whole balance closes the account and carries a further rule, so that has its own endpoint. The authority signs, and the stored authority is checked here rather than left to fail on chain. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well. It has to be an account other than the one this endpoint acts on.
// @Tags         v2-transaction-system-nonce
// @Accept       json
// @Produce      json
// @Param        body  body      SystemNonceWithdrawRequest  true  "Target nonce account, authority, recipient, and amount"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemNonceWithdrawResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/nonce/withdraw [post]
func (h *SystemTransactionHandler) SystemNonceWithdraw(w http.ResponseWriter, r *http.Request) {
	req := new(SystemNonceWithdrawRequest)
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

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	ix, err := core.System.WithdrawNonceAccount(req.TargetNonceAccountKey(), req.AuthorityKey(), req.ToKey(), req.ToLamports())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two. Both accounts here are nonce accounts, so
	// the names say which is which: buildNonce is the one being borrowed, and
	// the one being withdrawn from is read further down.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonceInfo, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if nonceInfo == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if nonceInfo.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), nonceInfo.Owner))
			return
		}
		if nonceInfo.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), nonceInfo.Space, core.NonceAccountSpace))
			return
		}

		data, err := nonceInfo.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account data: %s", err))
			return
		}
		buildNonce, err := core.DeserializeNonceAccount(data)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !buildNonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), buildNonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), buildNonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = buildNonce.Authority
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

	info, err := chain.Cli.AccountInfo(r.Context(), req.TargetNonceAccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
		return
	}
	if info == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("target_nonce_account: %s does not exist", req.TargetNonceAccountKey()))
		return
	}
	if info.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"target_nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
			req.TargetNonceAccountKey(), info.Owner))
		return
	}
	if info.Space != core.NonceAccountSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"target_nonce_account: %s is %d bytes, and a nonce account is %d",
			req.TargetNonceAccountKey(), info.Space, core.NonceAccountSpace))
		return
	}

	data, err := info.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account data: %s", err))
		return
	}
	nonce, err := core.DeserializeNonceAccount(data)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !nonce.Initialized() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("target_nonce_account: %s is not initialized", req.TargetNonceAccountKey()))
		return
	}
	if !nonce.Authority.Equal(req.AuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is not the authority of %s, which is %s",
			req.AuthorityKey(), req.TargetNonceAccountKey(), nonce.Authority))
		return
	}

	nonceRent, err := chain.Cli.MinimumBalanceForRentExemptionNonce(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	if info.Lamports < req.ToLamports() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"amount: %s holds %d lamports, short of %d", req.TargetNonceAccountKey(), info.Lamports, req.ToLamports()))
		return
	}

	remaining := info.Lamports - req.ToLamports()
	if remaining == 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"amount: taking all %d lamports closes the account, which nonce/withdraw/max does", info.Lamports))
		return
	}
	if remaining < nonceRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"amount: would leave %s with %d lamports, below the %d lamport rent-exemption minimum for %d bytes",
			req.TargetNonceAccountKey(), remaining, nonceRent, core.NonceAccountSpace))
		return
	}

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remainingFee := feePayerBalance - fee; remainingFee != 0 && remainingFee < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remainingFee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	raw, err := tx.Serialize()
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
	handler.WriteOK(w, NewSystemNonceWithdrawResponse(tx, raw, messageBytes, req.TargetNonceAccountKey(), req.AuthorityKey(), nonceAuthority, req.ToLamports(), remaining, fee))
}

// SystemNonceWithdrawMax godoc
// @Summary      Build a full withdrawal that closes a durable nonce account
// @Description  Takes the whole balance, which closes the account. The rent-exempt floor that constrains a partial withdrawal does not apply, since nothing is left to keep exempt. One rule replaces it and is not checked here: the runtime refuses to close an account whose stored nonce is still the blockhash the transaction executes against, so closing in the same block the nonce was last advanced or initialized fails with NonceBlockhashNotExpired. That cannot be decided before submitting, because the blockhash it is compared against is the one at execution rather than any this build could see. Waiting a block and rebuilding is the fix. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well. It has to be an account other than the one this endpoint acts on.
// @Tags         v2-transaction-system-nonce
// @Accept       json
// @Produce      json
// @Param        body  body      SystemNonceWithdrawMaxRequest  true  "Target nonce account, authority, and recipient"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemNonceWithdrawMaxResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/nonce/withdraw/max [post]
func (h *SystemTransactionHandler) SystemNonceWithdrawMax(w http.ResponseWriter, r *http.Request) {
	req := new(SystemNonceWithdrawMaxRequest)
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

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	info, err := chain.Cli.AccountInfo(r.Context(), req.TargetNonceAccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
		return
	}
	if info == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("target_nonce_account: %s does not exist", req.TargetNonceAccountKey()))
		return
	}
	if info.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"target_nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
			req.TargetNonceAccountKey(), info.Owner))
		return
	}
	if info.Space != core.NonceAccountSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"target_nonce_account: %s is %d bytes, and a nonce account is %d",
			req.TargetNonceAccountKey(), info.Space, core.NonceAccountSpace))
		return
	}

	data, err := info.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account data: %s", err))
		return
	}
	nonce, err := core.DeserializeNonceAccount(data)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !nonce.Initialized() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("target_nonce_account: %s is not initialized", req.TargetNonceAccountKey()))
		return
	}
	if !nonce.Authority.Equal(req.AuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is not the authority of %s, which is %s",
			req.AuthorityKey(), req.TargetNonceAccountKey(), nonce.Authority))
		return
	}
	if info.Lamports == 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("target_nonce_account: %s has no balance", req.TargetNonceAccountKey()))
		return
	}

	// The whole balance goes, so nothing is held back for rent: the account is
	// being closed rather than left underfunded.
	amount := info.Lamports

	ix, err := core.System.WithdrawNonceAccount(req.TargetNonceAccountKey(), req.AuthorityKey(), req.ToKey(), amount)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two. Both accounts here are nonce accounts, so
	// the names say which is which: buildNonce is the one being borrowed, and
	// the one being closed was read above.
	//
	// Unlike the other max endpoints this needs no probe. The amount is the
	// target's whole balance with nothing subtracted, since the fee payer
	// cannot be the target, so it does not depend on the fee and the real
	// message can be priced directly.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonceInfo, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if nonceInfo == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if nonceInfo.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), nonceInfo.Owner))
			return
		}
		if nonceInfo.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), nonceInfo.Space, core.NonceAccountSpace))
			return
		}

		nonceData, err := nonceInfo.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account data: %s", err))
			return
		}
		buildNonce, err := core.DeserializeNonceAccount(nonceData)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !buildNonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), buildNonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), buildNonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = buildNonce.Authority
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

	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	raw, err := tx.Serialize()
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
	handler.WriteOK(w, NewSystemNonceWithdrawMaxResponse(tx, raw, messageBytes, req.TargetNonceAccountKey(), req.AuthorityKey(), nonceAuthority, amount, fee))
}

// SystemNonceAuthorize godoc
// @Summary      Build a durable nonce authority change
// @Description  Hands control of a nonce account to another key. The stored nonce and the balance are untouched, so only who may advance and withdraw changes. That also invalidates anything the old authority signed but never submitted, since such a transaction advances the nonce as its first instruction and that now needs a signature the old authority cannot give. If the reason for changing is a leaked key, the old authority's pending transaction and this one race, so pair it with an advance. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well. It has to be an account other than the one this endpoint acts on.
// @Tags         v2-transaction-system-nonce
// @Accept       json
// @Produce      json
// @Param        body  body      SystemNonceAuthorizeRequest  true  "Target nonce account, current authority, and new authority"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemNonceAuthorizeResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/nonce/authorize [post]
func (h *SystemTransactionHandler) SystemNonceAuthorize(w http.ResponseWriter, r *http.Request) {
	req := new(SystemNonceAuthorizeRequest)
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

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	ix, err := core.System.AuthorizeNonceAccount(req.TargetNonceAccountKey(), req.AuthorityKey(), req.NewAuthorityKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two. Both accounts here are nonce accounts, so
	// the names say which is which: buildNonce is the one being borrowed, and
	// the one changing hands is read further down.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonceInfo, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if nonceInfo == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if nonceInfo.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), nonceInfo.Owner))
			return
		}
		if nonceInfo.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), nonceInfo.Space, core.NonceAccountSpace))
			return
		}

		nonceData, err := nonceInfo.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account data: %s", err))
			return
		}
		buildNonce, err := core.DeserializeNonceAccount(nonceData)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !buildNonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), buildNonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), buildNonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = buildNonce.Authority
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

	info, err := chain.Cli.AccountInfo(r.Context(), req.TargetNonceAccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
		return
	}
	if info == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("target_nonce_account: %s does not exist", req.TargetNonceAccountKey()))
		return
	}
	if info.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"target_nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
			req.TargetNonceAccountKey(), info.Owner))
		return
	}
	if info.Space != core.NonceAccountSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"target_nonce_account: %s is %d bytes, and a nonce account is %d",
			req.TargetNonceAccountKey(), info.Space, core.NonceAccountSpace))
		return
	}

	data, err := info.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account data: %s", err))
		return
	}
	nonce, err := core.DeserializeNonceAccount(data)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !nonce.Initialized() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("target_nonce_account: %s is not initialized", req.TargetNonceAccountKey()))
		return
	}
	if !nonce.Authority.Equal(req.AuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is not the authority of %s, which is %s",
			req.AuthorityKey(), req.TargetNonceAccountKey(), nonce.Authority))
		return
	}

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	raw, err := tx.Serialize()
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
	handler.WriteOK(w, NewSystemNonceAuthorizeResponse(tx, raw, messageBytes, req.TargetNonceAccountKey(), req.AuthorityKey(), req.NewAuthorityKey(), nonceAuthority, fee))
}

// SystemNonceUpgrade godoc
// @Summary      Build a Legacy nonce account migration
// @Description  Rewrites a Legacy nonce account as the current version. Legacy accounts stored the blockhash itself, which could collide with a real one; the current version stores a value derived from it that cannot. Nothing signs, since this is not a privileged operation, so anyone willing to pay the fee may upgrade anyone's account. No account this project creates can be upgraded: initialize has written the current version for a long time, only accounts predating that change are Legacy, and no instruction can produce one now. The check below rejects a current account before it reaches the chain. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well. It has to be an account other than the one this endpoint acts on.
// @Tags         v2-transaction-system-nonce
// @Accept       json
// @Produce      json
// @Param        body  body      SystemNonceUpgradeRequest  true  "Target nonce account"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemNonceUpgradeResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/nonce/upgrade [post]
func (h *SystemTransactionHandler) SystemNonceUpgrade(w http.ResponseWriter, r *http.Request) {
	req := new(SystemNonceUpgradeRequest)
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

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	ix, err := core.System.UpgradeNonceAccount(req.TargetNonceAccountKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two. Both accounts here are nonce accounts, so
	// the names say which is which: buildNonce is the one being borrowed, and
	// the Legacy one being migrated is read further down.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonceInfo, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if nonceInfo == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if nonceInfo.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), nonceInfo.Owner))
			return
		}
		if nonceInfo.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), nonceInfo.Space, core.NonceAccountSpace))
			return
		}

		nonceData, err := nonceInfo.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account data: %s", err))
			return
		}
		buildNonce, err := core.DeserializeNonceAccount(nonceData)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !buildNonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), buildNonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), buildNonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = buildNonce.Authority
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

	info, err := chain.Cli.AccountInfo(r.Context(), req.TargetNonceAccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
		return
	}
	if info == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("target_nonce_account: %s does not exist", req.TargetNonceAccountKey()))
		return
	}
	if info.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"target_nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
			req.TargetNonceAccountKey(), info.Owner))
		return
	}
	if info.Space != core.NonceAccountSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"target_nonce_account: %s is %d bytes, and a nonce account is %d",
			req.TargetNonceAccountKey(), info.Space, core.NonceAccountSpace))
		return
	}

	data, err := info.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account data: %s", err))
		return
	}
	nonce, err := core.DeserializeNonceAccount(data)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !nonce.Initialized() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("target_nonce_account: %s is not initialized", req.TargetNonceAccountKey()))
		return
	}
	if nonce.Version != core.NonceVersionLegacy {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"target_nonce_account: %s is already at version %d, and only a Legacy account can be upgraded",
			req.TargetNonceAccountKey(), nonce.Version))
		return
	}

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	raw, err := tx.Serialize()
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
	handler.WriteOK(w, NewSystemNonceUpgradeResponse(tx, raw, messageBytes, req.TargetNonceAccountKey(), nonceAuthority, nonce.Version, fee))
}
