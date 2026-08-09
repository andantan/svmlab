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
// @Description  Assembles a System Program transfer and returns the same shape as a v1 build, so sign and send accept it unchanged. The recent blockhash is always fetched, and the recipient is not required to exist yet. To send the sender's entire balance, use transfer/max instead. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SystemTransferRequest  true  "Sender, recipient, and amount"
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

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	ix, err := core.System.Transfer(req.FromKey(), req.ToKey(), req.Lamports())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
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

	// A resulting balance below this must be zero, or the runtime rejects the
	// transfer: an account cannot be left underfunded, only fully closed.
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

	spent := req.Lamports()
	if req.FromKey().Equal(req.FeePayerKey()) {
		spent += fee
	}
	if balance < spent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("amount: balance %d lamports does not cover %d lamports", balance, spent))
		return
	}
	if remaining := balance - spent; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("amount: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FromKey(), remaining, minRent))
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
	handler.WriteOK(w, NewSystemTransferResponse(tx, raw, messageBytes, nonceAuthority, req.Lamports(), fee))
}

// SystemTransferMax godoc
// @Summary      Build a native SOL transfer of the sender's entire balance
// @Description  Assembles a System Program transfer moving everything the sender can send. Resolving that amount needs the sender's balance and the fee, both fetched from the chain. The fee only comes out of the sender's balance when the sender is also the fee payer; with a separate fee payer the whole balance can go, which empties the account and lets the runtime reclaim it. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SystemTransferMaxRequest  true  "Sender and recipient"
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

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	// Resolving the nonce comes before pricing rather than after, unlike every
	// endpoint that knows its amount up front. Advancing the nonce is an extra
	// instruction whose authority signs, so leaving it out of the probe would
	// price a transaction with one signature too few.
	var (
		advance        *types.Instruction
		nonceState     *core.NonceAccount
		nonceAuthority *types.PublicKey
	)
	if !req.NonceAccountKey().IsNil() {
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
		nonceState, err = core.DeserializeNonceAccount(data)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !nonceState.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		if advance, err = core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonceState.Authority); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		nonceAuthority = nonceState.Authority
	}

	// The fee is priced from a message, and a message needs an amount, so a
	// zero-amount probe stands in. Nothing is lost by it: a fee depends on the
	// signature count and compute budget instructions, never on the lamports
	// being moved, so the probe prices the real transfer exactly.
	//
	// The probe carries the live blockhash either way. A nonce is not among the
	// cluster's recent blockhashes, so pricing against one comes back as
	// expired.
	probeIx, err := core.System.Transfer(req.FromKey(), req.ToKey(), 0)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	probeInstructions := types.NewInstructions(probeIx)

	var probe *types.Message
	if req.NonceAccountKey().IsNil() {
		if probe, err = types.NewMessage(req.FeePayerKey(), blockhash, probeInstructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		if probe, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, probeInstructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), probe, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	balance, err := chain.Cli.Balance(r.Context(), req.FromKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read balance: %s", err))
		return
	}
	if balance == 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("amount: %s has no balance", req.FromKey()))
		return
	}

	amount := balance
	if req.FromKey().Equal(req.FeePayerKey()) {
		if balance <= fee {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("amount: balance %d lamports does not cover the %d lamport fee", balance, fee))
			return
		}
		amount = balance - fee
	}

	ix, err := core.System.Transfer(req.FromKey(), req.ToKey(), amount)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// The real message is the one that carries the nonce, which is the whole
	// point of naming one: it holds a value the cluster does not consider
	// recent, so it never expires.
	var message *types.Message
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonceState.Nonce, advance, instructions); err != nil {
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
	handler.WriteOK(w, NewSystemTransferMaxResponse(tx, raw, messageBytes, nonceAuthority, amount, fee))
}

// SystemTransferMany godoc
// @Summary      Build one transaction paying several recipients
// @Description  Assembles one Transfer instruction per recipient, all leaving the same account, in a single transaction. This is the first endpoint to carry an arbitrary number of instructions, so it is the first bounded by transaction size rather than by anything it checks: a transaction travels in one 1232-byte packet and cannot be split, which caps the list somewhere around twenty and is reported as size and size_limit. The account keys show fewer entries than instructions, since the sender and the System Program appear in every one and a compiled message lists each key once. There is no max variant, because sending everything one account holds does not say how to divide it. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SystemTransferManyRequest  true  "Sender, recipients with amounts, and fee payer"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemTransferManyResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/transfer/many [post]
func (h *SystemTransactionHandler) SystemTransferMany(w http.ResponseWriter, r *http.Request) {
	req := new(SystemTransferManyRequest)
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

	// One instruction per recipient, in the order they were given. The order
	// is kept rather than sorted because it is what the caller will read back
	// in the response, and the runtime executes them in it.
	targets := req.Targets()
	ixs := make([]*types.Instruction, 0, len(targets))
	for i := range targets {
		ix, err := core.System.Transfer(req.FromKey(), targets[i].ToKey(), targets[i].Lamports())
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("transfers[%d]: %s", i, err))
			return
		}
		ixs = append(ixs, ix)
	}
	instructions := types.NewInstructions(ixs...)

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
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

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Serializing here rather than at the end, which is where every other
	// endpoint does it, because this is where the size limit is enforced and
	// this is the only endpoint that can reach it. A request naming too many
	// recipients is refused before it costs a fee lookup and three balance
	// reads, and the error names the byte count rather than a recipient count
	// that would only ever be an estimate.
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

	balance, err := chain.Cli.Balance(r.Context(), req.FromKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read balance: %s", err))
		return
	}

	spent := req.Total()
	if req.FromKey().Equal(req.FeePayerKey()) {
		// The total was already checked for overflow, but adding the fee to a
		// total near the top of a u64 could still wrap, and a wrapped figure
		// would read as affordable.
		if spent+fee < spent {
			handler.WriteError(w, http.StatusBadRequest, "transfers: the total plus the fee exceeds what a u64 can hold")
			return
		}
		spent += fee
	}
	if balance < spent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("transfers: balance %d lamports does not cover %d lamports", balance, spent))
		return
	}
	if remaining := balance - spent; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("transfers: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FromKey(), remaining, minRent))
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

	messageBytes, err := message.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode message: %s", err))
		return
	}

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewSystemTransferManyResponse(tx, raw, messageBytes, nonceAuthority, targets, req.Total(), fee))
}

// SystemTransferBatch godoc
// @Summary      Build one transaction paying from several accounts
// @Description  Assembles one Transfer instruction per entry, each with its own sender, in a single transaction. Every distinct sender signs, and a signature costs 64 bytes beside its 32 byte account key, so senders are three times as expensive as recipients and this fits far fewer transfers than transfer/many does. Naming a sender as the fee payer costs nothing, since it already signs; naming anyone else adds another 96 bytes. An entry may set max instead of amount to send whatever its sender still holds once its other entries and, if it is also the fee payer, the fee are taken out, which is a figure the request cannot state because the fee is not known until the transaction is priced. One max per sender, since everything an account holds cannot go to two places. Collecting a signature from every sender takes longer than a blockhash lasts, so naming nonce_account builds the transaction against the value that durable nonce account stores instead, and it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SystemTransferBatchRequest  true  "Transfers with their own senders, and a fee payer"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemTransferBatchResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/transfer/batch [post]
func (h *SystemTransactionHandler) SystemTransferBatch(w http.ResponseWriter, r *http.Request) {
	req := new(SystemTransferBatchRequest)
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

	// Resolving the nonce comes before pricing, as it does in transfer/max and
	// for the same reason: advancing the nonce is an extra instruction whose
	// authority signs, so leaving it out of the probe would price a
	// transaction with one signature too few.
	var (
		advance        *types.Instruction
		nonceState     *core.NonceAccount
		nonceAuthority *types.PublicKey
	)
	if !req.NonceAccountKey().IsNil() {
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
		nonceState, err = core.DeserializeNonceAccount(data)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !nonceState.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		if advance, err = core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonceState.Authority); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		nonceAuthority = nonceState.Authority
	}

	// A max entry has no amount yet, so it stands in at zero while the fee is
	// worked out. Nothing is lost by that: a fee depends on the signature
	// count and compute budget instructions, never on the lamports being
	// moved, so the probe prices the real batch exactly.
	//
	// The probe carries the live blockhash either way. A nonce is not among
	// the cluster's recent blockhashes, so pricing against one comes back as
	// expired.
	targets := req.Targets()
	probeIxs := make([]*types.Instruction, 0, len(targets))
	for i := range targets {
		ix, err := core.System.Transfer(targets[i].FromKey(), targets[i].ToKey(), targets[i].Lamports())
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("transfers[%d]: %s", i, err))
			return
		}
		probeIxs = append(probeIxs, ix)
	}
	probeInstructions := types.NewInstructions(probeIxs...)

	var probe *types.Message
	if req.NonceAccountKey().IsNil() {
		if probe, err = types.NewMessage(req.FeePayerKey(), blockhash, probeInstructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		if probe, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, probeInstructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	probeTx, err := types.NewTransaction(probe)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// The probe is the same length as the real transaction: a lamport count is
	// a fixed-width u64 whatever its value, and a stored nonce is the same
	// thirty-two bytes as a blockhash. So serializing it settles the size
	// limit here, before a batch that cannot be sent costs a balance lookup
	// per sender.
	if _, err = probeTx.Serialize(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), probe, rpc.CommitmentConfirmed)
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

	// What each sender can afford is a question about the account rather than
	// about any one of its transfers, so this runs once per distinct sender
	// and settles that sender's max entry along the way.
	var (
		total             uint64
		feePayerIsSpender bool
	)
	for _, sender := range req.Senders() {
		balance, err := chain.Cli.Balance(r.Context(), sender.Key(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read balance of %s: %s", sender.Key(), err))
			return
		}

		// The fee leaves the fee payer before any instruction runs, so it is
		// gone before this sender's transfers are counted.
		available := balance
		if sender.Key().Equal(req.FeePayerKey()) {
			feePayerIsSpender = true
			if available < fee {
				handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
					"fee_payer: balance %d lamports does not cover the %d lamport fee", balance, fee))
				return
			}
			available -= fee
		}

		if available < sender.Fixed() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"transfers: %s has %d lamports to send and its transfers come to %d",
				sender.Key(), available, sender.Fixed()))
			return
		}
		remaining := available - sender.Fixed()

		spent := sender.Fixed()
		if sender.HasMax() {
			// Nothing left to send has three causes and they call for
			// different fixes, so the message says which one it was rather
			// than blaming the other transfers in every case.
			switch {
			case balance == 0:
				handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
					"transfers[%d]: %s has no balance", sender.MaxIndex(), sender.Key()))
				return
			case available == 0:
				handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
					"transfers[%d]: %s holds %d lamports and the %d lamport fee takes all of it",
					sender.MaxIndex(), sender.Key(), balance, fee))
				return
			case remaining == 0:
				handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
					"transfers[%d]: %s has %d lamports to send and its other transfers come to exactly that",
					sender.MaxIndex(), sender.Key(), available))
				return
			}
			targets[sender.MaxIndex()].SetLamports(remaining)
			spent += remaining
			remaining = 0
		}
		if remaining != 0 && remaining < minRent {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"transfers: would leave %s with %d lamports, below the %d lamport rent-exemption minimum",
				sender.Key(), remaining, minRent))
			return
		}

		// No overflow guard here, unlike the per-sender sums. Every spend was
		// just checked against a real balance, so the total cannot exceed what
		// the cluster holds.
		total += spent
	}

	if !feePayerIsSpender {
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

	ixs := make([]*types.Instruction, 0, len(targets))
	for i := range targets {
		ix, err := core.System.Transfer(targets[i].FromKey(), targets[i].ToKey(), targets[i].Lamports())
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("transfers[%d]: %s", i, err))
			return
		}
		ixs = append(ixs, ix)
	}
	instructions := types.NewInstructions(ixs...)

	// The real message is the one that carries the nonce, which is the whole
	// point of naming one: it holds a value the cluster does not consider
	// recent, so it never expires.
	var message *types.Message
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonceState.Nonce, advance, instructions); err != nil {
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
	handler.WriteOK(w, NewSystemTransferBatchResponse(tx, raw, messageBytes, nonceAuthority, targets, total, fee))
}

// SystemCreateAccount godoc
// @Summary      Build a System Program account creation
// @Description  Funds a new account, sizes its data, and assigns it an owner. The owner must be executable: only the owning program may debit an account or write its data, so an account owned by a plain address is locked from the moment it exists. Pass the System Program for an ordinary account. The new account signs alongside the funder, which is what has no EVM counterpart: an address does not exist until someone holding its private key authorizes its creation. Lamports must reach the rent-exempt minimum for the requested space, which this checks before returning. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SystemCreateAccountRequest  true  "Funder, new account, owner, lamports, and space"
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

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	ix, err := core.System.CreateAccount(req.FromKey(), req.NewAccountKey(), req.OwnerKey(), req.ToLamports(), req.ToSpace())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
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

	// The new account has to reach the rent-exempt minimum for its own size,
	// which is a different number from the one a plain wallet must hold.
	newAccountRent, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), req.ToSpace(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	if req.ToLamports() < newAccountRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"lamports: %d does not meet the %d lamport rent-exemption minimum for %d bytes",
			req.ToLamports(), newAccountRent, req.ToSpace()))
		return
	}

	// Only the owning program may debit an account or write its data, so an
	// account handed to something that cannot be invoked is locked from the
	// moment it exists. The System Program is itself executable, so the
	// ordinary case passes.
	ownerInfo, err := chain.Cli.AccountInfo(r.Context(), req.OwnerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read owner: %s", err))
		return
	}
	if ownerInfo == nil || !ownerInfo.Executable {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"owner: %s is not an executable program, and an account it owns could never be debited or written",
			req.OwnerKey()))
		return
	}

	// Creating an account that already exists fails, and unlike a transfer to
	// an unfunded address there is no reading of it as intent.
	exists, err := chain.Cli.Exists(r.Context(), req.NewAccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to check new account: %s", err))
		return
	}
	if exists {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("new_account: %s already exists", req.NewAccountKey()))
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

	spent := req.ToLamports()
	if req.FromKey().Equal(req.FeePayerKey()) {
		spent += fee
	}
	if balance < spent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("lamports: balance %d lamports does not cover %d lamports", balance, spent))
		return
	}
	if remaining := balance - spent; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("lamports: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FromKey(), remaining, minRent))
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
	handler.WriteOK(w, NewSystemCreateAccountResponse(tx, raw, messageBytes, req.OwnerKey(), nonceAuthority, req.ToLamports(), newAccountRent, req.ToSpace(), fee))
}

// SystemAllocate godoc
// @Summary      Build a System Program allocation
// @Description  Reserves data space on an existing System-owned account. Only the owning program may size an account, so this works on an account the System Program still owns and not one already assigned elsewhere. Growing an account raises its rent-exempt floor, so the balance is checked against the minimum for the new size rather than the old one. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SystemAllocateRequest  true  "Account and space"
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

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	ix, err := core.System.Allocate(req.AccountKey(), req.ToSpace())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
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

	// One lookup answers everything the runtime will check: whether the
	// account exists, who owns it, whether it is already sized, and what it
	// holds.
	info, err := chain.Cli.AccountInfo(r.Context(), req.AccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read account: %s", err))
		return
	}
	if info == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s does not exist", req.AccountKey()))
		return
	}
	if info.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s is owned by %s, and only the owning program may size an account",
			req.AccountKey(), info.Owner))
		return
	}
	if info.Space != 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s is already allocated %d bytes", req.AccountKey(), info.Space))
		return
	}

	rentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), req.ToSpace(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	if info.Lamports < rentExempt {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"space: %s holds %d lamports, below the %d lamport rent-exemption minimum for %d bytes",
			req.AccountKey(), info.Lamports, rentExempt, req.ToSpace()))
		return
	}

	if !req.AccountKey().Equal(req.FeePayerKey()) {
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
	handler.WriteOK(w, NewSystemAllocateResponse(tx, raw, messageBytes, nonceAuthority, req.ToSpace(), rentExempt, fee))
}

// SystemAssign godoc
// @Summary      Build a System Program ownership assignment
// @Description  Hands a System-owned account to another program, which is the step that puts an account under a program's control. Ownership is a field on the account rather than a mapping the program keeps, which is the inverse of an EVM contract holding balances for its users in its own storage. The owner must be executable: only the owning program may debit an account or write its data, so assigning to a plain address locks the account and its lamports permanently. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SystemAssignRequest  true  "Account and new owner"
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

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	ix, err := core.System.Assign(req.AccountKey(), req.OwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
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

	// Assigning to something that cannot be invoked is unrecoverable: the new
	// owner can never debit the account, and the System Program can no longer
	// assign it back because assignment requires the current owner. The
	// System Program itself is executable, so assigning back to it passes.
	ownerInfo, err := chain.Cli.AccountInfo(r.Context(), req.OwnerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read owner: %s", err))
		return
	}
	if ownerInfo == nil || !ownerInfo.Executable {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"owner: %s is not an executable program, and assigning to it would lock the account permanently",
			req.OwnerKey()))
		return
	}

	info, err := chain.Cli.AccountInfo(r.Context(), req.AccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read account: %s", err))
		return
	}
	if info == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s does not exist", req.AccountKey()))
		return
	}
	if info.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s is owned by %s, and only the owning program may reassign an account",
			req.AccountKey(), info.Owner))
		return
	}

	if !req.AccountKey().Equal(req.FeePayerKey()) {
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
	handler.WriteOK(w, NewSystemAssignResponse(tx, raw, messageBytes, req.OwnerKey(), nonceAuthority, fee))
}

// SystemSeedCreateAccount godoc
// @Summary      Build an account creation at a seed-derived address
// @Description  Creates an account at SHA256(base || seed || owner) and hands it to that owner in one instruction, so a program-owned account needs no separate allocate and assign. The owner must be executable, and it changes the address: the same base and seed derive somewhere else for a different owner. The derived account never signs, which is the difference from create-account: nobody holds a secret for it, so base signs in its place and whoever controls base controls every address derived from it. The address is derived rather than accepted, since the runtime recomputes it and rejects a mismatch. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SystemSeedCreateAccountRequest  true  "Funder, base, seed, owner, lamports, and space"
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

	derived, err := types.CreateWithSeed(req.BaseKey(), req.Seed, req.OwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	ix, err := core.System.CreateAccountWithSeed(req.FromKey(), req.BaseKey(), req.Seed, req.OwnerKey(), req.ToLamports(), req.ToSpace())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
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

	newAccountRent, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), req.ToSpace(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	if req.ToLamports() < newAccountRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"lamports: %d does not meet the %d lamport rent-exemption minimum for %d bytes",
			req.ToLamports(), newAccountRent, req.ToSpace()))
		return
	}

	// Only the owning program may debit an account or write its data, so an
	// account handed to something that cannot be invoked is locked from the
	// moment it exists. The System Program is itself executable, so the
	// ordinary case passes.
	ownerInfo, err := chain.Cli.AccountInfo(r.Context(), req.OwnerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read owner: %s", err))
		return
	}
	if ownerInfo == nil || !ownerInfo.Executable {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"owner: %s is not an executable program, and an account it owns could never be debited or written",
			req.OwnerKey()))
		return
	}

	exists, err := chain.Cli.Exists(r.Context(), derived, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to check derived account: %s", err))
		return
	}
	if exists {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"seed: %s already exists, so base and seed together name an account that has been created", derived))
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

	spent := req.ToLamports()
	if req.FromKey().Equal(req.FeePayerKey()) {
		spent += fee
	}
	if balance < spent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("lamports: balance %d lamports does not cover %d lamports", balance, spent))
		return
	}
	if remaining := balance - spent; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("lamports: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FromKey(), remaining, minRent))
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
	handler.WriteOK(w, NewSystemSeedCreateAccountResponse(tx, raw, messageBytes, derived, req.OwnerKey(), nonceAuthority, req.ToLamports(), newAccountRent, req.ToSpace(), fee))
}

// SystemSeedTransfer godoc
// @Summary      Build a transfer out of a seed-derived address
// @Description  Debits SHA256(base || seed || owner) without that account signing, since base signs for it. That is what makes a derived address usable as a holding account: anyone can fund it, and only the holder of base can spend it. The account must still be System-owned for a system transfer to debit it, which is checked before returning. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SystemSeedTransferRequest  true  "Base, seed, owner, recipient, and amount"
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

	derived, err := types.CreateWithSeed(req.BaseKey(), req.Seed, req.OwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	ix, err := core.System.TransferWithSeed(req.BaseKey(), req.Seed, req.OwnerKey(), req.ToKey(), req.ToLamports())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	info, err := chain.Cli.AccountInfo(r.Context(), derived, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read derived account: %s", err))
		return
	}
	if info == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("seed: %s does not exist", derived))
		return
	}
	if info.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"seed: %s is owned by %s, and only the owning program may debit an account",
			derived, info.Owner))
		return
	}
	if info.Lamports < req.ToLamports() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"amount: %s holds %d lamports, short of %d", derived, info.Lamports, req.ToLamports()))
		return
	}
	if remaining := info.Lamports - req.ToLamports(); remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"amount: would leave %s with %d lamports, below the %d lamport rent-exemption minimum",
			derived, remaining, minRent))
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
	handler.WriteOK(w, NewSystemSeedTransferResponse(tx, raw, messageBytes, derived, nonceAuthority, req.ToLamports(), fee))
}

// SystemSeedAllocate godoc
// @Summary      Build an allocation on a seed-derived address
// @Description  Reserves data space on SHA256(base || seed || owner) with base signing in the account's place. Allocation still requires the account to be System-owned, so this is the step taken before assigning it away, on an address derived for its eventual owner from the start. Growing an account raises its rent-exempt floor, so the balance is checked against the minimum for the new size. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SystemSeedAllocateRequest  true  "Base, seed, owner, and space"
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

	derived, err := types.CreateWithSeed(req.BaseKey(), req.Seed, req.OwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	ix, err := core.System.AllocateWithSeed(req.BaseKey(), req.Seed, req.OwnerKey(), req.ToSpace())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
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

	info, err := chain.Cli.AccountInfo(r.Context(), derived, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read derived account: %s", err))
		return
	}
	if info == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("seed: %s does not exist", derived))
		return
	}
	if info.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"seed: %s is owned by %s, and only the owning program may size an account",
			derived, info.Owner))
		return
	}
	if info.Space != 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"seed: %s is already allocated %d bytes", derived, info.Space))
		return
	}

	rentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), req.ToSpace(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	if info.Lamports < rentExempt {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"space: %s holds %d lamports, below the %d lamport rent-exemption minimum for %d bytes",
			derived, info.Lamports, rentExempt, req.ToSpace()))
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
	handler.WriteOK(w, NewSystemSeedAllocateResponse(tx, raw, messageBytes, derived, nonceAuthority, req.ToSpace(), rentExempt, fee))
}

// SystemSeedAssign godoc
// @Summary      Build an ownership assignment on a seed-derived address
// @Description  Hands SHA256(base || seed || owner) to that same owner. There is no separate new-owner field, because one owner does both jobs: it is what the address is derived from and what the account is assigned to, so an account can only be handed to the program its own address already encodes. The owner must be executable, since assigning to a plain address locks the account permanently. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SystemSeedAssignRequest  true  "Base, seed, and owner"
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

	derived, err := types.CreateWithSeed(req.BaseKey(), req.Seed, req.OwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	ix, err := core.System.AssignWithSeed(req.BaseKey(), req.Seed, req.OwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
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

	ownerInfo, err := chain.Cli.AccountInfo(r.Context(), req.OwnerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read owner: %s", err))
		return
	}
	if ownerInfo == nil || !ownerInfo.Executable {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"owner: %s is not an executable program, and assigning to it would lock the account permanently",
			req.OwnerKey()))
		return
	}

	info, err := chain.Cli.AccountInfo(r.Context(), derived, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read derived account: %s", err))
		return
	}
	if info == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("seed: %s does not exist", derived))
		return
	}
	if info.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"seed: %s is owned by %s, and only the owning program may reassign an account",
			derived, info.Owner))
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
	handler.WriteOK(w, NewSystemSeedAssignResponse(tx, raw, messageBytes, derived, req.OwnerKey(), nonceAuthority, fee))
}

// SystemSeedTransferMax godoc
// @Summary      Build a transfer of a seed-derived address's entire balance
// @Description  Sends everything SHA256(base || seed || owner) holds. The amount is the whole balance with nothing held back, because a derived address can never pay the fee: a fee payer has to sign, and this account cannot. That also means no probe is needed to price the message first, since the amount does not depend on the fee here the way it does for a plain transfer. Emptying the account lets the runtime reclaim it. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SystemSeedTransferMaxRequest  true  "Base, seed, owner, and recipient"
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

	derived, err := types.CreateWithSeed(req.BaseKey(), req.Seed, req.OwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	info, err := chain.Cli.AccountInfo(r.Context(), derived, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read derived account: %s", err))
		return
	}
	if info == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("seed: %s does not exist", derived))
		return
	}
	if info.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"seed: %s is owned by %s, and only the owning program may debit an account",
			derived, info.Owner))
		return
	}
	if info.Lamports == 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("amount: %s has no balance", derived))
		return
	}

	// The whole balance goes, with no fee subtracted, because the fee comes
	// from an account that can sign and this one cannot.
	amount := info.Lamports

	ix, err := core.System.TransferWithSeed(req.BaseKey(), req.Seed, req.OwnerKey(), req.ToKey(), amount)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
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
	handler.WriteOK(w, NewSystemSeedTransferMaxResponse(tx, raw, messageBytes, derived, nonceAuthority, amount, fee))
}

// SystemNonceCreate godoc
// @Summary      Build a durable nonce account creation
// @Description  Creates the account and initializes it as a durable nonce in one transaction, which is the first v2 endpoint to carry more than one instruction. The nonce account appears twice: it signs for the creation, since an address does not exist until its key authorizes it, and is only writable for the initialization, which needs no authority. Message compilation lists it once with the union of both, which is why it shows up among the signers. Size and funding are not fields, since a nonce account is always the same size and has to hold exactly the rent-exempt minimum for it. Naming nonce_account builds the transaction against the value that durable nonce account stores rather than a recent blockhash, so it never expires; the advance that consumes it is prepended as the first instruction, and the response reports nonce_authority, which has to sign as well. It has to be an account other than the one this endpoint acts on.
// @Tags         transaction
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
// @Tags         transaction
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
// @Tags         transaction
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
// @Tags         transaction
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
// @Tags         transaction
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
// @Tags         transaction
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
// @Tags         transaction
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
