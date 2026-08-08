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

type TransactionHandler struct {
	cfg *config.Config
}

func NewTransactionHandler(cfg *config.Config) *TransactionHandler {
	return &TransactionHandler{cfg: cfg}
}

// SystemTransfer godoc
// @Summary      Build a native SOL transfer
// @Description  Assembles a System Program transfer and returns the same shape as a v1 build, so sign and send accept it unchanged. The recent blockhash is always fetched, and the recipient is not required to exist yet. To send the sender's entire balance, use transfer/max instead.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SystemTransferRequest  true  "Sender, recipient, and amount"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemTransferResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/transfer [post]
func (h *TransactionHandler) SystemTransfer(w http.ResponseWriter, r *http.Request) {
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
	message, err := types.NewMessage(req.FeePayerKey(), blockhash, types.NewInstructions(ix))
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), message, rpc.CommitmentConfirmed)
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

	handler.WriteOK(w, NewSystemTransferResponse(tx, raw, messageBytes, req.Lamports(), fee))
}

// SystemTransferMax godoc
// @Summary      Build a native SOL transfer of the sender's entire balance
// @Description  Assembles a System Program transfer moving everything the sender can send. Resolving that amount needs the sender's balance and the fee, both fetched from the chain. The fee only comes out of the sender's balance when the sender is also the fee payer; with a separate fee payer the whole balance can go, which empties the account and lets the runtime reclaim it.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SystemTransferMaxRequest  true  "Sender and recipient"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemTransferMaxResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/transfer/max [post]
func (h *TransactionHandler) SystemTransferMax(w http.ResponseWriter, r *http.Request) {
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

	// The fee is priced from a message, and a message needs an amount, so a
	// zero-amount probe stands in. Nothing is lost by it: a fee depends on the
	// signature count and compute budget instructions, never on the lamports
	// being moved, so the probe prices the real transfer exactly.
	probeIx, err := core.System.Transfer(req.FromKey(), req.ToKey(), 0)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	probe, err := types.NewMessage(req.FeePayerKey(), blockhash, types.NewInstructions(probeIx))
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
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
	message, err := types.NewMessage(req.FeePayerKey(), blockhash, types.NewInstructions(ix))
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
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

	handler.WriteOK(w, NewSystemTransferMaxResponse(tx, raw, messageBytes, amount, fee))
}

// SystemCreateAccount godoc
// @Summary      Build a System Program account creation
// @Description  Funds a new account and sizes its data, leaving it owned by the System Program. The owner is not a request field: only the owning program may debit an account or write its data, so handing a new account to anything other than a program locks its lamports permanently. Accounts owned by another program belong to that program's own endpoints. The new account signs alongside the funder, which is what has no EVM counterpart: an address does not exist until someone holding its private key authorizes its creation. Lamports must reach the rent-exempt minimum for the requested space, which this checks before returning.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SystemCreateAccountRequest  true  "Funder, new account, lamports, and space"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemCreateAccountResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/create-account [post]
func (h *TransactionHandler) SystemCreateAccount(w http.ResponseWriter, r *http.Request) {
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

	ix, err := core.System.CreateAccount(req.FromKey(), req.NewAccountKey(), core.System.ID(), req.ToLamports(), req.ToSpace())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	message, err := types.NewMessage(req.FeePayerKey(), blockhash, types.NewInstructions(ix))
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), message, rpc.CommitmentConfirmed)
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

	handler.WriteOK(w, NewSystemCreateAccountResponse(tx, raw, messageBytes, core.System.ID(), req.ToLamports(), newAccountRent, req.ToSpace(), fee))
}

// SystemAllocate godoc
// @Summary      Build a System Program allocation
// @Description  Reserves data space on an existing System-owned account. Only the owning program may size an account, so this works on an account the System Program still owns and not one already assigned elsewhere. Growing an account raises its rent-exempt floor, so the balance is checked against the minimum for the new size rather than the old one.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SystemAllocateRequest  true  "Account and space"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemAllocateResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/allocate [post]
func (h *TransactionHandler) SystemAllocate(w http.ResponseWriter, r *http.Request) {
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
	message, err := types.NewMessage(req.FeePayerKey(), blockhash, types.NewInstructions(ix))
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), message, rpc.CommitmentConfirmed)
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

	handler.WriteOK(w, NewSystemAllocateResponse(tx, raw, messageBytes, req.ToSpace(), rentExempt, fee))
}

// SystemAssign godoc
// @Summary      Build a System Program ownership assignment
// @Description  Hands a System-owned account to another program, which is the step that puts an account under a program's control. Ownership is a field on the account rather than a mapping the program keeps, which is the inverse of an EVM contract holding balances for its users in its own storage. The owner must be executable: only the owning program may debit an account or write its data, so assigning to a plain address locks the account and its lamports permanently.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SystemAssignRequest  true  "Account and new owner"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SystemAssignResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/assign [post]
func (h *TransactionHandler) SystemAssign(w http.ResponseWriter, r *http.Request) {
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
	message, err := types.NewMessage(req.FeePayerKey(), blockhash, types.NewInstructions(ix))
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), message, rpc.CommitmentConfirmed)
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

	handler.WriteOK(w, NewSystemAssignResponse(tx, raw, messageBytes, req.OwnerKey(), fee))
}
