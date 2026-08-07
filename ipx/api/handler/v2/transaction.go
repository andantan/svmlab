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
	cfg     *config.Config
	cluster *rpc.Cluster
}

func NewTransactionHandler(cfg *config.Config, cluster *rpc.Cluster) *TransactionHandler {
	return &TransactionHandler{cfg: cfg, cluster: cluster}
}

// Transfer godoc
// @Summary      Build a native SOL transfer
// @Description  Assembles a System Program transfer and returns the same shape as a v1 build, so sign and send accept it unchanged. Amount is a lamport count, or "max" to send everything the sender can. Sending to an account that does not exist is refused unless allow_unfunded_recipient is set, since base58 has no checksum and a mistyped address is otherwise indistinguishable from an intended new one.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      TransferRequest  true  "Sender, recipient, and amount"
// @Success      200   {object}  TransferResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v2/transaction/system/transfer [post]
func (h *TransactionHandler) Transfer(w http.ResponseWriter, r *http.Request) {
	req := new(TransferRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	chain, err := h.cluster.Get(req.ChainName, req.ChainNetwork)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !req.AllowUnfundedRecipient {
		exists, err := chain.Cli.Exists(r.Context(), req.ToKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to check recipient: %s", err))
			return
		}
		if !exists {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"to: account %s does not exist. Check the address, then set allow_unfunded_recipient to create it",
				req.ToKey()))
			return
		}
	}

	blockhash := req.Blockhash()
	if blockhash == nil {
		if blockhash, _, err = chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized); err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
			return
		}
	}

	// The fee is priced from a message, and a message needs an amount, so a
	// zero-amount probe stands in. Nothing is lost by it: a fee depends on the
	// signature count and compute budget instructions, never on the lamports
	// being moved, so the probe prices the real transfer exactly.
	probe, err := h.buildMessage(req, blockhash, 0)
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

	amount := req.Lamports()
	if req.IsMax() {
		if amount, err = h.maxAmount(r, chain, req, fee); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	message, err := h.buildMessage(req, blockhash, amount)
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

	handler.WriteOK(w, NewTransferResponse(tx, raw, messageBytes, amount, fee))
}

func (h *TransactionHandler) buildMessage(req *TransferRequest, blockhash *types.Hash, lamports uint64) (*types.Message, error) {
	ix, err := core.SystemProgram.Transfer(req.FromKey(), req.ToKey(), lamports)
	if err != nil {
		return nil, err
	}

	return types.NewMessage(req.FeePayerKey(), blockhash, []*types.Instruction{ix})
}

// maxAmount is what the sender can move once the fee is accounted for.
//
// The fee only comes out of the sender's balance when the sender is also
// paying it. With a separate fee payer the whole balance can go, which empties
// the account and lets the runtime reclaim it.
func (h *TransactionHandler) maxAmount(r *http.Request, chain *rpc.Chain, req *TransferRequest, fee uint64) (uint64, error) {
	balance, err := chain.Cli.Balance(r.Context(), req.FromKey(), rpc.CommitmentConfirmed)
	if err != nil {
		return 0, fmt.Errorf("failed to read balance: %w", err)
	}
	if balance == 0 {
		return 0, fmt.Errorf("amount: %s has no balance", req.FromKey())
	}

	if !req.PaysOwnFee() {
		return balance, nil
	}

	if balance <= fee {
		return 0, fmt.Errorf("amount: balance %d lamports does not cover the %d lamport fee", balance, fee)
	}

	return balance - fee, nil
}
