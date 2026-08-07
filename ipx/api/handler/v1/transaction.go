package v1

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/andantan/svmlab/api/handler"
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

// BuildTransaction godoc
// @Summary      Build an unsigned transaction
// @Description  Compiles instructions into a message and returns the unsigned transaction, the message bytes every signer signs, and the account ordering the compilation produced
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      BuildTransactionRequest  true  "Fee payer, blockhash, and instructions"
// @Success      200   {object}  BuildTransactionResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v1/transaction/build [post]
func (h *TransactionHandler) BuildTransaction(w http.ResponseWriter, r *http.Request) {
	req := new(BuildTransactionRequest)
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

	blockhash := req.Blockhash()
	if blockhash == nil {
		if blockhash, _, err = chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized); err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
			return
		}
	}

	message, err := types.NewMessage(req.FeePayerKey(), blockhash, req.ToInstructions())
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

	handler.WriteOK(w, NewBuildTransactionResponse(tx, raw, messageBytes))
}
