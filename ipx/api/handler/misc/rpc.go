package misc

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/internal/rpc"
)

type RPCHandler struct {
	cluster *rpc.Cluster
}

func NewRPCHandler(cluster *rpc.Cluster) *RPCHandler {
	return &RPCHandler{cluster: cluster}
}

// SendTransaction godoc
// @Summary      Broadcast a signed transaction
// @Description  Submits a fully signed transaction to the cluster and returns its signature. Acceptance is not execution; the transaction still has to land in a block.
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      SendTransactionRequest  true  "Signed transaction"
// @Success      200   {object}  SendTransactionResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/transaction/send [post]
func (h *RPCHandler) SendTransaction(w http.ResponseWriter, r *http.Request) {
	req := new(SendTransactionRequest)
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

	sig, err := chain.Cli.SendTransaction(
		r.Context(),
		req.ToTransaction(),
		req.SkipPreflight,
		rpc.Commitment(req.Commitment.Commitment),
	)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewSendTransactionResponse(sig))
}
