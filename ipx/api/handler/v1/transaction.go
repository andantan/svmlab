package v1

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/types"
	"github.com/andantan/svmlab/internal/rpc"
)

type TransactionHandler struct {
	cluster *rpc.Cluster
}

func NewTransactionHandler(cluster *rpc.Cluster) *TransactionHandler {
	return &TransactionHandler{cluster: cluster}
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

// SignTransaction godoc
// @Summary      Sign a transaction without broadcasting it
// @Description  Signs the transaction's message with each supplied key and places the signature in that key's slot. Keys may be supplied across several calls, so a transaction can be completed by co-signers.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SignTransactionRequest  true  "Transaction and private keys"
// @Success      200   {object}  SignTransactionResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v1/transaction/sign [post]
func (h *TransactionHandler) SignTransaction(w http.ResponseWriter, r *http.Request) {
	req := new(SignTransactionRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	tx := req.ToTransaction()
	if err := core.Signer.SignTransaction(tx, req.ToPrivateKeys()...); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	raw, err := tx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}

	handler.WriteOK(w, NewSignTransactionResponse(tx, raw))
}

// SendTransaction godoc
// @Summary      Broadcast a signed transaction
// @Description  Submits a fully signed transaction to the cluster and returns its signature. Acceptance is not execution; the transaction still has to land in a block.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        body  body      SendTransactionRequest  true  "Signed transaction"
// @Success      200   {object}  SendTransactionResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/v1/transaction/send [post]
func (h *TransactionHandler) SendTransaction(w http.ResponseWriter, r *http.Request) {
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
