package misc

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/internal/rpc"
)

// SendTransaction godoc
// @Summary      Broadcast a signed transaction
// @Description  Submits a fully signed transaction to the cluster and returns its signature. Acceptance is not execution; the transaction still has to land in a block.
// @Tags         cluster
// @Accept       json
// @Produce      json
// @Param        body  body      SendTransactionRequest  true  "Signed transaction"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SendTransactionResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/cluster/transaction/send [post]
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

	chain, err := rpc.ChainFromContext(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// skipPreflight is never true, and the preflight commitment is fixed:
	// the node-side simulation that runs before broadcast is what catches a
	// failure before it costs a signature, and there is no reason a caller
	// of this endpoint would want to skip it or tune what it checks against.
	sig, err := chain.Cli.SendTransaction(r.Context(), req.ToTransaction(), false, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewSendTransactionResponse(sig))
}

// SimulateTransaction godoc
// @Summary      Execute a transaction without submitting it
// @Description  Runs a fully signed transaction against the node's state without broadcasting it, and returns the program logs either way. The logs are the only account of why execution stopped; nothing here corresponds to a revert string.
// @Tags         cluster
// @Accept       json
// @Produce      json
// @Param        body  body      SimulateTransactionRequest  true  "Transaction"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SimulateTransactionResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/cluster/transaction/simulate [post]
func (h *RPCHandler) SimulateTransaction(w http.ResponseWriter, r *http.Request) {
	req := new(SimulateTransactionRequest)
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

	// Signatures are always verified, for the same reason the request
	// requires a fully signed transaction: catching a bad signature here
	// costs nothing, while skipping the check only defers the failure.
	value, err := chain.Cli.SimulateTransaction(r.Context(), req.ToTransaction(), true, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewSimulateTransactionResponse(value))
}

// SignatureStatus godoc
// @Summary      Read a transaction's status
// @Description  Stands in for an EVM receipt, but found can stay false forever: a transaction whose blockhash expired is forgotten and never lands.
// @Tags         cluster
// @Accept       json
// @Produce      json
// @Param        body  body      SignatureStatusRequest  true  "Signature"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SignatureStatusResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/cluster/transaction/status [post]
func (h *RPCHandler) SignatureStatus(w http.ResponseWriter, r *http.Request) {
	req := new(SignatureStatusRequest)
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

	// The node's recent cache forgets a signature quickly, and a status
	// query is pointless if it can't see past that.
	status, err := chain.Cli.SignatureStatus(r.Context(), req.ToSignature(), true)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewSignatureStatusResponse(req.ToSignature(), status))
}

// Fee godoc
// @Summary      Price a message
// @Description  The fee follows from the signature count and any compute budget instructions, both of which live in the message, so it is known before signing and cannot be exceeded by execution the way a gas estimate can.
// @Tags         cluster
// @Accept       json
// @Produce      json
// @Param        body  body      FeeRequest  true  "Message"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  FeeResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/cluster/transaction/fee [post]
func (h *RPCHandler) Fee(w http.ResponseWriter, r *http.Request) {
	req := new(FeeRequest)
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

	fee, valid, err := chain.Cli.FeeForMessage(r.Context(), req.ToMessage(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewFeeResponse(fee, valid))
}
