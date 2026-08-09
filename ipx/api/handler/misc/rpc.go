package misc

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/internal/rpc"
)

type RPCHandler struct{}

func NewRPCHandler() *RPCHandler {
	return &RPCHandler{}
}

// Raw godoc
// @Summary      Call any JSON-RPC method
// @Description  Passes a method straight through, so anything this API has not wrapped stays reachable.
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      RawRequest  true  "Method and params"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  map[string]interface{}
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/ [post]
func (h *RPCHandler) Raw(w http.ResponseWriter, r *http.Request) {
	req := new(RawRequest)
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

	var result json.RawMessage
	if err := chain.Cli.Call(r.Context(), rpc.Elem{Method: req.Method, Params: req.Params, Result: &result}); err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteJSON(w, http.StatusOK, map[string]any{"result": result})
}

// Batch godoc
// @Summary      Call several JSON-RPC methods in one round trip
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      BatchRequest  true  "Calls"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  map[string]interface{}
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/batch [post]
func (h *RPCHandler) Batch(w http.ResponseWriter, r *http.Request) {
	req := new(BatchRequest)
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

	results := make([]json.RawMessage, len(req.Calls))
	elems := new(rpc.Elems)
	for i, c := range req.Calls {
		elems.With(rpc.Elem{Method: c.Method, Params: c.Params, Result: &results[i]})
	}

	if err := chain.Cli.Batch(r.Context(), elems); err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteJSON(w, http.StatusOK, map[string]any{"results": results})
}
