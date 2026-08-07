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

// Balance godoc
// @Summary      Read an account's balance
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      AccountRequest  true  "Account"
// @Success      200   {object}  BalanceResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/balance [post]
func (h *RPCHandler) Balance(w http.ResponseWriter, r *http.Request) {
	req := new(AccountRequest)
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

	lamports, err := chain.Cli.Balance(r.Context(), req.ToPublicKey(), rpc.Commitment(req.Commitment.Commitment))
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewBalanceResponse(req.ToPublicKey(), lamports))
}

// Account godoc
// @Summary      Read an account's on-chain state
// @Description  Returns the owner, executable flag, data size, and data. An account that does not exist is reported with exists=false rather than as an error, since most 32-byte values name one nobody has created.
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      AccountRequest  true  "Account"
// @Success      200   {object}  AccountResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/account [post]
func (h *RPCHandler) Account(w http.ResponseWriter, r *http.Request) {
	req := new(AccountRequest)
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

	info, err := chain.Cli.AccountInfo(r.Context(), req.ToPublicKey(), rpc.Commitment(req.Commitment.Commitment))
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewAccountResponse(req.ToPublicKey(), info))
}

// Slot godoc
// @Summary      Read the current slot
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      ClusterRequest  true  "Cluster"
// @Success      200   {object}  SlotResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/slot [post]
func (h *RPCHandler) Slot(w http.ResponseWriter, r *http.Request) {
	req := new(ClusterRequest)
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

	slot, err := chain.Cli.Slot(r.Context(), rpc.Commitment(req.Commitment.Commitment))
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, &SlotResponse{Slot: slot})
}

// Health godoc
// @Summary      Read the node's health
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      ClusterRequest  true  "Cluster"
// @Success      200   {object}  HealthResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/health [post]
func (h *RPCHandler) Health(w http.ResponseWriter, r *http.Request) {
	req := new(ClusterRequest)
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

	health, err := chain.Cli.Health(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, &HealthResponse{Health: health})
}

// Version godoc
// @Summary      Read the node's software version
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      ClusterRequest  true  "Cluster"
// @Success      200   {object}  VersionResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/version [post]
func (h *RPCHandler) Version(w http.ResponseWriter, r *http.Request) {
	req := new(ClusterRequest)
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

	version, err := chain.Cli.Version(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, &VersionResponse{Version: version})
}

// GenesisHash godoc
// @Summary      Read the cluster's genesis hash and compare it to config
// @Description  A genesis hash is not folded into a signature the way EIP-155 binds a chain id, so nothing on chain prevents a transaction from replaying on another cluster. Comparing what the endpoint reports against what config names is the substitute check.
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      ClusterRequest  true  "Cluster"
// @Success      200   {object}  GenesisHashResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/genesis-hash [post]
func (h *RPCHandler) GenesisHash(w http.ResponseWriter, r *http.Request) {
	req := new(ClusterRequest)
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

	genesis, err := chain.Cli.GenesisHash(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, &GenesisHashResponse{
		GenesisHash: genesis,
		Configured:  chain.GenesisHash.Base58(),
		Matches:     genesis == chain.GenesisHash.Base58(),
	})
}

// Blockhash godoc
// @Summary      Read a recent blockhash
// @Description  Returns the blockhash to build against and the block height past which it is rejected, so expiry can be checked rather than guessed.
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      ClusterRequest  true  "Cluster"
// @Success      200   {object}  BlockhashResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/blockhash [post]
func (h *RPCHandler) Blockhash(w http.ResponseWriter, r *http.Request) {
	req := new(ClusterRequest)
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

	hash, lastValid, err := chain.Cli.LatestBlockhash(r.Context(), rpc.Commitment(req.Commitment.Commitment))
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, &BlockhashResponse{
		Blockhash:            hash.Base58(),
		LastValidBlockHeight: lastValid,
	})
}

// SimulateTransaction godoc
// @Summary      Execute a transaction without submitting it
// @Description  Runs the transaction against the node's state and returns the program logs either way. The logs are the only account of why execution stopped; nothing here corresponds to a revert string. With sig_verify off the transaction need not be signed, which is what makes this usable before deciding to sign.
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      SimulateTransactionRequest  true  "Transaction"
// @Success      200   {object}  SimulateTransactionResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/transaction/simulate [post]
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
	chain, err := h.cluster.Get(req.ChainName, req.ChainNetwork)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	value, err := chain.Cli.SimulateTransaction(r.Context(), req.ToTransaction(), req.SigVerify, rpc.Commitment(req.Commitment.Commitment))
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewSimulateTransactionResponse(value))
}

// SignatureStatus godoc
// @Summary      Read a transaction's status
// @Description  Stands in for an EVM receipt, but found can stay false forever: a transaction whose blockhash expired is forgotten and never lands.
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      SignatureStatusRequest  true  "Signature"
// @Success      200   {object}  SignatureStatusResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/transaction/status [post]
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
	chain, err := h.cluster.Get(req.ChainName, req.ChainNetwork)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	status, err := chain.Cli.SignatureStatus(r.Context(), req.ToSignature(), req.SearchHistory)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewSignatureStatusResponse(req.ToSignature(), status))
}

// Fee godoc
// @Summary      Price a message
// @Description  The fee follows from the signature count and any compute budget instructions, both of which live in the message, so it is known before signing and cannot be exceeded by execution the way a gas estimate can.
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      FeeRequest  true  "Message"
// @Success      200   {object}  FeeResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/fee [post]
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
	chain, err := h.cluster.Get(req.ChainName, req.ChainNetwork)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	fee, valid, err := chain.Cli.FeeForMessage(r.Context(), req.ToMessage(), rpc.Commitment(req.Commitment.Commitment))
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewFeeResponse(fee, valid))
}

// rentExemption answers the minimum balance for a size, shared by the typed
// endpoints below.
func (h *RPCHandler) rentExemption(w http.ResponseWriter, r *http.Request, accountType string, space uint64) {
	req := new(ClusterRequest)
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

	lamports, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), space, rpc.Commitment(req.Commitment.Commitment))
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewRentExemptionResponse(accountType, space, lamports))
}

// RentExemptionSystem godoc
// @Summary      Minimum balance for a plain wallet
// @Description  A wallet holds lamports and no data, so this is the floor any account must clear. It is also what a transfer to a previously unused address has to meet, since the transfer creates the account.
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      ClusterRequest  true  "Cluster"
// @Success      200   {object}  RentExemptionResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/rent-exemption/system [post]
func (h *RPCHandler) RentExemptionSystem(w http.ResponseWriter, r *http.Request) {
	h.rentExemption(w, r, "system", SpaceSystemAccount)
}

// RentExemptionMint godoc
// @Summary      Minimum balance for an SPL Token mint
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      ClusterRequest  true  "Cluster"
// @Success      200   {object}  RentExemptionResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/rent-exemption/mint [post]
func (h *RPCHandler) RentExemptionMint(w http.ResponseWriter, r *http.Request) {
	h.rentExemption(w, r, "mint", SpaceMint)
}

// RentExemptionToken godoc
// @Summary      Minimum balance for an SPL Token account
// @Description  Every token balance lives in an account of its own, so opening a position in a new token costs this much before any tokens move.
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      ClusterRequest  true  "Cluster"
// @Success      200   {object}  RentExemptionResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/rent-exemption/token [post]
func (h *RPCHandler) RentExemptionToken(w http.ResponseWriter, r *http.Request) {
	h.rentExemption(w, r, "token", SpaceTokenAccount)
}

// RentExemptionStake godoc
// @Summary      Minimum balance for a stake account
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      ClusterRequest  true  "Cluster"
// @Success      200   {object}  RentExemptionResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/rent-exemption/stake [post]
func (h *RPCHandler) RentExemptionStake(w http.ResponseWriter, r *http.Request) {
	h.rentExemption(w, r, "stake", SpaceStakeAccount)
}

// RentExemptionVote godoc
// @Summary      Minimum balance for a validator vote account
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      ClusterRequest  true  "Cluster"
// @Success      200   {object}  RentExemptionResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/rent-exemption/vote [post]
func (h *RPCHandler) RentExemptionVote(w http.ResponseWriter, r *http.Request) {
	h.rentExemption(w, r, "vote", SpaceVoteAccount)
}

// RentExemptionPublicKey godoc
// @Summary      Minimum balance for an account of the same size as an existing one
// @Description  Reads the size from a live account, which covers layouts none of the named endpoints describe. Pass a raw byte count to the getMinimumBalanceForRentExemption method through the raw endpoint instead.
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      AccountRequest  true  "Account"
// @Success      200   {object}  RentExemptionResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/rent-exemption/public-key [post]
func (h *RPCHandler) RentExemptionPublicKey(w http.ResponseWriter, r *http.Request) {
	req := new(AccountRequest)
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

	commitment := rpc.Commitment(req.Commitment.Commitment)
	info, err := chain.Cli.AccountInfo(r.Context(), req.ToPublicKey(), commitment)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if info == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("public_key: account %s does not exist", req.ToPublicKey()))
		return
	}

	lamports, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), info.Space, commitment)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewRentExemptionResponse("", info.Space, lamports))
}

// Airdrop godoc
// @Summary      Fund an account on devnet or testnet
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      AirdropRequest  true  "Account and amount"
// @Success      200   {object}  AirdropResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/airdrop [post]
func (h *RPCHandler) Airdrop(w http.ResponseWriter, r *http.Request) {
	req := new(AirdropRequest)
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

	sig, err := chain.Cli.RequestAirdrop(r.Context(), req.ToPublicKey(), req.Lamports(), rpc.Commitment(req.Commitment.Commitment))
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewAirdropResponse(sig))
}

// Raw godoc
// @Summary      Call any JSON-RPC method
// @Description  Passes a method straight through, so anything this API has not wrapped stays reachable.
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      RawRequest  true  "Method and params"
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
	chain, err := h.cluster.Get(req.ChainName, req.ChainNetwork)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
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
	chain, err := h.cluster.Get(req.ChainName, req.ChainNetwork)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
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
