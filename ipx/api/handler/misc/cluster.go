package misc

import (
	"net/http"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/internal/rpc"
)

// Slot godoc
// @Summary      Read the current slot
// @Tags         cluster
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SlotResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/cluster/slot [post]
func (h *RPCHandler) Slot(w http.ResponseWriter, r *http.Request) {
	chain, err := rpc.ChainFromContext(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	slot, err := chain.Cli.Slot(r.Context(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewSlotResponse(slot))
}

// Health godoc
// @Summary      Read the node's health
// @Tags         cluster
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  HealthResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/cluster/health [post]
func (h *RPCHandler) Health(w http.ResponseWriter, r *http.Request) {
	chain, err := rpc.ChainFromContext(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	health, err := chain.Cli.Health(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewHealthResponse(health))
}

// Version godoc
// @Summary      Read the node's software version
// @Tags         cluster
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  VersionResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/cluster/version [post]
func (h *RPCHandler) Version(w http.ResponseWriter, r *http.Request) {
	chain, err := rpc.ChainFromContext(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	version, err := chain.Cli.Version(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewVersionResponse(version))
}

// GenesisHash godoc
// @Summary      Read the cluster's genesis hash and compare it to config
// @Description  A genesis hash is not folded into a signature the way EIP-155 binds a chain id, so nothing on chain prevents a transaction from replaying on another cluster. Comparing what the endpoint reports against what config names is the substitute check.
// @Tags         cluster
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  GenesisHashResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/cluster/genesis-hash [post]
func (h *RPCHandler) GenesisHash(w http.ResponseWriter, r *http.Request) {
	chain, err := rpc.ChainFromContext(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	genesis, err := chain.Cli.GenesisHash(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewGenesisHashResponse(genesis, chain.GenesisHash.Base58()))
}

// BlockHash godoc
// @Summary      Read a recent blockhash
// @Description  Returns the blockhash to build against and the block height past which it is rejected, so expiry can be checked rather than guessed. Fetched at finalized commitment, since a blockhash from a less settled view risks belonging to a fork.
// @Tags         cluster
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  BlockhashResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/cluster/blockhash [post]
func (h *RPCHandler) BlockHash(w http.ResponseWriter, r *http.Request) {
	chain, err := rpc.ChainFromContext(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	hash, lastValid, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewBlockhashResponse(hash.Base58(), lastValid))
}
