package misc

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/internal/rpc"
)

type ProtocolHandler struct{}

func NewProtocolHandler() *ProtocolHandler {
	return &ProtocolHandler{}
}

// RentExemptionSystem godoc
// @Summary      Minimum balance for a plain wallet
// @Description  A wallet holds lamports and no data, so this is the floor any account must clear. It is also what a transfer to a previously unused address has to meet, since the transfer creates the account.
// @Tags         protocol
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  RentExemptionSystemResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/protocol/rent-exemption/system [post]
func (h *ProtocolHandler) RentExemptionSystem(w http.ResponseWriter, r *http.Request) {
	chain, err := rpc.ChainFromContext(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	lamports, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewRentExemptionSystemResponse(lamports))
}

// RentExemptionMint godoc
// @Summary      Minimum balance for an SPL Token mint
// @Tags         protocol
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  RentExemptionMintResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/protocol/rent-exemption/mint [post]
func (h *ProtocolHandler) RentExemptionMint(w http.ResponseWriter, r *http.Request) {
	chain, err := rpc.ChainFromContext(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	lamports, err := chain.Cli.MinimumBalanceForRentExemptionMint(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewRentExemptionMintResponse(lamports))
}

// RentExemptionToken godoc
// @Summary      Minimum balance for an SPL Token account
// @Description  Every token balance lives in an account of its own, so opening a position in a new token costs this much before any tokens move.
// @Tags         protocol
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  RentExemptionTokenResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/protocol/rent-exemption/token [post]
func (h *ProtocolHandler) RentExemptionToken(w http.ResponseWriter, r *http.Request) {
	chain, err := rpc.ChainFromContext(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	lamports, err := chain.Cli.MinimumBalanceForRentExemptionToken(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewRentExemptionTokenResponse(lamports))
}

// RentExemptionStake godoc
// @Summary      Minimum balance for a stake account
// @Tags         protocol
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  RentExemptionStakeResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/protocol/rent-exemption/stake [post]
func (h *ProtocolHandler) RentExemptionStake(w http.ResponseWriter, r *http.Request) {
	chain, err := rpc.ChainFromContext(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	lamports, err := chain.Cli.MinimumBalanceForRentExemptionStake(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewRentExemptionStakeResponse(lamports))
}

// RentExemptionVote godoc
// @Summary      Minimum balance for a validator vote account
// @Tags         protocol
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  RentExemptionVoteResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/protocol/rent-exemption/vote [post]
func (h *ProtocolHandler) RentExemptionVote(w http.ResponseWriter, r *http.Request) {
	chain, err := rpc.ChainFromContext(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	lamports, err := chain.Cli.MinimumBalanceForRentExemptionVote(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewRentExemptionVoteResponse(lamports))
}

// RentExemptionNonce godoc
// @Summary      Minimum balance for a durable nonce account
// @Description  A nonce account has to stay rent exempt to keep holding its nonce, so this is what one must be funded with. It is also the floor a partial withdrawal has to leave behind.
// @Tags         protocol
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  RentExemptionNonceResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/protocol/rent-exemption/nonce [post]
func (h *ProtocolHandler) RentExemptionNonce(w http.ResponseWriter, r *http.Request) {
	chain, err := rpc.ChainFromContext(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	lamports, err := chain.Cli.MinimumBalanceForRentExemptionNonce(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewRentExemptionNonceResponse(lamports))
}

// RentExemptionSpace godoc
// @Summary      Minimum balance for a size given directly
// @Description  Takes a byte count rather than an account kind, which covers layouts none of the named endpoints describe and sizes no live account holds yet.
// @Tags         protocol
// @Accept       json
// @Produce      json
// @Param        body  body      RentExemptionSpaceRequest  true  "Space"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  RentExemptionSpaceResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/protocol/rent-exemption/space [post]
func (h *ProtocolHandler) RentExemptionSpace(w http.ResponseWriter, r *http.Request) {
	req := new(RentExemptionSpaceRequest)
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

	lamports, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), req.ToSpace(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewRentExemptionSpaceResponse(req.ToSpace(), lamports))
}

// RentExemptionPublicKey godoc
// @Summary      Minimum balance for an account of the same size as an existing one
// @Description  Reads the size from a live account, so the caller does not have to know the layout. Pass a byte count to the space endpoint instead when the account does not exist yet.
// @Tags         protocol
// @Accept       json
// @Produce      json
// @Param        body  body      RentExemptionPublicKeyRequest  true  "Account"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  RentExemptionPublicKeyResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/protocol/rent-exemption/public-key [post]
func (h *ProtocolHandler) RentExemptionPublicKey(w http.ResponseWriter, r *http.Request) {
	req := new(RentExemptionPublicKeyRequest)
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

	info, err := chain.Cli.AccountInfo(r.Context(), req.ToPublicKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if info == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("public_key: account %s does not exist", req.ToPublicKey()))
		return
	}

	// The rent-exemption minimum is a protocol constant derived from the
	// size, not live state, so it is priced at a fixed commitment regardless
	// of the one the account lookup above used.
	lamports, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), info.Space, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewRentExemptionPublicKeyResponse(req.ToPublicKey(), info.Space, lamports))
}
