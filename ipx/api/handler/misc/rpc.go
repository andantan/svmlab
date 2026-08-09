package misc

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/internal/rpc"
)

type RPCHandler struct{}

func NewRPCHandler() *RPCHandler {
	return &RPCHandler{}
}

// SendTransaction godoc
// @Summary      Broadcast a signed transaction
// @Description  Submits a fully signed transaction to the cluster and returns its signature. Acceptance is not execution; the transaction still has to land in a block.
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      SendTransactionRequest  true  "Signed transaction"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
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

// Balance godoc
// @Summary      Read an account's balance
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      AccountRequest  true  "Account"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
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
	chain, err := rpc.ChainFromContext(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	lamports, err := chain.Cli.Balance(r.Context(), req.ToPublicKey(), rpc.CommitmentConfirmed)
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
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
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

	handler.WriteOK(w, NewAccountResponse(req.ToPublicKey(), info))
}

// AccountOwner godoc
// @Summary      Read who owns an account
// @Description  Only the owning program may debit an account or write its data. An account owned by anything other than the System Program cannot be moved with a system transfer, and one owned by a non-executable address cannot be moved at all, so system_owned answers whether the balance is still reachable.
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      AccountOwnerRequest  true  "Account"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  AccountOwnerResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/account/owner [post]
func (h *RPCHandler) AccountOwner(w http.ResponseWriter, r *http.Request) {
	req := new(AccountOwnerRequest)
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

	handler.WriteOK(w, NewAccountOwnerResponse(req.ToPublicKey(), info))
}

// Nonce godoc
// @Summary      Read a durable nonce account
// @Description  Parses the 80 bytes a nonce account holds. The stored nonce is what a transaction may carry in place of a recent blockhash so that it never expires, which is the opposite of an EVM nonce: there a per-account counter prevents replay, here expiry is what is being removed. An account sized by create-account but never initialized is a normal intermediate state and reports initialized=false with all-zero fields.
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      NonceRequest  true  "Nonce account"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  NonceResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/nonce [post]
func (h *RPCHandler) Nonce(w http.ResponseWriter, r *http.Request) {
	req := new(NonceRequest)
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
		handler.WriteOK(w, &NonceResponse{PublicKey: req.ToPublicKey().Base58()})
		return
	}
	if info.Owner != core.System.ID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"public_key: %s is owned by %s, and a nonce account is owned by the System Program",
			req.ToPublicKey(), info.Owner))
		return
	}
	if info.Space != core.NonceAccountSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"public_key: %s is %d bytes, and a nonce account is %d",
			req.ToPublicKey(), info.Space, core.NonceAccountSpace))
		return
	}

	data, err := info.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account data: %s", err))
		return
	}

	nonce, err := core.DeserializeNonceAccount(data)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	handler.WriteOK(w, NewNonceResponse(req.ToPublicKey(), nonce))
}

// Slot godoc
// @Summary      Read the current slot
// @Tags         rpc
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SlotResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/slot [post]
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

	handler.WriteOK(w, &SlotResponse{Slot: slot})
}

// Health godoc
// @Summary      Read the node's health
// @Tags         rpc
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  HealthResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/health [post]
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

	handler.WriteOK(w, &HealthResponse{Health: health})
}

// Version godoc
// @Summary      Read the node's software version
// @Tags         rpc
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  VersionResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/version [post]
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

	handler.WriteOK(w, &VersionResponse{Version: version})
}

// GenesisHash godoc
// @Summary      Read the cluster's genesis hash and compare it to config
// @Description  A genesis hash is not folded into a signature the way EIP-155 binds a chain id, so nothing on chain prevents a transaction from replaying on another cluster. Comparing what the endpoint reports against what config names is the substitute check.
// @Tags         rpc
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  GenesisHashResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/genesis-hash [post]
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

	handler.WriteOK(w, &GenesisHashResponse{
		GenesisHash: genesis,
		Configured:  chain.GenesisHash.Base58(),
		Matches:     genesis == chain.GenesisHash.Base58(),
	})
}

// BlockHash godoc
// @Summary      Read a recent blockhash
// @Description  Returns the blockhash to build against and the block height past which it is rejected, so expiry can be checked rather than guessed. Fetched at finalized commitment, since a blockhash from a less settled view risks belonging to a fork.
// @Tags         rpc
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  BlockhashResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/blockhash [post]
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

	handler.WriteOK(w, &BlockhashResponse{
		Blockhash:            hash.Base58(),
		LastValidBlockHeight: lastValid,
	})
}

// SimulateTransaction godoc
// @Summary      Execute a transaction without submitting it
// @Description  Runs a fully signed transaction against the node's state without broadcasting it, and returns the program logs either way. The logs are the only account of why execution stopped; nothing here corresponds to a revert string.
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      SimulateTransactionRequest  true  "Transaction"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
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
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      SignatureStatusRequest  true  "Signature"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
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
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      FeeRequest  true  "Message"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
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

// RentExemptionSystem godoc
// @Summary      Minimum balance for a plain wallet
// @Description  A wallet holds lamports and no data, so this is the floor any account must clear. It is also what a transfer to a previously unused address has to meet, since the transfer creates the account.
// @Tags         rpc
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  RentExemptionSystemResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/rent-exemption/system [post]
func (h *RPCHandler) RentExemptionSystem(w http.ResponseWriter, r *http.Request) {
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
// @Tags         rpc
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  RentExemptionMintResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/rent-exemption/mint [post]
func (h *RPCHandler) RentExemptionMint(w http.ResponseWriter, r *http.Request) {
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
// @Tags         rpc
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  RentExemptionTokenResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/rent-exemption/token [post]
func (h *RPCHandler) RentExemptionToken(w http.ResponseWriter, r *http.Request) {
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
// @Tags         rpc
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  RentExemptionStakeResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/rent-exemption/stake [post]
func (h *RPCHandler) RentExemptionStake(w http.ResponseWriter, r *http.Request) {
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
// @Tags         rpc
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  RentExemptionVoteResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/rent-exemption/vote [post]
func (h *RPCHandler) RentExemptionVote(w http.ResponseWriter, r *http.Request) {
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

// RentExemptionSpace godoc
// @Summary      Minimum balance for a size given directly
// @Description  Takes a byte count rather than an account kind, which covers layouts none of the named endpoints describe and sizes no live account holds yet.
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      RentExemptionSpaceRequest  true  "Space"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  RentExemptionSpaceResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/rpc/rent-exemption/space [post]
func (h *RPCHandler) RentExemptionSpace(w http.ResponseWriter, r *http.Request) {
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
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      AccountRequest  true  "Account"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  RentExemptionPublicKeyResponse
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

// Airdrop godoc
// @Summary      Fund an account on devnet or testnet
// @Description  Requests a fixed half a SOL. The amount is not a field because the faucet enforces its own limit, and asking above it fails the call rather than handing out less.
// @Tags         rpc
// @Accept       json
// @Produce      json
// @Param        body  body      AirdropRequest  true  "Account"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
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
	chain, err := rpc.ChainFromContext(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	sig, err := chain.Cli.RequestAirdrop(r.Context(), req.ToPublicKey(), AirdropAmount, rpc.CommitmentConfirmed)
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
