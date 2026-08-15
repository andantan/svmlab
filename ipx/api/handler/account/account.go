package account

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/types"
	"github.com/andantan/svmlab/internal/rpc"
)

type AccountHandler struct{}

func NewAccountHandler() *AccountHandler {
	return &AccountHandler{}
}

// Balance godoc
// @Summary      Read an account's balance
// @Tags         account
// @Accept       json
// @Produce      json
// @Param        body  body      AccountRequest  true  "Account"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  BalanceResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/account/balance [post]
func (h *AccountHandler) Balance(w http.ResponseWriter, r *http.Request) {
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

// State godoc
// @Summary      Read an account's on-chain state
// @Description  Returns the owner, executable flag, data size, balance, and data. An account that does not exist is reported with exists=false rather than as an error, since most 32-byte values name one nobody has created.
// @Tags         account
// @Accept       json
// @Produce      json
// @Param        body  body      AccountRequest  true  "Account"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  AccountResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/account/state [post]
func (h *AccountHandler) State(w http.ResponseWriter, r *http.Request) {
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

// Owner godoc
// @Summary      Read who owns an account
// @Description  Only the owning program may debit an account or write its data. An account owned by anything other than the System Program cannot be moved with a system transfer, and one owned by a non-executable address cannot be moved at all, so system_owned answers whether the balance is still reachable.
// @Tags         account
// @Accept       json
// @Produce      json
// @Param        body  body      AccountOwnerRequest  true  "Account"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  AccountOwnerResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/account/owner [post]
func (h *AccountHandler) Owner(w http.ResponseWriter, r *http.Request) {
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

// Authority godoc
// @Summary      Read the authority-bearing fields of an account
// @Description  Reports the authority for whichever kind of account public_key names: a durable nonce account's authority, a mint's mint_authority and freeze_authority, a token account's token_owner, delegate, and close_authority, or a multisig's m, n, and signers. type says which of these applies, and is system_account for a plain account with none of them, or unknown for a program-owned account this endpoint has no parser for.
// @Tags         account
// @Accept       json
// @Produce      json
// @Param        body  body      AccountAuthorityRequest  true  "Account"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  AccountAuthorityResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/account/authority [post]
func (h *AccountHandler) Authority(w http.ResponseWriter, r *http.Request) {
	req := new(AccountAuthorityRequest)
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

	resp, err := NewAccountAuthorityResponse(req.ToPublicKey(), info)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	handler.WriteOK(w, resp)
}

// Tokens godoc
// @Summary      List the token accounts a wallet owns
// @Description  Lists token accounts owned by a wallet under both the classic Token Program and Token-2022. The response keeps the program on each account because the two programs own separate accounts and no single token instruction can touch both at once.
// @Tags         account
// @Accept       json
// @Produce      json
// @Param        body  body      TokensRequest  true  "Wallet"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  TokensResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/account/tokens [post]
func (h *AccountHandler) Tokens(w http.ResponseWriter, r *http.Request) {
	req := new(TokensRequest)
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

	programs := types.NewPublicKeys(core.TokenProgramID, core.Token2022ProgramID)
	var found []rpc.KeyedAccount
	for _, program := range programs {
		accounts, err := chain.Cli.TokenAccountsByProgram(r.Context(), req.ToPublicKey(), program, rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, err.Error())
			return
		}
		found = append(found, accounts...)
	}

	entries, err := h.tokenEntries(r, chain, found)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	handler.WriteOK(w, NewTokensResponse(req.ToPublicKey(), entries))
}

func (h *AccountHandler) tokenEntries(r *http.Request, chain *rpc.Chain, found []rpc.KeyedAccount) ([]*TokenEntry, error) {
	// Decimals are cached across the listing. A wallet's accounts cluster on a
	// few mints, so reading each one per account would turn a single call into
	// dozens for no new information.
	decimals := make(map[string]*uint8)
	entries := make([]*TokenEntry, 0, len(found))
	for _, ka := range found {
		key, err := types.NewPublicKeyFromBase58(ka.Pubkey)
		if err != nil {
			return nil, fmt.Errorf("account %s: %s", ka.Pubkey, err)
		}
		data, err := ka.Account.Bytes()
		if err != nil {
			return nil, fmt.Errorf("account %s: %s", ka.Pubkey, err)
		}
		owner, err := types.NewPublicKeyFromBase58(ka.Account.Owner)
		if err != nil {
			return nil, fmt.Errorf("account %s: %s", ka.Pubkey, err)
		}
		account, err := core.DecodeTokenAccount(owner, data)
		if err != nil {
			return nil, fmt.Errorf("account %s: %s", ka.Pubkey, err)
		}

		mint := account.Mint.Base58()
		if _, ok := decimals[mint]; !ok {
			if parsed, err := chain.Cli.Mint(r.Context(), account.Mint, rpc.CommitmentConfirmed); err == nil && parsed != nil {
				decimals[mint] = &parsed.Decimals
			} else {
				decimals[mint] = nil
			}
		}

		entries = append(entries, &TokenEntry{
			PublicKey: key,
			Program:   ka.Account.Owner,
			Account:   account,
			Decimals:  decimals[mint],
		})
	}

	return entries, nil
}

// Nonce godoc
// @Summary      Read a durable nonce account
// @Description  Parses the 80 bytes a nonce account holds. The stored nonce is what a transaction may carry in place of a recent blockhash so that it never expires, which is the opposite of an EVM nonce: there a per-account counter prevents replay, here expiry is what is being removed. An account sized by create-account but never initialized is a normal intermediate state and reports initialized=false with all-zero fields.
// @Tags         account
// @Accept       json
// @Produce      json
// @Param        body  body      NonceRequest  true  "Nonce account"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  NonceResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/account/nonce [post]
func (h *AccountHandler) Nonce(w http.ResponseWriter, r *http.Request) {
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

// Airdrop godoc
// @Summary      Fund an account on devnet or testnet
// @Description  Requests a fixed half a SOL. The amount is not a field because the faucet enforces its own limit, and asking above it fails the call rather than handing out less.
// @Tags         account
// @Accept       json
// @Produce      json
// @Param        body  body      AirdropRequest  true  "Account"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  AirdropResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/account/airdrop [post]
func (h *AccountHandler) Airdrop(w http.ResponseWriter, r *http.Request) {
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
