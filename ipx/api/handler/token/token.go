package token

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/types"
	"github.com/andantan/svmlab/internal/rpc"
)

type TokenHandler struct{}

func NewTokenHandler() *TokenHandler {
	return &TokenHandler{}
}

// Mint godoc
// @Summary      Read an SPL Token mint
// @Description  Parses the 82 bytes a mint account holds. A mint is the closest thing Solana has to an ERC-20 contract, and what it lacks is the point: no balances and no allowances, since those live in separate token accounts owned by each holder. mint_authority and freeze_authority are omitted when absent, which is different from being the zero address; a mint whose mint authority was removed has a permanently fixed supply, and one initialized without a freeze authority can never gain one. Works for both classic Token and Token-2022, whose extensions sit past the base layout.
// @Tags         token
// @Accept       json
// @Produce      json
// @Param        body  body      MintRequest  true  "Mint account"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  MintResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/token/mint [post]
func (h *TokenHandler) Mint(w http.ResponseWriter, r *http.Request) {
	req := new(MintRequest)
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

	info, err := chain.Cli.AccountInfo(r.Context(), req.MintAccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if info == nil {
		handler.WriteOK(w, &MintResponse{PublicKey: req.MintAccountKey().Base58()})
		return
	}

	data, err := info.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account data: %s", err))
		return
	}
	owner, err := types.NewPublicKeyFromBase58(info.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	mint, err := core.DecodeMint(owner, data)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, "mint_account: "+err.Error())
		return
	}

	handler.WriteOK(w, NewMintResponse(req.MintAccountKey(), info.Owner, mint))
}

// Account godoc
// @Summary      Read an SPL Token holder account
// @Description  Parses the 165 bytes a token account holds. owner is not the runtime owner: that is the token program, which is what may write the data, while owner here is the wallet whose signature the program accepts. amount is base units with no scale of its own, so the mint is read as well to report amount_ui; when the mint cannot be read the base units are still returned and decimals is omitted rather than guessed. Works for both classic Token and Token-2022, whose extensions sit past the base layout.
// @Tags         token
// @Accept       json
// @Produce      json
// @Param        body  body      AccountRequest  true  "Token account"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  AccountResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/token/account [post]
func (h *TokenHandler) Account(w http.ResponseWriter, r *http.Request) {
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

	info, err := chain.Cli.AccountInfo(r.Context(), req.TokenAccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if info == nil {
		handler.WriteOK(w, &AccountResponse{PublicKey: req.TokenAccountKey().Base58()})
		return
	}

	data, err := info.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account data: %s", err))
		return
	}
	owner, err := types.NewPublicKeyFromBase58(info.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	account, err := core.DecodeTokenAccount(owner, data)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, "token_account: "+err.Error())
		return
	}

	// The mint is read for its decimals, which the account does not carry. A
	// failure here narrows the response rather than failing it: the balance is
	// still reported in base units, and a scale that could not be confirmed is
	// left out rather than guessed, since a balance shown against the wrong
	// decimals is wrong by orders of magnitude and reads as authoritative.
	var decimals *uint8
	if parsed, err := chain.Cli.Mint(r.Context(), account.Mint, rpc.CommitmentConfirmed); err == nil && parsed != nil {
		decimals = &parsed.Decimals
	}

	handler.WriteOK(w, NewAccountResponse(req.TokenAccountKey(), info.Owner, account, decimals))
}
