package token

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/codec"
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

// ATADerive godoc
// @Summary      Derive the canonical associated token account for a wallet and mint
// @Description  Returns the address create-ata and create-ata-idempotent will create and everything else in this API that takes owner + mint derives internally, plus the canonical bump: PDA.Find always searches from 255 downward and stops at the first off-curve point, which is not a choice — the Associated Token Account program recomputes and validates that same bump internally and accepts no other. This is a pure computation, not a chain read: it never checks whether the derived address actually exists.
// @Tags         token
// @Accept       json
// @Produce      json
// @Param        body  body      ATADeriveRequest  true  "Owner, mint, and program"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  ATADeriveResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/token/ata/derive [post]
func (h *TokenHandler) ATADerive(w http.ResponseWriter, r *http.Request) {
	req := new(ATADeriveRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	account, bump, err := core.ATA.Derive(req.OwnerKey(), req.MintKey(), req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	handler.WriteOK(w, NewATADeriveResponse(req.OwnerKey(), req.MintKey(), req.TokenProgramID(), account, bump))
}

// ATAValidate godoc
// @Summary      Check a supplied address against the canonical associated token account
// @Description  Recomputes the associated token account for owner, mint, and program the same way ata/derive does, and compares it against associated_token_account. valid is true only when the two match exactly; derived is always returned so a caller who gets false back knows the right address without a second call. Like ata/derive, this never checks whether either address actually exists on chain — it is purely a derivation check.
// @Tags         token
// @Accept       json
// @Produce      json
// @Param        body  body      ATAValidateRequest  true  "Owner, mint, program, and the address to check"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  ATAValidateResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/token/ata/validate [post]
func (h *TokenHandler) ATAValidate(w http.ResponseWriter, r *http.Request) {
	req := new(ATAValidateRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	derived, bump, err := core.ATA.Derive(req.OwnerKey(), req.MintKey(), req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	handler.WriteOK(w, NewATAValidateResponse(req.OwnerKey(), req.MintKey(), req.TokenProgramID(), req.AssociatedTokenAccountKey(), derived, bump))
}

// AmountToUi godoc
// @Summary      Format a raw token amount as a UI string, using the mint's own program
// @Description  Builds AmountToUiAmount and simulates it — never sends it, since it writes nothing. In this version of the program a mint can only specify decimals, so against a plain mint this is exactly amount / 10^decimals and could be computed without the network at all; it earns its keep only against a Token-2022 mint carrying the interest-bearing extension, where the true UI string includes interest accrued since the mint's last update and only the program can compute that. fee_payer is required even though nothing is ever sent: the node still checks the simulated payer can afford the fee before running the instruction.
// @Tags         token
// @Accept       json
// @Produce      json
// @Param        body  body      AmountToUiRequest  true  "Mint, raw amount, fee payer, and program"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  AmountToUiResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/token/amount-to-ui [post]
func (h *TokenHandler) AmountToUi(w http.ResponseWriter, r *http.Request) {
	req := new(AmountToUiRequest)
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

	tokenProgram, err := core.TokenProgram(req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	ix, err := tokenProgram.AmountToUiAmount(req.MintKey(), req.ToAmount())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// This transaction is never signed and never sent, only simulated: the
	// blockhash field is 32 zero bytes, which the node replaces with its own
	// current one before execution, and the fee payer's single signature
	// slot is left empty since sigVerify is off for the same call.
	message, err := types.NewMessage(req.FeePayerKey(), types.NewHash([types.HashLength]byte{}), types.NewInstructions(ix))
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

	value, err := chain.Cli.SimulateUnsignedTransaction(r.Context(), raw, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if value.Failed() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("simulation failed: %s", value.Err))
		return
	}

	decoded, err := value.DecodedReturnData()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if decoded == nil {
		handler.WriteError(w, http.StatusBadGateway, "mint: program returned no data")
		return
	}

	handler.WriteOK(w, NewAmountToUiResponse(req.MintKey(), req.TokenProgramID(), req.ToAmount(), string(decoded)))
}

// UiToAmount godoc
// @Summary      Parse a UI amount string back into a raw token amount, using the mint's own program
// @Description  Builds UiAmountToAmount and simulates it — never sends it, since it writes nothing. AmountToUi's inverse, for the same reason: against a plain mint this is a decimals multiply a client could do itself, and it earns its keep only against a Token-2022 mint carrying the interest-bearing extension. fee_payer is required even though nothing is ever sent: the node still checks the simulated payer can afford the fee before running the instruction.
// @Tags         token
// @Accept       json
// @Produce      json
// @Param        body  body      UiToAmountRequest  true  "Mint, UI amount string, fee payer, and program"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  UiToAmountResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/token/ui-to-amount [post]
func (h *TokenHandler) UiToAmount(w http.ResponseWriter, r *http.Request) {
	req := new(UiToAmountRequest)
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

	tokenProgram, err := core.TokenProgram(req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	ix, err := tokenProgram.UiAmountToAmount(req.MintKey(), req.ToUIAmount())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// This transaction is never signed and never sent, only simulated: the
	// blockhash field is 32 zero bytes, which the node replaces with its own
	// current one before execution, and the fee payer's single signature
	// slot is left empty since sigVerify is off for the same call.
	message, err := types.NewMessage(req.FeePayerKey(), types.NewHash([types.HashLength]byte{}), types.NewInstructions(ix))
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

	value, err := chain.Cli.SimulateUnsignedTransaction(r.Context(), raw, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if value.Failed() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("simulation failed: %s", value.Err))
		return
	}

	decoded, err := value.DecodedReturnData()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if decoded == nil || len(decoded) != 8 {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("mint: program returned %d bytes, expected 8", len(decoded)))
		return
	}

	amount, _, err := codec.Binary.ReadU64(decoded)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("mint: %s", err))
		return
	}

	handler.WriteOK(w, NewUiToAmountResponse(req.MintKey(), req.TokenProgramID(), req.ToUIAmount(), amount))
}

// GetAccountDataSize godoc
// @Summary      Ask the program for the exact byte size an account needs for a mint and a set of extensions
// @Description  Builds GetAccountDataSize and simulates it — never sends it, since it writes nothing. Returns the same authority Reallocate itself defers to, asked directly rather than recomputed client-side: a hardcoded copy of the program's own extension-size table would drift the moment the program changes a layout, the same reason a rent-exemption minimum is always asked of the cluster rather than assumed. extension_types may be empty, in which case the response is the bare size a Token-2022 account with no extensions needs. fee_payer is required even though nothing is ever sent: the node still checks the simulated payer can afford the fee before running the instruction.
// @Tags         token
// @Accept       json
// @Produce      json
// @Param        body  body      GetAccountDataSizeRequest  true  "Mint, extension types, fee payer, and program"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  GetAccountDataSizeResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/token/extensions/get-account-data-size [post]
func (h *TokenHandler) GetAccountDataSize(w http.ResponseWriter, r *http.Request) {
	req := new(GetAccountDataSizeRequest)
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

	tokenProgram, err := core.TokenProgram(req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	ix, err := tokenProgram.GetAccountDataSize(req.MintKey(), req.ToExtensionTypes())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// This transaction is never signed and never sent, only simulated: the
	// blockhash field is 32 zero bytes, which the node replaces with its own
	// current one before execution, and the fee payer's single signature
	// slot is left empty since sigVerify is off for the same call.
	message, err := types.NewMessage(req.FeePayerKey(), types.NewHash([types.HashLength]byte{}), types.NewInstructions(ix))
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

	value, err := chain.Cli.SimulateUnsignedTransaction(r.Context(), raw, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if value.Failed() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("simulation failed: %s", value.Err))
		return
	}

	decoded, err := value.DecodedReturnData()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if decoded == nil || len(decoded) != 8 {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("mint: program returned %d bytes, expected 8", len(decoded)))
		return
	}

	size, _, err := codec.Binary.ReadU64(decoded)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("mint: %s", err))
		return
	}

	handler.WriteOK(w, NewGetAccountDataSizeResponse(req.MintKey(), req.TokenProgramID(), req.ExtensionTypes, size))
}

// MintDataSize godoc
// @Summary      Compute the byte size a new mint needs for a set of extensions
// @Description  Computed client-side, never asked of the chain: GetAccountDataSize only ever answers "how big does an account need to be to hold this mint", never "how big does this mint itself need to be" -- a different question the interface crate exposes no return-data instruction for at all. create-mint's own System.CreateAccount always sizes for a bare 82-byte mint; a mint that will carry any extension has to be created at this size instead, with create-mint bypassed in favor of system/create-account directly. Each named type must be a mint extension, not a token-account one (rejected here the same way the deployed program would reject it on chain, without the round trip). token_metadata is also rejected: its size depends on actual name/symbol/uri content this endpoint never sees.
// @Tags         token
// @Accept       json
// @Produce      json
// @Param        body  body      MintDataSizeRequest  true  "Extension types the new mint will carry"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  MintDataSizeResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/token/extensions/mint/data-size [post]
func (h *TokenHandler) MintDataSize(w http.ResponseWriter, r *http.Request) {
	req := new(MintDataSizeRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	size, err := core.CalculateMintExtensionsLen(req.ToExtensionTypes())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	handler.WriteOK(w, NewMintDataSizeResponse(req.ExtensionTypes, size))
}
