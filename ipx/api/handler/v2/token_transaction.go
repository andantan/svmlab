package v2

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/types"
	"github.com/andantan/svmlab/internal/config"
	"github.com/andantan/svmlab/internal/rpc"
)

type TokenTransactionHandler struct {
	cfg *config.Config
}

func NewTokenTransactionHandler(cfg *config.Config) *TokenTransactionHandler {
	return &TokenTransactionHandler{cfg: cfg}
}

// CreateMint godoc
// @Summary      Fund and initialize an SPL Token mint
// @Description  System CreateAccount and InitializeMint2 as one transaction. An uninitialized Token-owned account can be initialized by anybody else before its intended owner does, so the two never exist as separate endpoints.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                true  "Cluster name"
// @Param        X-Chain-Network  header    string                true  "Cluster network"
// @Param        body             body      CreateMintRequest      true  "Mint parameters"
// @Success      200              {object}  CreateMintResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/create-mint [post]
func (h *TokenTransactionHandler) CreateMint(w http.ResponseWriter, r *http.Request) {
	req := new(CreateMintRequest)
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

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	// The mint has to reach its own rent-exempt minimum, which is a different
	// number from the one a plain wallet must hold and is resolved before the
	// instruction is built rather than after, since CreateMint takes it as an
	// argument.
	rentExempt, err := chain.Cli.MinimumBalanceForRentExemptionMint(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	instructions, err := tokenProgram.CreateMint(req.FromKey(), req.MintKey(), req.MintAuthorityKey(), req.FreezeAuthorityKey(), req.ToDecimals(), rentExempt)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	// Creating a mint that already exists fails on chain, and unlike a
	// transfer to an unfunded address there is no reading of it as intent.
	exists, err := chain.Cli.Exists(r.Context(), req.MintKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to check mint: %s", err))
		return
	}
	if exists {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s already exists", req.MintKey()))
		return
	}

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	balance, err := chain.Cli.Balance(r.Context(), req.FromKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read balance: %s", err))
		return
	}

	spent := rentExempt
	if req.FromKey().Equal(req.FeePayerKey()) {
		spent += fee
	}
	if balance < spent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("from: balance %d lamports does not cover %d lamports", balance, spent))
		return
	}
	if remaining := balance - spent; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("from: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FromKey(), remaining, minRent))
		return
	}

	if !req.FromKey().Equal(req.FeePayerKey()) {
		feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
			return
		}
		if feePayerBalance < fee {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
			return
		}
		if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
			return
		}
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewCreateMintResponse(
		tx, raw, messageBytes,
		req.MintKey(), req.TokenProgramID(), req.MintAuthorityKey(), req.FreezeAuthorityKey(), nonceAuthority,
		req.ToDecimals(), rentExempt, fee,
	))
}

// CreateAccount godoc
// @Summary      Fund and initialize an SPL Token holder account
// @Description  System CreateAccount and InitializeAccount3 as one transaction. An uninitialized Token-owned account initialized by somebody else names their wallet as owner, which is why the two never exist as separate endpoints.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                  true  "Cluster name"
// @Param        X-Chain-Network  header    string                  true  "Cluster network"
// @Param        body             body      CreateAccountRequest    true  "Token account parameters"
// @Success      200              {object}  CreateAccountResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/create-account [post]
func (h *TokenTransactionHandler) CreateAccount(w http.ResponseWriter, r *http.Request) {
	req := new(CreateAccountRequest)
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

	// The mint has to already exist and belong to the program the account is
	// being opened against, or the instruction fails on chain rather than
	// here.
	mintInfo, err := chain.Cli.AccountInfo(r.Context(), req.MintKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read mint: %s", err))
		return
	}
	if mintInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"mint: %s is owned by %s, not %s", req.MintKey(), mintInfo.Owner, req.TokenProgramID()))
		return
	}

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	// The token account has to reach its own rent-exempt minimum, a different
	// number from both a plain wallet's and a mint's, and is resolved before
	// the instruction is built since CreateAccount takes it as an argument.
	rentExempt, err := chain.Cli.MinimumBalanceForRentExemptionToken(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	instructions, err := tokenProgram.CreateAccount(req.FromKey(), req.AccountKey(), req.MintKey(), req.OwnerKey(), rentExempt)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	// Creating an account that already exists fails on chain, and unlike a
	// transfer to an unfunded address there is no reading of it as intent.
	exists, err := chain.Cli.Exists(r.Context(), req.AccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to check account: %s", err))
		return
	}
	if exists {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s already exists", req.AccountKey()))
		return
	}

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	balance, err := chain.Cli.Balance(r.Context(), req.FromKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read balance: %s", err))
		return
	}

	spent := rentExempt
	if req.FromKey().Equal(req.FeePayerKey()) {
		spent += fee
	}
	if balance < spent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("from: balance %d lamports does not cover %d lamports", balance, spent))
		return
	}
	if remaining := balance - spent; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("from: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FromKey(), remaining, minRent))
		return
	}

	if !req.FromKey().Equal(req.FeePayerKey()) {
		feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
			return
		}
		if feePayerBalance < fee {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
			return
		}
		if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
			return
		}
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewCreateAccountResponse(
		tx, raw, messageBytes,
		req.AccountKey(), req.MintKey(), req.OwnerKey(), req.TokenProgramID(), nonceAuthority,
		rentExempt, fee,
	))
}

// MintToChecked godoc
// @Summary      Mint new supply into a token account
// @Description  Creates new supply and credits an existing token account. decimals is checked against the mint rather than filled in from it, which is what catches a client that formatted amount against the wrong decimals as a 400 instead of an on-chain failure.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                  true  "Cluster name"
// @Param        X-Chain-Network  header    string                  true  "Cluster network"
// @Param        body             body      MintToCheckedRequest    true  "Mint-to parameters"
// @Success      200              {object}  MintToCheckedResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/mint-to-checked [post]
func (h *TokenTransactionHandler) MintToChecked(w http.ResponseWriter, r *http.Request) {
	req := new(MintToCheckedRequest)
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

	mintInfo, err := chain.Cli.AccountInfo(r.Context(), req.MintKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read mint: %s", err))
		return
	}
	if mintInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}
	owner, err := types.NewPublicKeyFromBase58(mintInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint owner: %s", err))
		return
	}
	mint, err := core.DecodeMint(owner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if !owner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"mint: %s is owned by %s, not %s", req.MintKey(), owner, req.TokenProgramID()))
		return
	}
	if mint.Decimals != req.ToDecimals() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"decimals: %d does not match the mint's %d", req.ToDecimals(), mint.Decimals))
		return
	}
	if !mint.Mintable() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s has no mint authority left", req.MintKey()))
		return
	}
	if mint.MintAuthority.IsNil() || !mint.MintAuthority.Equal(req.AuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is not the mint authority of %s", req.AuthorityKey(), req.MintKey()))
		return
	}

	destInfo, err := chain.Cli.AccountInfo(r.Context(), req.DestinationKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read destination: %s", err))
		return
	}
	if destInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s does not exist", req.DestinationKey()))
		return
	}
	destData, err := destInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination: %s", err))
		return
	}
	destOwner, err := types.NewPublicKeyFromBase58(destInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination owner: %s", err))
		return
	}
	if !destOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"destination: %s is owned by %s, not %s", req.DestinationKey(), destOwner, req.TokenProgramID()))
		return
	}
	destAccount, err := core.DecodeTokenAccount(destOwner, destData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s", err))
		return
	}
	if !destAccount.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"destination: %s holds %s, not %s", req.DestinationKey(), destAccount.Mint, req.MintKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info, err := chain.Cli.AccountInfo(r.Context(), req.AuthorityKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read authority: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s does not exist", req.AuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s: %s", req.AuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.MintToChecked(req.MintKey(), req.DestinationKey(), req.AuthorityKey(), req.ToMultisigSigners(), req.ToAmount(), req.ToDecimals())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	// Minting moves no lamports of its own, so the fee payer's balance is the
	// only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewMintToCheckedResponse(
		tx, raw, messageBytes,
		req.MintKey(), req.DestinationKey(), req.AuthorityKey(), req.TokenProgramID(), nonceAuthority,
		req.ToAmount(), req.ToDecimals(), fee,
	))
}

// TransferChecked godoc
// @Summary      Move a balance between two token accounts of the same mint
// @Description  Transfers between token accounts, never to a wallet address directly. decimals is checked against the mint rather than filled in from it, catching a client that formatted amount against the wrong decimals as a 400 instead of an on-chain failure. authority must be the source account's owner, or its delegate for no more than the delegated amount.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                    true  "Cluster name"
// @Param        X-Chain-Network  header    string                    true  "Cluster network"
// @Param        body             body      TransferCheckedRequest    true  "Transfer parameters"
// @Success      200              {object}  TransferCheckedResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/transfer-checked [post]
func (h *TokenTransactionHandler) TransferChecked(w http.ResponseWriter, r *http.Request) {
	req := new(TransferCheckedRequest)
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

	mintInfo, err := chain.Cli.AccountInfo(r.Context(), req.MintKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read mint: %s", err))
		return
	}
	if mintInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}
	mintOwner, err := types.NewPublicKeyFromBase58(mintInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint owner: %s", err))
		return
	}
	if !mintOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if mint.Decimals != req.ToDecimals() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"decimals: %d does not match the mint's %d", req.ToDecimals(), mint.Decimals))
		return
	}

	sourceInfo, err := chain.Cli.AccountInfo(r.Context(), req.SourceKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read source: %s", err))
		return
	}
	if sourceInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source: %s does not exist", req.SourceKey()))
		return
	}
	sourceData, err := sourceInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source: %s", err))
		return
	}
	sourceOwner, err := types.NewPublicKeyFromBase58(sourceInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source owner: %s", err))
		return
	}
	if !sourceOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"source: %s is owned by %s, not %s", req.SourceKey(), sourceOwner, req.TokenProgramID()))
		return
	}
	source, err := core.DecodeTokenAccount(sourceOwner, sourceData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source: %s", err))
		return
	}
	if !source.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"source: %s holds %s, not %s", req.SourceKey(), source.Mint, req.MintKey()))
		return
	}
	if source.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source: %s is frozen", req.SourceKey()))
		return
	}
	if source.Amount < req.ToAmount() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"amount: %d exceeds the source's balance of %d", req.ToAmount(), source.Amount))
		return
	}

	// The authority is the account's owner, or its delegate for no more than
	// what was delegated. Minting checks the mint's authority instead; a
	// transfer spends a balance, so it is the holder's to authorize, not the
	// mint's.
	switch {
	case source.Owner.Equal(req.AuthorityKey()):
	case !source.Delegate.IsNil() && source.Delegate.Equal(req.AuthorityKey()) && req.ToAmount() <= source.Delegated():
	default:
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is neither the owner of %s nor a delegate approved for %d",
			req.AuthorityKey(), req.SourceKey(), req.ToAmount()))
		return
	}

	destInfo, err := chain.Cli.AccountInfo(r.Context(), req.DestinationKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read destination: %s", err))
		return
	}
	if destInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s does not exist", req.DestinationKey()))
		return
	}
	destData, err := destInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination: %s", err))
		return
	}
	destOwner, err := types.NewPublicKeyFromBase58(destInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination owner: %s", err))
		return
	}
	if !destOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"destination: %s is owned by %s, not %s", req.DestinationKey(), destOwner, req.TokenProgramID()))
		return
	}
	destination, err := core.DecodeTokenAccount(destOwner, destData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s", err))
		return
	}
	if !destination.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"destination: %s holds %s, not %s", req.DestinationKey(), destination.Mint, req.MintKey()))
		return
	}
	if destination.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s is frozen", req.DestinationKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info, err := chain.Cli.AccountInfo(r.Context(), req.AuthorityKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read authority: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s does not exist", req.AuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s: %s", req.AuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.TransferChecked(req.SourceKey(), req.MintKey(), req.DestinationKey(), req.AuthorityKey(), req.ToMultisigSigners(), req.ToAmount(), req.ToDecimals())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	// A transfer moves no lamports of its own, so the fee payer's balance is
	// the only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewTransferCheckedResponse(
		tx, raw, messageBytes,
		req.SourceKey(), req.MintKey(), req.DestinationKey(), req.AuthorityKey(), req.TokenProgramID(), nonceAuthority,
		req.ToAmount(), req.ToDecimals(), fee,
	))
}

// BurnChecked godoc
// @Summary      Destroy supply held by a token account
// @Description  Reduces the mint's total supply and the account's balance together. decimals is checked against the mint rather than filled in from it, catching a client that formatted amount against the wrong decimals as a 400 instead of an on-chain failure. authority must be the account's owner, or its delegate for no more than the delegated amount — the mint's own authority has no say over what a holder chooses to burn.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                true  "Cluster name"
// @Param        X-Chain-Network  header    string                true  "Cluster network"
// @Param        body             body      BurnCheckedRequest    true  "Burn parameters"
// @Success      200              {object}  BurnCheckedResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/burn-checked [post]
func (h *TokenTransactionHandler) BurnChecked(w http.ResponseWriter, r *http.Request) {
	req := new(BurnCheckedRequest)
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

	mintInfo, err := chain.Cli.AccountInfo(r.Context(), req.MintKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read mint: %s", err))
		return
	}
	if mintInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}
	mintOwner, err := types.NewPublicKeyFromBase58(mintInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint owner: %s", err))
		return
	}
	if !mintOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if mint.Decimals != req.ToDecimals() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"decimals: %d does not match the mint's %d", req.ToDecimals(), mint.Decimals))
		return
	}

	accountInfo, err := chain.Cli.AccountInfo(r.Context(), req.AccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read account: %s", err))
		return
	}
	if accountInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s does not exist", req.AccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s is owned by %s, not %s", req.AccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s", err))
		return
	}
	if !account.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s holds %s, not %s", req.AccountKey(), account.Mint, req.MintKey()))
		return
	}
	if account.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s is frozen", req.AccountKey()))
		return
	}
	if account.Amount < req.ToAmount() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"amount: %d exceeds the account's balance of %d", req.ToAmount(), account.Amount))
		return
	}

	// The authority is the account's owner, or its delegate for no more than
	// what was delegated. The mint's own authority has no say over what a
	// holder chooses to burn: burning spends a balance, so it is the holder's
	// to authorize.
	switch {
	case account.Owner.Equal(req.AuthorityKey()):
	case !account.Delegate.IsNil() && account.Delegate.Equal(req.AuthorityKey()) && req.ToAmount() <= account.Delegated():
	default:
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is neither the owner of %s nor a delegate approved for %d",
			req.AuthorityKey(), req.AccountKey(), req.ToAmount()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info, err := chain.Cli.AccountInfo(r.Context(), req.AuthorityKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read authority: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s does not exist", req.AuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s: %s", req.AuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.BurnChecked(req.AccountKey(), req.MintKey(), req.AuthorityKey(), req.ToMultisigSigners(), req.ToAmount(), req.ToDecimals())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	// Burning moves no lamports of its own, so the fee payer's balance is the
	// only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewBurnCheckedResponse(
		tx, raw, messageBytes,
		req.AccountKey(), req.MintKey(), req.AuthorityKey(), req.TokenProgramID(), nonceAuthority,
		req.ToAmount(), req.ToDecimals(), fee,
	))
}

// CloseAccount godoc
// @Summary      Close a token account and reclaim its rent
// @Description  The account must already hold no tokens; the balance is not swept, it has to be zero. A wrapped SOL account is the exception, since its lamports are its balance, and closing it is how SOL is unwrapped. authority must be the account's owner or its close authority. The reclaimed lamports go to destination.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                  true  "Cluster name"
// @Param        X-Chain-Network  header    string                  true  "Cluster network"
// @Param        body             body      CloseAccountRequest     true  "Close parameters"
// @Success      200              {object}  CloseAccountResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/close-account [post]
func (h *TokenTransactionHandler) CloseAccount(w http.ResponseWriter, r *http.Request) {
	req := new(CloseAccountRequest)
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

	accountInfo, err := chain.Cli.AccountInfo(r.Context(), req.AccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read account: %s", err))
		return
	}
	if accountInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s does not exist", req.AccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s is owned by %s, not %s", req.AccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s", err))
		return
	}

	// A wrapped SOL account holds its balance as lamports rather than as a
	// separate token amount, so the program lets it close with a nonzero
	// Amount: closing it is how the SOL is unwrapped, not a way to destroy
	// tokens without burning them.
	if !account.IsNative && account.Amount != 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s holds a balance of %d and must be emptied first", req.AccountKey(), account.Amount))
		return
	}

	// The program checks close_authority.unwrap_or(owner): once a close
	// authority is set, it alone may close the account, and the owner who set
	// it can no longer do so directly. This is a replacement, not an added
	// option, which is the same reason revoking a delegation clears it rather
	// than merely adding the owner back beside it.
	requiredAuthority := account.Owner
	if !account.CloseAuthority.IsNil() {
		requiredAuthority = account.CloseAuthority
	}
	if !requiredAuthority.Equal(req.AuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is not the current close authority of %s", req.AuthorityKey(), req.AccountKey()))
		return
	}

	destExists, err := chain.Cli.Exists(r.Context(), req.DestinationKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to check destination: %s", err))
		return
	}
	if !destExists {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s does not exist", req.DestinationKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info, err := chain.Cli.AccountInfo(r.Context(), req.AuthorityKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read authority: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s does not exist", req.AuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s: %s", req.AuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.CloseAccount(req.AccountKey(), req.DestinationKey(), req.AuthorityKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewCloseAccountResponse(
		tx, raw, messageBytes,
		req.AccountKey(), req.DestinationKey(), req.AuthorityKey(), req.TokenProgramID(), nonceAuthority,
		accountInfo.Lamports, fee,
	))
}

// CreateATA godoc
// @Summary      Create the canonical token account for a wallet and mint
// @Description  Derives the associated token address and creates it. The address is not a request field: it follows from wallet, mint, and program, so nothing generates a keypair for it and nothing has to remember it. The account itself does not sign, unlike a keypair token account, because a program derived address has no private key. Fails if the account already exists; use create-ata-idempotent when that is not known in advance.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                            true  "Cluster name"
// @Param        X-Chain-Network  header    string                            true  "Cluster network"
// @Param        body             body      CreateATARequest    true  "Associated account parameters"
// @Success      200              {object}  CreateATAResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/create-ata [post]
func (h *TokenTransactionHandler) CreateATA(w http.ResponseWriter, r *http.Request) {
	req := new(CreateATARequest)
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

	// The mint has to exist and belong to the program that is a seed of the
	// address, or the derived account would be for a mint that is not there.
	mintInfo, err := chain.Cli.AccountInfo(r.Context(), req.MintKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read mint: %s", err))
		return
	}
	if mintInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"mint: %s is owned by %s, not %s", req.MintKey(), mintInfo.Owner, req.TokenProgramID()))
		return
	}

	account, bump, err := core.ATA.Derive(req.WalletKey(), req.MintKey(), req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// The plain create fails on an account that is already there, so the
	// caller learns that here rather than from a rejected transaction.
	exists, err := chain.Cli.Exists(r.Context(), account, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to check associated account: %s", err))
		return
	}
	if exists {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s already exists; use create-ata-idempotent", account))
		return
	}

	ix, err := core.ATA.Create(req.RentPayerKey(), req.WalletKey(), req.MintKey(), req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	// The payer funds a 165-byte token account, the same size a keypair one
	// takes, since being derived changes the address and not the layout.
	rentExempt, err := chain.Cli.MinimumBalanceForRentExemptionToken(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	balance, err := chain.Cli.Balance(r.Context(), req.RentPayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read payer balance: %s", err))
		return
	}

	spent := rentExempt
	if req.RentPayerKey().Equal(req.FeePayerKey()) {
		spent += fee
	}
	if balance < spent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: balance %d lamports does not cover %d lamports", balance, spent))
		return
	}
	if remaining := balance - spent; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.RentPayerKey(), remaining, minRent))
		return
	}

	if !req.RentPayerKey().Equal(req.FeePayerKey()) {
		feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
			return
		}
		if feePayerBalance < fee {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
			return
		}
		if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
			return
		}
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewCreateATAResponse(
		tx, raw, messageBytes,
		account, req.WalletKey(), req.MintKey(), req.TokenProgramID(), nonceAuthority,
		bump, rentExempt, fee,
	))
}

// CreateATAIdempotent godoc
// @Summary      Create the canonical token account, succeeding if it exists
// @Description  Same as create-ata, except the instruction succeeds rather than fails when the account is already there. This is the one to prepend to a transfer: checking first and creating only if absent leaves a window in which somebody else creates it, and the plain create would then fail the whole transaction over an account that exists and is correct.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                            true  "Cluster name"
// @Param        X-Chain-Network  header    string                            true  "Cluster network"
// @Param        body             body      CreateATAIdempotentRequest    true  "Associated account parameters"
// @Success      200              {object}  CreateATAIdempotentResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/create-ata-idempotent [post]
func (h *TokenTransactionHandler) CreateATAIdempotent(w http.ResponseWriter, r *http.Request) {
	req := new(CreateATAIdempotentRequest)
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

	mintInfo, err := chain.Cli.AccountInfo(r.Context(), req.MintKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read mint: %s", err))
		return
	}
	if mintInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"mint: %s is owned by %s, not %s", req.MintKey(), mintInfo.Owner, req.TokenProgramID()))
		return
	}

	account, bump, err := core.ATA.Derive(req.WalletKey(), req.MintKey(), req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// No existence check here, deliberately: tolerating an account that is
	// already there is the entire difference between this endpoint and the
	// plain create.
	exists, err := chain.Cli.Exists(r.Context(), account, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to check associated account: %s", err))
		return
	}

	ix, err := core.ATA.CreateIdempotent(req.RentPayerKey(), req.WalletKey(), req.MintKey(), req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	rentExempt, err := chain.Cli.MinimumBalanceForRentExemptionToken(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	balance, err := chain.Cli.Balance(r.Context(), req.RentPayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read payer balance: %s", err))
		return
	}

	// An account that is already there costs nothing to rent, so requiring the
	// payer to hold what it would have cost would reject a transaction that
	// spends only the fee.
	spent := uint64(0)
	if !exists {
		spent = rentExempt
	}
	if req.RentPayerKey().Equal(req.FeePayerKey()) {
		spent += fee
	}
	if balance < spent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: balance %d lamports does not cover %d lamports", balance, spent))
		return
	}
	if remaining := balance - spent; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.RentPayerKey(), remaining, minRent))
		return
	}

	if !req.RentPayerKey().Equal(req.FeePayerKey()) {
		feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
			return
		}
		if feePayerBalance < fee {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
			return
		}
		if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
			return
		}
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewCreateATAIdempotentResponse(
		tx, raw, messageBytes,
		account, req.WalletKey(), req.MintKey(), req.TokenProgramID(), nonceAuthority,
		bump, rentExempt, fee,
	))
}

// TransferToWallet godoc
// @Summary      Move a balance between the associated token accounts of two wallets
// @Description  Derives both sides' associated token accounts from account and destination and transfers between them, prepending an idempotent create for the destination when it does not exist yet. Both fields are wallet addresses, not token accounts, which is the whole reason this endpoint exists rather than being transfer-checked with a flag: neither side computes an associated address first. The source's associated account is never created, since an account nobody has funded has nothing to send. decimals is checked against the mint rather than filled in from it, catching a client that formatted amount against the wrong decimals as a 400 instead of an on-chain failure. authority must be account's associated account owner, or its delegate for no more than the delegated amount.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                      true  "Cluster name"
// @Param        X-Chain-Network  header    string                      true  "Cluster network"
// @Param        body             body      TransferToWalletRequest     true  "Transfer parameters"
// @Success      200              {object}  TransferToWalletResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/transfer-to-wallet [post]
func (h *TokenTransactionHandler) TransferToWallet(w http.ResponseWriter, r *http.Request) {
	req := new(TransferToWalletRequest)
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

	mintInfo, err := chain.Cli.AccountInfo(r.Context(), req.MintKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read mint: %s", err))
		return
	}
	if mintInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}
	mintOwner, err := types.NewPublicKeyFromBase58(mintInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint owner: %s", err))
		return
	}
	if !mintOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if mint.Decimals != req.ToDecimals() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"decimals: %d does not match the mint's %d", req.ToDecimals(), mint.Decimals))
		return
	}

	// Account's associated token account is derived rather than accepted
	// directly, the same way destination's is below. Unlike destination it is
	// never created here: an account nobody has funded has nothing to send,
	// so a missing source fails rather than being created empty.
	sourceAssociatedAccount, _, err := core.ATA.Derive(req.AccountKey(), req.MintKey(), req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	sourceInfo, err := chain.Cli.AccountInfo(r.Context(), sourceAssociatedAccount, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read source: %s", err))
		return
	}
	if sourceInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s has no associated token account for %s", req.AccountKey(), req.MintKey()))
		return
	}
	sourceData, err := sourceInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source: %s", err))
		return
	}
	sourceOwner, err := types.NewPublicKeyFromBase58(sourceInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source owner: %s", err))
		return
	}
	if !sourceOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s is owned by %s, not %s", sourceAssociatedAccount, sourceOwner, req.TokenProgramID()))
		return
	}
	source, err := core.DecodeTokenAccount(sourceOwner, sourceData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s", err))
		return
	}
	if !source.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s holds %s, not %s", sourceAssociatedAccount, source.Mint, req.MintKey()))
		return
	}
	if source.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s is frozen", sourceAssociatedAccount))
		return
	}
	if source.Amount < req.ToAmount() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"amount: %d exceeds the account's balance of %d", req.ToAmount(), source.Amount))
		return
	}

	// The authority is the account's owner, or its delegate for no more than
	// what was delegated, the same rule transfer-checked applies to any
	// source: a transfer spends a balance, so it is the holder's to
	// authorize.
	switch {
	case source.Owner.Equal(req.AuthorityKey()):
	case !source.Delegate.IsNil() && source.Delegate.Equal(req.AuthorityKey()) && req.ToAmount() <= source.Delegated():
	default:
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is neither the owner of %s nor a delegate approved for %d",
			req.AuthorityKey(), sourceAssociatedAccount, req.ToAmount()))
		return
	}

	destinationAssociatedAccount, _, err := core.ATA.Derive(req.DestinationKey(), req.MintKey(), req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if destinationAssociatedAccount.Equal(sourceAssociatedAccount) {
		handler.WriteError(w, http.StatusBadRequest, "destination: derives to the same associated account as account")
		return
	}

	destExists, err := chain.Cli.Exists(r.Context(), destinationAssociatedAccount, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to check destination: %s", err))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info, err := chain.Cli.AccountInfo(r.Context(), req.AuthorityKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read authority: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s does not exist", req.AuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s: %s", req.AuthorityKey(), err))
			return
		}
	}

	transferIx, err := tokenProgram.TransferChecked(sourceAssociatedAccount, req.MintKey(), destinationAssociatedAccount, req.AuthorityKey(), req.ToMultisigSigners(), req.ToAmount(), req.ToDecimals())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	var instructions types.Instructions
	if destExists {
		instructions = types.NewInstructions(transferIx)
	} else {
		createIx, err := core.ATA.CreateIdempotent(req.RentPayerKey(), req.DestinationKey(), req.MintKey(), req.TokenProgramID())
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		instructions = types.NewInstructions(createIx, transferIx)
	}

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		// A nonce is not among the cluster's recent blockhashes, so pricing the
		// real message comes back as expired. The fee follows from the
		// signature count and any compute budget instructions, never from the
		// blockhash, so the same shape against a live one prices it exactly.
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	// The rent-exemption deposit is only owed when the associated account has
	// to be created. An already-funded destination means this transaction moves
	// nothing but the fee.
	var rentExempt uint64
	if !destExists {
		if rentExempt, err = chain.Cli.MinimumBalanceForRentExemptionToken(r.Context()); err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
			return
		}

		rentPayerBalance, err := chain.Cli.Balance(r.Context(), req.RentPayerKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent payer balance: %s", err))
			return
		}

		spent := rentExempt
		if req.RentPayerKey().Equal(req.FeePayerKey()) {
			spent += fee
		}
		if rentPayerBalance < spent {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: balance %d lamports does not cover %d lamports", rentPayerBalance, spent))
			return
		}
		if remaining := rentPayerBalance - spent; remaining != 0 && remaining < minRent {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.RentPayerKey(), remaining, minRent))
			return
		}
	}

	if destExists || !req.RentPayerKey().Equal(req.FeePayerKey()) {
		feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
			return
		}
		if feePayerBalance < fee {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
			return
		}
		if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
			return
		}
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewTransferToWalletResponse(
		tx, raw, messageBytes,
		req.AccountKey(), sourceAssociatedAccount, req.MintKey(), req.DestinationKey(), destinationAssociatedAccount, req.AuthorityKey(), req.TokenProgramID(), nonceAuthority,
		req.ToAmount(), req.ToDecimals(), !destExists, rentExempt, fee,
	))
}

// ApproveChecked godoc
// @Summary      Grant a delegate limited spending rights over a token account
// @Description  Authorizes delegate to move up to amount from account, on the account owner's behalf. A second approve replaces the delegation entirely rather than adding to it, since the program stores one delegate and one amount, not a list; the owner may still move the whole balance regardless of what a delegate holds. Only the account's owner may approve, never an existing delegate, so re-delegating is not possible through this endpoint. decimals is checked against the mint the same way every other checked endpoint checks it.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                  true  "Cluster name"
// @Param        X-Chain-Network  header    string                  true  "Cluster network"
// @Param        body             body      ApproveCheckedRequest   true  "Delegation parameters"
// @Success      200              {object}  ApproveCheckedResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/approve-checked [post]
func (h *TokenTransactionHandler) ApproveChecked(w http.ResponseWriter, r *http.Request) {
	req := new(ApproveCheckedRequest)
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

	mintInfo, err := chain.Cli.AccountInfo(r.Context(), req.MintKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read mint: %s", err))
		return
	}
	if mintInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}
	mintOwner, err := types.NewPublicKeyFromBase58(mintInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint owner: %s", err))
		return
	}
	if !mintOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if mint.Decimals != req.ToDecimals() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"decimals: %d does not match the mint's %d", req.ToDecimals(), mint.Decimals))
		return
	}

	accountInfo, err := chain.Cli.AccountInfo(r.Context(), req.AccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read account: %s", err))
		return
	}
	if accountInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s does not exist", req.AccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s is owned by %s, not %s", req.AccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s", err))
		return
	}
	if !account.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s holds %s, not %s", req.AccountKey(), account.Mint, req.MintKey()))
		return
	}
	if account.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s is frozen", req.AccountKey()))
		return
	}

	// Only the owner may approve, never an existing delegate: a delegate
	// re-delegating would let it hand its own spending rights to a third
	// party the owner never chose.
	if !account.Owner.Equal(req.AuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is not the owner of %s", req.AuthorityKey(), req.AccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info, err := chain.Cli.AccountInfo(r.Context(), req.AuthorityKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read authority: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s does not exist", req.AuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s: %s", req.AuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.ApproveChecked(req.AccountKey(), req.MintKey(), req.DelegateKey(), req.AuthorityKey(), req.ToMultisigSigners(), req.ToAmount(), req.ToDecimals())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	// Approving moves no lamports of its own, so the fee payer's balance is
	// the only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewApproveCheckedResponse(
		tx, raw, messageBytes,
		req.AccountKey(), req.MintKey(), req.DelegateKey(), req.AuthorityKey(), req.TokenProgramID(), nonceAuthority,
		req.ToAmount(), req.ToDecimals(), fee,
	))
}

// Revoke godoc
// @Summary      Clear whatever delegation an account currently has
// @Description  Revokes an account's delegate and delegated amount, whatever they are, without naming either: the program clears what is stored, so there is nothing to get wrong by naming it. An account with no delegate revokes cleanly too. Only the account's owner may revoke, matching approve-checked's rule that only the owner may grant one.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string          true  "Cluster name"
// @Param        X-Chain-Network  header    string          true  "Cluster network"
// @Param        body             body      RevokeRequest   true  "Revoke parameters"
// @Success      200              {object}  RevokeResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/revoke [post]
func (h *TokenTransactionHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	req := new(RevokeRequest)
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

	accountInfo, err := chain.Cli.AccountInfo(r.Context(), req.AccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read account: %s", err))
		return
	}
	if accountInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s does not exist", req.AccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s is owned by %s, not %s", req.AccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s", err))
		return
	}

	// Only the owner may revoke, the same rule approve-checked applies to
	// granting: a delegate holds no authority over the delegation itself, only
	// over what it was allowed to spend.
	if !account.Owner.Equal(req.AuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is not the owner of %s", req.AuthorityKey(), req.AccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info, err := chain.Cli.AccountInfo(r.Context(), req.AuthorityKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read authority: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s does not exist", req.AuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s: %s", req.AuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.Revoke(req.AccountKey(), req.AuthorityKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	// Revoking moves no lamports of its own, so the fee payer's balance is the
	// only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewRevokeResponse(
		tx, raw, messageBytes,
		req.AccountKey(), req.AuthorityKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// SetMintAuthorityReplace godoc
// @Summary      Replace a mint's mint authority
// @Description  Hands mint_authority to new_authority. The current authority must be the mint's existing mint_authority exactly; there is no delegate concept for this role.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                  true  "Cluster name"
// @Param        X-Chain-Network  header    string                  true  "Cluster network"
// @Param        body             body      SetMintAuthorityReplaceRequest  true  "Authority change parameters"
// @Success      200              {object}  SetMintAuthorityReplaceResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/set-authority/mint/replace [post]
func (h *TokenTransactionHandler) SetMintAuthorityReplace(w http.ResponseWriter, r *http.Request) {
	req := new(SetMintAuthorityReplaceRequest)
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

	mintInfo, err := chain.Cli.AccountInfo(r.Context(), req.MintKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read mint: %s", err))
		return
	}
	if mintInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}
	mintOwner, err := types.NewPublicKeyFromBase58(mintInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint owner: %s", err))
		return
	}
	if !mintOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if !mint.Mintable() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s has no mint authority left to change", req.MintKey()))
		return
	}
	if !mint.MintAuthority.Equal(req.AuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is not the mint authority of %s", req.AuthorityKey(), req.MintKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info, err := chain.Cli.AccountInfo(r.Context(), req.AuthorityKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read authority: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s does not exist", req.AuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s: %s", req.AuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.SetAuthority(req.MintKey(), core.TokenAuthorityMintTokens, req.AuthorityKey(), req.NewAuthorityKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	// Replace a mint's mint authority moves no lamports of its own, so the fee payer's balance is
	// the only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewSetMintAuthorityReplaceResponse(
		tx, raw, messageBytes,
		req.MintKey(), req.AuthorityKey(), req.TokenProgramID(), nonceAuthority, req.NewAuthorityKey(),
		fee,
	))
}

// SetMintAuthorityClear godoc
// @Summary      Remove a mint's mint authority permanently
// @Description  Clears mint_authority to None. This caps the supply forever: the program accepts a None mint_authority, and once it is None nothing can ever sign as that authority again to restore it.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                  true  "Cluster name"
// @Param        X-Chain-Network  header    string                  true  "Cluster network"
// @Param        body             body      SetMintAuthorityClearRequest  true  "Authority change parameters"
// @Success      200              {object}  SetMintAuthorityClearResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/set-authority/mint/clear [post]
func (h *TokenTransactionHandler) SetMintAuthorityClear(w http.ResponseWriter, r *http.Request) {
	req := new(SetMintAuthorityClearRequest)
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

	mintInfo, err := chain.Cli.AccountInfo(r.Context(), req.MintKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read mint: %s", err))
		return
	}
	if mintInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}
	mintOwner, err := types.NewPublicKeyFromBase58(mintInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint owner: %s", err))
		return
	}
	if !mintOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if !mint.Mintable() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s has no mint authority left to change", req.MintKey()))
		return
	}
	if !mint.MintAuthority.Equal(req.AuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is not the mint authority of %s", req.AuthorityKey(), req.MintKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info, err := chain.Cli.AccountInfo(r.Context(), req.AuthorityKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read authority: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s does not exist", req.AuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s: %s", req.AuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.SetAuthority(req.MintKey(), core.TokenAuthorityMintTokens, req.AuthorityKey(), nil, req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	// Remove a mint's mint authority permanently moves no lamports of its own, so the fee payer's balance is
	// the only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewSetMintAuthorityClearResponse(
		tx, raw, messageBytes,
		req.MintKey(), req.AuthorityKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// SetFreezeAuthorityReplace godoc
// @Summary      Replace a mint's freeze authority
// @Description  Hands freeze_authority to new_authority. The current authority must be the mint's existing freeze_authority exactly.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                  true  "Cluster name"
// @Param        X-Chain-Network  header    string                  true  "Cluster network"
// @Param        body             body      SetFreezeAuthorityReplaceRequest  true  "Authority change parameters"
// @Success      200              {object}  SetFreezeAuthorityReplaceResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/set-authority/freeze/replace [post]
func (h *TokenTransactionHandler) SetFreezeAuthorityReplace(w http.ResponseWriter, r *http.Request) {
	req := new(SetFreezeAuthorityReplaceRequest)
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

	mintInfo, err := chain.Cli.AccountInfo(r.Context(), req.MintKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read mint: %s", err))
		return
	}
	if mintInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}
	mintOwner, err := types.NewPublicKeyFromBase58(mintInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint owner: %s", err))
		return
	}
	if !mintOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if !mint.Freezable() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s has no freeze authority left to change", req.MintKey()))
		return
	}
	if !mint.FreezeAuthority.Equal(req.AuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is not the freeze authority of %s", req.AuthorityKey(), req.MintKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info, err := chain.Cli.AccountInfo(r.Context(), req.AuthorityKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read authority: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s does not exist", req.AuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s: %s", req.AuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.SetAuthority(req.MintKey(), core.TokenAuthorityFreezeAccount, req.AuthorityKey(), req.NewAuthorityKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	// Replace a mint's freeze authority moves no lamports of its own, so the fee payer's balance is
	// the only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewSetFreezeAuthorityReplaceResponse(
		tx, raw, messageBytes,
		req.MintKey(), req.AuthorityKey(), req.TokenProgramID(), nonceAuthority, req.NewAuthorityKey(),
		fee,
	))
}

// SetFreezeAuthorityClear godoc
// @Summary      Remove a mint's freeze authority permanently
// @Description  Clears freeze_authority to None. No holder of this mint can ever be frozen afterward, and nothing can restore the capability.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                  true  "Cluster name"
// @Param        X-Chain-Network  header    string                  true  "Cluster network"
// @Param        body             body      SetFreezeAuthorityClearRequest  true  "Authority change parameters"
// @Success      200              {object}  SetFreezeAuthorityClearResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/set-authority/freeze/clear [post]
func (h *TokenTransactionHandler) SetFreezeAuthorityClear(w http.ResponseWriter, r *http.Request) {
	req := new(SetFreezeAuthorityClearRequest)
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

	mintInfo, err := chain.Cli.AccountInfo(r.Context(), req.MintKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read mint: %s", err))
		return
	}
	if mintInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}
	mintOwner, err := types.NewPublicKeyFromBase58(mintInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint owner: %s", err))
		return
	}
	if !mintOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if !mint.Freezable() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s has no freeze authority left to change", req.MintKey()))
		return
	}
	if !mint.FreezeAuthority.Equal(req.AuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is not the freeze authority of %s", req.AuthorityKey(), req.MintKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info, err := chain.Cli.AccountInfo(r.Context(), req.AuthorityKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read authority: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s does not exist", req.AuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s: %s", req.AuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.SetAuthority(req.MintKey(), core.TokenAuthorityFreezeAccount, req.AuthorityKey(), nil, req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	// Remove a mint's freeze authority permanently moves no lamports of its own, so the fee payer's balance is
	// the only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewSetFreezeAuthorityClearResponse(
		tx, raw, messageBytes,
		req.MintKey(), req.AuthorityKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// SetAccountOwnerReplace godoc
// @Summary      Replace a token account's owner
// @Description  Hands the account to new_authority. The current authority must be the account's existing owner exactly, never a delegate. There is no clear variant: the owner field has no None representation on chain, and the program rejects one.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                  true  "Cluster name"
// @Param        X-Chain-Network  header    string                  true  "Cluster network"
// @Param        body             body      SetAccountOwnerReplaceRequest  true  "Authority change parameters"
// @Success      200              {object}  SetAccountOwnerReplaceResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/set-authority/owner/replace [post]
func (h *TokenTransactionHandler) SetAccountOwnerReplace(w http.ResponseWriter, r *http.Request) {
	req := new(SetAccountOwnerReplaceRequest)
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

	accountInfo, err := chain.Cli.AccountInfo(r.Context(), req.AccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read account: %s", err))
		return
	}
	if accountInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s does not exist", req.AccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s is owned by %s, not %s", req.AccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s", err))
		return
	}
	if !account.Owner.Equal(req.AuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s is not the owner of %s", req.AuthorityKey(), req.AccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info, err := chain.Cli.AccountInfo(r.Context(), req.AuthorityKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read authority: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s does not exist", req.AuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s: %s", req.AuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.SetAuthority(req.AccountKey(), core.TokenAuthorityAccountOwner, req.AuthorityKey(), req.NewAuthorityKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	// Replace a token account's owner moves no lamports of its own, so the fee payer's balance is
	// the only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewSetAccountOwnerReplaceResponse(
		tx, raw, messageBytes,
		req.AccountKey(), req.AuthorityKey(), req.TokenProgramID(), nonceAuthority, req.NewAuthorityKey(),
		fee,
	))
}

// SetCloseAuthorityReplace godoc
// @Summary      Replace a token account's close authority
// @Description  Hands close_authority to new_authority. The current authority is whichever one is already recorded: the account's close authority if one is set, otherwise its owner, the same rule close-account itself checks.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                  true  "Cluster name"
// @Param        X-Chain-Network  header    string                  true  "Cluster network"
// @Param        body             body      SetCloseAuthorityReplaceRequest  true  "Authority change parameters"
// @Success      200              {object}  SetCloseAuthorityReplaceResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/set-authority/close/replace [post]
func (h *TokenTransactionHandler) SetCloseAuthorityReplace(w http.ResponseWriter, r *http.Request) {
	req := new(SetCloseAuthorityReplaceRequest)
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

	accountInfo, err := chain.Cli.AccountInfo(r.Context(), req.AccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read account: %s", err))
		return
	}
	if accountInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s does not exist", req.AccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s is owned by %s, not %s", req.AccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s", err))
		return
	}
	// The program checks close_authority.unwrap_or(owner): once a close
	// authority is set, it alone may close the account, and the owner who set
	// it can no longer do so directly. This is a replacement, not an added
	// option, which is the same reason revoking a delegation clears it rather
	// than merely adding the owner back beside it.
	requiredAuthority := account.Owner
	if !account.CloseAuthority.IsNil() {
		requiredAuthority = account.CloseAuthority
	}
	if !requiredAuthority.Equal(req.AuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is not the current close authority of %s", req.AuthorityKey(), req.AccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info, err := chain.Cli.AccountInfo(r.Context(), req.AuthorityKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read authority: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s does not exist", req.AuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s: %s", req.AuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.SetAuthority(req.AccountKey(), core.TokenAuthorityCloseAccount, req.AuthorityKey(), req.NewAuthorityKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	// Replace a token account's close authority moves no lamports of its own, so the fee payer's balance is
	// the only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewSetCloseAuthorityReplaceResponse(
		tx, raw, messageBytes,
		req.AccountKey(), req.AuthorityKey(), req.TokenProgramID(), nonceAuthority, req.NewAuthorityKey(),
		fee,
	))
}

// SetCloseAuthorityClear godoc
// @Summary      Remove a token account's close authority
// @Description  Clears close_authority to None. This is recoverable: the owner never goes away, and close-account already falls back to the owner when no close authority is set, so clearing this only reverts to that default.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                  true  "Cluster name"
// @Param        X-Chain-Network  header    string                  true  "Cluster network"
// @Param        body             body      SetCloseAuthorityClearRequest  true  "Authority change parameters"
// @Success      200              {object}  SetCloseAuthorityClearResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/set-authority/close/clear [post]
func (h *TokenTransactionHandler) SetCloseAuthorityClear(w http.ResponseWriter, r *http.Request) {
	req := new(SetCloseAuthorityClearRequest)
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

	accountInfo, err := chain.Cli.AccountInfo(r.Context(), req.AccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read account: %s", err))
		return
	}
	if accountInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s does not exist", req.AccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s is owned by %s, not %s", req.AccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s", err))
		return
	}
	// The program checks close_authority.unwrap_or(owner): once a close
	// authority is set, it alone may close the account, and the owner who set
	// it can no longer do so directly. This is a replacement, not an added
	// option, which is the same reason revoking a delegation clears it rather
	// than merely adding the owner back beside it.
	requiredAuthority := account.Owner
	if !account.CloseAuthority.IsNil() {
		requiredAuthority = account.CloseAuthority
	}
	if !requiredAuthority.Equal(req.AuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is not the current close authority of %s", req.AuthorityKey(), req.AccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info, err := chain.Cli.AccountInfo(r.Context(), req.AuthorityKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read authority: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s does not exist", req.AuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s: %s", req.AuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.SetAuthority(req.AccountKey(), core.TokenAuthorityCloseAccount, req.AuthorityKey(), nil, req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	// Remove a token account's close authority moves no lamports of its own, so the fee payer's balance is
	// the only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewSetCloseAuthorityClearResponse(
		tx, raw, messageBytes,
		req.AccountKey(), req.AuthorityKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// FreezeAccount godoc
// @Summary      Suspend a token account
// @Description  Freezes a token account, so it rejects transfer, burn, and approve until thawed. The authority is the mint's freeze authority, not the account's owner or any delegate: freezing is a mint-level power to suspend any account holding it, on a different axis from who may spend a balance. Only works on a mint that was initialized with a freeze authority.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                true  "Cluster name"
// @Param        X-Chain-Network  header    string                true  "Cluster network"
// @Param        body             body      FreezeAccountRequest  true  "Freeze parameters"
// @Success      200              {object}  FreezeAccountResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/freeze-account [post]
func (h *TokenTransactionHandler) FreezeAccount(w http.ResponseWriter, r *http.Request) {
	req := new(FreezeAccountRequest)
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

	mintInfo, err := chain.Cli.AccountInfo(r.Context(), req.MintKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read mint: %s", err))
		return
	}
	if mintInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}
	mintOwner, err := types.NewPublicKeyFromBase58(mintInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint owner: %s", err))
		return
	}
	if !mintOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if !mint.Freezable() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s has no freeze authority", req.MintKey()))
		return
	}
	if !mint.FreezeAuthority.Equal(req.AuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is not the freeze authority of %s", req.AuthorityKey(), req.MintKey()))
		return
	}

	accountInfo, err := chain.Cli.AccountInfo(r.Context(), req.AccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read account: %s", err))
		return
	}
	if accountInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s does not exist", req.AccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s is owned by %s, not %s", req.AccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s", err))
		return
	}
	if !account.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s holds %s, not %s", req.AccountKey(), account.Mint, req.MintKey()))
		return
	}
	if account.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s is already frozen", req.AccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info, err := chain.Cli.AccountInfo(r.Context(), req.AuthorityKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read authority: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s does not exist", req.AuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s: %s", req.AuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.FreezeAccount(req.AccountKey(), req.MintKey(), req.AuthorityKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	// Freezing moves no lamports of its own, so the fee payer's balance is the
	// only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewFreezeAccountResponse(
		tx, raw, messageBytes,
		req.AccountKey(), req.MintKey(), req.AuthorityKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// ThawAccount godoc
// @Summary      Resume a suspended token account
// @Description  Reverses FreezeAccount, letting transfer, burn, and approve resume against the account. The authority is the mint's freeze authority, the same rule FreezeAccount applies.
// @Tags         transaction
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string              true  "Cluster name"
// @Param        X-Chain-Network  header    string              true  "Cluster network"
// @Param        body             body      ThawAccountRequest  true  "Thaw parameters"
// @Success      200              {object}  ThawAccountResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/thaw-account [post]
func (h *TokenTransactionHandler) ThawAccount(w http.ResponseWriter, r *http.Request) {
	req := new(ThawAccountRequest)
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

	mintInfo, err := chain.Cli.AccountInfo(r.Context(), req.MintKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read mint: %s", err))
		return
	}
	if mintInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}
	mintOwner, err := types.NewPublicKeyFromBase58(mintInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint owner: %s", err))
		return
	}
	if !mintOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if !mint.Freezable() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s has no freeze authority", req.MintKey()))
		return
	}
	if !mint.FreezeAuthority.Equal(req.AuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"authority: %s is not the freeze authority of %s", req.AuthorityKey(), req.MintKey()))
		return
	}

	accountInfo, err := chain.Cli.AccountInfo(r.Context(), req.AccountKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read account: %s", err))
		return
	}
	if accountInfo == nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s does not exist", req.AccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s is owned by %s, not %s", req.AccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s", err))
		return
	}
	if !account.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
			"account: %s holds %s, not %s", req.AccountKey(), account.Mint, req.MintKey()))
		return
	}
	if !account.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s is not frozen", req.AccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info, err := chain.Cli.AccountInfo(r.Context(), req.AuthorityKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read authority: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s does not exist", req.AuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s: %s", req.AuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.ThawAccount(req.AccountKey(), req.MintKey(), req.AuthorityKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	blockhash, _, err := chain.Cli.LatestBlockhash(r.Context(), rpc.CommitmentFinalized)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to fetch blockhash: %s", err))
		return
	}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.NonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), blockhash, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		info, err := chain.Cli.AccountInfo(r.Context(), req.NonceAccountKey(), rpc.CommitmentConfirmed)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read nonce account: %s", err))
			return
		}
		if info == nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s does not exist", req.NonceAccountKey()))
			return
		}
		if info.Owner != core.System.ID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is owned by %s, and a nonce account is owned by the System Program",
				req.NonceAccountKey(), info.Owner))
			return
		}
		if info.Space != core.NonceAccountSpace {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf(
				"nonce_account: %s is %d bytes, and a nonce account is %d",
				req.NonceAccountKey(), info.Space, core.NonceAccountSpace))
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
		if !nonce.Initialized() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("nonce_account: %s is not initialized", req.NonceAccountKey()))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.NonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), blockhash, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		nonceAuthority = nonce.Authority
	}

	fee, ok, err := chain.Cli.FeeForMessage(r.Context(), priced, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to price message: %s", err))
		return
	}
	if !ok {
		handler.WriteError(w, http.StatusBadRequest, "recent_blockhash has expired")
		return
	}

	// Thawing moves no lamports of its own, so the fee payer's balance is the
	// only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	feePayerBalance, err := chain.Cli.Balance(r.Context(), req.FeePayerKey(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read fee payer balance: %s", err))
		return
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if remaining := feePayerBalance - fee; remaining != 0 && remaining < minRent {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), remaining, minRent))
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

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewThawAccountResponse(
		tx, raw, messageBytes,
		req.AccountKey(), req.MintKey(), req.AuthorityKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}
