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
