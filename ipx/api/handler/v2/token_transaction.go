package v2

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/codec"
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
// @Summary      Fund a new account, sized and owned for an SPL Token mint
// @Description  System CreateAccount only, sized and owned for a mint but not initialized. This is deliberately the low-level half: nothing stops somebody else from initializing the account first, in between this transaction and the next; a caller who wants that race closed should build create+initialize as two instructions in one transaction themselves. Initializing is a separate call: initialize-mint2, or initialize-mint for the original opcode. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-mint-account
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

	// The mint has to reach its own rent-exempt minimum, which is a different
	// number from the one a plain wallet must hold and is resolved before the
	// instruction is built rather than after, since CreateMint takes it as an
	// argument.
	rentExempt, err := chain.Cli.MinimumBalanceForRentExemptionMint(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	// Every account this handler ever needs is read in one round trip.
	// rent_payer and fee_payer are frequently the same key under different
	// roles, and batching rather than fetching each alone is what makes that
	// overlap cheap instead of redundant reads.
	lookups := []*types.PublicKey{
		req.RentPayerKey(),
		req.FeePayerKey(),
		req.MintKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	// Creating a mint that already exists fails on chain, and unlike a
	// transfer to an unfunded address there is no reading of it as intent.
	if accounts[req.MintKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s already exists", req.MintKey()))
		return
	}

	// CreateMint's own CreateAccount moves rent_payer's lamports the same way
	// a plain Transfer does internally, and the runtime rejects that source
	// outright if it carries any data, regardless of who owns it.
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	instruction, err := tokenProgram.CreateMint(req.RentPayerKey(), req.MintKey(), rentExempt)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := []*types.Instruction{instruction}

	// Without a nonce the message is built against the blockhash just fetched
	// and expires with it. With one it is built against the value that account
	// stores and never expires, so which constructor runs is the whole
	// difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	// rent_payer and fee_payer may be the same account wearing two hats, so
	// what each distinct key owes is summed by address rather than checked
	// once per role.
	spent := map[string]uint64{
		req.RentPayerKey().Base58(): 0,
		req.FeePayerKey().Base58():  0,
	}
	spent[req.RentPayerKey().Base58()] += rentExempt
	spent[req.FeePayerKey().Base58()] += fee

	for payer, amount := range spent {
		var balance uint64
		if info := accounts[payer]; info.Exists() {
			balance = info.Lamports
		}
		if balance < amount {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: balance %d does not cover %d", payer, balance, amount))
			return
		}
		if !types.RentExemptAfter(balance, amount, minRent) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: would leave %d lamports, below the %d lamport rent-exemption minimum", payer, balance-amount, minRent))
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
		req.RentPayerKey(), req.FeePayerKey(), req.MintKey(), req.TokenProgramID(), nonceAuthority,
		rentExempt, fee,
	))
}

// InitializeMint godoc
// @Summary      Initialize an already-existing account as an SPL Token mint (original opcode)
// @Description  Raw InitializeMint, the original opcode that carries the rent sysvar as a read-only account alongside mint; the program stopped reading it once rent collection was disabled. See initialize-mint2 for the variant without it. mint must already exist, be owned by program, be at least 82 bytes (Token-2022 extensions may make it larger), and be uninitialized. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-mint-account
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                  true  "Cluster name"
// @Param        X-Chain-Network  header    string                  true  "Cluster network"
// @Param        body             body      InitializeMintRequest    true  "Initialize-mint parameters"
// @Success      200              {object}  InitializeMintResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/initialize-mint [post]
func (h *TokenTransactionHandler) InitializeMint(w http.ResponseWriter, r *http.Request) {
	req := new(InitializeMintRequest)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.MintKey(),
		req.FeePayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist; create it first (see system/create-account)", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is not owned by %s", req.MintKey(), req.TokenProgramID()))
		return
	}
	if mintInfo.Space < core.MintSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is %d bytes, expected at least %d", req.MintKey(), mintInfo.Space, core.MintSpace))
		return
	}

	raw, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("mint: %s %s", req.MintKey(), err))
		return
	}
	// raw may carry Token-2022 extension bytes past core.MintSpace; only the
	// base layout is ever decoded here.
	decoded, err := core.DeserializeMint(raw[:core.MintSpace])
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("mint: %s %s", req.MintKey(), err))
		return
	}
	if decoded.IsInitialized {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is already initialized", req.MintKey()))
		return
	}

	instruction, err := tokenProgram.InitializeMint(req.MintKey(), req.MintAuthorityKey(), req.FreezeAuthorityKey(), req.ToDecimals())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := []*types.Instruction{instruction}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	txRaw, err := tx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode message: %s", err))
		return
	}

	handler.WriteOK(w, NewInitializeMintResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.MintKey(), req.TokenProgramID(), req.MintAuthorityKey(), req.FreezeAuthorityKey(), nonceAuthority,
		req.ToDecimals(), fee,
	))
}

// InitializeMint2 godoc
// @Summary      Initialize an already-existing account as an SPL Token mint
// @Description  Raw InitializeMint2, with no CreateAccount alongside it: mint must already exist, be owned by program, be at least 82 bytes (Token-2022 extensions may make it larger), and be uninitialized. This is the natural pairing for create-mint, which only creates the account and never initializes it; nothing stops somebody else from initializing it first in between, so a caller who wants that race closed has to build create+initialize as two instructions in one transaction themselves. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-mint-account
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                    true  "Cluster name"
// @Param        X-Chain-Network  header    string                    true  "Cluster network"
// @Param        body             body      InitializeMint2Request     true  "Initialize-mint parameters"
// @Success      200              {object}  InitializeMint2Response
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/initialize-mint2 [post]
func (h *TokenTransactionHandler) InitializeMint2(w http.ResponseWriter, r *http.Request) {
	req := new(InitializeMint2Request)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.MintKey(),
		req.FeePayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist; create it first (see system/create-account)", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is not owned by %s", req.MintKey(), req.TokenProgramID()))
		return
	}
	if mintInfo.Space < core.MintSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is %d bytes, expected at least %d", req.MintKey(), mintInfo.Space, core.MintSpace))
		return
	}

	raw, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("mint: %s %s", req.MintKey(), err))
		return
	}
	// raw may carry Token-2022 extension bytes past core.MintSpace; only the
	// base layout is ever decoded here.
	decoded, err := core.DeserializeMint(raw[:core.MintSpace])
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("mint: %s %s", req.MintKey(), err))
		return
	}
	if decoded.IsInitialized {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is already initialized", req.MintKey()))
		return
	}

	instruction, err := tokenProgram.InitializeMint2(req.MintKey(), req.MintAuthorityKey(), req.FreezeAuthorityKey(), req.ToDecimals())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := []*types.Instruction{instruction}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	txRaw, err := tx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode message: %s", err))
		return
	}

	handler.WriteOK(w, NewInitializeMint2Response(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.MintKey(), req.TokenProgramID(), req.MintAuthorityKey(), req.FreezeAuthorityKey(), nonceAuthority,
		req.ToDecimals(), fee,
	))
}

// InitializeAccount godoc
// @Summary      Initialize an already-existing account as an SPL Token holder account (original opcode)
// @Description  Raw InitializeAccount, the original opcode that passes owner as a read-only account and carries the rent sysvar alongside it; the program never checks owner against a signer, and neither is read for anything but its address. See initialize-account3 for the variant without either. token_account must already exist, be owned by program, be at least 165 bytes (Token-2022 extensions may make it larger), and be uninitialized. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-token-account
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                     true  "Cluster name"
// @Param        X-Chain-Network  header    string                     true  "Cluster network"
// @Param        body             body      InitializeAccountRequest   true  "Initialize-account parameters"
// @Success      200              {object}  InitializeAccountResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/initialize-account [post]
func (h *TokenTransactionHandler) InitializeAccount(w http.ResponseWriter, r *http.Request) {
	req := new(InitializeAccountRequest)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.TokenAccountKey(),
		req.MintKey(),
		req.FeePayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintInfo.Owner, req.TokenProgramID()))
		return
	}

	tokenAccountInfo := accounts[req.TokenAccountKey().Base58()]
	if !tokenAccountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist; create it first (see system/create-account)", req.TokenAccountKey()))
		return
	}
	if tokenAccountInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is not owned by %s", req.TokenAccountKey(), req.TokenProgramID()))
		return
	}
	if tokenAccountInfo.Space < core.TokenAccountSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is %d bytes, expected at least %d", req.TokenAccountKey(), tokenAccountInfo.Space, core.TokenAccountSpace))
		return
	}

	raw, err := tokenAccountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("token_account: %s %s", req.TokenAccountKey(), err))
		return
	}
	// raw may carry Token-2022 extension bytes past core.TokenAccountSpace;
	// only the base layout is ever decoded here.
	decoded, err := core.DeserializeTokenAccount(raw[:core.TokenAccountSpace])
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("token_account: %s %s", req.TokenAccountKey(), err))
		return
	}
	if decoded.Initialized() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is already initialized", req.TokenAccountKey()))
		return
	}

	instruction, err := tokenProgram.InitializeAccount(req.TokenAccountKey(), req.MintKey(), req.OwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := []*types.Instruction{instruction}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	txRaw, err := tx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode message: %s", err))
		return
	}

	handler.WriteOK(w, NewInitializeAccountResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.TokenAccountKey(), req.MintKey(), req.OwnerKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// InitializeAccount2 godoc
// @Summary      Initialize an already-existing account as an SPL Token holder account (owner in data)
// @Description  Raw InitializeAccount2: owner rides in the instruction data rather than as an account, dropping the account InitializeAccount carries; the rent sysvar is still read. See initialize-account3 for the variant without it. token_account must already exist, be owned by program, be at least 165 bytes (Token-2022 extensions may make it larger), and be uninitialized. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-token-account
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                      true  "Cluster name"
// @Param        X-Chain-Network  header    string                      true  "Cluster network"
// @Param        body             body      InitializeAccount2Request   true  "Initialize-account parameters"
// @Success      200              {object}  InitializeAccount2Response
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/initialize-account2 [post]
func (h *TokenTransactionHandler) InitializeAccount2(w http.ResponseWriter, r *http.Request) {
	req := new(InitializeAccount2Request)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.TokenAccountKey(),
		req.MintKey(),
		req.FeePayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintInfo.Owner, req.TokenProgramID()))
		return
	}

	tokenAccountInfo := accounts[req.TokenAccountKey().Base58()]
	if !tokenAccountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist; create it first (see system/create-account)", req.TokenAccountKey()))
		return
	}
	if tokenAccountInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is not owned by %s", req.TokenAccountKey(), req.TokenProgramID()))
		return
	}
	if tokenAccountInfo.Space < core.TokenAccountSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is %d bytes, expected at least %d", req.TokenAccountKey(), tokenAccountInfo.Space, core.TokenAccountSpace))
		return
	}

	raw, err := tokenAccountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("token_account: %s %s", req.TokenAccountKey(), err))
		return
	}
	// raw may carry Token-2022 extension bytes past core.TokenAccountSpace;
	// only the base layout is ever decoded here.
	decoded, err := core.DeserializeTokenAccount(raw[:core.TokenAccountSpace])
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("token_account: %s %s", req.TokenAccountKey(), err))
		return
	}
	if decoded.Initialized() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is already initialized", req.TokenAccountKey()))
		return
	}

	instruction, err := tokenProgram.InitializeAccount2(req.TokenAccountKey(), req.MintKey(), req.OwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := []*types.Instruction{instruction}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	txRaw, err := tx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode message: %s", err))
		return
	}

	handler.WriteOK(w, NewInitializeAccount2Response(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.TokenAccountKey(), req.MintKey(), req.OwnerKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// InitializeAccount3 godoc
// @Summary      Initialize an already-existing account as an SPL Token holder account
// @Description  Raw InitializeAccount3: owner rides in the instruction data and the rent sysvar is dropped entirely. This is the natural pairing for create-kta, which only creates the account and never initializes it. token_account must already exist, be owned by program, be at least 165 bytes (Token-2022 extensions may make it larger), and be uninitialized. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-token-account
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                      true  "Cluster name"
// @Param        X-Chain-Network  header    string                      true  "Cluster network"
// @Param        body             body      InitializeAccount3Request   true  "Initialize-account parameters"
// @Success      200              {object}  InitializeAccount3Response
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/initialize-account3 [post]
func (h *TokenTransactionHandler) InitializeAccount3(w http.ResponseWriter, r *http.Request) {
	req := new(InitializeAccount3Request)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.TokenAccountKey(),
		req.MintKey(),
		req.FeePayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintInfo.Owner, req.TokenProgramID()))
		return
	}

	tokenAccountInfo := accounts[req.TokenAccountKey().Base58()]
	if !tokenAccountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist; create it first (see system/create-account)", req.TokenAccountKey()))
		return
	}
	if tokenAccountInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is not owned by %s", req.TokenAccountKey(), req.TokenProgramID()))
		return
	}
	if tokenAccountInfo.Space < core.TokenAccountSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is %d bytes, expected at least %d", req.TokenAccountKey(), tokenAccountInfo.Space, core.TokenAccountSpace))
		return
	}

	raw, err := tokenAccountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("token_account: %s %s", req.TokenAccountKey(), err))
		return
	}
	// raw may carry Token-2022 extension bytes past core.TokenAccountSpace;
	// only the base layout is ever decoded here.
	decoded, err := core.DeserializeTokenAccount(raw[:core.TokenAccountSpace])
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("token_account: %s %s", req.TokenAccountKey(), err))
		return
	}
	if decoded.Initialized() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is already initialized", req.TokenAccountKey()))
		return
	}

	instruction, err := tokenProgram.InitializeAccount3(req.TokenAccountKey(), req.MintKey(), req.OwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := []*types.Instruction{instruction}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	txRaw, err := tx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode message: %s", err))
		return
	}

	handler.WriteOK(w, NewInitializeAccount3Response(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.TokenAccountKey(), req.MintKey(), req.OwnerKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// InitializeWrappedSol godoc
// @Summary      Initialize an already-existing account as a wrapped-SOL holder account
// @Description  Raw InitializeAccount3 with mint fixed to program's own native mint, rather than taken from the request. Classic Token's native mint is the fixed well-known address; Token-2022's is a separate PDA, resolved here rather than hardcoded. There is no create-wrapped-sol or wrap-sol composite: this pairs with create-kta/create-ata the same way initialize-account3 does, and funding it is a plain system/transfer followed by sync-native. token_account must already exist, be owned by program, be at least 165 bytes (Token-2022 extensions may make it larger), and be uninitialized. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-token-account
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                          true  "Cluster name"
// @Param        X-Chain-Network  header    string                          true  "Cluster network"
// @Param        body             body      InitializeWrappedSolRequest    true  "Initialize-wrapped-sol parameters"
// @Success      200              {object}  InitializeWrappedSolResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/initialize-wrapped-sol [post]
func (h *TokenTransactionHandler) InitializeWrappedSol(w http.ResponseWriter, r *http.Request) {
	req := new(InitializeWrappedSolRequest)
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

	// Program alone selects the native mint; nothing about it is a caller
	// choice, so it is resolved here rather than read as a request field.
	nativeMint, err := tokenProgram.NativeMint()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.TokenAccountKey(),
		req.FeePayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	tokenAccountInfo := accounts[req.TokenAccountKey().Base58()]
	if !tokenAccountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist; create it first (see create-kta/create-ata)", req.TokenAccountKey()))
		return
	}
	if tokenAccountInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is not owned by %s", req.TokenAccountKey(), req.TokenProgramID()))
		return
	}
	if tokenAccountInfo.Space < core.TokenAccountSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is %d bytes, expected at least %d", req.TokenAccountKey(), tokenAccountInfo.Space, core.TokenAccountSpace))
		return
	}

	raw, err := tokenAccountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("token_account: %s %s", req.TokenAccountKey(), err))
		return
	}
	// raw may carry Token-2022 extension bytes past core.TokenAccountSpace;
	// only the base layout is ever decoded here.
	decoded, err := core.DeserializeTokenAccount(raw[:core.TokenAccountSpace])
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("token_account: %s %s", req.TokenAccountKey(), err))
		return
	}
	if decoded.Initialized() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is already initialized", req.TokenAccountKey()))
		return
	}

	instruction, err := tokenProgram.InitializeAccount3(req.TokenAccountKey(), nativeMint, req.OwnerKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := []*types.Instruction{instruction}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	txRaw, err := tx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode message: %s", err))
		return
	}

	handler.WriteOK(w, NewInitializeWrappedSolResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.TokenAccountKey(), nativeMint, req.OwnerKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// SyncNative godoc
// @Summary      Recompute a wrapped-SOL account's token balance from its lamports
// @Description  A wrapped-SOL account's amount is not the same field as its lamports: lamports can change independently, by a plain System transfer landing on the account directly, and nothing updates amount when that happens. This is the only instruction that reconciles the two, setting amount to lamports minus the rent-exempt reserve. token_account must already exist, be owned by program, and actually be a wrapped-SOL account — the program rejects one that is not, and this endpoint checks the same thing client-side. There is no authority: recomputing a derived value from what the account already holds needs nobody's permission. estimated_amount in the response is exactly that — an estimate computed from the account's lamports at read time, not the value the program itself will use, which is computed fresh at landing time. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-token-account
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string               true  "Cluster name"
// @Param        X-Chain-Network  header    string               true  "Cluster network"
// @Param        body             body      SyncNativeRequest    true  "Sync-native parameters"
// @Success      200              {object}  SyncNativeResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/sync-native [post]
func (h *TokenTransactionHandler) SyncNative(w http.ResponseWriter, r *http.Request) {
	req := new(SyncNativeRequest)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.TokenAccountKey(),
		req.FeePayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	accountInfo := accounts[req.TokenAccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is owned by %s, not %s", req.TokenAccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account: %s", err))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s", err))
		return
	}
	if !account.IsNative {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is not a wrapped-SOL account", req.TokenAccountKey()))
		return
	}

	var estimatedAmount uint64
	if accountInfo.Lamports > account.RentReserve {
		estimatedAmount = accountInfo.Lamports - account.RentReserve
	}

	instruction, err := tokenProgram.SyncNative(req.TokenAccountKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := []*types.Instruction{instruction}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	txRaw, err := tx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode message: %s", err))
		return
	}

	handler.WriteOK(w, NewSyncNativeResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.TokenAccountKey(), account.Mint, req.TokenProgramID(), nonceAuthority,
		estimatedAmount, fee,
	))
}

// UnwrapLamports godoc
// @Summary      Pull exactly amount lamports out of a wrapped-SOL account without closing it
// @Description  Unlike close-account, source_token_account is never consumed: it stays exactly as it was, still rent-exempt and still wrapping whatever is left — the partial counterpart to closing a wrapped-SOL account entirely. The instruction's amount is an optional u64 with a one-byte tag, not the 4-byte COption tag older instructions use; this endpoint always sends it present, and unwrap-lamports/max always sends it absent. amount must not exceed the wrapped balance. source_token_account_authority must be its owner, or its delegate for no more than the delegated amount — spending wrapped SOL out as raw lamports is a spend, not a close, the same axis transfer-checked and burn-checked use rather than close-account's close_authority.unwrap_or(owner). source_token_account must already exist, be owned by program, and actually be a wrapped-SOL account. destination_token_account receives the unwrapped lamports directly as SOL, not tokens; it need not be a token account at all. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-token-account
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                   true  "Cluster name"
// @Param        X-Chain-Network  header    string                   true  "Cluster network"
// @Param        body             body      UnwrapLamportsRequest    true  "Unwrap-lamports parameters"
// @Success      200              {object}  UnwrapLamportsResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/unwrap-lamports [post]
func (h *TokenTransactionHandler) UnwrapLamports(w http.ResponseWriter, r *http.Request) {
	req := new(UnwrapLamportsRequest)
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

	// Every account this handler ever needs is read in one round trip.
	// source_token_account_authority is always included, whether or not
	// multisig_signers is empty, since fetching it once here is cheaper than
	// a conditional second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.SourceTokenAccountKey(),
		req.FeePayerKey(),
		req.SourceTokenAccountAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	sourceInfo := accounts[req.SourceTokenAccountKey().Base58()]
	if !sourceInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s does not exist", req.SourceTokenAccountKey()))
		return
	}
	sourceOwner, err := types.NewPublicKeyFromBase58(sourceInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account owner: %s", err))
		return
	}
	if !sourceOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s is owned by %s, not %s", req.SourceTokenAccountKey(), sourceOwner, req.TokenProgramID()))
		return
	}
	sourceData, err := sourceInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account: %s", err))
		return
	}
	source, err := core.DecodeTokenAccount(sourceOwner, sourceData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s", err))
		return
	}
	if !source.IsNative {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s is not a wrapped-SOL account", req.SourceTokenAccountKey()))
		return
	}

	if source.Amount < req.ToAmount() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("amount: %d exceeds the source_token_account's balance of %d", req.ToAmount(), source.Amount))
		return
	}

	// source_token_account_authority is the account's owner, or its delegate
	// for no more than what was delegated — spending wrapped SOL out as raw
	// lamports is a spend, not a close, so this follows Transfer/Burn's rule
	// rather than close-account's close_authority.unwrap_or(owner).
	switch {
	case source.Owner.Equal(req.SourceTokenAccountAuthorityKey()):
	case !source.Delegate.IsNil() && source.Delegate.Equal(req.SourceTokenAccountAuthorityKey()) && req.ToAmount() <= source.Delegated():
	default:
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s is neither the owner of %s nor a delegate approved for %d", req.SourceTokenAccountAuthorityKey(), req.SourceTokenAccountKey(), req.ToAmount()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.SourceTokenAccountAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s does not exist", req.SourceTokenAccountAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s: %s", req.SourceTokenAccountAuthorityKey(), err))
			return
		}
	}

	amount := req.ToAmount()
	ix, err := tokenProgram.UnwrapLamports(req.SourceTokenAccountKey(), req.DestinationTokenAccountKey(), req.SourceTokenAccountAuthorityKey(), req.ToMultisigSigners(), &amount)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	// This moves lamports out of source_token_account, not fee_payer, so the
	// fee payer's balance is the only one that has to cover the fee itself.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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

	handler.WriteOK(w, NewUnwrapLamportsResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), req.SourceTokenAccountKey(), req.DestinationTokenAccountKey(), req.SourceTokenAccountAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		req.ToAmount(), fee,
	))
}

// UnwrapLamportsMax godoc
// @Summary      Pull a wrapped-SOL account's entire balance out as lamports without closing it
// @Description  Same as unwrap-lamports, except the instruction's amount goes out absent, which the program reads as the whole wrapped balance. source_token_account is left holding exactly its rent-exempt reserve, still initialized and still wrapped SOL, ready to be funded again — which is what separates this from close-account. source_token_account_authority must be its owner, or its delegate approved for at least the whole balance. estimated_amount in the response is the wrapped balance at read time; the program computes the real figure when this lands. source_token_account must already exist, be owned by program, and actually be a wrapped-SOL account. destination_token_account receives the unwrapped lamports directly as SOL, not tokens; it need not be a token account at all. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-token-account
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                   true  "Cluster name"
// @Param        X-Chain-Network  header    string                   true  "Cluster network"
// @Param        body             body      UnwrapLamportsMaxRequest true  "Unwrap-lamports parameters"
// @Success      200              {object}  UnwrapLamportsMaxResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/unwrap-lamports/max [post]
func (h *TokenTransactionHandler) UnwrapLamportsMax(w http.ResponseWriter, r *http.Request) {
	req := new(UnwrapLamportsMaxRequest)
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

	// Every account this handler ever needs is read in one round trip.
	// source_token_account_authority is always included, whether or not
	// multisig_signers is empty, since fetching it once here is cheaper than
	// a conditional second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.SourceTokenAccountKey(),
		req.FeePayerKey(),
		req.SourceTokenAccountAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	sourceInfo := accounts[req.SourceTokenAccountKey().Base58()]
	if !sourceInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s does not exist", req.SourceTokenAccountKey()))
		return
	}
	sourceOwner, err := types.NewPublicKeyFromBase58(sourceInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account owner: %s", err))
		return
	}
	if !sourceOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s is owned by %s, not %s", req.SourceTokenAccountKey(), sourceOwner, req.TokenProgramID()))
		return
	}
	sourceData, err := sourceInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account: %s", err))
		return
	}
	source, err := core.DecodeTokenAccount(sourceOwner, sourceData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s", err))
		return
	}
	if !source.IsNative {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s is not a wrapped-SOL account", req.SourceTokenAccountKey()))
		return
	}

	if source.Amount == 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s has no wrapped balance", req.SourceTokenAccountKey()))
		return
	}

	// The whole wrapped balance is what moves, so a delegate has to be
	// approved for all of it, the same bound transfer/max applies.
	switch {
	case source.Owner.Equal(req.SourceTokenAccountAuthorityKey()):
	case !source.Delegate.IsNil() && source.Delegate.Equal(req.SourceTokenAccountAuthorityKey()) && source.Amount <= source.Delegated():
	default:
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s is neither the owner of %s nor a delegate approved for %d", req.SourceTokenAccountAuthorityKey(), req.SourceTokenAccountKey(), source.Amount))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.SourceTokenAccountAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s does not exist", req.SourceTokenAccountAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s: %s", req.SourceTokenAccountAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.UnwrapLamports(req.SourceTokenAccountKey(), req.DestinationTokenAccountKey(), req.SourceTokenAccountAuthorityKey(), req.ToMultisigSigners(), nil)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	// This moves lamports out of source_token_account, not fee_payer, so the
	// fee payer's balance is the only one that has to cover the fee itself.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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

	handler.WriteOK(w, NewUnwrapLamportsMaxResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), req.SourceTokenAccountKey(), req.DestinationTokenAccountKey(), req.SourceTokenAccountAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		source.Amount, fee,
	))
}

// InitializeMultisig godoc
// @Summary      Initialize an already-existing account as a Token multisig (original opcode)
// @Description  Raw InitializeMultisig, the original opcode that carries the rent sysvar as a read-only account alongside multisig; the program never reads it for anything else. See initialize-multisig2 for the variant without it. multisig_account must already exist, be owned by program, be exactly 355 bytes, and be uninitialized. Anywhere the Token Program takes an authority, a multisig may stand in for it instead, and the named signers sign in its place. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-multisig
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                       true  "Cluster name"
// @Param        X-Chain-Network  header    string                       true  "Cluster network"
// @Param        body             body      InitializeMultisigRequest    true  "Initialize-multisig parameters"
// @Success      200              {object}  InitializeMultisigResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/initialize-multisig [post]
func (h *TokenTransactionHandler) InitializeMultisig(w http.ResponseWriter, r *http.Request) {
	req := new(InitializeMultisigRequest)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.MultisigAccountKey(),
		req.FeePayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	multisigInfo := accounts[req.MultisigAccountKey().Base58()]
	if !multisigInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("multisig_account: %s does not exist; create it first (see system/create-account)", req.MultisigAccountKey()))
		return
	}
	if multisigInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("multisig_account: %s is not owned by %s", req.MultisigAccountKey(), req.TokenProgramID()))
		return
	}
	if multisigInfo.Space != core.MultisigSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("multisig_account: %s is %d bytes, expected %d", req.MultisigAccountKey(), multisigInfo.Space, core.MultisigSpace))
		return
	}

	raw, err := multisigInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("multisig_account: %s %s", req.MultisigAccountKey(), err))
		return
	}
	decoded, err := core.DeserializeMultisig(raw)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("multisig_account: %s %s", req.MultisigAccountKey(), err))
		return
	}
	if decoded.IsInitialized {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("multisig_account: %s is already initialized", req.MultisigAccountKey()))
		return
	}

	instruction, err := tokenProgram.InitializeMultisig(req.MultisigAccountKey(), req.ToM(), req.SignerKeys())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := []*types.Instruction{instruction}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	txRaw, err := tx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode message: %s", err))
		return
	}

	handler.WriteOK(w, NewInitializeMultisigResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.MultisigAccountKey(), req.TokenProgramID(), nonceAuthority, req.SignerKeys(),
		req.ToM(), fee,
	))
}

// InitializeMultisig2 godoc
// @Summary      Initialize an already-existing account as a Token multisig
// @Description  Raw InitializeMultisig2: the rent sysvar InitializeMultisig reads is dropped. multisig_account must already exist, be owned by program, be exactly 355 bytes, and be uninitialized. Anywhere the Token Program takes an authority, a multisig may stand in for it instead, and the named signers sign in its place. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-multisig
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                        true  "Cluster name"
// @Param        X-Chain-Network  header    string                        true  "Cluster network"
// @Param        body             body      InitializeMultisig2Request    true  "Initialize-multisig parameters"
// @Success      200              {object}  InitializeMultisig2Response
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/initialize-multisig2 [post]
func (h *TokenTransactionHandler) InitializeMultisig2(w http.ResponseWriter, r *http.Request) {
	req := new(InitializeMultisig2Request)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.MultisigAccountKey(),
		req.FeePayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	multisigInfo := accounts[req.MultisigAccountKey().Base58()]
	if !multisigInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("multisig_account: %s does not exist; create it first (see system/create-account)", req.MultisigAccountKey()))
		return
	}
	if multisigInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("multisig_account: %s is not owned by %s", req.MultisigAccountKey(), req.TokenProgramID()))
		return
	}
	if multisigInfo.Space != core.MultisigSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("multisig_account: %s is %d bytes, expected %d", req.MultisigAccountKey(), multisigInfo.Space, core.MultisigSpace))
		return
	}

	raw, err := multisigInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("multisig_account: %s %s", req.MultisigAccountKey(), err))
		return
	}
	decoded, err := core.DeserializeMultisig(raw)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("multisig_account: %s %s", req.MultisigAccountKey(), err))
		return
	}
	if decoded.IsInitialized {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("multisig_account: %s is already initialized", req.MultisigAccountKey()))
		return
	}

	instruction, err := tokenProgram.InitializeMultisig2(req.MultisigAccountKey(), req.ToM(), req.SignerKeys())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := []*types.Instruction{instruction}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	txRaw, err := tx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode message: %s", err))
		return
	}

	handler.WriteOK(w, NewInitializeMultisig2Response(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.MultisigAccountKey(), req.TokenProgramID(), nonceAuthority, req.SignerKeys(),
		req.ToM(), fee,
	))
}

// InitializeImmutableOwner godoc
// @Summary      Permanently lock a token account's owner field
// @Description  Locks token_account's owner field against SetAuthority forever. This is a Token-2022 extension: it needs extension space appended after the classic 165-byte layout, which classic Token accounts never have. On Token-2022 this attaches the real extension; on classic Token, upstream documents this opcode as a no-op, kept only so the Associated Token Account program can call it on either program without branching, so program accepts either. token_account must already exist, be owned by program, be at least 165 bytes, and — critically — still be Uninitialized at the base layout: the program itself requires extensions to attach before initialize-account*/initialize-mint* commits the account, not after, so this has to run first or it fails on chain. Whether the extension space itself is actually reserved is not verified here (Token-2022 extension TLV parsing is its own separate undertaking), so that specific mismatch still fails on chain rather than as a 400. There is no authority: nothing about locking the owner field needs proving. The Associated Token Account program calls this automatically on every account it creates, regardless of program, before its own initialize-account3 equivalent. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-token-account
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                              true  "Cluster name"
// @Param        X-Chain-Network  header    string                              true  "Cluster network"
// @Param        body             body      InitializeImmutableOwnerRequest    true  "Initialize-immutable-owner parameters"
// @Success      200              {object}  InitializeImmutableOwnerResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/initialize-immutable-owner [post]
func (h *TokenTransactionHandler) InitializeImmutableOwner(w http.ResponseWriter, r *http.Request) {
	req := new(InitializeImmutableOwnerRequest)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.TokenAccountKey(),
		req.FeePayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	tokenAccountInfo := accounts[req.TokenAccountKey().Base58()]
	if !tokenAccountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	if tokenAccountInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is not owned by %s", req.TokenAccountKey(), req.TokenProgramID()))
		return
	}
	if tokenAccountInfo.Space < core.TokenAccountSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is %d bytes, expected at least %d", req.TokenAccountKey(), tokenAccountInfo.Space, core.TokenAccountSpace))
		return
	}

	// The base layout has to still be Uninitialized: the program itself
	// requires this (unpack_uninitialized), since extensions have to be
	// attached before InitializeAccount* commits the account, not after. This
	// reads only the base 165 bytes, not the extension TLV data past it,
	// which is enough to answer that one question without a full Token-2022
	// extension parser.
	raw, err := tokenAccountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("token_account: %s %s", req.TokenAccountKey(), err))
		return
	}
	decoded, err := core.DeserializeTokenAccount(raw[:core.TokenAccountSpace])
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("token_account: %s %s", req.TokenAccountKey(), err))
		return
	}
	if decoded.Initialized() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is already initialized; immutable owner has to be set up before initialize-account*, not after", req.TokenAccountKey()))
		return
	}

	instruction, err := tokenProgram.InitializeImmutableOwner(req.TokenAccountKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := []*types.Instruction{instruction}

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	txRaw, err := tx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode message: %s", err))
		return
	}

	handler.WriteOK(w, NewInitializeImmutableOwnerResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.TokenAccountKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// CreateKTA godoc
// @Summary      Fund a new account, sized and owned for a keypair SPL Token holder account (KTA)
// @Description  System CreateAccount only, sized and owned for a holder account but not initialized. This is deliberately the low-level half: nothing stops somebody else from initializing the account first, naming their own wallet as owner, in between this transaction and the next; a caller who wants that race closed should build create+initialize as two instructions in one transaction themselves. Initializing is a separate call: initialize-account3, or initialize-account/initialize-account2 for the original opcodes. This produces a plain keypair account rather than an associated one (see create-ata): the address is whatever key was generated for it, and nothing can rediscover it from the wallet and mint the way an associated token account can be. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-token-account
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                  true  "Cluster name"
// @Param        X-Chain-Network  header    string                  true  "Cluster network"
// @Param        body             body      CreateKTARequest    true  "Token account parameters"
// @Success      200              {object}  CreateKTAResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/create-kta [post]
func (h *TokenTransactionHandler) CreateKTA(w http.ResponseWriter, r *http.Request) {
	req := new(CreateKTARequest)
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

	// The token account has to reach its own rent-exempt minimum, a different
	// number from both a plain wallet's and a mint's, and is resolved before
	// the instruction is built since CreateAccount takes it as an argument.
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

	// Every account this handler ever needs is read in one round trip.
	// rent_payer and fee_payer are frequently the same key under different
	// roles, and batching rather than fetching each alone is what makes that
	// overlap cheap instead of redundant reads.
	lookups := []*types.PublicKey{
		req.RentPayerKey(),
		req.FeePayerKey(),
		req.TokenAccountKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	// Creating an account that already exists fails on chain, and unlike a
	// transfer to an unfunded address there is no reading of it as intent.
	if accounts[req.TokenAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s already exists", req.TokenAccountKey()))
		return
	}

	// CreateAccount's own System CreateAccount moves rent_payer's lamports
	// the same way a plain Transfer does internally, and the runtime rejects
	// that source outright if it carries any data, regardless of who owns it.
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	instruction, err := tokenProgram.CreateAccount(req.RentPayerKey(), req.TokenAccountKey(), rentExempt)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := []*types.Instruction{instruction}

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	// rent_payer and fee_payer may be the same account wearing two hats, so
	// what each distinct key owes is summed by address rather than checked
	// once per role.
	spent := map[string]uint64{
		req.RentPayerKey().Base58(): 0,
		req.FeePayerKey().Base58():  0,
	}
	spent[req.RentPayerKey().Base58()] += rentExempt
	spent[req.FeePayerKey().Base58()] += fee

	for payer, amount := range spent {
		var balance uint64
		if info := accounts[payer]; info.Exists() {
			balance = info.Lamports
		}
		if balance < amount {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: balance %d does not cover %d", payer, balance, amount))
			return
		}
		if !types.RentExemptAfter(balance, amount, minRent) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: would leave %d lamports, below the %d lamport rent-exemption minimum", payer, balance-amount, minRent))
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
	handler.WriteOK(w, NewCreateKTAResponse(
		tx, raw, messageBytes,
		req.RentPayerKey(), req.FeePayerKey(), req.TokenAccountKey(), req.TokenProgramID(), nonceAuthority,
		rentExempt, fee,
	))
}

// CreateMultisig godoc
// @Summary      Fund a new account, sized and owned for a Token multisig
// @Description  System CreateAccount only, sized and owned for a multisig but not initialized. This is deliberately the low-level half, the same as create-mint and create-kta: nothing stops somebody else from initializing the account first, with their own m and signers, in between this transaction and the next; a caller who wants that race closed should build create+initialize as two instructions in one transaction themselves. Initializing is a separate call: initialize-multisig2, or initialize-multisig for the original opcode. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-multisig
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                    true  "Cluster name"
// @Param        X-Chain-Network  header    string                    true  "Cluster network"
// @Param        body             body      CreateMultisigRequest     true  "Multisig parameters"
// @Success      200              {object}  CreateMultisigResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/create-multisig [post]
func (h *TokenTransactionHandler) CreateMultisig(w http.ResponseWriter, r *http.Request) {
	req := new(CreateMultisigRequest)
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

	// The multisig has to reach its own rent-exempt minimum, a different
	// number from a plain wallet's, a mint's, and a token account's, and is
	// resolved before the instruction is built since CreateAccount takes it
	// as an argument.
	rentExempt, err := chain.Cli.MinimumBalanceForRentExemptionMultisig(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	// Every account this handler ever needs is read in one round trip.
	// rent_payer and fee_payer are frequently the same key under different
	// roles, and batching rather than fetching each alone is what makes that
	// overlap cheap instead of redundant reads.
	lookups := []*types.PublicKey{
		req.RentPayerKey(),
		req.FeePayerKey(),
		req.MultisigAccountKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	// Creating an account that already exists fails on chain, and unlike a
	// transfer to an unfunded address there is no reading of it as intent.
	if accounts[req.MultisigAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("multisig_account: %s already exists", req.MultisigAccountKey()))
		return
	}

	// CreateMultisig's own System CreateAccount moves rent_payer's lamports
	// the same way a plain Transfer does internally, and the runtime rejects
	// that source outright if it carries any data, regardless of who owns it.
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	instruction, err := tokenProgram.CreateMultisig(req.RentPayerKey(), req.MultisigAccountKey(), rentExempt)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := []*types.Instruction{instruction}

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	// rent_payer and fee_payer may be the same account wearing two hats, so
	// what each distinct key owes is summed by address rather than checked
	// once per role.
	spent := map[string]uint64{
		req.RentPayerKey().Base58(): 0,
		req.FeePayerKey().Base58():  0,
	}
	spent[req.RentPayerKey().Base58()] += rentExempt
	spent[req.FeePayerKey().Base58()] += fee

	for payer, amount := range spent {
		var balance uint64
		if info := accounts[payer]; info.Exists() {
			balance = info.Lamports
		}
		if balance < amount {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: balance %d does not cover %d", payer, balance, amount))
			return
		}
		if !types.RentExemptAfter(balance, amount, minRent) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: would leave %d lamports, below the %d lamport rent-exemption minimum", payer, balance-amount, minRent))
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
	handler.WriteOK(w, NewCreateMultisigResponse(
		tx, raw, messageBytes,
		req.RentPayerKey(), req.FeePayerKey(), req.MultisigAccountKey(), req.TokenProgramID(), nonceAuthority,
		rentExempt, fee,
	))
}

// Transfer godoc
// @Summary      Move a balance between two token accounts (original opcode)
// @Description  Raw Transfer, the original opcode: neither the mint nor its decimals is named or verified against the accounts, which is exactly the failure mode transfer-checked exists to catch. mint is still resolved server-side from source_token_account's own stored value and reported in the response; destination_token_account is still checked against it. source_token_account_authority must be source_token_account's owner, or its delegate for no more than the delegated amount. This is for compatibility with the original opcode; transfer-checked remains the normal public path. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-transfer
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string             true  "Cluster name"
// @Param        X-Chain-Network  header    string             true  "Cluster network"
// @Param        body             body      TransferRequest    true  "Transfer parameters"
// @Success      200              {object}  TransferResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/transfer [post]
func (h *TokenTransactionHandler) Transfer(w http.ResponseWriter, r *http.Request) {
	req := new(TransferRequest)
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

	// Every account this handler ever needs is read in one round trip.
	// source_token_account_authority is always included, whether or not
	// multisig_signers is empty, since fetching it once here is cheaper than
	// a conditional second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.SourceTokenAccountKey(),
		req.DestinationTokenAccountKey(),
		req.FeePayerKey(),
		req.SourceTokenAccountAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	sourceInfo := accounts[req.SourceTokenAccountKey().Base58()]
	if !sourceInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s does not exist", req.SourceTokenAccountKey()))
		return
	}
	sourceData, err := sourceInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account: %s", err))
		return
	}
	sourceOwner, err := types.NewPublicKeyFromBase58(sourceInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account owner: %s", err))
		return
	}
	if !sourceOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s is owned by %s, not %s", req.SourceTokenAccountKey(), sourceOwner, req.TokenProgramID()))
		return
	}
	source, err := core.DecodeTokenAccount(sourceOwner, sourceData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s", err))
		return
	}
	if source.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s is frozen", req.SourceTokenAccountKey()))
		return
	}
	if source.Amount < req.ToAmount() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("amount: %d exceeds the source_token_account's balance of %d", req.ToAmount(), source.Amount))
		return
	}

	// source_token_account_authority is the account's owner, or its delegate
	// for no more than what was delegated.
	switch {
	case source.Owner.Equal(req.SourceTokenAccountAuthorityKey()):
	case !source.Delegate.IsNil() && source.Delegate.Equal(req.SourceTokenAccountAuthorityKey()) && req.ToAmount() <= source.Delegated():
	default:
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s is neither the owner of %s nor a delegate approved for %d", req.SourceTokenAccountAuthorityKey(), req.SourceTokenAccountKey(), req.ToAmount()))
		return
	}

	destInfo := accounts[req.DestinationTokenAccountKey().Base58()]
	if !destInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s does not exist", req.DestinationTokenAccountKey()))
		return
	}
	destData, err := destInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination_token_account: %s", err))
		return
	}
	destOwner, err := types.NewPublicKeyFromBase58(destInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination_token_account owner: %s", err))
		return
	}
	if !destOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s is owned by %s, not %s", req.DestinationTokenAccountKey(), destOwner, req.TokenProgramID()))
		return
	}
	destination, err := core.DecodeTokenAccount(destOwner, destData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s", err))
		return
	}
	if !destination.Mint.Equal(source.Mint) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s holds %s, not %s", req.DestinationTokenAccountKey(), destination.Mint, source.Mint))
		return
	}
	if destination.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s is frozen", req.DestinationTokenAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.SourceTokenAccountAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s does not exist", req.SourceTokenAccountAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s: %s", req.SourceTokenAccountAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.Transfer(req.SourceTokenAccountKey(), req.DestinationTokenAccountKey(), req.SourceTokenAccountAuthorityKey(), req.ToMultisigSigners(), req.ToAmount())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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

	handler.WriteOK(w, NewTransferResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), req.SourceTokenAccountKey(), source.Mint, req.DestinationTokenAccountKey(), req.SourceTokenAccountAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		req.ToAmount(), fee,
	))
}

// TransferMax godoc
// @Summary      Sweep a token account's entire balance to another token account (original opcode)
// @Description  Same as transfer, except the amount moved is source_token_account's current balance rather than a caller-given one. Neither the mint nor decimals is named or verified against the accounts, the same as transfer; mint is still resolved server-side and reported in the response. Unlike a lamport sweep, source_token_account carries no rent-exemption floor: a token account can hold zero tokens and still exist, so it is always swept all the way to zero, even when it is also fee_payer. This is for compatibility with the original opcode; transfer-checked/max remains the normal public path. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-transfer
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                true  "Cluster name"
// @Param        X-Chain-Network  header    string                true  "Cluster network"
// @Param        body             body      TransferMaxRequest    true  "Transfer parameters"
// @Success      200              {object}  TransferMaxResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/transfer/max [post]
func (h *TokenTransactionHandler) TransferMax(w http.ResponseWriter, r *http.Request) {
	req := new(TransferMaxRequest)
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

	lookups := []*types.PublicKey{
		req.SourceTokenAccountKey(),
		req.DestinationTokenAccountKey(),
		req.FeePayerKey(),
		req.SourceTokenAccountAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	sourceInfo := accounts[req.SourceTokenAccountKey().Base58()]
	if !sourceInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s does not exist", req.SourceTokenAccountKey()))
		return
	}
	sourceData, err := sourceInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account: %s", err))
		return
	}
	sourceOwner, err := types.NewPublicKeyFromBase58(sourceInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account owner: %s", err))
		return
	}
	if !sourceOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s is owned by %s, not %s", req.SourceTokenAccountKey(), sourceOwner, req.TokenProgramID()))
		return
	}
	source, err := core.DecodeTokenAccount(sourceOwner, sourceData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s", err))
		return
	}
	if source.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s is frozen", req.SourceTokenAccountKey()))
		return
	}
	if source.Amount == 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s has no balance", req.SourceTokenAccountKey()))
		return
	}
	amount := source.Amount

	switch {
	case source.Owner.Equal(req.SourceTokenAccountAuthorityKey()):
	case !source.Delegate.IsNil() && source.Delegate.Equal(req.SourceTokenAccountAuthorityKey()) && amount <= source.Delegated():
	default:
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s is neither the owner of %s nor a delegate approved for %d", req.SourceTokenAccountAuthorityKey(), req.SourceTokenAccountKey(), amount))
		return
	}

	destInfo := accounts[req.DestinationTokenAccountKey().Base58()]
	if !destInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s does not exist", req.DestinationTokenAccountKey()))
		return
	}
	destData, err := destInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination_token_account: %s", err))
		return
	}
	destOwner, err := types.NewPublicKeyFromBase58(destInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination_token_account owner: %s", err))
		return
	}
	if !destOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s is owned by %s, not %s", req.DestinationTokenAccountKey(), destOwner, req.TokenProgramID()))
		return
	}
	destination, err := core.DecodeTokenAccount(destOwner, destData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s", err))
		return
	}
	if !destination.Mint.Equal(source.Mint) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s holds %s, not %s", req.DestinationTokenAccountKey(), destination.Mint, source.Mint))
		return
	}
	if destination.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s is frozen", req.DestinationTokenAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.SourceTokenAccountAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s does not exist", req.SourceTokenAccountAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s: %s", req.SourceTokenAccountAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.Transfer(req.SourceTokenAccountKey(), req.DestinationTokenAccountKey(), req.SourceTokenAccountAuthorityKey(), req.ToMultisigSigners(), amount)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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

	handler.WriteOK(w, NewTransferMaxResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), req.SourceTokenAccountKey(), source.Mint, req.DestinationTokenAccountKey(), req.SourceTokenAccountAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		amount, fee,
	))
}

// Approve godoc
// @Summary      Grant a delegate spending rights over a token account (original opcode)
// @Description  Raw Approve, the original opcode: neither the mint nor its decimals is named or verified against the account. mint is still resolved server-side from token_account's own stored value and reported in the response. token_account_owner must be token_account's owner, never an existing delegate. This is for compatibility with the original opcode; approve-checked remains the normal public path. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-delegation
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string            true  "Cluster name"
// @Param        X-Chain-Network  header    string            true  "Cluster network"
// @Param        body             body      ApproveRequest    true  "Approve parameters"
// @Success      200              {object}  ApproveResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/approve [post]
func (h *TokenTransactionHandler) Approve(w http.ResponseWriter, r *http.Request) {
	req := new(ApproveRequest)
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

	// Every account this handler ever needs is read in one round trip.
	// token_account_owner is always included, whether or not
	// multisig_signers is empty, since fetching it once here is cheaper than
	// a conditional second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.TokenAccountKey(),
		req.FeePayerKey(),
		req.TokenAccountOwnerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	accountInfo := accounts[req.TokenAccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is owned by %s, not %s", req.TokenAccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s", err))
		return
	}
	if account.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is frozen", req.TokenAccountKey()))
		return
	}

	// Only the owner may approve, never an existing delegate: a delegate
	// re-delegating would let it hand its own spending rights to a third
	// party the owner never chose.
	if !account.Owner.Equal(req.TokenAccountOwnerKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_owner: %s is not the owner of %s", req.TokenAccountOwnerKey(), req.TokenAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.TokenAccountOwnerKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_owner: %s does not exist", req.TokenAccountOwnerKey()))
			return
		}
		ownerOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_owner owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_owner: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), ownerOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_owner: %s: %s", req.TokenAccountOwnerKey(), err))
			return
		}
	}

	ix, err := tokenProgram.Approve(req.TokenAccountKey(), req.DelegateKey(), req.TokenAccountOwnerKey(), req.ToMultisigSigners(), req.ToAmount())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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

	handler.WriteOK(w, NewApproveResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), req.TokenAccountKey(), account.Mint, req.DelegateKey(), req.TokenAccountOwnerKey(), req.TokenProgramID(), nonceAuthority,
		req.ToAmount(), fee,
	))
}

// ApproveMax godoc
// @Summary      Grant a delegate the maximum representable amount over a token account (original opcode)
// @Description  Same as approve, except no amount is read at all: it grants the maximum representable base-unit amount directly, mirroring approve-checked/max and the standard effectively-unlimited approval pattern. Neither the mint nor decimals is named or verified against the account, the same as approve; mint is still resolved server-side and reported in the response. token_account_owner must be token_account's owner, never an existing delegate. This is for compatibility with the original opcode; approve-checked/max remains the normal public path. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-delegation
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string               true  "Cluster name"
// @Param        X-Chain-Network  header    string               true  "Cluster network"
// @Param        body             body      ApproveMaxRequest    true  "Approve parameters"
// @Success      200              {object}  ApproveMaxResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/approve/max [post]
func (h *TokenTransactionHandler) ApproveMax(w http.ResponseWriter, r *http.Request) {
	req := new(ApproveMaxRequest)
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

	lookups := []*types.PublicKey{
		req.TokenAccountKey(),
		req.FeePayerKey(),
		req.TokenAccountOwnerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	accountInfo := accounts[req.TokenAccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is owned by %s, not %s", req.TokenAccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s", err))
		return
	}
	if account.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is frozen", req.TokenAccountKey()))
		return
	}

	if !account.Owner.Equal(req.TokenAccountOwnerKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_owner: %s is not the owner of %s", req.TokenAccountOwnerKey(), req.TokenAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.TokenAccountOwnerKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_owner: %s does not exist", req.TokenAccountOwnerKey()))
			return
		}
		ownerOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_owner owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_owner: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), ownerOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_owner: %s: %s", req.TokenAccountOwnerKey(), err))
			return
		}
	}

	ix, err := tokenProgram.Approve(req.TokenAccountKey(), req.DelegateKey(), req.TokenAccountOwnerKey(), req.ToMultisigSigners(), math.MaxUint64)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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

	handler.WriteOK(w, NewApproveMaxResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), req.TokenAccountKey(), account.Mint, req.DelegateKey(), req.TokenAccountOwnerKey(), req.TokenProgramID(), nonceAuthority,
		math.MaxUint64, fee,
	))
}

// MintTo godoc
// @Summary      Create new supply into an existing token account (original opcode)
// @Description  Raw MintTo, the original opcode: decimals is neither named nor verified against the mint. mint_authority must be mint's own mint authority. This is for compatibility with the original opcode; mint-to-checked remains the normal public path. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-supply
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string          true  "Cluster name"
// @Param        X-Chain-Network  header    string          true  "Cluster network"
// @Param        body             body      MintToRequest   true  "Mint parameters"
// @Success      200              {object}  MintToResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/mint-to [post]
func (h *TokenTransactionHandler) MintTo(w http.ResponseWriter, r *http.Request) {
	req := new(MintToRequest)
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

	// Every account this handler ever needs is read in one round trip.
	// mint_authority is always included, whether or not multisig_signers is
	// empty, since fetching it once here is cheaper than a conditional
	// second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.MintKey(),
		req.TokenAccountKey(),
		req.FeePayerKey(),
		req.MintAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), owner, req.TokenProgramID()))
		return
	}
	if !mint.Mintable() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s has no mint authority left", req.MintKey()))
		return
	}
	if mint.MintAuthority.IsNil() || !mint.MintAuthority.Equal(req.MintAuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint_authority: %s is not the mint authority of %s", req.MintAuthorityKey(), req.MintKey()))
		return
	}

	destInfo := accounts[req.TokenAccountKey().Base58()]
	if !destInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	destData, err := destInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account: %s", err))
		return
	}
	destOwner, err := types.NewPublicKeyFromBase58(destInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination owner: %s", err))
		return
	}
	if !destOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is owned by %s, not %s", req.TokenAccountKey(), destOwner, req.TokenProgramID()))
		return
	}
	destAccount, err := core.DecodeTokenAccount(destOwner, destData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s", err))
		return
	}
	if !destAccount.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s holds %s, not %s", req.TokenAccountKey(), destAccount.Mint, req.MintKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.MintAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint_authority: %s does not exist", req.MintAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint_authority: %s: %s", req.MintAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.MintTo(req.MintKey(), req.TokenAccountKey(), req.MintAuthorityKey(), req.ToMultisigSigners(), req.ToAmount())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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

	handler.WriteOK(w, NewMintToResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), req.MintKey(), req.TokenAccountKey(), req.MintAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		req.ToAmount(), fee,
	))
}

// Burn godoc
// @Summary      Destroy supply held by a token account (original opcode)
// @Description  Raw Burn, the original opcode: decimals is neither named nor verified against the mint. token_account_authority must be token_account's owner, or its delegate for no more than the delegated amount. This is for compatibility with the original opcode; burn-checked remains the normal public path. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-supply
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string        true  "Cluster name"
// @Param        X-Chain-Network  header    string        true  "Cluster network"
// @Param        body             body      BurnRequest   true  "Burn parameters"
// @Success      200              {object}  BurnResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/burn [post]
func (h *TokenTransactionHandler) Burn(w http.ResponseWriter, r *http.Request) {
	req := new(BurnRequest)
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

	// Every account this handler ever needs is read in one round trip.
	// token_account_authority is always included, whether or not
	// multisig_signers is empty, since fetching it once here is cheaper than
	// a conditional second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.MintKey(),
		req.TokenAccountKey(),
		req.FeePayerKey(),
		req.TokenAccountAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	mintOwner, err := types.NewPublicKeyFromBase58(mintInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint owner: %s", err))
		return
	}
	if !mintOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}

	accountInfo := accounts[req.TokenAccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is owned by %s, not %s", req.TokenAccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s", err))
		return
	}
	if !account.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s holds %s, not %s", req.TokenAccountKey(), account.Mint, req.MintKey()))
		return
	}
	if account.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is frozen", req.TokenAccountKey()))
		return
	}
	if account.Amount < req.ToAmount() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("amount: %d exceeds the token_account's balance of %d", req.ToAmount(), account.Amount))
		return
	}

	// token_account_authority is the account's owner, or its delegate for no
	// more than what was delegated.
	switch {
	case account.Owner.Equal(req.TokenAccountAuthorityKey()):
	case !account.Delegate.IsNil() && account.Delegate.Equal(req.TokenAccountAuthorityKey()) && req.ToAmount() <= account.Delegated():
	default:
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_authority: %s is neither the owner of %s nor a delegate approved for %d", req.TokenAccountAuthorityKey(), req.TokenAccountKey(), req.ToAmount()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.TokenAccountAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_authority: %s does not exist", req.TokenAccountAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_authority: %s: %s", req.TokenAccountAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.Burn(req.TokenAccountKey(), req.MintKey(), req.TokenAccountAuthorityKey(), req.ToMultisigSigners(), req.ToAmount())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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

	handler.WriteOK(w, NewBurnResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), req.TokenAccountKey(), req.MintKey(), req.TokenAccountAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		req.ToAmount(), fee,
	))
}

// BurnMax godoc
// @Summary      Destroy a token account's entire balance (original opcode)
// @Description  Same as burn, except the amount destroyed is token_account's current balance rather than a caller-given one. decimals is neither named nor verified against the mint, the same as burn. Unlike a lamport sweep, token_account carries no rent-exemption floor tied to its token balance, so it is always swept all the way to zero. This is for compatibility with the original opcode; burn-checked/max remains the normal public path. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-supply
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string            true  "Cluster name"
// @Param        X-Chain-Network  header    string            true  "Cluster network"
// @Param        body             body      BurnMaxRequest    true  "Burn parameters"
// @Success      200              {object}  BurnMaxResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/burn/max [post]
func (h *TokenTransactionHandler) BurnMax(w http.ResponseWriter, r *http.Request) {
	req := new(BurnMaxRequest)
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

	lookups := []*types.PublicKey{
		req.MintKey(),
		req.TokenAccountKey(),
		req.FeePayerKey(),
		req.TokenAccountAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	mintOwner, err := types.NewPublicKeyFromBase58(mintInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint owner: %s", err))
		return
	}
	if !mintOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}

	accountInfo := accounts[req.TokenAccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is owned by %s, not %s", req.TokenAccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s", err))
		return
	}
	if !account.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s holds %s, not %s", req.TokenAccountKey(), account.Mint, req.MintKey()))
		return
	}
	if account.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is frozen", req.TokenAccountKey()))
		return
	}
	if account.Amount == 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s has no balance", req.TokenAccountKey()))
		return
	}
	amount := account.Amount

	switch {
	case account.Owner.Equal(req.TokenAccountAuthorityKey()):
	case !account.Delegate.IsNil() && account.Delegate.Equal(req.TokenAccountAuthorityKey()) && amount <= account.Delegated():
	default:
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_authority: %s is neither the owner of %s nor a delegate approved for %d", req.TokenAccountAuthorityKey(), req.TokenAccountKey(), amount))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.TokenAccountAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_authority: %s does not exist", req.TokenAccountAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_authority: %s: %s", req.TokenAccountAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.Burn(req.TokenAccountKey(), req.MintKey(), req.TokenAccountAuthorityKey(), req.ToMultisigSigners(), amount)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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

	handler.WriteOK(w, NewBurnMaxResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), req.TokenAccountKey(), req.MintKey(), req.TokenAccountAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		amount, fee,
	))
}

// MintToChecked godoc
// @Summary      Mint new supply into a token account
// @Description  Creates new supply and credits an existing token account. decimals is checked against the mint rather than filled in from it, which is what catches a client that formatted amount against the wrong decimals as a 400 instead of an on-chain failure. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-supply
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

	// Every account this handler ever needs is read in one round trip.
	// authority is always included, whether or not multisig_signers is
	// empty, since fetching it once here is cheaper than a conditional
	// second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.MintKey(),
		req.TokenAccountKey(),
		req.FeePayerKey(),
		req.MintAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), owner, req.TokenProgramID()))
		return
	}
	if mint.Decimals != req.ToDecimals() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("decimals: %d does not match the mint's %d", req.ToDecimals(), mint.Decimals))
		return
	}
	if !mint.Mintable() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s has no mint authority left", req.MintKey()))
		return
	}
	if mint.MintAuthority.IsNil() || !mint.MintAuthority.Equal(req.MintAuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint_authority: %s is not the mint authority of %s", req.MintAuthorityKey(), req.MintKey()))
		return
	}

	destInfo := accounts[req.TokenAccountKey().Base58()]
	if !destInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	destData, err := destInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account: %s", err))
		return
	}
	destOwner, err := types.NewPublicKeyFromBase58(destInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination owner: %s", err))
		return
	}
	if !destOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is owned by %s, not %s", req.TokenAccountKey(), destOwner, req.TokenProgramID()))
		return
	}
	destAccount, err := core.DecodeTokenAccount(destOwner, destData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s", err))
		return
	}
	if !destAccount.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s holds %s, not %s", req.TokenAccountKey(), destAccount.Mint, req.MintKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.MintAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint_authority: %s does not exist", req.MintAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint_authority: %s: %s", req.MintAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.MintToChecked(req.MintKey(), req.TokenAccountKey(), req.MintAuthorityKey(), req.ToMultisigSigners(), req.ToAmount(), req.ToDecimals())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
		req.FeePayerKey(), req.MintKey(), req.TokenAccountKey(), req.MintAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		req.ToAmount(), req.ToDecimals(), fee,
	))
}

// TransferChecked godoc
// @Summary      Move a balance between two token accounts of the same mint
// @Description  Transfers between token accounts, never to a wallet address directly. decimals is checked against the mint rather than filled in from it, catching a client that formatted amount against the wrong decimals as a 400 instead of an on-chain failure. source_token_account_authority must be source_token_account's owner, or its delegate for no more than the delegated amount. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-transfer
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

	// Every account this handler ever needs is read in one round trip.
	// source_token_account_authority is always included, whether or not
	// multisig_signers is empty, since fetching it once here is cheaper than
	// a conditional second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.MintKey(),
		req.SourceTokenAccountKey(),
		req.DestinationTokenAccountKey(),
		req.FeePayerKey(),
		req.SourceTokenAccountAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if mint.Decimals != req.ToDecimals() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("decimals: %d does not match the mint's %d", req.ToDecimals(), mint.Decimals))
		return
	}

	sourceInfo := accounts[req.SourceTokenAccountKey().Base58()]
	if !sourceInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s does not exist", req.SourceTokenAccountKey()))
		return
	}
	sourceData, err := sourceInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account: %s", err))
		return
	}
	sourceOwner, err := types.NewPublicKeyFromBase58(sourceInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account owner: %s", err))
		return
	}
	if !sourceOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s is owned by %s, not %s", req.SourceTokenAccountKey(), sourceOwner, req.TokenProgramID()))
		return
	}
	source, err := core.DecodeTokenAccount(sourceOwner, sourceData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s", err))
		return
	}
	if !source.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s holds %s, not %s", req.SourceTokenAccountKey(), source.Mint, req.MintKey()))
		return
	}
	if source.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s is frozen", req.SourceTokenAccountKey()))
		return
	}
	if source.Amount < req.ToAmount() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("amount: %d exceeds the source_token_account's balance of %d", req.ToAmount(), source.Amount))
		return
	}

	// source_token_account_authority is the account's owner, or its delegate
	// for no more than what was delegated. Minting checks the mint's
	// authority instead; a transfer spends a balance, so it is the holder's
	// to authorize, not the mint's.
	switch {
	case source.Owner.Equal(req.SourceTokenAccountAuthorityKey()):
	case !source.Delegate.IsNil() && source.Delegate.Equal(req.SourceTokenAccountAuthorityKey()) && req.ToAmount() <= source.Delegated():
	default:
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s is neither the owner of %s nor a delegate approved for %d", req.SourceTokenAccountAuthorityKey(), req.SourceTokenAccountKey(), req.ToAmount()))
		return
	}

	destInfo := accounts[req.DestinationTokenAccountKey().Base58()]
	if !destInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s does not exist", req.DestinationTokenAccountKey()))
		return
	}
	destData, err := destInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination_token_account: %s", err))
		return
	}
	destOwner, err := types.NewPublicKeyFromBase58(destInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination_token_account owner: %s", err))
		return
	}
	if !destOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s is owned by %s, not %s", req.DestinationTokenAccountKey(), destOwner, req.TokenProgramID()))
		return
	}
	destination, err := core.DecodeTokenAccount(destOwner, destData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s", err))
		return
	}
	if !destination.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s holds %s, not %s", req.DestinationTokenAccountKey(), destination.Mint, req.MintKey()))
		return
	}
	if destination.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s is frozen", req.DestinationTokenAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.SourceTokenAccountAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s does not exist", req.SourceTokenAccountAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s: %s", req.SourceTokenAccountAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.TransferChecked(req.SourceTokenAccountKey(), req.MintKey(), req.DestinationTokenAccountKey(), req.SourceTokenAccountAuthorityKey(), req.ToMultisigSigners(), req.ToAmount(), req.ToDecimals())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
		req.FeePayerKey(), req.SourceTokenAccountKey(), req.MintKey(), req.DestinationTokenAccountKey(), req.SourceTokenAccountAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		req.ToAmount(), req.ToDecimals(), fee,
	))
}

// TransferCheckedMax godoc
// @Summary      Sweep a token account's entire balance to another token account
// @Description  Same as transfer-checked, except the amount moved is source_token_account's current balance rather than a caller-given one. decimals is never a request field, since there is no client-computed amount to protect against a wrong decimals assumption; the mint's own value is used to build the instruction directly. Unlike a lamport sweep, source_token_account carries no rent-exemption floor: a token account can hold zero tokens and still exist, so it is always swept all the way to zero, even when it is also fee_payer. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-transfer
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                      true  "Cluster name"
// @Param        X-Chain-Network  header    string                      true  "Cluster network"
// @Param        body             body      TransferCheckedMaxRequest   true  "Transfer parameters"
// @Success      200              {object}  TransferCheckedMaxResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/transfer-checked/max [post]
func (h *TokenTransactionHandler) TransferCheckedMax(w http.ResponseWriter, r *http.Request) {
	req := new(TransferCheckedMaxRequest)
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

	// Every account this handler ever needs is read in one round trip.
	// source_token_account_authority is always included, whether or not
	// multisig_signers is empty, since fetching it once here is cheaper than
	// a conditional second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.MintKey(),
		req.SourceTokenAccountKey(),
		req.DestinationTokenAccountKey(),
		req.FeePayerKey(),
		req.SourceTokenAccountAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}

	sourceInfo := accounts[req.SourceTokenAccountKey().Base58()]
	if !sourceInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s does not exist", req.SourceTokenAccountKey()))
		return
	}
	sourceData, err := sourceInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account: %s", err))
		return
	}
	sourceOwner, err := types.NewPublicKeyFromBase58(sourceInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account owner: %s", err))
		return
	}
	if !sourceOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s is owned by %s, not %s", req.SourceTokenAccountKey(), sourceOwner, req.TokenProgramID()))
		return
	}
	source, err := core.DecodeTokenAccount(sourceOwner, sourceData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s", err))
		return
	}
	if !source.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s holds %s, not %s", req.SourceTokenAccountKey(), source.Mint, req.MintKey()))
		return
	}
	if source.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s is frozen", req.SourceTokenAccountKey()))
		return
	}
	if source.Amount == 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s has no balance", req.SourceTokenAccountKey()))
		return
	}
	amount := source.Amount

	// source_token_account_authority is the account's owner, or its delegate
	// for no more than what was delegated. Minting checks the mint's
	// authority instead; a transfer spends a balance, so it is the holder's
	// to authorize, not the mint's.
	switch {
	case source.Owner.Equal(req.SourceTokenAccountAuthorityKey()):
	case !source.Delegate.IsNil() && source.Delegate.Equal(req.SourceTokenAccountAuthorityKey()) && amount <= source.Delegated():
	default:
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s is neither the owner of %s nor a delegate approved for %d", req.SourceTokenAccountAuthorityKey(), req.SourceTokenAccountKey(), amount))
		return
	}

	destInfo := accounts[req.DestinationTokenAccountKey().Base58()]
	if !destInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s does not exist", req.DestinationTokenAccountKey()))
		return
	}
	destData, err := destInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination_token_account: %s", err))
		return
	}
	destOwner, err := types.NewPublicKeyFromBase58(destInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination_token_account owner: %s", err))
		return
	}
	if !destOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s is owned by %s, not %s", req.DestinationTokenAccountKey(), destOwner, req.TokenProgramID()))
		return
	}
	destination, err := core.DecodeTokenAccount(destOwner, destData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s", err))
		return
	}
	if !destination.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s holds %s, not %s", req.DestinationTokenAccountKey(), destination.Mint, req.MintKey()))
		return
	}
	if destination.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s is frozen", req.DestinationTokenAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.SourceTokenAccountAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s does not exist", req.SourceTokenAccountAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s: %s", req.SourceTokenAccountAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.TransferChecked(req.SourceTokenAccountKey(), req.MintKey(), req.DestinationTokenAccountKey(), req.SourceTokenAccountAuthorityKey(), req.ToMultisigSigners(), amount, mint.Decimals)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
	handler.WriteOK(w, NewTransferCheckedMaxResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), req.SourceTokenAccountKey(), req.MintKey(), req.DestinationTokenAccountKey(), req.SourceTokenAccountAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		amount, mint.Decimals, fee,
	))
}

// BurnChecked godoc
// @Summary      Destroy supply held by a token account
// @Description  Reduces the mint's total supply and token_account's balance together. decimals is checked against the mint rather than filled in from it, catching a client that formatted amount against the wrong decimals as a 400 instead of an on-chain failure. token_account_authority must be token_account's owner, or its delegate for no more than the delegated amount — the mint's own authority has no say over what a holder chooses to burn. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-supply
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

	// Every account this handler ever needs is read in one round trip.
	// token_account_authority is always included, whether or not
	// multisig_signers is empty, since fetching it once here is cheaper than
	// a conditional second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.MintKey(),
		req.TokenAccountKey(),
		req.FeePayerKey(),
		req.TokenAccountAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if mint.Decimals != req.ToDecimals() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("decimals: %d does not match the mint's %d", req.ToDecimals(), mint.Decimals))
		return
	}

	accountInfo := accounts[req.TokenAccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is owned by %s, not %s", req.TokenAccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s", err))
		return
	}
	if !account.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s holds %s, not %s", req.TokenAccountKey(), account.Mint, req.MintKey()))
		return
	}
	if account.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is frozen", req.TokenAccountKey()))
		return
	}
	if account.Amount < req.ToAmount() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("amount: %d exceeds the token_account's balance of %d", req.ToAmount(), account.Amount))
		return
	}

	// token_account_authority is the account's owner, or its delegate for no
	// more than what was delegated. The mint's own authority has no say over
	// what a holder chooses to burn: burning spends a balance, so it is the
	// holder's to authorize.
	switch {
	case account.Owner.Equal(req.TokenAccountAuthorityKey()):
	case !account.Delegate.IsNil() && account.Delegate.Equal(req.TokenAccountAuthorityKey()) && req.ToAmount() <= account.Delegated():
	default:
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_authority: %s is neither the owner of %s nor a delegate approved for %d", req.TokenAccountAuthorityKey(), req.TokenAccountKey(), req.ToAmount()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.TokenAccountAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_authority: %s does not exist", req.TokenAccountAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_authority: %s: %s", req.TokenAccountAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.BurnChecked(req.TokenAccountKey(), req.MintKey(), req.TokenAccountAuthorityKey(), req.ToMultisigSigners(), req.ToAmount(), req.ToDecimals())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
		req.FeePayerKey(), req.TokenAccountKey(), req.MintKey(), req.TokenAccountAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		req.ToAmount(), req.ToDecimals(), fee,
	))
}

// BurnCheckedMax godoc
// @Summary      Destroy a token account's entire balance
// @Description  Same as burn-checked, except the amount destroyed is token_account's current balance rather than a caller-given one. decimals is never a request field, since there is no client-computed amount to protect against a wrong decimals assumption; the mint's own value is used to build the instruction directly. Unlike a lamport sweep, token_account carries no rent-exemption floor tied to its token balance, so it is always swept all the way to zero. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-supply
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                   true  "Cluster name"
// @Param        X-Chain-Network  header    string                   true  "Cluster network"
// @Param        body             body      BurnCheckedMaxRequest    true  "Burn parameters"
// @Success      200              {object}  BurnCheckedMaxResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/burn-checked/max [post]
func (h *TokenTransactionHandler) BurnCheckedMax(w http.ResponseWriter, r *http.Request) {
	req := new(BurnCheckedMaxRequest)
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

	// Every account this handler ever needs is read in one round trip.
	// token_account_authority is always included, whether or not
	// multisig_signers is empty, since fetching it once here is cheaper than
	// a conditional second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.MintKey(),
		req.TokenAccountKey(),
		req.FeePayerKey(),
		req.TokenAccountAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}

	accountInfo := accounts[req.TokenAccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is owned by %s, not %s", req.TokenAccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s", err))
		return
	}
	if !account.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s holds %s, not %s", req.TokenAccountKey(), account.Mint, req.MintKey()))
		return
	}
	if account.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is frozen", req.TokenAccountKey()))
		return
	}
	if account.Amount == 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s has no balance", req.TokenAccountKey()))
		return
	}
	amount := account.Amount

	// token_account_authority is the account's owner, or its delegate for no
	// more than what was delegated. The mint's own authority has no say over
	// what a holder chooses to burn: burning spends a balance, so it is the
	// holder's to authorize.
	switch {
	case account.Owner.Equal(req.TokenAccountAuthorityKey()):
	case !account.Delegate.IsNil() && account.Delegate.Equal(req.TokenAccountAuthorityKey()) && amount <= account.Delegated():
	default:
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_authority: %s is neither the owner of %s nor a delegate approved for %d", req.TokenAccountAuthorityKey(), req.TokenAccountKey(), amount))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.TokenAccountAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_authority: %s does not exist", req.TokenAccountAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_authority: %s: %s", req.TokenAccountAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.BurnChecked(req.TokenAccountKey(), req.MintKey(), req.TokenAccountAuthorityKey(), req.ToMultisigSigners(), amount, mint.Decimals)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
	handler.WriteOK(w, NewBurnCheckedMaxResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), req.TokenAccountKey(), req.MintKey(), req.TokenAccountAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		amount, mint.Decimals, fee,
	))
}

// CloseAccount godoc
// @Summary      Close a token account and reclaim its rent
// @Description  token_account must already hold no tokens; the balance is not swept, it has to be zero. A wrapped SOL account is the exception, since its lamports are its balance, and closing it is how SOL is unwrapped. token_account_close_authority must be token_account's owner or its close authority. The reclaimed lamports go to recipient_account. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-token-account
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

	// Every account this handler ever needs is read in one round trip.
	// token_account_close_authority is always included, whether or not
	// multisig_signers is empty, since fetching it once here is cheaper than
	// a conditional second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.TokenAccountKey(),
		req.RecipientAccountKey(),
		req.FeePayerKey(),
		req.TokenAccountCloseAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	accountInfo := accounts[req.TokenAccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is owned by %s, not %s", req.TokenAccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s", err))
		return
	}

	// A wrapped SOL account holds its balance as lamports rather than as a
	// separate token amount, so the program lets it close with a nonzero
	// Amount: closing it is how the SOL is unwrapped, not a way to destroy
	// tokens without burning them.
	if !account.IsNative && account.Amount != 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s holds a balance of %d and must be emptied first", req.TokenAccountKey(), account.Amount))
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
	if !requiredAuthority.Equal(req.TokenAccountCloseAuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_close_authority: %s is not the current close authority of %s", req.TokenAccountCloseAuthorityKey(), req.TokenAccountKey()))
		return
	}

	if !accounts[req.RecipientAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("recipient_account: %s does not exist", req.RecipientAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.TokenAccountCloseAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_close_authority: %s does not exist", req.TokenAccountCloseAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_close_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_close_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_close_authority: %s: %s", req.TokenAccountCloseAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.CloseAccount(req.TokenAccountKey(), req.RecipientAccountKey(), req.TokenAccountCloseAuthorityKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
		req.FeePayerKey(), req.TokenAccountKey(), req.RecipientAccountKey(), req.TokenAccountCloseAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		accountInfo.Lamports, fee,
	))
}

// CloseMint godoc
// @Summary      Close a Token-2022 mint via its MintCloseAuthority extension
// @Description  Closes mint, reclaiming its rent to recipient_account, authorized by the MintCloseAuthority extension's close_authority -- not mint_authority or freeze_authority. mint must already have zero supply (the program rejects otherwise with MintHasSupply) and must already carry the extension with an authority set (see extensions/mint-close-authority/initialize, or set-authority/replace if it was skipped at initialization time and later granted). This is the same generic CloseAccount instruction (opcode 9) close-account itself sends, since upstream's own processor tries a token account first and falls back to a mint -- the only reason this is a separate endpoint is that close-account's own validation decodes TokenAccount and checks its close_authority field, neither of which describes a mint, so mint's own extension has to be decoded and checked here instead. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-extensions
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string             true  "Cluster name"
// @Param        X-Chain-Network  header    string             true  "Cluster network"
// @Param        body             body      CloseMintRequest   true  "Mint, recipient, close authority, and program"
// @Success      200              {object}  CloseMintResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/extensions/mint-close-authority/close [post]
func (h *TokenTransactionHandler) CloseMint(w http.ResponseWriter, r *http.Request) {
	req := new(CloseMintRequest)
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

	lookups := []*types.PublicKey{
		req.MintKey(),
		req.RecipientAccountKey(),
		req.FeePayerKey(),
		req.CloseAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintInfo.Owner, req.TokenProgramID()))
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
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if mint.Supply != 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s has a supply of %d and must be reduced to zero first", req.MintKey(), mint.Supply))
		return
	}

	currentCloseAuthority, err := core.DecodeMintCloseAuthority(mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if currentCloseAuthority.IsNil() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s has no close authority and can never be closed", req.MintKey()))
		return
	}
	if !currentCloseAuthority.Equal(req.CloseAuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("close_authority: %s is not the close authority of %s", req.CloseAuthorityKey(), req.MintKey()))
		return
	}

	if !accounts[req.RecipientAccountKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("recipient_account: %s does not exist", req.RecipientAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.CloseAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("close_authority: %s does not exist", req.CloseAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode close_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode close_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("close_authority: %s: %s", req.CloseAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.CloseAccount(req.MintKey(), req.RecipientAccountKey(), req.CloseAuthorityKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
	handler.WriteOK(w, NewCloseMintResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), req.MintKey(), req.RecipientAccountKey(), req.CloseAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		mintInfo.Lamports, fee,
	))
}

// WithdrawExcessLamports godoc
// @Summary      Recover a Token-owned account's excess lamports above its rent-exemption minimum
// @Description  Recovers whatever lamports account holds beyond its own rent-exemption minimum, to destination. Unlike close-account, account is never consumed — it stays exactly as it was, rent-exempt and still carrying whatever mint, token, or multisig state it held. This is for the ordinary way an account ends up overfunded: a plain System transfer landing on it by mistake, since System's own Transfer takes any account regardless of who owns it. Which role authority actually has to be depends on what account is (a mint's close authority extension, a token account's close_authority.unwrap_or(owner), or a multisig's own enrolled signers) and this endpoint has no Token-2022 extension parser to settle that ahead of time, so a wrong authority fails on chain rather than as a 400. estimated_recovered in the response is exactly that — an estimate computed from account's balance and size at read time, not the value the program itself will use, which is computed fresh at landing time. This opcode is unverified: confirm it exists on the deployed program before relying on it. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-token-account
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                           true  "Cluster name"
// @Param        X-Chain-Network  header    string                           true  "Cluster network"
// @Param        body             body      WithdrawExcessLamportsRequest   true  "Withdraw-excess-lamports parameters"
// @Success      200              {object}  WithdrawExcessLamportsResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/withdraw-excess-lamports [post]
func (h *TokenTransactionHandler) WithdrawExcessLamports(w http.ResponseWriter, r *http.Request) {
	req := new(WithdrawExcessLamportsRequest)
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

	// Every account this handler ever needs is read in one round trip.
	// authority is always included, whether or not multisig_signers is
	// empty, since fetching it once here is cheaper than a conditional
	// second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.AccountKey(),
		req.DestinationKey(),
		req.FeePayerKey(),
		req.AuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	accountInfo := accounts[req.AccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s does not exist", req.AccountKey()))
		return
	}
	if accountInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s is not owned by %s", req.AccountKey(), req.TokenProgramID()))
		return
	}

	if !accounts[req.DestinationKey().Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s does not exist", req.DestinationKey()))
		return
	}

	// This only verifies that authority, if named, is itself a valid
	// multisig satisfied by signers — a structural check independent of
	// which role account's real type requires, which is not resolved here.
	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.AuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s does not exist", req.AuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("authority: %s: %s", req.AuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.WithdrawExcessLamports(req.AccountKey(), req.DestinationKey(), req.AuthorityKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	// The account's own rent-exemption minimum depends on its actual size,
	// which may include Token-2022 extension bytes past the base layout —
	// this reads exactly what is there rather than assuming core.MintSpace
	// or core.TokenAccountSpace.
	accountRentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), accountInfo.Space, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	var estimatedRecovered uint64
	if accountInfo.Lamports > accountRentExempt {
		estimatedRecovered = accountInfo.Lamports - accountRentExempt
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

	handler.WriteOK(w, NewWithdrawExcessLamportsResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), req.AccountKey(), req.DestinationKey(), req.AuthorityKey(), req.TokenProgramID(), nonceAuthority,
		estimatedRecovered, fee,
	))
}

// CreateATA godoc
// @Summary      Create the canonical token account for an owner and mint
// @Description  Derives the associated token address and creates it. The address is not a request field: it follows from owner, mint, and program, so nothing generates a keypair for it and nothing has to remember it. The account itself does not sign, unlike a keypair token account, because a program derived address has no private key. Fails if the account already exists; use create-ata-idempotent when that is not known in advance. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-ata
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

	associatedTokenAccount, bump, err := core.ATA.Derive(req.OwnerKey(), req.MintKey(), req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Every account this handler ever needs is read in one round trip.
	// rent_payer and fee_payer are frequently the same key under different
	// roles, and batching rather than fetching each alone is what makes that
	// overlap cheap instead of redundant reads.
	lookups := []*types.PublicKey{
		req.MintKey(),
		req.RentPayerKey(),
		req.FeePayerKey(),
		associatedTokenAccount,
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	// The mint has to exist and belong to the program that is a seed of the
	// address, or the derived account would be for a mint that is not there.
	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintInfo.Owner, req.TokenProgramID()))
		return
	}

	// The plain create fails on an account that is already there, so the
	// caller learns that here rather than from a rejected transaction.
	if accounts[associatedTokenAccount.Base58()].Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("associated_token_account: %s already exists; use create-ata-idempotent", associatedTokenAccount))
		return
	}

	// CreateATA moves rent_payer's lamports the same way a plain Transfer
	// does internally, and the runtime rejects that source outright if it
	// carries any data, regardless of who owns it.
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	ix, err := core.ATA.Create(req.RentPayerKey(), req.OwnerKey(), req.MintKey(), req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	// rent_payer and fee_payer may be the same account wearing two hats, so
	// what each distinct key owes is summed by address rather than checked
	// once per role.
	spent := map[string]uint64{
		req.RentPayerKey().Base58(): 0,
		req.FeePayerKey().Base58():  0,
	}
	spent[req.RentPayerKey().Base58()] += rentExempt
	spent[req.FeePayerKey().Base58()] += fee

	for payer, amount := range spent {
		var balance uint64
		if info := accounts[payer]; info.Exists() {
			balance = info.Lamports
		}
		if balance < amount {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: balance %d does not cover %d", payer, balance, amount))
			return
		}
		if !types.RentExemptAfter(balance, amount, minRent) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: would leave %d lamports, below the %d lamport rent-exemption minimum", payer, balance-amount, minRent))
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
		req.RentPayerKey(), req.FeePayerKey(), associatedTokenAccount, req.OwnerKey(), req.MintKey(), req.TokenProgramID(), nonceAuthority,
		bump, rentExempt, fee,
	))
}

// CreateATAIdempotent godoc
// @Summary      Create the canonical token account, succeeding if it exists
// @Description  Same as create-ata, except the instruction succeeds rather than fails when the account is already there. This is the one to prepend to a transfer: checking first and creating only if absent leaves a window in which somebody else creates it, and the plain create would then fail the whole transaction over an account that exists and is correct. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-ata
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

	associatedTokenAccount, bump, err := core.ATA.Derive(req.OwnerKey(), req.MintKey(), req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Every account this handler ever needs is read in one round trip.
	// rent_payer and fee_payer are frequently the same key under different
	// roles, and batching rather than fetching each alone is what makes that
	// overlap cheap instead of redundant reads.
	lookups := []*types.PublicKey{
		req.MintKey(),
		req.RentPayerKey(),
		req.FeePayerKey(),
		associatedTokenAccount,
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintInfo.Owner, req.TokenProgramID()))
		return
	}

	// No existence check here, deliberately: tolerating an account that is
	// already there is the entire difference between this endpoint and the
	// plain create.
	exists := accounts[associatedTokenAccount.Base58()].Exists()

	// CreateATAIdempotent moves rent_payer's lamports the same way a plain
	// Transfer does internally, and the runtime rejects that source outright
	// if it carries any data, regardless of who owns it.
	if accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund an account's creation", req.RentPayerKey()))
		return
	}

	ix, err := core.ATA.CreateIdempotent(req.RentPayerKey(), req.OwnerKey(), req.MintKey(), req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	// rent_payer and fee_payer may be the same account wearing two hats, so
	// what each distinct key owes is summed by address rather than checked
	// once per role. An account that is already there costs nothing to rent,
	// so requiring the payer to hold what it would have cost would reject a
	// transaction that spends only the fee.
	spent := map[string]uint64{
		req.RentPayerKey().Base58(): 0,
		req.FeePayerKey().Base58():  0,
	}
	if !exists {
		spent[req.RentPayerKey().Base58()] += rentExempt
	}
	spent[req.FeePayerKey().Base58()] += fee

	for payer, amount := range spent {
		var balance uint64
		if info := accounts[payer]; info.Exists() {
			balance = info.Lamports
		}
		if balance < amount {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: balance %d does not cover %d", payer, balance, amount))
			return
		}
		if !types.RentExemptAfter(balance, amount, minRent) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: would leave %d lamports, below the %d lamport rent-exemption minimum", payer, balance-amount, minRent))
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
		req.RentPayerKey(), req.FeePayerKey(), associatedTokenAccount, req.OwnerKey(), req.MintKey(), req.TokenProgramID(), nonceAuthority,
		bump, rentExempt, fee,
	))
}

// ATARecoverNested godoc
// @Summary      Recover a nested associated token account
// @Description  Moves the balance out of a nested associated token account — one created by mistakenly deriving from another associated account as if it were a wallet — into wallet's real associated account for the same mint, and closes the nested one. Three addresses are derived internally, none are request fields: owner_account is wallet's associated account for owner_mint (the one mistaken for a wallet), nested_account is owner_account's own associated account for nested_mint (the mistake itself, being closed), and destination is wallet's real associated account for nested_mint (where the balance and reclaimed rent both end up). wallet signs, since only the real owner may authorize closing an account that pays its lamports back there. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-ata
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                      true  "Cluster name"
// @Param        X-Chain-Network  header    string                      true  "Cluster network"
// @Param        body             body      ATARecoverNestedRequest     true  "Recovery parameters"
// @Success      200              {object}  ATARecoverNestedResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/ata/recover-nested [post]
func (h *TokenTransactionHandler) ATARecoverNested(w http.ResponseWriter, r *http.Request) {
	req := new(ATARecoverNestedRequest)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	ownerAccount, _, err := core.ATA.Derive(req.WalletKey(), req.OwnerMintKey(), req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	nestedAccount, _, err := core.ATA.Derive(ownerAccount, req.NestedMintKey(), req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	destination, _, err := core.ATA.Derive(req.WalletKey(), req.NestedMintKey(), req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	lookups := []*types.PublicKey{req.FeePayerKey()}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	ix, err := core.ATA.RecoverNested(req.WalletKey(), req.OwnerMintKey(), req.NestedMintKey(), req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d does not cover %d", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %d lamports, below the %d lamport rent-exemption minimum", feePayerBalance-fee, minRent))
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
	handler.WriteOK(w, NewATARecoverNestedResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), req.WalletKey(), req.OwnerMintKey(), req.NestedMintKey(), req.TokenProgramID(), nonceAuthority,
		ownerAccount, nestedAccount, destination,
		fee,
	))
}

// TransferFromATA godoc
// @Summary      Move a balance from an owner's associated token account to any token account
// @Description  Derives the source's associated token account from owner and mint; destination_token_account is an exact address, keypair or associated, exactly as transfer-checked takes it. The source is never created here: an account nobody has funded has nothing to send, so a missing one fails rather than being created empty. decimals is checked against the mint rather than filled in from it, catching a client that formatted amount against the wrong decimals as a 400 instead of an on-chain failure. source_token_account_authority must be the derived source's owner, or its delegate for no more than the delegated amount. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-ata
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                      true  "Cluster name"
// @Param        X-Chain-Network  header    string                      true  "Cluster network"
// @Param        body             body      TransferFromATARequest      true  "Transfer parameters"
// @Success      200              {object}  TransferFromATAResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/transfer-from-ata [post]
func (h *TokenTransactionHandler) TransferFromATA(w http.ResponseWriter, r *http.Request) {
	req := new(TransferFromATARequest)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	// Owner's associated token account is derived rather than accepted
	// directly. Unlike destination_token_account it is never created here:
	// an account nobody has funded has nothing to send, so a missing source
	// fails rather than being created empty.
	sourceTokenAccount, _, err := core.ATA.Derive(req.OwnerKey(), req.MintKey(), req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if sourceTokenAccount.Equal(req.DestinationTokenAccountKey()) {
		handler.WriteError(w, http.StatusBadRequest, "destination_token_account: derives to the same associated account as owner")
		return
	}

	// Every account this handler ever needs is read in one round trip.
	// source_token_account_authority is always included, whether or not
	// multisig_signers is empty, since fetching it once here is cheaper than
	// a conditional second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.MintKey(),
		sourceTokenAccount,
		req.DestinationTokenAccountKey(),
		req.FeePayerKey(),
		req.SourceTokenAccountAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if mint.Decimals != req.ToDecimals() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("decimals: %d does not match the mint's %d", req.ToDecimals(), mint.Decimals))
		return
	}

	sourceInfo := accounts[sourceTokenAccount.Base58()]
	if !sourceInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("owner: %s has no associated token account for %s", req.OwnerKey(), req.MintKey()))
		return
	}
	sourceData, err := sourceInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode owner's associated token account: %s", err))
		return
	}
	sourceOwner, err := types.NewPublicKeyFromBase58(sourceInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode owner's associated token account owner: %s", err))
		return
	}
	if !sourceOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("owner: %s's associated token account %s is owned by %s, not %s", req.OwnerKey(), sourceTokenAccount, sourceOwner, req.TokenProgramID()))
		return
	}
	source, err := core.DecodeTokenAccount(sourceOwner, sourceData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("owner: %s's associated token account: %s", req.OwnerKey(), err))
		return
	}
	if !source.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("owner: %s's associated token account %s holds %s, not %s", req.OwnerKey(), sourceTokenAccount, source.Mint, req.MintKey()))
		return
	}
	if source.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("owner: %s's associated token account %s is frozen", req.OwnerKey(), sourceTokenAccount))
		return
	}
	if source.Amount < req.ToAmount() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("amount: %d exceeds the owner's associated token account balance of %d", req.ToAmount(), source.Amount))
		return
	}

	// source_token_account_authority is the derived account's owner, or its
	// delegate for no more than what was delegated. Minting checks the
	// mint's authority instead; a transfer spends a balance, so it is the
	// holder's to authorize, not the mint's.
	switch {
	case source.Owner.Equal(req.SourceTokenAccountAuthorityKey()):
	case !source.Delegate.IsNil() && source.Delegate.Equal(req.SourceTokenAccountAuthorityKey()) && req.ToAmount() <= source.Delegated():
	default:
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s is neither the owner of %s nor a delegate approved for %d", req.SourceTokenAccountAuthorityKey(), sourceTokenAccount, req.ToAmount()))
		return
	}

	destInfo := accounts[req.DestinationTokenAccountKey().Base58()]
	if !destInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s does not exist", req.DestinationTokenAccountKey()))
		return
	}
	destData, err := destInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination_token_account: %s", err))
		return
	}
	destOwner, err := types.NewPublicKeyFromBase58(destInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination_token_account owner: %s", err))
		return
	}
	if !destOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s is owned by %s, not %s", req.DestinationTokenAccountKey(), destOwner, req.TokenProgramID()))
		return
	}
	destination, err := core.DecodeTokenAccount(destOwner, destData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s", err))
		return
	}
	if !destination.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s holds %s, not %s", req.DestinationTokenAccountKey(), destination.Mint, req.MintKey()))
		return
	}
	if destination.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s is frozen", req.DestinationTokenAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.SourceTokenAccountAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s does not exist", req.SourceTokenAccountAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s: %s", req.SourceTokenAccountAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.TransferChecked(sourceTokenAccount, req.MintKey(), req.DestinationTokenAccountKey(), req.SourceTokenAccountAuthorityKey(), req.ToMultisigSigners(), req.ToAmount(), req.ToDecimals())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
	handler.WriteOK(w, NewTransferFromATAResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), sourceTokenAccount, req.OwnerKey(), req.MintKey(), req.DestinationTokenAccountKey(), req.SourceTokenAccountAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		req.ToAmount(), req.ToDecimals(), fee,
	))
}

// TransferFromATAMax godoc
// @Summary      Sweep an owner's associated token account balance to any token account
// @Description  Same as transfer-from-ata, except the amount moved is the derived source's current balance rather than a caller-given one. decimals is never a request field, since there is no client-computed amount to protect against a wrong decimals assumption; the mint's own value is used to build the instruction directly. Unlike a lamport sweep, the source carries no rent-exemption floor: a token account can hold zero tokens and still exist, so it is always swept all the way to zero, even when it is also fee_payer. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-ata
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                       true  "Cluster name"
// @Param        X-Chain-Network  header    string                       true  "Cluster network"
// @Param        body             body      TransferFromATAMaxRequest    true  "Transfer parameters"
// @Success      200              {object}  TransferFromATAMaxResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/transfer-from-ata/max [post]
func (h *TokenTransactionHandler) TransferFromATAMax(w http.ResponseWriter, r *http.Request) {
	req := new(TransferFromATAMaxRequest)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	// Owner's associated token account is derived rather than accepted
	// directly. Unlike destination_token_account it is never created here:
	// an account nobody has funded has nothing to send, so a missing source
	// fails rather than being created empty.
	sourceTokenAccount, _, err := core.ATA.Derive(req.OwnerKey(), req.MintKey(), req.TokenProgramID())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if sourceTokenAccount.Equal(req.DestinationTokenAccountKey()) {
		handler.WriteError(w, http.StatusBadRequest, "destination_token_account: derives to the same associated account as owner")
		return
	}

	// Every account this handler ever needs is read in one round trip.
	// source_token_account_authority is always included, whether or not
	// multisig_signers is empty, since fetching it once here is cheaper than
	// a conditional second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.MintKey(),
		sourceTokenAccount,
		req.DestinationTokenAccountKey(),
		req.FeePayerKey(),
		req.SourceTokenAccountAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}

	sourceInfo := accounts[sourceTokenAccount.Base58()]
	if !sourceInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("owner: %s has no associated token account for %s", req.OwnerKey(), req.MintKey()))
		return
	}
	sourceData, err := sourceInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode owner's associated token account: %s", err))
		return
	}
	sourceOwner, err := types.NewPublicKeyFromBase58(sourceInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode owner's associated token account owner: %s", err))
		return
	}
	if !sourceOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("owner: %s's associated token account %s is owned by %s, not %s", req.OwnerKey(), sourceTokenAccount, sourceOwner, req.TokenProgramID()))
		return
	}
	source, err := core.DecodeTokenAccount(sourceOwner, sourceData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("owner: %s's associated token account: %s", req.OwnerKey(), err))
		return
	}
	if !source.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("owner: %s's associated token account %s holds %s, not %s", req.OwnerKey(), sourceTokenAccount, source.Mint, req.MintKey()))
		return
	}
	if source.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("owner: %s's associated token account %s is frozen", req.OwnerKey(), sourceTokenAccount))
		return
	}
	if source.Amount == 0 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("owner: %s's associated token account %s has no balance", req.OwnerKey(), sourceTokenAccount))
		return
	}
	amount := source.Amount

	// source_token_account_authority is the derived account's owner, or its
	// delegate for no more than what was delegated. Minting checks the
	// mint's authority instead; a transfer spends a balance, so it is the
	// holder's to authorize, not the mint's.
	switch {
	case source.Owner.Equal(req.SourceTokenAccountAuthorityKey()):
	case !source.Delegate.IsNil() && source.Delegate.Equal(req.SourceTokenAccountAuthorityKey()) && amount <= source.Delegated():
	default:
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s is neither the owner of %s nor a delegate approved for %d", req.SourceTokenAccountAuthorityKey(), sourceTokenAccount, amount))
		return
	}

	destInfo := accounts[req.DestinationTokenAccountKey().Base58()]
	if !destInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s does not exist", req.DestinationTokenAccountKey()))
		return
	}
	destData, err := destInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination_token_account: %s", err))
		return
	}
	destOwner, err := types.NewPublicKeyFromBase58(destInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination_token_account owner: %s", err))
		return
	}
	if !destOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s is owned by %s, not %s", req.DestinationTokenAccountKey(), destOwner, req.TokenProgramID()))
		return
	}
	destination, err := core.DecodeTokenAccount(destOwner, destData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s", err))
		return
	}
	if !destination.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s holds %s, not %s", req.DestinationTokenAccountKey(), destination.Mint, req.MintKey()))
		return
	}
	if destination.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s is frozen", req.DestinationTokenAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.SourceTokenAccountAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s does not exist", req.SourceTokenAccountAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s: %s", req.SourceTokenAccountAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.TransferChecked(sourceTokenAccount, req.MintKey(), req.DestinationTokenAccountKey(), req.SourceTokenAccountAuthorityKey(), req.ToMultisigSigners(), amount, mint.Decimals)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
	handler.WriteOK(w, NewTransferFromATAMaxResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), sourceTokenAccount, req.OwnerKey(), req.MintKey(), req.DestinationTokenAccountKey(), req.SourceTokenAccountAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		amount, mint.Decimals, fee,
	))
}

// ApproveChecked godoc
// @Summary      Grant a delegate limited spending rights over a token account
// @Description  Authorizes delegate to move up to amount from token_account, on token_account_owner's behalf. A second approve replaces the delegation entirely rather than adding to it, since the program stores one delegate and one amount, not a list; the owner may still move the whole balance regardless of what a delegate holds. Only token_account's owner may approve, never an existing delegate, so re-delegating is not possible through this endpoint. decimals is checked against the mint the same way every other checked endpoint checks it. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-delegation
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

	// Every account this handler ever needs is read in one round trip.
	// token_account_owner is always included, whether or not
	// multisig_signers is empty, since fetching it once here is cheaper than
	// a conditional second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.MintKey(),
		req.TokenAccountKey(),
		req.FeePayerKey(),
		req.TokenAccountOwnerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if mint.Decimals != req.ToDecimals() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("decimals: %d does not match the mint's %d", req.ToDecimals(), mint.Decimals))
		return
	}

	accountInfo := accounts[req.TokenAccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is owned by %s, not %s", req.TokenAccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s", err))
		return
	}
	if !account.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s holds %s, not %s", req.TokenAccountKey(), account.Mint, req.MintKey()))
		return
	}
	if account.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is frozen", req.TokenAccountKey()))
		return
	}

	// Only the owner may approve, never an existing delegate: a delegate
	// re-delegating would let it hand its own spending rights to a third
	// party the owner never chose.
	if !account.Owner.Equal(req.TokenAccountOwnerKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_owner: %s is not the owner of %s", req.TokenAccountOwnerKey(), req.TokenAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.TokenAccountOwnerKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_owner: %s does not exist", req.TokenAccountOwnerKey()))
			return
		}
		ownerOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_owner owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_owner: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), ownerOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_owner: %s: %s", req.TokenAccountOwnerKey(), err))
			return
		}
	}

	ix, err := tokenProgram.ApproveChecked(req.TokenAccountKey(), req.MintKey(), req.DelegateKey(), req.TokenAccountOwnerKey(), req.ToMultisigSigners(), req.ToAmount(), req.ToDecimals())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
		req.FeePayerKey(), req.TokenAccountKey(), req.MintKey(), req.DelegateKey(), req.TokenAccountOwnerKey(), req.TokenProgramID(), nonceAuthority,
		req.ToAmount(), req.ToDecimals(), fee,
	))
}

// ApproveCheckedMax godoc
// @Summary      Grant a delegate effectively unlimited spending rights over a token account
// @Description  Same as approve-checked, except the amount granted is always the maximum representable base-unit value rather than a caller-given one — the standard effectively-unlimited approval, since that value is far beyond any real balance and never needs re-approving as the balance changes. The delegate can still only ever move what token_account actually holds; the amount here is a ceiling, not a balance. decimals is never a request field, since there is no client-computed amount to protect against a wrong decimals assumption; the mint's own value is used to build the instruction directly. Only token_account_owner may approve, never an existing delegate, so re-delegating is not possible through this endpoint. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-delegation
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                     true  "Cluster name"
// @Param        X-Chain-Network  header    string                     true  "Cluster network"
// @Param        body             body      ApproveCheckedMaxRequest   true  "Delegation parameters"
// @Success      200              {object}  ApproveCheckedMaxResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/approve-checked/max [post]
func (h *TokenTransactionHandler) ApproveCheckedMax(w http.ResponseWriter, r *http.Request) {
	req := new(ApproveCheckedMaxRequest)
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

	// Every account this handler ever needs is read in one round trip.
	// token_account_owner is always included, whether or not
	// multisig_signers is empty, since fetching it once here is cheaper than
	// a conditional second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.MintKey(),
		req.TokenAccountKey(),
		req.FeePayerKey(),
		req.TokenAccountOwnerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}

	accountInfo := accounts[req.TokenAccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is owned by %s, not %s", req.TokenAccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s", err))
		return
	}
	if !account.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s holds %s, not %s", req.TokenAccountKey(), account.Mint, req.MintKey()))
		return
	}
	if account.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is frozen", req.TokenAccountKey()))
		return
	}

	// Only the owner may approve, never an existing delegate: a delegate
	// re-delegating would let it hand its own spending rights to a third
	// party the owner never chose.
	if !account.Owner.Equal(req.TokenAccountOwnerKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_owner: %s is not the owner of %s", req.TokenAccountOwnerKey(), req.TokenAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.TokenAccountOwnerKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_owner: %s does not exist", req.TokenAccountOwnerKey()))
			return
		}
		ownerOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_owner owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_owner: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), ownerOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_owner: %s: %s", req.TokenAccountOwnerKey(), err))
			return
		}
	}

	ix, err := tokenProgram.ApproveChecked(req.TokenAccountKey(), req.MintKey(), req.DelegateKey(), req.TokenAccountOwnerKey(), req.ToMultisigSigners(), math.MaxUint64, mint.Decimals)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
	handler.WriteOK(w, NewApproveCheckedMaxResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), req.TokenAccountKey(), req.MintKey(), req.DelegateKey(), req.TokenAccountOwnerKey(), req.TokenProgramID(), nonceAuthority,
		math.MaxUint64, mint.Decimals, fee,
	))
}

// Revoke godoc
// @Summary      Clear whatever delegation an account currently has
// @Description  Revokes token_account's delegate and delegated amount, whatever they are, without naming either: the program clears what is stored, so there is nothing to get wrong by naming it. A token_account with no delegate revokes cleanly too. Only token_account_owner may revoke, matching approve-checked's rule that only the owner may grant one. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-delegation
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

	// Every account this handler ever needs is read in one round trip.
	// token_account_owner is always included, whether or not
	// multisig_signers is empty, since fetching it once here is cheaper than
	// a conditional second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.TokenAccountKey(),
		req.FeePayerKey(),
		req.TokenAccountOwnerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	accountInfo := accounts[req.TokenAccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is owned by %s, not %s", req.TokenAccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s", err))
		return
	}

	// Only the owner may revoke, the same rule approve-checked applies to
	// granting: a delegate holds no authority over the delegation itself, only
	// over what it was allowed to spend.
	if !account.Owner.Equal(req.TokenAccountOwnerKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_owner: %s is not the owner of %s", req.TokenAccountOwnerKey(), req.TokenAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.TokenAccountOwnerKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_owner: %s does not exist", req.TokenAccountOwnerKey()))
			return
		}
		ownerOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_owner owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_owner: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), ownerOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_owner: %s: %s", req.TokenAccountOwnerKey(), err))
			return
		}
	}

	ix, err := tokenProgram.Revoke(req.TokenAccountKey(), req.TokenAccountOwnerKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
		req.FeePayerKey(), req.TokenAccountKey(), req.TokenAccountOwnerKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// SetMintAuthorityReplace godoc
// @Summary      Replace a mint's mint authority
// @Description  Hands mint_authority to new_mint_authority. mint_authority must be the mint's existing mint_authority exactly; there is no delegate concept for this role. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-authority
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

	// Every account this handler ever needs is read in one round trip.
	// mint_authority is always included, whether or not multisig_signers is
	// empty, since fetching it once here is cheaper than a conditional
	// second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.MintKey(),
		req.FeePayerKey(),
		req.MintAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
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
	if !mint.MintAuthority.Equal(req.MintAuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint_authority: %s is not the mint authority of %s", req.MintAuthorityKey(), req.MintKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.MintAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint_authority: %s does not exist", req.MintAuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint_authority: %s: %s", req.MintAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.SetAuthority(req.MintKey(), core.TokenAuthorityMintTokens, req.MintAuthorityKey(), req.NewMintAuthorityKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	// Replacing a mint's mint authority moves no lamports of its own, so the
	// fee payer's balance is the only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
		req.FeePayerKey(), req.MintKey(), req.MintAuthorityKey(), req.TokenProgramID(), nonceAuthority, req.NewMintAuthorityKey(),
		fee,
	))
}

// SetMintAuthorityClear godoc
// @Summary      Remove a mint's mint authority permanently
// @Description  Clears mint_authority to None. This caps the supply forever: the program accepts a None mint_authority, and once it is None nothing can ever sign as that authority again to restore it. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-authority
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

	// Every account this handler ever needs is read in one round trip.
	// mint_authority is always included, whether or not multisig_signers is
	// empty, since fetching it once here is cheaper than a conditional
	// second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.MintKey(),
		req.FeePayerKey(),
		req.MintAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
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
	if !mint.MintAuthority.Equal(req.MintAuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint_authority: %s is not the mint authority of %s", req.MintAuthorityKey(), req.MintKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.MintAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint_authority: %s does not exist", req.MintAuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint_authority: %s: %s", req.MintAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.SetAuthority(req.MintKey(), core.TokenAuthorityMintTokens, req.MintAuthorityKey(), nil, req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	// Clearing a mint's mint authority moves no lamports of its own, so the
	// fee payer's balance is the only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
		req.FeePayerKey(), req.MintKey(), req.MintAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// SetFreezeAuthorityReplace godoc
// @Summary      Replace a mint's freeze authority
// @Description  Hands freeze_authority to new_freeze_authority. freeze_authority must be the mint's existing freeze_authority exactly. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-authority
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

	// Every account this handler ever needs is read in one round trip.
	// freeze_authority is always included, whether or not multisig_signers
	// is empty, since fetching it once here is cheaper than a conditional
	// second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.MintKey(),
		req.FeePayerKey(),
		req.FreezeAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
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
	if !mint.FreezeAuthority.Equal(req.FreezeAuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("freeze_authority: %s is not the freeze authority of %s", req.FreezeAuthorityKey(), req.MintKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.FreezeAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("freeze_authority: %s does not exist", req.FreezeAuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode freeze_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode freeze_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("freeze_authority: %s: %s", req.FreezeAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.SetAuthority(req.MintKey(), core.TokenAuthorityFreezeAccount, req.FreezeAuthorityKey(), req.NewFreezeAuthorityKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	// Replacing a mint's freeze authority moves no lamports of its own, so
	// the fee payer's balance is the only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
		req.FeePayerKey(), req.MintKey(), req.FreezeAuthorityKey(), req.TokenProgramID(), nonceAuthority, req.NewFreezeAuthorityKey(),
		fee,
	))
}

// SetFreezeAuthorityClear godoc
// @Summary      Remove a mint's freeze authority permanently
// @Description  Clears freeze_authority to None. No holder of this mint can ever be frozen afterward, and nothing can restore the capability. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-authority
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

	// Every account this handler ever needs is read in one round trip.
	// freeze_authority is always included, whether or not multisig_signers
	// is empty, since fetching it once here is cheaper than a conditional
	// second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.MintKey(),
		req.FeePayerKey(),
		req.FreezeAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
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
	if !mint.FreezeAuthority.Equal(req.FreezeAuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("freeze_authority: %s is not the freeze authority of %s", req.FreezeAuthorityKey(), req.MintKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.FreezeAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("freeze_authority: %s does not exist", req.FreezeAuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode freeze_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode freeze_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("freeze_authority: %s: %s", req.FreezeAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.SetAuthority(req.MintKey(), core.TokenAuthorityFreezeAccount, req.FreezeAuthorityKey(), nil, req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	// Clearing a mint's freeze authority moves no lamports of its own, so
	// the fee payer's balance is the only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
		req.FeePayerKey(), req.MintKey(), req.FreezeAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// SetAccountOwnerReplace godoc
// @Summary      Replace a token account's owner
// @Description  Hands token_account to new_token_account_owner. token_account_owner must be token_account's existing owner exactly, never a delegate. There is no clear variant: the owner field has no None representation on chain, and the program rejects one. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-authority
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

	// Every account this handler ever needs is read in one round trip.
	// token_account_owner is always included, whether or not
	// multisig_signers is empty, since fetching it once here is cheaper than
	// a conditional second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.TokenAccountKey(),
		req.FeePayerKey(),
		req.TokenAccountOwnerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	accountInfo := accounts[req.TokenAccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is owned by %s, not %s", req.TokenAccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s", err))
		return
	}
	if !account.Owner.Equal(req.TokenAccountOwnerKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_owner: %s is not the owner of %s", req.TokenAccountOwnerKey(), req.TokenAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.TokenAccountOwnerKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_owner: %s does not exist", req.TokenAccountOwnerKey()))
			return
		}
		ownerOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_owner owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_owner: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), ownerOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_owner: %s: %s", req.TokenAccountOwnerKey(), err))
			return
		}
	}

	ix, err := tokenProgram.SetAuthority(req.TokenAccountKey(), core.TokenAuthorityAccountOwner, req.TokenAccountOwnerKey(), req.NewTokenAccountOwnerKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	// Replacing a token account's owner moves no lamports of its own, so
	// the fee payer's balance is the only one that has to cover anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
		req.FeePayerKey(), req.TokenAccountKey(), req.TokenAccountOwnerKey(), req.TokenProgramID(), nonceAuthority, req.NewTokenAccountOwnerKey(),
		fee,
	))
}

// SetCloseAuthorityReplace godoc
// @Summary      Replace a token account's close authority
// @Description  Hands token_account_close_authority to new_token_account_close_authority. token_account_close_authority is whichever one is already recorded: the account's close authority if one is set, otherwise its owner, the same rule close-account itself checks. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-authority
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

	// Every account this handler ever needs is read in one round trip.
	// token_account_close_authority is always included, whether or not
	// multisig_signers is empty, since fetching it once here is cheaper than
	// a conditional second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.TokenAccountKey(),
		req.FeePayerKey(),
		req.TokenAccountCloseAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	accountInfo := accounts[req.TokenAccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is owned by %s, not %s", req.TokenAccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s", err))
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
	if !requiredAuthority.Equal(req.TokenAccountCloseAuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_close_authority: %s is not the current close authority of %s", req.TokenAccountCloseAuthorityKey(), req.TokenAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.TokenAccountCloseAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_close_authority: %s does not exist", req.TokenAccountCloseAuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_close_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_close_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_close_authority: %s: %s", req.TokenAccountCloseAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.SetAuthority(req.TokenAccountKey(), core.TokenAuthorityCloseAccount, req.TokenAccountCloseAuthorityKey(), req.NewTokenAccountCloseAuthorityKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	// Replacing a token account's close authority moves no lamports of its
	// own, so the fee payer's balance is the only one that has to cover
	// anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
		req.FeePayerKey(), req.TokenAccountKey(), req.TokenAccountCloseAuthorityKey(), req.TokenProgramID(), nonceAuthority, req.NewTokenAccountCloseAuthorityKey(),
		fee,
	))
}

// SetCloseAuthorityClear godoc
// @Summary      Remove a token account's close authority
// @Description  Clears close_authority to None. This is recoverable: the owner never goes away, and close-account already falls back to the owner when no close authority is set, so clearing this only reverts to that default. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-authority
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

	// Every account this handler ever needs is read in one round trip.
	// token_account_close_authority is always included, whether or not
	// multisig_signers is empty, since fetching it once here is cheaper than
	// a conditional second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.TokenAccountKey(),
		req.FeePayerKey(),
		req.TokenAccountCloseAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	accountInfo := accounts[req.TokenAccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is owned by %s, not %s", req.TokenAccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s", err))
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
	if !requiredAuthority.Equal(req.TokenAccountCloseAuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_close_authority: %s is not the current close authority of %s", req.TokenAccountCloseAuthorityKey(), req.TokenAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.TokenAccountCloseAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_close_authority: %s does not exist", req.TokenAccountCloseAuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_close_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account_close_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account_close_authority: %s: %s", req.TokenAccountCloseAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.SetAuthority(req.TokenAccountKey(), core.TokenAuthorityCloseAccount, req.TokenAccountCloseAuthorityKey(), nil, req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	// Clearing a token account's close authority moves no lamports of its
	// own, so the fee payer's balance is the only one that has to cover
	// anything.
	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
		req.FeePayerKey(), req.TokenAccountKey(), req.TokenAccountCloseAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// FreezeAccount godoc
// @Summary      Suspend a token account
// @Description  Freezes token_account, so it rejects transfer, burn, and approve until thawed. freeze_authority is the mint's freeze authority, not the account's owner or any delegate: freezing is a mint-level power to suspend any account holding it, on a different axis from who may spend a balance. Only works on a mint that was initialized with a freeze authority. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-freeze
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

	// Every account this handler ever needs is read in one round trip.
	// freeze_authority is always included, whether or not multisig_signers
	// is empty, since fetching it once here is cheaper than a conditional
	// second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.MintKey(),
		req.TokenAccountKey(),
		req.FeePayerKey(),
		req.FreezeAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
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
	if !mint.FreezeAuthority.Equal(req.FreezeAuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("freeze_authority: %s is not the freeze authority of %s", req.FreezeAuthorityKey(), req.MintKey()))
		return
	}

	accountInfo := accounts[req.TokenAccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is owned by %s, not %s", req.TokenAccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s", err))
		return
	}
	if !account.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s holds %s, not %s", req.TokenAccountKey(), account.Mint, req.MintKey()))
		return
	}
	if account.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is already frozen", req.TokenAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.FreezeAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("freeze_authority: %s does not exist", req.FreezeAuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode freeze_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode freeze_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("freeze_authority: %s: %s", req.FreezeAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.FreezeAccount(req.TokenAccountKey(), req.MintKey(), req.FreezeAuthorityKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
		req.FeePayerKey(), req.TokenAccountKey(), req.MintKey(), req.FreezeAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// ThawAccount godoc
// @Summary      Resume a suspended token account
// @Description  Reverses FreezeAccount, letting transfer, burn, and approve resume against token_account. freeze_authority is the mint's freeze authority, the same rule FreezeAccount applies. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-freeze
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

	// Every account this handler ever needs is read in one round trip.
	// freeze_authority is always included, whether or not multisig_signers
	// is empty, since fetching it once here is cheaper than a conditional
	// second round trip for the multisig branch below.
	lookups := []*types.PublicKey{
		req.MintKey(),
		req.TokenAccountKey(),
		req.FeePayerKey(),
		req.FreezeAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
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
	if !mint.FreezeAuthority.Equal(req.FreezeAuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("freeze_authority: %s is not the freeze authority of %s", req.FreezeAuthorityKey(), req.MintKey()))
		return
	}

	accountInfo := accounts[req.TokenAccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s does not exist", req.TokenAccountKey()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account: %s", err))
		return
	}
	accountOwner, err := types.NewPublicKeyFromBase58(accountInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode token_account owner: %s", err))
		return
	}
	if !accountOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is owned by %s, not %s", req.TokenAccountKey(), accountOwner, req.TokenProgramID()))
		return
	}
	account, err := core.DecodeTokenAccount(accountOwner, accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s", err))
		return
	}
	if !account.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s holds %s, not %s", req.TokenAccountKey(), account.Mint, req.MintKey()))
		return
	}
	if !account.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("token_account: %s is not frozen", req.TokenAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.FreezeAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("freeze_authority: %s does not exist", req.FreezeAuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode freeze_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode freeze_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("freeze_authority: %s: %s", req.FreezeAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.ThawAccount(req.TokenAccountKey(), req.MintKey(), req.FreezeAuthorityKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
		req.FeePayerKey(), req.TokenAccountKey(), req.MintKey(), req.FreezeAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// ReallocateTransferFeeConfig godoc
// @Summary      Grow a token account to hold room for TransferFeeConfig
// @Description  Checks whether account already holds enough space for its existing extensions plus TransferFeeConfig, and grows it if not. The instruction itself only ever needs the one new extension: Reallocate reads account's own existing extensions on chain and unions them with what this sends, so a caller never resends what is already there. Getting the resize's rent right is this endpoint's own job: it reads account's current extensions and actual lamports, asks GetAccountDataSize for the full target size once TransferFeeConfig is unioned in, and only then knows rent_payer's shortfall — the same authority Reallocate itself defers to, asked directly rather than recomputed here. TransferFeeConfig is a mint-side extension in the interface crate's own numbering, not what Reallocate's own account list expects (always a token account); nothing here stops a caller from naming it anyway, and the deployed program is what rejects it, not this endpoint. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-extensions
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                                  true  "Cluster name"
// @Param        X-Chain-Network  header    string                                  true  "Cluster network"
// @Param        body             body      ReallocateTransferFeeConfigRequest      true  "Account, rent payer, owner, fee payer, and program"
// @Success      200              {object}  ReallocateTransferFeeConfigResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/extensions/transfer-fee-config/reallocate [post]
func (h *TokenTransactionHandler) ReallocateTransferFeeConfig(w http.ResponseWriter, r *http.Request) {
	req := new(ReallocateTransferFeeConfigRequest)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	// Every account this handler ever needs is read in one round trip.
	// rent_payer and fee_payer are frequently the same key under different
	// roles, and batching rather than fetching each alone is what makes that
	// overlap cheap instead of redundant reads.
	lookups := []*types.PublicKey{
		req.AccountKey(),
		req.RentPayerKey(),
		req.FeePayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	accountInfo := accounts[req.AccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s does not exist", req.AccountKey()))
		return
	}
	if accountInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s is owned by %s, not %s", req.AccountKey(), accountInfo.Owner, req.TokenProgramID()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account: %s", err))
		return
	}
	tokenAccount, err := core.DecodeTokenAccount(req.TokenProgramID(), accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s", err))
		return
	}

	// Reallocate itself only ever needs the one new extension in its own
	// instruction data -- it reads account's existing extensions on chain
	// and unions them in. GetAccountDataSize has no account to read
	// existing state from at all (only a mint), so this handler does that
	// union itself, purely to work out the rent this resize actually costs.
	existing := core.ExistingExtensionTypes(accountData)
	target := append(append([]core.ExtensionType{}, existing...), core.ExtensionTypeTransferFeeConfig)

	sizeIx, err := tokenProgram.GetAccountDataSize(tokenAccount.Mint, target)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// This inner transaction is never signed and never sent, only
	// simulated: the blockhash field is 32 zero bytes, which the node
	// replaces with its own current one before execution, and the fee
	// payer's single signature slot is left empty since sigVerify is off
	// for the same call.
	sizeMessage, err := types.NewMessage(req.FeePayerKey(), types.NewHash([types.HashLength]byte{}), types.NewInstructions(sizeIx))
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	sizeTx, err := types.NewTransaction(sizeMessage)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sizeRaw, err := sizeTx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}
	sizeValue, err := chain.Cli.SimulateUnsignedTransaction(r.Context(), sizeRaw, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if sizeValue.Failed() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("get_account_data_size simulation failed: %s", sizeValue.Err))
		return
	}
	sizeDecoded, err := sizeValue.DecodedReturnData()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if sizeDecoded == nil || len(sizeDecoded) != 8 {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("get_account_data_size: program returned %d bytes, expected 8", len(sizeDecoded)))
		return
	}
	targetSize, _, err := codec.Binary.ReadU64(sizeDecoded)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	targetRentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), targetSize, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	var rentShortfall uint64
	if targetRentExempt > accountInfo.Lamports {
		rentShortfall = targetRentExempt - accountInfo.Lamports
	}

	// Reallocate moves rent_payer's lamports into account the same way a
	// plain Transfer does internally (a resize can only add lamports to an
	// account another program owns via a System CPI), and the runtime
	// rejects that source outright if it carries any data, regardless of
	// who owns it.
	if rentShortfall > 0 && accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund the resize", req.RentPayerKey()))
		return
	}

	ix, err := tokenProgram.Reallocate(req.AccountKey(), req.RentPayerKey(), req.OwnerKey(), req.ToMultisigSigners(), []core.ExtensionType{core.ExtensionTypeTransferFeeConfig})
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	// rent_payer and fee_payer may be the same account wearing two hats, so
	// what each distinct key owes is summed by address rather than checked
	// once per role.
	spent := map[string]uint64{
		req.RentPayerKey().Base58(): 0,
		req.FeePayerKey().Base58():  0,
	}
	spent[req.RentPayerKey().Base58()] += rentShortfall
	spent[req.FeePayerKey().Base58()] += fee

	for payer, amount := range spent {
		var balance uint64
		if info := accounts[payer]; info.Exists() {
			balance = info.Lamports
		}
		if balance < amount {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: balance %d does not cover %d", payer, balance, amount))
			return
		}
		if !types.RentExemptAfter(balance, amount, minRent) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: would leave %d lamports, below the %d lamport rent-exemption minimum", payer, balance-amount, minRent))
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
	handler.WriteOK(w, NewReallocateTransferFeeConfigResponse(
		tx, raw, messageBytes,
		req.RentPayerKey(), req.FeePayerKey(), req.AccountKey(), req.OwnerKey(), req.TokenProgramID(), nonceAuthority,
		targetSize, rentShortfall, fee,
	))
}

// ReallocateMintCloseAuthority godoc
// @Summary      Grow a token account to hold room for MintCloseAuthority
// @Description  Checks whether account already holds enough space for its existing extensions plus MintCloseAuthority, and grows it if not. The instruction itself only ever needs the one new extension: Reallocate reads account's own existing extensions on chain and unions them with what this sends, so a caller never resends what is already there. Getting the resize's rent right is this endpoint's own job: it reads account's current extensions and actual lamports, asks GetAccountDataSize for the full target size once MintCloseAuthority is unioned in, and only then knows rent_payer's shortfall — the same authority Reallocate itself defers to, asked directly rather than recomputed here. MintCloseAuthority is a mint-side extension in the interface crate's own numbering, not what Reallocate's own account list expects (always a token account); nothing here stops a caller from naming it anyway, and the deployed program is what rejects it, not this endpoint. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-extensions
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                                  true  "Cluster name"
// @Param        X-Chain-Network  header    string                                  true  "Cluster network"
// @Param        body             body      ReallocateMintCloseAuthorityRequest    true  "Account, rent payer, owner, fee payer, and program"
// @Success      200              {object}  ReallocateMintCloseAuthorityResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/extensions/mint-close-authority/reallocate [post]
func (h *TokenTransactionHandler) ReallocateMintCloseAuthority(w http.ResponseWriter, r *http.Request) {
	req := new(ReallocateMintCloseAuthorityRequest)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	// Every account this handler ever needs is read in one round trip.
	// rent_payer and fee_payer are frequently the same key under different
	// roles, and batching rather than fetching each alone is what makes that
	// overlap cheap instead of redundant reads.
	lookups := []*types.PublicKey{
		req.AccountKey(),
		req.RentPayerKey(),
		req.FeePayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	accountInfo := accounts[req.AccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s does not exist", req.AccountKey()))
		return
	}
	if accountInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s is owned by %s, not %s", req.AccountKey(), accountInfo.Owner, req.TokenProgramID()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account: %s", err))
		return
	}
	tokenAccount, err := core.DecodeTokenAccount(req.TokenProgramID(), accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s", err))
		return
	}

	// Reallocate itself only ever needs the one new extension in its own
	// instruction data -- it reads account's existing extensions on chain
	// and unions them in. GetAccountDataSize has no account to read
	// existing state from at all (only a mint), so this handler does that
	// union itself, purely to work out the rent this resize actually costs.
	existing := core.ExistingExtensionTypes(accountData)
	target := append(append([]core.ExtensionType{}, existing...), core.ExtensionTypeMintCloseAuthority)

	sizeIx, err := tokenProgram.GetAccountDataSize(tokenAccount.Mint, target)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// This inner transaction is never signed and never sent, only
	// simulated: the blockhash field is 32 zero bytes, which the node
	// replaces with its own current one before execution, and the fee
	// payer's single signature slot is left empty since sigVerify is off
	// for the same call.
	sizeMessage, err := types.NewMessage(req.FeePayerKey(), types.NewHash([types.HashLength]byte{}), types.NewInstructions(sizeIx))
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	sizeTx, err := types.NewTransaction(sizeMessage)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sizeRaw, err := sizeTx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}
	sizeValue, err := chain.Cli.SimulateUnsignedTransaction(r.Context(), sizeRaw, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if sizeValue.Failed() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("get_account_data_size simulation failed: %s", sizeValue.Err))
		return
	}
	sizeDecoded, err := sizeValue.DecodedReturnData()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if sizeDecoded == nil || len(sizeDecoded) != 8 {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("get_account_data_size: program returned %d bytes, expected 8", len(sizeDecoded)))
		return
	}
	targetSize, _, err := codec.Binary.ReadU64(sizeDecoded)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	targetRentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), targetSize, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	var rentShortfall uint64
	if targetRentExempt > accountInfo.Lamports {
		rentShortfall = targetRentExempt - accountInfo.Lamports
	}

	// Reallocate moves rent_payer's lamports into account the same way a
	// plain Transfer does internally (a resize can only add lamports to an
	// account another program owns via a System CPI), and the runtime
	// rejects that source outright if it carries any data, regardless of
	// who owns it.
	if rentShortfall > 0 && accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund the resize", req.RentPayerKey()))
		return
	}

	ix, err := tokenProgram.Reallocate(req.AccountKey(), req.RentPayerKey(), req.OwnerKey(), req.ToMultisigSigners(), []core.ExtensionType{core.ExtensionTypeMintCloseAuthority})
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	// rent_payer and fee_payer may be the same account wearing two hats, so
	// what each distinct key owes is summed by address rather than checked
	// once per role.
	spent := map[string]uint64{
		req.RentPayerKey().Base58(): 0,
		req.FeePayerKey().Base58():  0,
	}
	spent[req.RentPayerKey().Base58()] += rentShortfall
	spent[req.FeePayerKey().Base58()] += fee

	for payer, amount := range spent {
		var balance uint64
		if info := accounts[payer]; info.Exists() {
			balance = info.Lamports
		}
		if balance < amount {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: balance %d does not cover %d", payer, balance, amount))
			return
		}
		if !types.RentExemptAfter(balance, amount, minRent) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: would leave %d lamports, below the %d lamport rent-exemption minimum", payer, balance-amount, minRent))
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
	handler.WriteOK(w, NewReallocateMintCloseAuthorityResponse(
		tx, raw, messageBytes,
		req.RentPayerKey(), req.FeePayerKey(), req.AccountKey(), req.OwnerKey(), req.TokenProgramID(), nonceAuthority,
		targetSize, rentShortfall, fee,
	))
}

// ReallocateTransferFeeAmount godoc
// @Summary      Grow a token account to hold room for TransferFeeAmount
// @Description  Checks whether account already holds enough space for its existing extensions plus TransferFeeAmount, and grows it if not -- the account-side extension a destination needs before it can receive a transfer from a fee-charging mint; without it, any transfer that computes a non-zero fee fails as InvalidState. The instruction itself only ever needs the one new extension: Reallocate reads account's own existing extensions on chain and unions them with what this sends, so a caller never resends what is already there. Getting the resize's rent right is this endpoint's own job: it reads account's current extensions and actual lamports, asks GetAccountDataSize for the full target size once TransferFeeAmount is unioned in, and only then knows rent_payer's shortfall — the same authority Reallocate itself defers to, asked directly rather than recomputed here. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-extensions
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                                  true  "Cluster name"
// @Param        X-Chain-Network  header    string                                  true  "Cluster network"
// @Param        body             body      ReallocateTransferFeeAmountRequest      true  "Account, rent payer, owner, fee payer, and program"
// @Success      200              {object}  ReallocateTransferFeeAmountResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/extensions/transfer-fee-amount/reallocate [post]
func (h *TokenTransactionHandler) ReallocateTransferFeeAmount(w http.ResponseWriter, r *http.Request) {
	req := new(ReallocateTransferFeeAmountRequest)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	// Every account this handler ever needs is read in one round trip.
	// rent_payer and fee_payer are frequently the same key under different
	// roles, and batching rather than fetching each alone is what makes that
	// overlap cheap instead of redundant reads.
	lookups := []*types.PublicKey{
		req.AccountKey(),
		req.RentPayerKey(),
		req.FeePayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	accountInfo := accounts[req.AccountKey().Base58()]
	if !accountInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s does not exist", req.AccountKey()))
		return
	}
	if accountInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s is owned by %s, not %s", req.AccountKey(), accountInfo.Owner, req.TokenProgramID()))
		return
	}
	accountData, err := accountInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode account: %s", err))
		return
	}
	tokenAccount, err := core.DecodeTokenAccount(req.TokenProgramID(), accountData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("account: %s", err))
		return
	}

	// Reallocate itself only ever needs the one new extension in its own
	// instruction data -- it reads account's existing extensions on chain
	// and unions them in. GetAccountDataSize has no account to read
	// existing state from at all (only a mint), so this handler does that
	// union itself, purely to work out the rent this resize actually costs.
	existing := core.ExistingExtensionTypes(accountData)
	target := append(append([]core.ExtensionType{}, existing...), core.ExtensionTypeTransferFeeAmount)

	sizeIx, err := tokenProgram.GetAccountDataSize(tokenAccount.Mint, target)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// This inner transaction is never signed and never sent, only
	// simulated: the blockhash field is 32 zero bytes, which the node
	// replaces with its own current one before execution, and the fee
	// payer's single signature slot is left empty since sigVerify is off
	// for the same call.
	sizeMessage, err := types.NewMessage(req.FeePayerKey(), types.NewHash([types.HashLength]byte{}), types.NewInstructions(sizeIx))
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	sizeTx, err := types.NewTransaction(sizeMessage)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sizeRaw, err := sizeTx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}
	sizeValue, err := chain.Cli.SimulateUnsignedTransaction(r.Context(), sizeRaw, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if sizeValue.Failed() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("get_account_data_size simulation failed: %s", sizeValue.Err))
		return
	}
	sizeDecoded, err := sizeValue.DecodedReturnData()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if sizeDecoded == nil || len(sizeDecoded) != 8 {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("get_account_data_size: program returned %d bytes, expected 8", len(sizeDecoded)))
		return
	}
	targetSize, _, err := codec.Binary.ReadU64(sizeDecoded)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	targetRentExempt, err := chain.Cli.MinimumBalanceForRentExemption(r.Context(), targetSize, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}
	var rentShortfall uint64
	if targetRentExempt > accountInfo.Lamports {
		rentShortfall = targetRentExempt - accountInfo.Lamports
	}

	// Reallocate moves rent_payer's lamports into account the same way a
	// plain Transfer does internally (a resize can only add lamports to an
	// account another program owns via a System CPI), and the runtime
	// rejects that source outright if it carries any data, regardless of
	// who owns it.
	if rentShortfall > 0 && accounts[req.RentPayerKey().Base58()].CarriesData() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("rent_payer: %s carries data and cannot fund the resize", req.RentPayerKey()))
		return
	}

	ix, err := tokenProgram.Reallocate(req.AccountKey(), req.RentPayerKey(), req.OwnerKey(), req.ToMultisigSigners(), []core.ExtensionType{core.ExtensionTypeTransferFeeAmount})
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	// Without a nonce the message is built against the blockhash resolved
	// above and expires with it. With one it is built against the value that
	// account stores and never expires, so which constructor runs is the
	// whole difference between the two.
	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
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
		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	// rent_payer and fee_payer may be the same account wearing two hats, so
	// what each distinct key owes is summed by address rather than checked
	// once per role.
	spent := map[string]uint64{
		req.RentPayerKey().Base58(): 0,
		req.FeePayerKey().Base58():  0,
	}
	spent[req.RentPayerKey().Base58()] += rentShortfall
	spent[req.FeePayerKey().Base58()] += fee

	for payer, amount := range spent {
		var balance uint64
		if info := accounts[payer]; info.Exists() {
			balance = info.Lamports
		}
		if balance < amount {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: balance %d does not cover %d", payer, balance, amount))
			return
		}
		if !types.RentExemptAfter(balance, amount, minRent) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("%s: would leave %d lamports, below the %d lamport rent-exemption minimum", payer, balance-amount, minRent))
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
	handler.WriteOK(w, NewReallocateTransferFeeAmountResponse(
		tx, raw, messageBytes,
		req.RentPayerKey(), req.FeePayerKey(), req.AccountKey(), req.OwnerKey(), req.TokenProgramID(), nonceAuthority,
		targetSize, rentShortfall, fee,
	))
}

// InitializeTransferFeeConfig godoc
// @Summary      Attach the TransferFeeConfig extension to a mint
// @Description  Fixes the fee rate every transfer-checked-with-fee withholds and who may later change it (transfer_fee_config_authority) or withdraw what accumulates (withdraw_withheld_authority). This can only ever run in the narrow window every mint extension shares: after create-mint has allocated the account and before initialize-mint2 locks the extension list forever -- there is no path back into an already-initialized mint, no Reallocate equivalent exists for mints at all. transfer_fee_basis_points is out of 10,000 and is validated here rather than left to come back as an on-chain rejection. Either authority may be left empty to permanently forgo that capability; unlike a mint or freeze authority there is no later instruction that grants one where none was set. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-extensions
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                               true  "Cluster name"
// @Param        X-Chain-Network  header    string                               true  "Cluster network"
// @Param        body             body      InitializeTransferFeeConfigRequest  true  "Mint, authorities, fee rate, and program"
// @Success      200              {object}  InitializeTransferFeeConfigResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/extensions/transfer-fee-config/initialize [post]
func (h *TokenTransactionHandler) InitializeTransferFeeConfig(w http.ResponseWriter, r *http.Request) {
	req := new(InitializeTransferFeeConfigRequest)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.MintKey(),
		req.FeePayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist; create it first (see create-mint)", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is not owned by %s", req.MintKey(), req.TokenProgramID()))
		return
	}
	if mintInfo.Space < core.MintSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is %d bytes, expected at least %d", req.MintKey(), mintInfo.Space, core.MintSpace))
		return
	}

	// The base layout has to still be uninitialized: extensions have to be
	// attached before initialize-mint2 commits the mint, not after. This
	// reads only the base 82 bytes, not any extension TLV data past it.
	raw, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("mint: %s %s", req.MintKey(), err))
		return
	}
	decodedMint, err := core.DeserializeMint(raw[:core.MintSpace])
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("mint: %s %s", req.MintKey(), err))
		return
	}
	if decodedMint.IsInitialized {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is already initialized; the transfer fee config has to be set up before initialize-mint2, not after", req.MintKey()))
		return
	}

	instruction, err := tokenProgram.InitializeTransferFeeConfig(req.MintKey(), req.TransferFeeConfigAuthorityKey(), req.WithdrawWithheldAuthorityKey(), req.TransferFeeBasisPoints, req.ToMaximumFee())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(instruction)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	txRaw, err := tx.Serialize()
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
	handler.WriteOK(w, NewInitializeTransferFeeConfigResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.MintKey(), req.TransferFeeConfigAuthorityKey(), req.WithdrawWithheldAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		req.TransferFeeBasisPoints, req.ToMaximumFee(), fee,
	))
}

// InitializeMintCloseAuthority godoc
// @Summary      Attach the MintCloseAuthority extension to a mint
// @Description  Names who may later close the mint via close-account -- without this extension a mint can never be closed at all, since the base layout has no close-authority field of its own the way a token account does. This can only ever run in the narrow window every mint extension shares: after create-mint has allocated the account and before initialize-mint2 locks the extension list forever -- there is no path back into an already-initialized mint, no Reallocate equivalent exists for mints at all. close_authority may be left empty to skip the extension; unlike transfer_fee_config_authority, upstream also exposes AuthorityType::CloseMint through the plain set-authority instruction, so a close authority can still be granted or replaced later even if none is set here. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-extensions
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                                true  "Cluster name"
// @Param        X-Chain-Network  header    string                                true  "Cluster network"
// @Param        body             body      InitializeMintCloseAuthorityRequest  true  "Mint, close authority, and program"
// @Success      200              {object}  InitializeMintCloseAuthorityResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/extensions/mint-close-authority/initialize [post]
func (h *TokenTransactionHandler) InitializeMintCloseAuthority(w http.ResponseWriter, r *http.Request) {
	req := new(InitializeMintCloseAuthorityRequest)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.MintKey(),
		req.FeePayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist; create it first (see create-mint)", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is not owned by %s", req.MintKey(), req.TokenProgramID()))
		return
	}
	if mintInfo.Space < core.MintSpace {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is %d bytes, expected at least %d", req.MintKey(), mintInfo.Space, core.MintSpace))
		return
	}

	// The base layout has to still be uninitialized: extensions have to be
	// attached before initialize-mint2 commits the mint, not after. This
	// reads only the base 82 bytes, not any extension TLV data past it.
	raw, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("mint: %s %s", req.MintKey(), err))
		return
	}
	decodedMint, err := core.DeserializeMint(raw[:core.MintSpace])
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("mint: %s %s", req.MintKey(), err))
		return
	}
	if decodedMint.IsInitialized {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is already initialized; the close authority has to be set up before initialize-mint2, not after", req.MintKey()))
		return
	}

	instruction, err := tokenProgram.InitializeMintCloseAuthority(req.MintKey(), req.CloseAuthorityKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(instruction)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	txRaw, err := tx.Serialize()
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
	handler.WriteOK(w, NewInitializeMintCloseAuthorityResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.MintKey(), req.CloseAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// SetCloseMintAuthorityReplace godoc
// @Summary      Replace a mint's MintCloseAuthority close authority
// @Description  Hands the MintCloseAuthority extension's close_authority to new_close_authority. close_authority must be the mint's current close authority exactly; there is no delegate concept for this role. Unlike mint_authority or freeze_authority, this reuses the plain SetAuthority instruction with AuthorityType::CloseMint rather than a dedicated sub-instruction. Mint must already carry the extension with a close_authority set (see extensions/mint-close-authority/initialize) -- there is no granting one here where none exists. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-extensions
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                                 true  "Cluster name"
// @Param        X-Chain-Network  header    string                                 true  "Cluster network"
// @Param        body             body      SetCloseMintAuthorityReplaceRequest    true  "Authority change parameters"
// @Success      200              {object}  SetCloseMintAuthorityReplaceResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/extensions/mint-close-authority/replace [post]
func (h *TokenTransactionHandler) SetCloseMintAuthorityReplace(w http.ResponseWriter, r *http.Request) {
	req := new(SetCloseMintAuthorityReplaceRequest)
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

	lookups := []*types.PublicKey{
		req.MintKey(),
		req.FeePayerKey(),
		req.CloseAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintInfo.Owner, req.TokenProgramID()))
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}
	currentCloseAuthority, err := core.DecodeMintCloseAuthority(mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if currentCloseAuthority.IsNil() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s has no close authority left to change", req.MintKey()))
		return
	}
	if !currentCloseAuthority.Equal(req.CloseAuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("close_authority: %s is not the close authority of %s", req.CloseAuthorityKey(), req.MintKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.CloseAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("close_authority: %s does not exist", req.CloseAuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode close_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode close_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("close_authority: %s: %s", req.CloseAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.SetAuthority(req.MintKey(), core.TokenAuthorityCloseMint, req.CloseAuthorityKey(), req.NewCloseAuthorityKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
	handler.WriteOK(w, NewSetCloseMintAuthorityReplaceResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), req.MintKey(), req.CloseAuthorityKey(), req.TokenProgramID(), nonceAuthority, req.NewCloseAuthorityKey(),
		fee,
	))
}

// SetCloseMintAuthorityClear godoc
// @Summary      Remove a mint's MintCloseAuthority close authority permanently
// @Description  Clears the MintCloseAuthority extension's close_authority to None. This makes the mint permanently unclosable: the program accepts a None close_authority, and once it is None nothing can ever sign close-account against this mint again, nor can this endpoint or replace ever restore one. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-extensions
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                               true  "Cluster name"
// @Param        X-Chain-Network  header    string                               true  "Cluster network"
// @Param        body             body      SetCloseMintAuthorityClearRequest   true  "Authority change parameters"
// @Success      200              {object}  SetCloseMintAuthorityClearResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/extensions/mint-close-authority/clear [post]
func (h *TokenTransactionHandler) SetCloseMintAuthorityClear(w http.ResponseWriter, r *http.Request) {
	req := new(SetCloseMintAuthorityClearRequest)
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

	lookups := []*types.PublicKey{
		req.MintKey(),
		req.FeePayerKey(),
		req.CloseAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintInfo.Owner, req.TokenProgramID()))
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}
	currentCloseAuthority, err := core.DecodeMintCloseAuthority(mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if currentCloseAuthority.IsNil() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s has no close authority left to change", req.MintKey()))
		return
	}
	if !currentCloseAuthority.Equal(req.CloseAuthorityKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("close_authority: %s is not the close authority of %s", req.CloseAuthorityKey(), req.MintKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.CloseAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("close_authority: %s does not exist", req.CloseAuthorityKey()))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode close_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode close_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), owner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("close_authority: %s: %s", req.CloseAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.SetAuthority(req.MintKey(), core.TokenAuthorityCloseMint, req.CloseAuthorityKey(), nil, req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
	handler.WriteOK(w, NewSetCloseMintAuthorityClearResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), req.MintKey(), req.CloseAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// SetTransferFee godoc
// @Summary      Change the TransferFeeConfig rate on a mint
// @Description  Sets a new fee rate and maximum, authorized by transfer_fee_config_authority (the role initialize-transfer-fee-config named), not mint's own mint or freeze authority. The change is not immediate: the program keeps an older and a newer rate side by side, each stamped with the epoch it takes effect at. What this sets becomes the newer rate, effective at the start of the next epoch; whatever was already active keeps applying until then, enforced on chain rather than by anything this endpoint does. transfer_fee_basis_points is out of 10,000 and is validated here rather than left to come back as an on-chain rejection. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-extensions
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                    true  "Cluster name"
// @Param        X-Chain-Network  header    string                    true  "Cluster network"
// @Param        body             body      SetTransferFeeRequest     true  "Mint, authority, new fee rate, and program"
// @Success      200              {object}  SetTransferFeeResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/extensions/transfer-fee-config/set [post]
func (h *TokenTransactionHandler) SetTransferFee(w http.ResponseWriter, r *http.Request) {
	req := new(SetTransferFeeRequest)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.MintKey(),
		req.FeePayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is not owned by %s", req.MintKey(), req.TokenProgramID()))
		return
	}

	instruction, err := tokenProgram.SetTransferFee(req.MintKey(), req.TransferFeeConfigAuthorityKey(), req.ToMultisigSigners(), req.TransferFeeBasisPoints, req.ToMaximumFee())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(instruction)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	txRaw, err := tx.Serialize()
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
	handler.WriteOK(w, NewSetTransferFeeResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.MintKey(), req.TransferFeeConfigAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		req.TransferFeeBasisPoints, req.ToMaximumFee(), fee,
	))
}

// TransferCheckedWithFee godoc
// @Summary      Move tokens between accounts, withholding the mint's transfer fee
// @Description  TransferChecked plus a fee: source_token_account_authority and decimals are checked exactly the same way, and the fee withheld into destination_token_account's TransferFeeAmount extension is the only addition. There is no fee field to set -- unlike Reallocate's own generous tolerance, the deployed program recomputes this fee itself from mint's current TransferFeeConfig rate and requires whatever this instruction carries to match byte for byte, failing the whole transfer as FeeMismatch over a single base unit of difference. This handler reads mint's TransferFeeConfig and the cluster's current epoch itself and computes the one fee that can ever be correct, reported back as transfer_fee and epoch. Building a transaction here and sending it after the epoch rolls over risks landing against a stale rate; rebuild first if that much time has passed. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-extensions
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                          true  "Cluster name"
// @Param        X-Chain-Network  header    string                          true  "Cluster network"
// @Param        body             body      TransferCheckedWithFeeRequest   true  "Transfer parameters"
// @Success      200              {object}  TransferCheckedWithFeeResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/extensions/transfer-fee-config/transfer [post]
func (h *TokenTransactionHandler) TransferCheckedWithFee(w http.ResponseWriter, r *http.Request) {
	req := new(TransferCheckedWithFeeRequest)
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

	// Every account this handler ever needs is read in one round trip.
	lookups := []*types.PublicKey{
		req.MintKey(),
		req.SourceTokenAccountKey(),
		req.DestinationTokenAccountKey(),
		req.FeePayerKey(),
		req.SourceTokenAccountAuthorityKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
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
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintOwner, req.TokenProgramID()))
		return
	}
	mint, err := core.DecodeMint(mintOwner, mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s", err))
		return
	}
	if mint.Decimals != req.ToDecimals() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("decimals: %d does not match the mint's %d", req.ToDecimals(), mint.Decimals))
		return
	}

	// The full, untrimmed mint data is what carries the TransferFeeConfig
	// TLV entry past the base 82-byte layout DecodeMint above only ever
	// looks at.
	transferFeeConfig, err := core.DecodeTransferFeeConfig(mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s: %s", req.MintKey(), err))
		return
	}

	epochInfo, err := chain.Cli.EpochInfo(r.Context(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read epoch info: %s", err))
		return
	}
	transferFee := transferFeeConfig.CalculateFee(epochInfo.Epoch, req.ToAmount())

	sourceInfo := accounts[req.SourceTokenAccountKey().Base58()]
	if !sourceInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s does not exist", req.SourceTokenAccountKey()))
		return
	}
	sourceData, err := sourceInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account: %s", err))
		return
	}
	sourceOwner, err := types.NewPublicKeyFromBase58(sourceInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account owner: %s", err))
		return
	}
	if !sourceOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s is owned by %s, not %s", req.SourceTokenAccountKey(), sourceOwner, req.TokenProgramID()))
		return
	}
	source, err := core.DecodeTokenAccount(sourceOwner, sourceData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s", err))
		return
	}
	if !source.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s holds %s, not %s", req.SourceTokenAccountKey(), source.Mint, req.MintKey()))
		return
	}
	if source.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account: %s is frozen", req.SourceTokenAccountKey()))
		return
	}
	if source.Amount < req.ToAmount() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("amount: %d exceeds the source_token_account's balance of %d", req.ToAmount(), source.Amount))
		return
	}

	switch {
	case source.Owner.Equal(req.SourceTokenAccountAuthorityKey()):
	case !source.Delegate.IsNil() && source.Delegate.Equal(req.SourceTokenAccountAuthorityKey()) && req.ToAmount() <= source.Delegated():
	default:
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s is neither the owner of %s nor a delegate approved for %d", req.SourceTokenAccountAuthorityKey(), req.SourceTokenAccountKey(), req.ToAmount()))
		return
	}

	destInfo := accounts[req.DestinationTokenAccountKey().Base58()]
	if !destInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s does not exist", req.DestinationTokenAccountKey()))
		return
	}
	destData, err := destInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination_token_account: %s", err))
		return
	}
	destOwner, err := types.NewPublicKeyFromBase58(destInfo.Owner)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination_token_account owner: %s", err))
		return
	}
	if !destOwner.Equal(req.TokenProgramID()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s is owned by %s, not %s", req.DestinationTokenAccountKey(), destOwner, req.TokenProgramID()))
		return
	}
	destination, err := core.DecodeTokenAccount(destOwner, destData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s", err))
		return
	}
	if !destination.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s holds %s, not %s", req.DestinationTokenAccountKey(), destination.Mint, req.MintKey()))
		return
	}
	if destination.Frozen() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination_token_account: %s is frozen", req.DestinationTokenAccountKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.SourceTokenAccountAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s does not exist", req.SourceTokenAccountAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_account_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_account_authority: %s: %s", req.SourceTokenAccountAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.TransferCheckedWithFee(req.SourceTokenAccountKey(), req.MintKey(), req.DestinationTokenAccountKey(), req.SourceTokenAccountAuthorityKey(), req.ToMultisigSigners(), req.ToAmount(), req.ToDecimals(), transferFee)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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
	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: balance %d lamports does not cover the %d lamport fee", feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: would leave %s with %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
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
	handler.WriteOK(w, NewTransferCheckedWithFeeResponse(
		tx, raw, messageBytes,
		req.FeePayerKey(), req.SourceTokenAccountKey(), req.MintKey(), req.DestinationTokenAccountKey(), req.SourceTokenAccountAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		req.ToAmount(), req.ToDecimals(), transferFee, epochInfo.Epoch, fee,
	))
}

// HarvestWithheldTokensToMint godoc
// @Summary      Sweep withheld transfer fees from token accounts into the mint
// @Description  Sweeps whatever each of source_token_accounts has withheld in its own TransferFeeAmount extension into mint's TransferFeeConfig withheld_amount. This is permissionless: no authority field exists here at all, since moving a balance between two places it can already only ever sit -- an account's own withheld fees, or the mint's -- needs nobody's permission, only the mint they all agree on. Getting a balance out of the mint (or straight out of the accounts, bypassing the mint) is withdraw-withheld-tokens-from-mint/from-accounts's job instead, and those do require withdraw_withheld_authority's signature. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-extensions
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                              true  "Cluster name"
// @Param        X-Chain-Network  header    string                              true  "Cluster network"
// @Param        body             body      HarvestWithheldTokensToMintRequest  true  "Mint, source token accounts, fee payer, and program"
// @Success      200              {object}  HarvestWithheldTokensToMintResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/extensions/transfer-fee-config/harvest [post]
func (h *TokenTransactionHandler) HarvestWithheldTokensToMint(w http.ResponseWriter, r *http.Request) {
	req := new(HarvestWithheldTokensToMintRequest)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := append([]*types.PublicKey{req.MintKey(), req.FeePayerKey()}, req.ToSourceTokenAccounts()...)
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintInfo.Owner, req.TokenProgramID()))
		return
	}

	for i, source := range req.ToSourceTokenAccounts() {
		info := accounts[source.Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_accounts[%d]: %s does not exist", i, source))
			return
		}
		if info.Owner != req.TokenProgramID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_accounts[%d]: %s is owned by %s, not %s", i, source, info.Owner, req.TokenProgramID()))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_accounts[%d]: %s", i, err))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_accounts[%d] owner: %s", i, err))
			return
		}
		account, err := core.DecodeTokenAccount(owner, data)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_accounts[%d]: %s", i, err))
			return
		}
		if !account.Mint.Equal(req.MintKey()) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_accounts[%d]: %s holds %s, not %s", i, source, account.Mint, req.MintKey()))
			return
		}
	}

	ix, err := tokenProgram.HarvestWithheldTokensToMint(req.MintKey(), req.ToSourceTokenAccounts())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	txRaw, err := tx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode message: %s", err))
		return
	}

	sourceStrings := make([]string, len(req.ToSourceTokenAccounts()))
	for i, s := range req.ToSourceTokenAccounts() {
		sourceStrings[i] = s.Base58()
	}

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewHarvestWithheldTokensToMintResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.MintKey(), req.TokenProgramID(), nonceAuthority,
		sourceStrings, fee,
	))
}

// WithdrawWithheldTokensFromMint godoc
// @Summary      Withdraw a mint's accumulated withheld transfer fees
// @Description  Moves mint's own TransferFeeConfig withheld_amount out to destination as real tokens, authorized by withdraw_withheld_authority rather than mint's own mint or freeze authority. This is the counterpart harvest-withheld-tokens-to-mint's permissionless sweep feeds: harvesting only ever moves a balance into the mint, never out of it, so getting it out from there to somewhere spendable is this endpoint's job alone, and it is the one step in the whole withheld-fee lifecycle that actually requires a signature. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-extensions
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                                    true  "Cluster name"
// @Param        X-Chain-Network  header    string                                    true  "Cluster network"
// @Param        body             body      WithdrawWithheldTokensFromMintRequest     true  "Mint, destination, authority, and program"
// @Success      200              {object}  WithdrawWithheldTokensFromMintResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/extensions/transfer-fee-config/withdraw-from-mint [post]
func (h *TokenTransactionHandler) WithdrawWithheldTokensFromMint(w http.ResponseWriter, r *http.Request) {
	req := new(WithdrawWithheldTokensFromMintRequest)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := []*types.PublicKey{
		req.MintKey(),
		req.DestinationKey(),
		req.FeePayerKey(),
	}
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintInfo.Owner, req.TokenProgramID()))
		return
	}

	destInfo := accounts[req.DestinationKey().Base58()]
	if !destInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s does not exist", req.DestinationKey()))
		return
	}
	if destInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s is owned by %s, not %s", req.DestinationKey(), destInfo.Owner, req.TokenProgramID()))
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
	destination, err := core.DecodeTokenAccount(destOwner, destData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s", err))
		return
	}
	if !destination.Mint.Equal(req.MintKey()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s holds %s, not %s", req.DestinationKey(), destination.Mint, req.MintKey()))
		return
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.WithdrawWithheldAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("withdraw_withheld_authority: %s does not exist", req.WithdrawWithheldAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode withdraw_withheld_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode withdraw_withheld_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("withdraw_withheld_authority: %s: %s", req.WithdrawWithheldAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.WithdrawWithheldTokensFromMint(req.MintKey(), req.DestinationKey(), req.WithdrawWithheldAuthorityKey(), req.ToMultisigSigners())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	txRaw, err := tx.Serialize()
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
	handler.WriteOK(w, NewWithdrawWithheldTokensFromMintResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.MintKey(), req.DestinationKey(), req.WithdrawWithheldAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		fee,
	))
}

// WithdrawWithheldTokensFromAccounts godoc
// @Summary      Withdraw withheld transfer fees directly from token accounts
// @Description  Moves whatever each of source_token_accounts has withheld in its own TransferFeeAmount extension straight to destination, bypassing mint's own TransferFeeConfig withheld_amount entirely -- the shortcut harvest-withheld-tokens-to-mint does not take. mint itself is read-only: it is named only so the program can confirm every source actually belongs to it, never written to. Unlike harvest-withheld-tokens-to-mint this does require withdraw_withheld_authority to sign, the same authority withdraw-withheld-tokens-from-mint answers to, since real tokens are leaving the accounts entirely rather than settling into a shared pool anyone could later account for. recent_blockhash is always required and is never fetched server-side. Left alone, it also builds the message and expires whenever the runtime says it does. Naming durable_nonce_account builds the message against the value that account stores instead, so the transaction never expires, and prepends the advance that consumes it; recent_blockhash then only prices the transaction. The response reports nonce_authority in that case, which has to sign as well.
// @Tags         v2-transaction-token-extensions
// @Accept       json
// @Produce      json
// @Param        X-Chain-Name     header    string                                        true  "Cluster name"
// @Param        X-Chain-Network  header    string                                        true  "Cluster network"
// @Param        body             body      WithdrawWithheldTokensFromAccountsRequest     true  "Mint, destination, authority, source token accounts, and program"
// @Success      200              {object}  WithdrawWithheldTokensFromAccountsResponse
// @Failure      400              {object}  map[string]string
// @Router       /svm/v2/transaction/token/extensions/transfer-fee-config/withdraw-from-accounts [post]
func (h *TokenTransactionHandler) WithdrawWithheldTokensFromAccounts(w http.ResponseWriter, r *http.Request) {
	req := new(WithdrawWithheldTokensFromAccountsRequest)
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

	minRent, err := chain.Cli.MinimumBalanceForRentExemptionSystem(r.Context())
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read rent-exemption minimum: %s", err))
		return
	}

	lookups := append([]*types.PublicKey{
		req.MintKey(),
		req.DestinationKey(),
		req.FeePayerKey(),
		req.WithdrawWithheldAuthorityKey(),
	}, req.ToSourceTokenAccounts()...)
	if !req.DurableNonceAccountKey().IsNil() {
		lookups = append(lookups, req.DurableNonceAccountKey())
	}
	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), lookups, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}

	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	if mintInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is owned by %s, not %s", req.MintKey(), mintInfo.Owner, req.TokenProgramID()))
		return
	}

	destInfo := accounts[req.DestinationKey().Base58()]
	if !destInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s does not exist", req.DestinationKey()))
		return
	}
	if destInfo.Owner != req.TokenProgramID().Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s is owned by %s, not %s", req.DestinationKey(), destInfo.Owner, req.TokenProgramID()))
		return
	}

	for i, source := range req.ToSourceTokenAccounts() {
		info := accounts[source.Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_accounts[%d]: %s does not exist", i, source))
			return
		}
		if info.Owner != req.TokenProgramID().Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_accounts[%d]: %s is owned by %s, not %s", i, source, info.Owner, req.TokenProgramID()))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_accounts[%d]: %s", i, err))
			return
		}
		owner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_token_accounts[%d] owner: %s", i, err))
			return
		}
		account, err := core.DecodeTokenAccount(owner, data)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_accounts[%d]: %s", i, err))
			return
		}
		if !account.Mint.Equal(req.MintKey()) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_token_accounts[%d]: %s holds %s, not %s", i, source, account.Mint, req.MintKey()))
			return
		}
	}

	if signers := req.ToMultisigSigners(); len(signers) > 0 {
		info := accounts[req.WithdrawWithheldAuthorityKey().Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("withdraw_withheld_authority: %s does not exist", req.WithdrawWithheldAuthorityKey()))
			return
		}
		authorityOwner, err := types.NewPublicKeyFromBase58(info.Owner)
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode withdraw_withheld_authority owner: %s", err))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode withdraw_withheld_authority: %s", err))
			return
		}
		if _, err := core.RequireMultisigAuthority(req.TokenProgramID(), authorityOwner, data, signers); err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("withdraw_withheld_authority: %s: %s", req.WithdrawWithheldAuthorityKey(), err))
			return
		}
	}

	ix, err := tokenProgram.WithdrawWithheldTokensFromAccounts(req.MintKey(), req.DestinationKey(), req.WithdrawWithheldAuthorityKey(), req.ToMultisigSigners(), req.ToSourceTokenAccounts())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	instructions := types.NewInstructions(ix)

	var (
		message        *types.Message
		priced         *types.Message
		nonceAuthority *types.PublicKey
	)
	if req.DurableNonceAccountKey().IsNil() {
		if message, err = types.NewMessage(req.FeePayerKey(), req.Blockhash(), instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		priced = message
	} else {
		nonce, err := accounts[req.DurableNonceAccountKey().Base58()].NonceAccount()
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("durable_nonce_account: %s %s", req.DurableNonceAccountKey(), err))
			return
		}

		advance, err := core.System.AdvanceNonceAccount(req.DurableNonceAccountKey(), nonce.Authority)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if message, err = types.NewNonceMessage(req.FeePayerKey(), nonce.Nonce, advance, instructions); err != nil {
			handler.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if priced, err = types.NewNonceMessage(req.FeePayerKey(), req.Blockhash(), advance, instructions); err != nil {
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

	var feePayerBalance uint64
	if info := accounts[req.FeePayerKey().Base58()]; info.Exists() {
		feePayerBalance = info.Lamports
	}
	if feePayerBalance < fee {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s balance %d does not cover %d", req.FeePayerKey(), feePayerBalance, fee))
		return
	}
	if !types.RentExemptAfter(feePayerBalance, fee, minRent) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("fee_payer: %s would leave %d lamports, below the %d lamport rent-exemption minimum", req.FeePayerKey(), feePayerBalance-fee, minRent))
		return
	}

	tx, err := types.NewTransaction(message)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	txRaw, err := tx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}

	messageBytes, err := message.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode message: %s", err))
		return
	}

	sourceStrings := make([]string, len(req.ToSourceTokenAccounts()))
	for i, s := range req.ToSourceTokenAccounts() {
		sourceStrings[i] = s.Base58()
	}

	// nonceAuthority is nil without a nonce, and IsNil is nil safe.
	handler.WriteOK(w, NewWithdrawWithheldTokensFromAccountsResponse(
		tx, txRaw, messageBytes,
		req.FeePayerKey(), req.MintKey(), req.DestinationKey(), req.WithdrawWithheldAuthorityKey(), req.TokenProgramID(), nonceAuthority,
		sourceStrings, fee,
	))
}
