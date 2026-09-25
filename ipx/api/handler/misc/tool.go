package misc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
	"github.com/andantan/svmlab/core/zkbridge"
	"github.com/andantan/svmlab/internal/rpc"
)

type ToolHandler struct{}

func NewToolHandler() *ToolHandler {
	return &ToolHandler{}
}

// GenerateKeypair godoc
// @Summary      Generate an ed25519 key pair
// @Description  Returns a new key pair in the base58 form config.yaml expects, so it can be added as a keys entry and used as a signer. Nothing is written or funded: the address does not exist on any cluster until a transaction creates it, which is what makes a fresh pair usable as the new_account of a create-account build.
// @Tags         tool
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  GenerateKeypairResponse
// @Failure      500   {object}  map[string]string
// @Router       /svm/tool/generate/ed25519-keypair [post]
func (h *ToolHandler) GenerateKeypair(w http.ResponseWriter, r *http.Request) {
	key, err := core.GenerateKey()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to generate key: %s", err))
		return
	}

	handler.WriteOK(w, NewGenerateKeypairResponse(key))
}

// GenerateElGamalKeypair godoc
// @Summary      Generate a ristretto255 ElGamal key pair
// @Description  Returns a new ElGamal key pair for Token-2022's ConfidentialTransfer family -- auditor_elgamal_pubkey on extensions/confidential-transfer-mint/initialize is one consumer. Neither value is a Solana address: both are base58-encoded raw 32-byte ristretto255 values (a scalar and a group element), not ed25519 keys, and cannot sign a transaction or hold lamports.
// @Tags         tool
// @Produce      json
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  GenerateElGamalKeypairResponse
// @Failure      500   {object}  map[string]string
// @Router       /svm/tool/generate/elgamal-keypair [post]
func (h *ToolHandler) GenerateElGamalKeypair(w http.ResponseWriter, r *http.Request) {
	key, err := core.GenerateElGamalKey()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to generate key: %s", err))
		return
	}

	handler.WriteOK(w, NewGenerateElGamalKeypairResponse(key))
}

// ProvePubkeyValidity godoc
// @Summary      Build a PubkeyValidityProof for an ElGamal secret key
// @Description  Derives the public key secret_key determines and builds a sigma-protocol proof that whoever holds secret_key knows it -- what extensions/confidential-transfer-account/configure-account requires alongside the public key it names, since nothing else lets the deployed program tell a real ElGamal public key from 32 arbitrary bytes. The proof is zero-knowledge: public_key and proof in the response reveal nothing about secret_key beyond what configure-account already needs to see.
// @Tags         tool
// @Accept       json
// @Produce      json
// @Param        body  body      ProvePubkeyValidityRequest  true  "ElGamal secret key"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  ProvePubkeyValidityResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/tool/prove/pubkey-validity [post]
func (h *ToolHandler) ProvePubkeyValidity(w http.ResponseWriter, r *http.Request) {
	req := new(ProvePubkeyValidityRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	publicKey, err := core.DeriveElGamalPublicKey(req.ToSecretKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("secret_key: %s", err))
		return
	}

	proof, err := core.ProvePubkeyValidity(req.ToSecretKey(), publicKey)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to build proof: %s", err))
		return
	}

	handler.WriteOK(w, NewProvePubkeyValidityResponse(publicKey, proof))
}

// AeKeySeedMessage godoc
// @Summary      Build the message to sign for an account's AeKey
// @Description  Returns the exact bytes upstream's AeKey::seed_from_signer signs to derive an account's AeKey deterministically -- b"AeKey" followed by token_account's own bytes, the public seed convention real tooling (solana-foundation's Confidential-Balances-Sample) uses. Sign the returned message (base64) with the account owner's own key via sign/, then pass the resulting signature to derive/ae-key.
// @Tags         tool
// @Accept       json
// @Produce      json
// @Param        body  body      AeKeySeedMessageRequest  true  "Token account"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  AeKeySeedMessageResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/tool/derive/ae-key-seed-message [post]
func (h *ToolHandler) AeKeySeedMessage(w http.ResponseWriter, r *http.Request) {
	req := new(AeKeySeedMessageRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	message, err := core.AeKeySeedMessage(req.TokenAccountKey().Bytes())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	handler.WriteOK(w, NewAeKeySeedMessageResponse(message))
}

// DeriveAeKey godoc
// @Summary      Derive an AeKey from a signature
// @Description  Reproduces AeKey::new_from_signer's second half: given the Ed25519 signature over ae-key-seed-message's own output, returns the AeKey that signature determines (two rounds of SHA3-512, keeping the first 16 bytes of the second). A real wallet rederiving the same key needs the same signature every time, so this never generates one itself.
// @Tags         tool
// @Accept       json
// @Produce      json
// @Param        body  body      DeriveAeKeyRequest  true  "Signature over ae-key-seed-message's output"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  DeriveAeKeyResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/tool/derive/ae-key [post]
func (h *ToolHandler) DeriveAeKey(w http.ResponseWriter, r *http.Request) {
	req := new(DeriveAeKeyRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	aeKey, err := core.DeriveAeKeyFromSignature(req.ToSignature())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	handler.WriteOK(w, NewDeriveAeKeyResponse(aeKey))
}

// ConvertBase58To64 godoc
// @Summary      Convert a base58 string to base64
// @Description  Decodes value as base58 and re-encodes the same bytes as base64. Works on any base58 value — a public key, a signature, a hash — since it never interprets what the bytes mean.
// @Tags         tool
// @Accept       json
// @Produce      json
// @Param        body  body      ConvertBase58To64Request  true  "Value"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  ConvertBase58To64Response
// @Failure      400   {object}  map[string]string
// @Router       /svm/tool/convert/base58264 [post]
func (h *ToolHandler) ConvertBase58To64(w http.ResponseWriter, r *http.Request) {
	req := new(ConvertBase58To64Request)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	base64, err := codec.Base58.ToBase64(req.ToValue())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("value: invalid base58: %s", err))
		return
	}

	handler.WriteOK(w, NewConvertBase58To64Response(base64))
}

// ConvertBase64To58 godoc
// @Summary      Convert a base64 string to base58
// @Description  Decodes value as base64 and re-encodes the same bytes as base58. Works on any base64 value — a transaction, a message, arbitrary bytes — since it never interprets what the bytes mean.
// @Tags         tool
// @Accept       json
// @Produce      json
// @Param        body  body      ConvertBase64To58Request  true  "Value"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  ConvertBase64To58Response
// @Failure      400   {object}  map[string]string
// @Router       /svm/tool/convert/base64258 [post]
func (h *ToolHandler) ConvertBase64To58(w http.ResponseWriter, r *http.Request) {
	req := new(ConvertBase64To58Request)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	base58, err := codec.Base64.ToBase58(req.ToValue())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("value: invalid base64: %s", err))
		return
	}

	handler.WriteOK(w, NewConvertBase64To58Response(base58))
}

// ProveConfidentialTransfer godoc
// @Summary      Build the three proofs one ConfidentialTransfer needs
// @Description  Builds the equality, ciphertext-validity, and range proofs a single confidential transfer requires, in one call, because they are built from the same fresh randomness and only agree with each other if drawn together. Each proof_data blob goes to the matching zk-elgamal-proof/context-state/verify endpoint (equality_proof_data to verify/ciphertext-commitment-equality, validity_proof_data to verify/batched-grouped-ciphertext-3-handles-validity, range_proof_data to verify/batched-range-proof-u128), and auditor_ciphertext_lo/hi and new_source_decryptable_available_balance are what the transfer instruction itself carries. The response cannot be rebuilt: a second call draws new randomness and produces proofs that no longer match any context-state account already verified from the first. The source balance must not change between building these proofs and the transfer landing, or the transfer's own checks against the stored balance fail.
// @Tags         tool
// @Accept       json
// @Produce      json
// @Param        body  body      ProveConfidentialTransferRequest  true  "Transfer inputs"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  ProveConfidentialTransferResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/tool/prove/confidential-transfer [post]
func (h *ToolHandler) ProveConfidentialTransfer(w http.ResponseWriter, r *http.Request) {
	req := new(ProveConfidentialTransferRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	sourcePublicKey, err := core.DeriveElGamalPublicKey(req.ToSourceSecretKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_elgamal_secret_key: %s", err))
		return
	}

	proofs, err := core.BuildTransferProofs(
		req.ToSourceSecretKey(), sourcePublicKey, req.ToDestinationElgamalPubkey(), req.ToAuditorElgamalPubkey(),
		req.ToCurrentAvailableBalanceCiphertext(), req.ToCurrentDecryptableAvailableBalance(), req.ToAeKey(),
		req.ToAmount(),
	)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	handler.WriteOK(w, NewProveConfidentialTransferResponse(proofs, sourcePublicKey))
}

// ProveConfidentialWithdraw godoc
// @Summary      Build the two proofs one confidential Withdraw needs
// @Description  Builds the equality and 64-bit range proofs a single confidential withdrawal requires, in one call, because they are built from the same fresh randomness and only agree with each other if drawn together. equality_proof_data goes to zk-elgamal-proof/context-state/verify/ciphertext-commitment-equality and range_proof_data to verify/batched-range-proof-u64, and new_decryptable_available_balance is what the withdraw instruction itself carries. The response cannot be rebuilt: a second call draws new randomness and produces proofs that no longer match any context-state account already verified from the first. The account's balance must not change between building these proofs and the withdrawal landing.
// @Tags         tool
// @Accept       json
// @Produce      json
// @Param        body  body      ProveConfidentialWithdrawRequest  true  "Withdraw inputs"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  ProveConfidentialWithdrawResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/tool/prove/confidential-withdraw [post]
func (h *ToolHandler) ProveConfidentialWithdraw(w http.ResponseWriter, r *http.Request) {
	req := new(ProveConfidentialWithdrawRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	publicKey, err := core.DeriveElGamalPublicKey(req.ToElgamalSecretKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("elgamal_secret_key: %s", err))
		return
	}

	proofs, err := core.BuildWithdrawProofs(
		req.ToElgamalSecretKey(), publicKey,
		req.ToCurrentAvailableBalanceCiphertext(), req.ToCurrentDecryptableAvailableBalance(), req.ToAeKey(),
		req.ToAmount(),
	)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	handler.WriteOK(w, NewProveConfidentialWithdrawResponse(proofs, publicKey))
}

// ProveConfidentialEmptyAccount godoc
// @Summary      Build the zero-ciphertext proof one confidential EmptyAccount needs
// @Description  Proves that the account's available balance ciphertext encrypts zero under its ElGamal key. zero_ciphertext_proof_data goes to zk-elgamal-proof/context-state/verify/zero-ciphertext. The ciphertext must already encrypt zero -- withdraw the whole balance first -- or the proof will not verify against the deployed program. This does not check that itself, since a confidential balance cannot be read without its AE key.
// @Tags         tool
// @Accept       json
// @Produce      json
// @Param        body  body      ProveConfidentialEmptyAccountRequest  true  "EmptyAccount inputs"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  ProveConfidentialEmptyAccountResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/tool/prove/confidential-empty-account [post]
func (h *ToolHandler) ProveConfidentialEmptyAccount(w http.ResponseWriter, r *http.Request) {
	req := new(ProveConfidentialEmptyAccountRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	publicKey, err := core.DeriveElGamalPublicKey(req.ToElgamalSecretKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("elgamal_secret_key: %s", err))
		return
	}

	proof, err := zkbridge.ProveZeroCiphertext(req.ToElgamalSecretKey(), publicKey, req.ToAvailableBalanceCiphertext())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	handler.WriteOK(w, NewProveConfidentialEmptyAccountResponse(proof, publicKey))
}

// ProveConfidentialTransferWithFee godoc
// @Summary      Build the five proofs one confidential TransferWithFee needs
// @Description  Builds the equality, transfer-amount validity, percentage-with-cap, fee validity, and 256-bit range proofs a single confidential transfer on a fee-charging mint requires, in one call, because they are built from the same fresh randomness and only agree with each other if drawn together. The mint is named rather than its parameters being passed in: the transfer fee rate and cap in effect this epoch (TransferFeeConfig), the auditor key (ConfidentialTransferMint), and the withdraw withheld authority key (ConfidentialTransferFeeConfig) are read from it, since the deployed program recomputes them from the same place and rejects proofs built for different values. Each *_proof_data blob goes to the matching zk-elgamal-proof/context-state/verify endpoint, and auditor_ciphertext_lo/hi and new_source_decryptable_available_balance are what the transfer-with-fee instruction itself carries. The response cannot be rebuilt: a second call draws new randomness and produces proofs that no longer match any context-state account already verified from the first. The source balance must not change, and the epoch must not roll over into a different fee, between building these proofs and the transfer landing.
// @Tags         tool
// @Accept       json
// @Produce      json
// @Param        body  body      ProveConfidentialTransferWithFeeRequest  true  "Transfer-with-fee inputs"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  ProveConfidentialTransferWithFeeResponse
// @Failure      400   {object}  map[string]string
// @Failure      502   {object}  map[string]string
// @Router       /svm/tool/prove/confidential-transfer-with-fee [post]
func (h *ToolHandler) ProveConfidentialTransferWithFee(w http.ResponseWriter, r *http.Request) {
	req := new(ProveConfidentialTransferWithFeeRequest)
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

	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), []*types.PublicKey{req.MintKey()}, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read mint: %s", err))
		return
	}
	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	if mintInfo.Owner != core.Token2022ProgramID.Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is not owned by Token-2022", req.MintKey()))
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}

	feeConfig, err := core.DecodeTransferFeeConfig(mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s: %s", req.MintKey(), err))
		return
	}
	auditorPublicKey, err := core.ConfidentialTransferMintAuditor(mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s: %s", req.MintKey(), err))
		return
	}
	withdrawPublicKey, err := core.ConfidentialTransferFeeWithdrawAuthority(mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s: %s", req.MintKey(), err))
		return
	}
	epochInfo, err := chain.Cli.EpochInfo(r.Context(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read epoch info: %s", err))
		return
	}
	rate := feeConfig.EffectiveTransferFee(epochInfo.Epoch)

	sourcePublicKey, err := core.DeriveElGamalPublicKey(req.ToSourceSecretKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_elgamal_secret_key: %s", err))
		return
	}

	proofs, err := core.BuildTransferWithFeeProofs(
		req.ToSourceSecretKey(), sourcePublicKey, req.ToDestinationElgamalPubkey(), auditorPublicKey, withdrawPublicKey,
		req.ToCurrentAvailableBalanceCiphertext(), req.ToCurrentDecryptableAvailableBalance(), req.ToAeKey(),
		req.ToAmount(), rate.TransferFeeBasisPoints, rate.MaximumFee,
	)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	handler.WriteOK(w, NewProveConfidentialTransferWithFeeResponse(
		proofs, sourcePublicKey, auditorPublicKey, withdrawPublicKey,
		rate.TransferFeeBasisPoints, rate.MaximumFee, epochInfo.Epoch,
	))
}

// SplitRecordChunks godoc
// @Summary      Split bytes into record/write chunks
// @Description  Splits data (base58-encoded, typically a proof_data blob from a tool/prove endpoint) into the writes that put all of it into a SPL Record account. A proof too large for one transaction -- a 256-bit range proof is 1064 bytes -- is written into a record account first and then verified from there (zk-elgamal-proof/context-state/verify-from-account), and a single record/write carries at most about 1000 bytes. Each chunk's offset and data go straight into a record/write request; total_length is the data_length for record/create-account; proof_offset (33, the record header) is the proof_offset the verify-from-account request needs. chunk_size defaults to 900, which fits a transaction with or without a durable nonce, and cannot exceed 1000.
// @Tags         tool
// @Accept       json
// @Produce      json
// @Param        body  body      SplitRecordChunksRequest  true  "Bytes to split"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SplitRecordChunksResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/tool/split/record-chunks [post]
func (h *ToolHandler) SplitRecordChunks(w http.ResponseWriter, r *http.Request) {
	req := new(SplitRecordChunksRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	handler.WriteOK(w, NewSplitRecordChunksResponse(req.data, req.chunkSize))
}

// ProveConfidentialWithdrawWithheldFromMint godoc
// @Summary      Build the proof one confidential WithdrawWithheldTokensFromMint needs
// @Description  Decrypts the mint's withheld confidential fee amount with the withdraw authority's ElGamal secret key, re-encrypts that amount under the destination account's ElGamal key, and proves the two ciphertexts encrypt the same value. The mint's withheld ciphertext, the withdraw authority's public key, and the destination's ElGamal key and current decryptable balance are read from chain, since the deployed program compares the proof against exactly those. ciphertext_ciphertext_equality_proof_data goes to zk-elgamal-proof/context-state/verify/ciphertext-ciphertext-equality, and new_decryptable_available_balance is what the withdraw instruction itself carries. The withheld amount must fit in 32 bits. The response cannot be rebuilt against a context-state account already verified from an earlier call, and it goes stale if more fees are harvested onto the mint, or the destination's decryptable balance changes, before the withdraw lands.
// @Tags         tool
// @Accept       json
// @Produce      json
// @Param        body  body      ProveConfidentialWithdrawWithheldFromMintRequest  true  "Mint, destination, withdraw authority secret, AE key"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  ProveConfidentialWithdrawWithheldFromMintResponse
// @Failure      400   {object}  map[string]string
// @Failure      502   {object}  map[string]string
// @Router       /svm/tool/prove/confidential-withdraw-withheld-from-mint [post]
func (h *ToolHandler) ProveConfidentialWithdrawWithheldFromMint(w http.ResponseWriter, r *http.Request) {
	req := new(ProveConfidentialWithdrawWithheldFromMintRequest)
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

	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), []*types.PublicKey{req.MintKey(), req.DestinationKey()}, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}
	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	destInfo := accounts[req.DestinationKey().Base58()]
	if !destInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s does not exist", req.DestinationKey()))
		return
	}
	if mintInfo.Owner != core.Token2022ProgramID.Base58() || destInfo.Owner != core.Token2022ProgramID.Base58() {
		handler.WriteError(w, http.StatusBadRequest, "mint and destination must both be owned by Token-2022")
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}
	destData, err := destInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination: %s", err))
		return
	}
	if len(destData) < 32 || !bytes.Equal(destData[:32], req.MintKey().Bytes()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s does not hold mint %s", req.DestinationKey(), req.MintKey()))
		return
	}

	withheld, err := core.ConfidentialTransferFeeWithheldAmount(mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s: %s", req.MintKey(), err))
		return
	}
	withdrawPublicKey, err := core.ConfidentialTransferFeeWithdrawAuthority(mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s: %s", req.MintKey(), err))
		return
	}
	destPublicKey, destDecryptable, err := core.ConfidentialTransferAccountKeys(destData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s: %s", req.DestinationKey(), err))
		return
	}

	derived, err := core.DeriveElGamalPublicKey(req.ToWithdrawSecretKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("withdraw_elgamal_secret_key: %s", err))
		return
	}
	if !bytes.Equal(derived, withdrawPublicKey) {
		handler.WriteError(w, http.StatusBadRequest, "withdraw_elgamal_secret_key does not match the mint's withdraw withheld authority ElGamal public key")
		return
	}

	proof, err := core.BuildWithdrawWithheldFromMintProof(
		req.ToWithdrawSecretKey(), withdrawPublicKey, destPublicKey,
		withheld, destDecryptable, req.ToAeKey(),
	)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	handler.WriteOK(w, &ProveConfidentialWithdrawWithheldFromMintResponse{
		CiphertextCiphertextEqualityProofData: codec.Base58.Encode(proof.EqualityProof),
		NewDecryptableAvailableBalance:        codec.Base58.Encode(proof.NewDecryptableAvailableBalance),
		WithheldAmount:                        strconv.FormatUint(proof.Amount, 10),
		WithdrawElgamalPubkey:                 codec.Base58.Encode(withdrawPublicKey),
		DestinationElgamalPubkey:              codec.Base58.Encode(destPublicKey),
	})
}

// ProveConfidentialWithdrawWithheldFromAccounts godoc
// @Summary      Build the proof one confidential WithdrawWithheldTokensFromAccounts needs
// @Description  Sums the withheld confidential fee ciphertexts of source_accounts, decrypts the total with the withdraw authority's ElGamal secret key, re-encrypts it under the destination account's ElGamal key, and proves the two ciphertexts encrypt the same value. The sources' withheld amounts, the withdraw authority's public key (from the mint), and the destination's ElGamal key and current decryptable balance are read from chain, since the deployed program compares the proof against exactly those. ciphertext_ciphertext_equality_proof_data goes to zk-elgamal-proof/context-state/verify/ciphertext-ciphertext-equality, and new_decryptable_available_balance is what the withdraw instruction itself carries. The total must fit in 32 bits. The response goes stale if any source's withheld amount, or the destination's decryptable balance, changes before the withdraw lands.
// @Tags         tool
// @Accept       json
// @Produce      json
// @Param        body  body      ProveConfidentialWithdrawWithheldFromAccountsRequest  true  "Mint, sources, destination, withdraw authority secret, AE key"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  ProveConfidentialWithdrawWithheldFromAccountsResponse
// @Failure      400   {object}  map[string]string
// @Failure      502   {object}  map[string]string
// @Router       /svm/tool/prove/confidential-withdraw-withheld-from-accounts [post]
func (h *ToolHandler) ProveConfidentialWithdrawWithheldFromAccounts(w http.ResponseWriter, r *http.Request) {
	req := new(ProveConfidentialWithdrawWithheldFromAccountsRequest)
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

	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), []*types.PublicKey{req.MintKey(), req.DestinationKey()}, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}
	srcAccounts, err := chain.Cli.GetMultipleAccounts(r.Context(), req.SourceKeys(), rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read source accounts: %s", err))
		return
	}
	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	destInfo := accounts[req.DestinationKey().Base58()]
	if !destInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s does not exist", req.DestinationKey()))
		return
	}
	if mintInfo.Owner != core.Token2022ProgramID.Base58() || destInfo.Owner != core.Token2022ProgramID.Base58() {
		handler.WriteError(w, http.StatusBadRequest, "mint and destination must both be owned by Token-2022")
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}
	destData, err := destInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination: %s", err))
		return
	}
	if len(destData) < 32 || !bytes.Equal(destData[:32], req.MintKey().Bytes()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s does not hold mint %s", req.DestinationKey(), req.MintKey()))
		return
	}

	var withheld [][]byte
	for i, src := range req.SourceKeys() {
		info := srcAccounts[src.Base58()]
		if !info.Exists() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_accounts[%d]: %s does not exist", i, src))
			return
		}
		if info.Owner != core.Token2022ProgramID.Base58() {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_accounts[%d]: %s is not owned by Token-2022", i, src))
			return
		}
		data, err := info.Bytes()
		if err != nil {
			handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source_accounts[%d]: %s", i, err))
			return
		}
		if len(data) < 32 || !bytes.Equal(data[:32], req.MintKey().Bytes()) {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_accounts[%d]: %s does not hold mint %s", i, src, req.MintKey()))
			return
		}
		ct, err := core.ConfidentialTransferFeeAmountWithheld(data)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_accounts[%d]: %s: %s", i, src, err))
			return
		}
		withheld = append(withheld, ct)
	}
	withdrawPublicKey, err := core.ConfidentialTransferFeeWithdrawAuthority(mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s: %s", req.MintKey(), err))
		return
	}
	destPublicKey, destDecryptable, err := core.ConfidentialTransferAccountKeys(destData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s: %s", req.DestinationKey(), err))
		return
	}

	derived, err := core.DeriveElGamalPublicKey(req.ToWithdrawSecretKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("withdraw_elgamal_secret_key: %s", err))
		return
	}
	if !bytes.Equal(derived, withdrawPublicKey) {
		handler.WriteError(w, http.StatusBadRequest, "withdraw_elgamal_secret_key does not match the mint's withdraw withheld authority ElGamal public key")
		return
	}

	proof, err := core.BuildWithdrawWithheldFromAccountsProof(
		req.ToWithdrawSecretKey(), withdrawPublicKey, destPublicKey,
		withheld, destDecryptable, req.ToAeKey(),
	)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	handler.WriteOK(w, &ProveConfidentialWithdrawWithheldFromAccountsResponse{
		CiphertextCiphertextEqualityProofData: codec.Base58.Encode(proof.EqualityProof),
		NewDecryptableAvailableBalance:        codec.Base58.Encode(proof.NewDecryptableAvailableBalance),
		WithheldAmount:                        strconv.FormatUint(proof.Amount, 10),
		WithdrawElgamalPubkey:                 codec.Base58.Encode(withdrawPublicKey),
		DestinationElgamalPubkey:              codec.Base58.Encode(destPublicKey),
	})
}

// ProveConfidentialMint godoc
// @Summary      Build the three proofs one confidential Mint needs
// @Description  Builds the commitment-equality, batched grouped 3-handle validity and batched u128 range proofs a single confidential mint requires, in one call, because they are built from the same fresh randomness and only agree with each other if drawn together. The mint and the destination account are named rather than their contents passed in: the mint's current confidential supply and decryptable supply, the supply and auditor ElGamal keys, and the destination's ElGamal key are read from chain, since the deployed program compares the proofs against exactly those. supply_elgamal_secret_key has to match the mint's supply key and supply_ae_key has to decrypt its decryptable supply, and both are checked. Each *_proof_data blob goes to the matching zk-elgamal-proof/context-state/verify endpoint, and auditor_ciphertext_lo/hi and new_decryptable_supply are what the mint instruction itself carries. The response cannot be rebuilt: a second call draws new randomness and produces proofs that no longer match any context-state account already verified from the first. The mint's supply must not change between building these proofs and the mint landing.
// @Tags         tool
// @Accept       json
// @Produce      json
// @Param        body  body      ProveConfidentialMintRequest  true  "Mint, destination, supply keys, amount"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  ProveConfidentialMintResponse
// @Failure      400   {object}  map[string]string
// @Failure      502   {object}  map[string]string
// @Router       /svm/tool/prove/confidential-mint [post]
func (h *ToolHandler) ProveConfidentialMint(w http.ResponseWriter, r *http.Request) {
	req := new(ProveConfidentialMintRequest)
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

	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), []*types.PublicKey{req.MintKey(), req.DestinationKey()}, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}
	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	destInfo := accounts[req.DestinationKey().Base58()]
	if !destInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s does not exist", req.DestinationKey()))
		return
	}
	if mintInfo.Owner != core.Token2022ProgramID.Base58() || destInfo.Owner != core.Token2022ProgramID.Base58() {
		handler.WriteError(w, http.StatusBadRequest, "mint and destination must both be owned by Token-2022")
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}
	destData, err := destInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode destination: %s", err))
		return
	}
	if len(destData) < 32 || !bytes.Equal(destData[:32], req.MintKey().Bytes()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s does not hold mint %s", req.DestinationKey(), req.MintKey()))
		return
	}

	state, err := core.DecodeConfidentialMintBurn(mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s: %s", req.MintKey(), err))
		return
	}
	auditorPublicKey, err := core.ConfidentialTransferMintAuditor(mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s: %s", req.MintKey(), err))
		return
	}
	destPublicKey, _, err := core.ConfidentialTransferAccountKeys(destData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("destination: %s: %s", req.DestinationKey(), err))
		return
	}

	derived, err := core.DeriveElGamalPublicKey(req.ToSupplySecretKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("supply_elgamal_secret_key: %s", err))
		return
	}
	if !bytes.Equal(derived, state.SupplyElGamalPubkey) {
		handler.WriteError(w, http.StatusBadRequest, "supply_elgamal_secret_key does not match the mint's supply ElGamal public key")
		return
	}

	currentSupply, err := core.DecryptAeAmount(req.ToSupplyAeKey(), state.DecryptableSupply)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("supply_ae_key does not decrypt the mint's decryptable supply: %s", err))
		return
	}

	proofs, err := core.BuildMintProofs(
		req.ToSupplySecretKey(), state.SupplyElGamalPubkey, destPublicKey, auditorPublicKey,
		state.ConfidentialSupply, state.DecryptableSupply, req.ToSupplyAeKey(),
		req.ToAmount(),
	)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	res := &ProveConfidentialMintResponse{
		EqualityProofData:        codec.Base58.Encode(proofs.EqualityProof),
		ValidityProofData:        codec.Base58.Encode(proofs.ValidityProof),
		RangeProofData:           codec.Base58.Encode(proofs.RangeProof),
		AuditorCiphertextLo:      codec.Base58.Encode(proofs.AuditorCiphertextLo),
		AuditorCiphertextHi:      codec.Base58.Encode(proofs.AuditorCiphertextHi),
		NewDecryptableSupply:     codec.Base58.Encode(proofs.NewDecryptableSupply),
		SupplyElgamalPubkey:      codec.Base58.Encode(state.SupplyElGamalPubkey),
		DestinationElgamalPubkey: codec.Base58.Encode(destPublicKey),
		CurrentSupply:            strconv.FormatUint(currentSupply, 10),
		NewSupply:                strconv.FormatUint(currentSupply+req.ToAmount(), 10),
	}
	if auditorPublicKey != nil {
		res.AuditorElgamalPubkey = codec.Base58.Encode(auditorPublicKey)
	}
	handler.WriteOK(w, res)
}

// ProveConfidentialBurn godoc
// @Summary      Build the three proofs one confidential Burn needs
// @Description  Builds the commitment-equality, batched grouped 3-handle validity and batched u128 range proofs a single confidential burn requires, in one call, because they are built from the same fresh randomness and only agree with each other if drawn together. The mint and the source account are named rather than their contents passed in: the source's available balance ciphertext, decryptable balance and ElGamal key, and the mint's supply and auditor keys are read from chain, since the deployed program compares the proofs against exactly those. source_elgamal_secret_key has to match the source's ElGamal key and ae_key has to decrypt its decryptable balance, and both are checked, as is the amount against that balance. Each *_proof_data blob goes to the matching zk-elgamal-proof/context-state/verify endpoint, and auditor_ciphertext_lo/hi and new_decryptable_available_balance are what the burn instruction itself carries. The response cannot be rebuilt: a second call draws new randomness and produces proofs that no longer match any context-state account already verified from the first. The source's available balance must not change between building these proofs and the burn landing.
// @Tags         tool
// @Accept       json
// @Produce      json
// @Param        body  body      ProveConfidentialBurnRequest  true  "Mint, source, source ElGamal secret, AE key, amount"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  ProveConfidentialBurnResponse
// @Failure      400   {object}  map[string]string
// @Failure      502   {object}  map[string]string
// @Router       /svm/tool/prove/confidential-burn [post]
func (h *ToolHandler) ProveConfidentialBurn(w http.ResponseWriter, r *http.Request) {
	req := new(ProveConfidentialBurnRequest)
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

	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), []*types.PublicKey{req.MintKey(), req.SourceKey()}, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read accounts: %s", err))
		return
	}
	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	srcInfo := accounts[req.SourceKey().Base58()]
	if !srcInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source: %s does not exist", req.SourceKey()))
		return
	}
	if mintInfo.Owner != core.Token2022ProgramID.Base58() || srcInfo.Owner != core.Token2022ProgramID.Base58() {
		handler.WriteError(w, http.StatusBadRequest, "mint and source must both be owned by Token-2022")
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}
	srcData, err := srcInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode source: %s", err))
		return
	}
	if len(srcData) < 32 || !bytes.Equal(srcData[:32], req.MintKey().Bytes()) {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source: %s does not hold mint %s", req.SourceKey(), req.MintKey()))
		return
	}

	state, err := core.DecodeConfidentialMintBurn(mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s: %s", req.MintKey(), err))
		return
	}
	auditorPublicKey, err := core.ConfidentialTransferMintAuditor(mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s: %s", req.MintKey(), err))
		return
	}
	sourceExt := core.FindExtensionData(srcData, core.ExtensionTypeConfidentialTransferAccount)
	if len(sourceExt) != 295 {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source: %s does not carry the ConfidentialTransferAccount extension", req.SourceKey()))
		return
	}
	sourcePublicKey := sourceExt[1:33]
	availableCiphertext := sourceExt[161:225]
	decryptableBalance := sourceExt[225:261]

	derived, err := core.DeriveElGamalPublicKey(req.ToSourceSecretKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("source_elgamal_secret_key: %s", err))
		return
	}
	if !bytes.Equal(derived, sourcePublicKey) {
		handler.WriteError(w, http.StatusBadRequest, "source_elgamal_secret_key does not match the source account's ElGamal public key")
		return
	}

	proofs, err := core.BuildBurnProofs(
		req.ToSourceSecretKey(), sourcePublicKey, state.SupplyElGamalPubkey, auditorPublicKey,
		availableCiphertext, decryptableBalance, req.ToAeKey(),
		req.ToAmount(),
	)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	res := &ProveConfidentialBurnResponse{
		EqualityProofData:              codec.Base58.Encode(proofs.EqualityProof),
		ValidityProofData:              codec.Base58.Encode(proofs.ValidityProof),
		RangeProofData:                 codec.Base58.Encode(proofs.RangeProof),
		AuditorCiphertextLo:            codec.Base58.Encode(proofs.AuditorCiphertextLo),
		AuditorCiphertextHi:            codec.Base58.Encode(proofs.AuditorCiphertextHi),
		NewDecryptableAvailableBalance: codec.Base58.Encode(proofs.NewSourceDecryptableAvailableBalance),
		SourceElgamalPubkey:            codec.Base58.Encode(sourcePublicKey),
		SupplyElgamalPubkey:            codec.Base58.Encode(state.SupplyElGamalPubkey),
	}
	if auditorPublicKey != nil {
		res.AuditorElgamalPubkey = codec.Base58.Encode(auditorPublicKey)
	}
	handler.WriteOK(w, res)
}

// ProveConfidentialRotateSupplyElGamalPubkey godoc
// @Summary      Build the proof one RotateSupplyElGamalPubkey needs
// @Description  Decrypts the mint's confidential supply with the current supply ElGamal secret key, re-encrypts it under new_supply_elgamal_pubkey, and proves the two ciphertexts encrypt the same value. The mint's supply ciphertext and key are read from chain, since the deployed program compares the proof against exactly those, and the given secret is checked against the mint's supply key. ciphertext_ciphertext_equality_proof_data goes to zk-elgamal-proof/context-state/verify/ciphertext-ciphertext-equality. The supply must fit in 32 bits. The response goes stale if a mint or burn changes the supply before the rotation lands, and the mint's pending burn must be zero when it does.
// @Tags         tool
// @Accept       json
// @Produce      json
// @Param        body  body      ProveConfidentialRotateSupplyElGamalPubkeyRequest  true  "Mint, current supply secret, new supply key"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  ProveConfidentialRotateSupplyElGamalPubkeyResponse
// @Failure      400   {object}  map[string]string
// @Failure      502   {object}  map[string]string
// @Router       /svm/tool/prove/confidential-rotate-supply-elgamal-pubkey [post]
func (h *ToolHandler) ProveConfidentialRotateSupplyElGamalPubkey(w http.ResponseWriter, r *http.Request) {
	req := new(ProveConfidentialRotateSupplyElGamalPubkeyRequest)
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

	accounts, err := chain.Cli.GetMultipleAccounts(r.Context(), []*types.PublicKey{req.MintKey()}, rpc.CommitmentConfirmed)
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to read mint: %s", err))
		return
	}
	mintInfo := accounts[req.MintKey().Base58()]
	if !mintInfo.Exists() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s does not exist", req.MintKey()))
		return
	}
	if mintInfo.Owner != core.Token2022ProgramID.Base58() {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s is not owned by Token-2022", req.MintKey()))
		return
	}
	mintData, err := mintInfo.Bytes()
	if err != nil {
		handler.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to decode mint: %s", err))
		return
	}
	state, err := core.DecodeConfidentialMintBurn(mintData)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("mint: %s: %s", req.MintKey(), err))
		return
	}

	derived, err := core.DeriveElGamalPublicKey(req.ToSupplySecretKey())
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("supply_elgamal_secret_key: %s", err))
		return
	}
	if !bytes.Equal(derived, state.SupplyElGamalPubkey) {
		handler.WriteError(w, http.StatusBadRequest, "supply_elgamal_secret_key does not match the mint's supply ElGamal public key")
		return
	}

	proof, supply, err := core.BuildRotateSupplyProof(req.ToSupplySecretKey(), state.SupplyElGamalPubkey, req.ToNewSupplyPubkey(), state.ConfidentialSupply)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	handler.WriteOK(w, &ProveConfidentialRotateSupplyElGamalPubkeyResponse{
		CiphertextCiphertextEqualityProofData: codec.Base58.Encode(proof),
		CurrentSupply:                         strconv.FormatUint(supply, 10),
		CurrentSupplyElgamalPubkey:            codec.Base58.Encode(state.SupplyElGamalPubkey),
		NewSupplyElgamalPubkey:                codec.Base58.Encode(req.ToNewSupplyPubkey()),
	})
}
