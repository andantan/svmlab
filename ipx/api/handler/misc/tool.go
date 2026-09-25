package misc

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/codec"
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
