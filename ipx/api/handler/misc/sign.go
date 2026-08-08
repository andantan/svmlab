package misc

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/types"
	"github.com/andantan/svmlab/internal/config"
)

type SignHandler struct {
	cfg *config.Config
}

func NewSignHandler(cfg *config.Config) *SignHandler {
	return &SignHandler{cfg: cfg}
}

// SignTransaction godoc
// @Summary      Sign a serialized transaction
// @Description  Signs the message inside a serialized transaction and writes each signature into its signer's slot, found from the key rather than from the order given. The message is never rebuilt, so the bytes a caller signs are exactly the bytes they were given. public_keys are resolved from config.yaml and private_keys carry the secret directly, for a signer such as a newly created account that is not registered; the two may be mixed in one call. Keys may also be named across several calls, so co-signers can complete a transaction one at a time.
// @Tags         sign
// @Accept       json
// @Produce      json
// @Param        body  body      SignTransactionRequest  true  "Transaction and its signers"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SignTransactionResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/sign/transaction [post]
func (h *SignHandler) SignTransaction(w http.ResponseWriter, r *http.Request) {
	req := new(SignTransactionRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	privs := make([]*types.PrivateKey, 0, len(req.PublicKeys)+len(req.PrivateKeys))
	for i, pub := range req.PublicKeys {
		entry, err := h.cfg.KeyByPublicKey(pub)
		if err != nil {
			handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("public_keys[%d]: %s", i, err))
			return
		}

		key, err := core.DeriveKeyFromBase58(entry.PrivateKey, entry.PublicKey)
		if err != nil {
			handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("public_keys[%d]: failed to derive key: %s", i, err))
			return
		}
		privs = append(privs, key.PrivateKey)
	}
	privs = append(privs, req.ToPrivateKeys()...)

	tx := req.ToTransaction()
	if err := core.Signer.SignTransaction(tx, privs...); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	raw, err := tx.Serialize()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encode tx: %s", err))
		return
	}

	handler.WriteOK(w, NewSignTransactionResponse(tx, raw))
}

// Sign godoc
// @Summary      Sign arbitrary bytes
// @Description  Signs the given bytes with a key resolved from config.yaml and returns the bare signature, assembling nothing around it. The input is the message itself, not a digest: ed25519 hashes internally, so a pre-hashed input yields a signature no verifier holding the real message can check. Pass the message field a build returns to reproduce what the transaction signer does.
// @Tags         sign
// @Accept       json
// @Produce      json
// @Param        body  body      SignRequest  true  "Signer public key and message"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  SignResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/sign [post]
func (h *SignHandler) Sign(w http.ResponseWriter, r *http.Request) {
	req := new(SignRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	entry, err := h.cfg.KeyByPublicKey(req.PublicKey)
	if err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("public_key: %s", err))
		return
	}

	key, err := core.DeriveKeyFromBase58(entry.PrivateKey, entry.PublicKey)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to derive key: %s", err))
		return
	}

	sig, err := core.Signer.Sign(req.ToMessage(), key.PrivateKey)
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sign: %s", err))
		return
	}

	handler.WriteOK(w, NewSignResponse(key.PublicKey, sig))
}

// Verify godoc
// @Summary      Verify a signature
// @Description  Checks a signature against a message and a public key. The key is required and cannot be recovered from the signature, since ed25519 offers no equivalent of ecrecover. Any key may be given, not only one from config.
// @Tags         sign
// @Accept       json
// @Produce      json
// @Param        body  body      VerifyRequest  true  "Public key, message, and signature"
// @Param        X-Chain-Name     header    string  true  "Chain name, e.g. solana"
// @Param        X-Chain-Network  header    string  true  "Chain network, e.g. testnet"
// @Success      200   {object}  VerifyResponse
// @Failure      400   {object}  map[string]string
// @Router       /svm/sign/verify [post]
func (h *SignHandler) Verify(w http.ResponseWriter, r *http.Request) {
	req := new(VerifyRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		handler.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %s", err))
		return
	}
	if err := req.ValidateRequest(); err != nil {
		handler.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	valid := core.Signer.Verify(req.ToMessage(), req.ToSignature(), req.ToPublicKey())
	handler.WriteOK(w, NewVerifyResponse(valid))
}
