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
// @Router       /svm/tool/generate/keypair [post]
func (h *ToolHandler) GenerateKeypair(w http.ResponseWriter, r *http.Request) {
	key, err := core.GenerateKey()
	if err != nil {
		handler.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to generate key: %s", err))
		return
	}

	handler.WriteOK(w, NewGenerateKeypairResponse(key))
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
