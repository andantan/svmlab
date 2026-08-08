package misc

import (
	"fmt"
	"net/http"

	"github.com/andantan/svmlab/api/handler"
	"github.com/andantan/svmlab/core"
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
