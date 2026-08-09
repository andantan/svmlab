package misc

type SlotResponse struct {
	Slot uint64 `json:"slot"`
}

func NewSlotResponse(slot uint64) *SlotResponse {
	return &SlotResponse{
		Slot: slot,
	}
}

type HealthResponse struct {
	Health string `json:"health"`
}

func NewHealthResponse(health string) *HealthResponse {
	return &HealthResponse{
		Health: health,
	}
}

type VersionResponse struct {
	Version map[string]any `json:"version"`
}

func NewVersionResponse(version map[string]any) *VersionResponse {
	return &VersionResponse{
		Version: version,
	}
}

// GenesisHashResponse reports the cluster's identity and whether it is the one
// config names.
//
// A genesis hash is not folded into a signature the way EIP-155 binds a chain
// id, so nothing on chain stops a transaction from replaying elsewhere. This
// check is the substitute: confirm the endpoint is the cluster expected before
// trusting anything else it says.
type GenesisHashResponse struct {
	GenesisHash string `json:"genesis_hash"`
	Configured  string `json:"configured"`
	Matches     bool   `json:"matches"`
}

func NewGenesisHashResponse(genesis, configured string) *GenesisHashResponse {
	return &GenesisHashResponse{
		GenesisHash: genesis,
		Configured:  configured,
		Matches:     genesis == configured,
	}
}

// BlockhashResponse carries the blockhash and the height at which it dies.
type BlockhashResponse struct {
	Blockhash            string `json:"blockhash"`
	LastValidBlockHeight uint64 `json:"last_valid_block_height"`
}

func NewBlockhashResponse(blockhash string, lastValidBlockHeight uint64) *BlockhashResponse {
	return &BlockhashResponse{
		Blockhash:            blockhash,
		LastValidBlockHeight: lastValidBlockHeight,
	}
}
