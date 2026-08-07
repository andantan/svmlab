package handler

import (
	"errors"
	"strings"
)

// ChainSelector is embedded in request DTOs so callers pick a cluster
// per-request via body fields instead of a path/header parameter.
type ChainSelector struct {
	ChainName    string `json:"chain_name"    example:"solana"`
	ChainNetwork string `json:"chain_network" example:"devnet"`
}

func (c *ChainSelector) ValidateChainSelector() error {
	c.ChainName = strings.TrimSpace(c.ChainName)
	c.ChainNetwork = strings.TrimSpace(c.ChainNetwork)

	if c.ChainName == "" {
		return errors.New("chain_name is required")
	}
	if c.ChainNetwork == "" {
		return errors.New("chain_network is required")
	}

	return nil
}

// Commitment is embedded in request DTOs that read cluster state.
//
// It takes the place of evmlab's block tag, but is a confirmation level rather
// than a height, so it has no "latest" equivalent and defaults to confirmed
// when a caller leaves it out.
type Commitment struct {
	Commitment string `json:"commitment" example:"confirmed"`
}

func (c *Commitment) ValidateCommitment() error {
	c.Commitment = strings.TrimSpace(strings.ToLower(c.Commitment))

	switch c.Commitment {
	case "":
		c.Commitment = "confirmed"
	case "processed", "confirmed", "finalized":
	default:
		return errors.New("commitment: must be processed, confirmed, or finalized")
	}

	return nil
}
