package misc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/types"
)

// The rent-exemption responses below report the minimum balance an account of
// a given size must hold to persist.
//
// An EVM account has no such floor; here an account below it is subject to
// removal, which is why creating one has to meet the threshold. Each endpoint
// has its own type, so the account kind is the type rather than a field
// repeating the route that was called.

type RentExemptionSystemResponse struct {
	Space    uint64 `json:"space"`
	Lamports string `json:"lamports"`
	SOL      string `json:"sol"`
}

func NewRentExemptionSystemResponse(lamports uint64) *RentExemptionSystemResponse {
	return &RentExemptionSystemResponse{
		Space:    core.SystemAccountSpace,
		Lamports: strconv.FormatUint(lamports, 10),
		SOL:      types.LamportsToSol(lamports),
	}
}

type RentExemptionMintResponse struct {
	Space    uint64 `json:"space"`
	Lamports string `json:"lamports"`
	SOL      string `json:"sol"`
}

func NewRentExemptionMintResponse(lamports uint64) *RentExemptionMintResponse {
	return &RentExemptionMintResponse{
		Space:    core.MintSpace,
		Lamports: strconv.FormatUint(lamports, 10),
		SOL:      types.LamportsToSol(lamports),
	}
}

type RentExemptionTokenResponse struct {
	Space    uint64 `json:"space"`
	Lamports string `json:"lamports"`
	SOL      string `json:"sol"`
}

func NewRentExemptionTokenResponse(lamports uint64) *RentExemptionTokenResponse {
	return &RentExemptionTokenResponse{
		Space:    core.TokenAccountSpace,
		Lamports: strconv.FormatUint(lamports, 10),
		SOL:      types.LamportsToSol(lamports),
	}
}

type RentExemptionStakeResponse struct {
	Space    uint64 `json:"space"`
	Lamports string `json:"lamports"`
	SOL      string `json:"sol"`
}

func NewRentExemptionStakeResponse(lamports uint64) *RentExemptionStakeResponse {
	return &RentExemptionStakeResponse{
		Space:    core.StakeAccountSpace,
		Lamports: strconv.FormatUint(lamports, 10),
		SOL:      types.LamportsToSol(lamports),
	}
}

type RentExemptionVoteResponse struct {
	Space    uint64 `json:"space"`
	Lamports string `json:"lamports"`
	SOL      string `json:"sol"`
}

func NewRentExemptionVoteResponse(lamports uint64) *RentExemptionVoteResponse {
	return &RentExemptionVoteResponse{
		Space:    core.VoteAccountSpace,
		Lamports: strconv.FormatUint(lamports, 10),
		SOL:      types.LamportsToSol(lamports),
	}
}

type RentExemptionNonceResponse struct {
	Space    uint64 `json:"space"`
	Lamports string `json:"lamports"`
	SOL      string `json:"sol"`
}

func NewRentExemptionNonceResponse(lamports uint64) *RentExemptionNonceResponse {
	return &RentExemptionNonceResponse{
		Space:    core.NonceAccountSpace,
		Lamports: strconv.FormatUint(lamports, 10),
		SOL:      types.LamportsToSol(lamports),
	}
}

type RentExemptionSpaceResponse struct {
	Space    uint64 `json:"space"`
	Lamports string `json:"lamports"`
	SOL      string `json:"sol"`
}

func NewRentExemptionSpaceResponse(space, lamports uint64) *RentExemptionSpaceResponse {
	return &RentExemptionSpaceResponse{
		Space:    space,
		Lamports: strconv.FormatUint(lamports, 10),
		SOL:      types.LamportsToSol(lamports),
	}
}

// RentExemptionPublicKeyResponse names the account the size was read from,
// which the other rent endpoints have no equivalent of.
type RentExemptionPublicKeyResponse struct {
	PublicKey string `json:"public_key"`
	Space     uint64 `json:"space"`
	Lamports  string `json:"lamports"`
	SOL       string `json:"sol"`
}

func NewRentExemptionPublicKeyResponse(k *types.PublicKey, space, lamports uint64) *RentExemptionPublicKeyResponse {
	return &RentExemptionPublicKeyResponse{
		PublicKey: k.Base58(),
		Space:     space,
		Lamports:  strconv.FormatUint(lamports, 10),
		SOL:       types.LamportsToSol(lamports),
	}
}

// RentExemptionSpaceRequest asks for the minimum balance for a size given
// directly, rather than one implied by an account kind or read off a live
// account.
type RentExemptionSpaceRequest struct {
	Space string `json:"space" example:"165"`

	space uint64
}

func (r *RentExemptionSpaceRequest) ValidateRequest() error {
	space := strings.TrimSpace(r.Space)
	if space == "" {
		return errors.New("space is required")
	}

	var err error
	if r.space, err = strconv.ParseUint(space, 10, 64); err != nil {
		return errors.New("space: must be a decimal byte count")
	}
	if r.space > core.MaxPermittedDataLength {
		return fmt.Errorf("space: %d bytes exceeds the %d byte limit", r.space, core.MaxPermittedDataLength)
	}

	return nil
}

func (r *RentExemptionSpaceRequest) ToSpace() uint64 {
	return r.space
}

// RentExemptionPublicKeyRequest asks for the minimum balance for an account
// size read from an existing account.
type RentExemptionPublicKeyRequest struct {
	PublicKey string `json:"public_key" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	publicKey *types.PublicKey
}

func (r *RentExemptionPublicKeyRequest) ValidateRequest() error {
	var err error
	if r.publicKey, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.PublicKey)); err != nil {
		return errors.New("public_key: " + err.Error())
	}

	return nil
}

func (r *RentExemptionPublicKeyRequest) ToPublicKey() *types.PublicKey {
	return r.publicKey
}
