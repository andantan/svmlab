package types

import (
	"crypto/sha256"
	"fmt"
)

// The limits and the marker that govern deriving an address rather than
// holding one.
//
// Both derivations Solana offers are here in spirit even though only one is
// here in code: CreateWithSeed below, and the program derived address that
// core.PDA builds on core.Ed25519. They share MaxSeedLength because the runtime
// enforces one MAX_SEED_LEN for both, and they share PDAMarker because the rule
// one of them enforces is about the other.
const (
	// MaxSeedLength is the longest a single seed may be, for either
	// derivation.
	MaxSeedLength = 32

	// MaxSeeds bounds how many seeds a program derived address may hash. It
	// has no CreateWithSeed counterpart, which takes exactly one seed.
	MaxSeeds = 16

	// PDAMarker is what a program derived address appends to its seeds before
	// hashing, so that a PDA can never be produced by any other derivation.
	//
	// It is why CreateWithSeed refuses an owner ending in these bytes: a
	// caller able to choose such an owner could make that derivation land on
	// an address a program believes only it can authorize.
	PDAMarker = "ProgramDerivedAddress"
)

// CreateWithSeed derives an address from a base key, a seed, and an owner.
//
//	address = SHA256(base || seed || owner)
//
// This is not a program derived address. There is no curve check and no bump:
// the result may well land on the curve, and nothing cares, because a PDA is
// unsignable by construction while this address is merely never signed for.
// Authority here is the base key, so whoever can sign for base controls every
// address derived from it, and the derived account never signs for itself.
//
// Deriving an address is separate from using one. Only the System Program's
// with-seed instructions accept such an address, and building those is what
// core's System builders do with the result.
func CreateWithSeed(base *PublicKey, seed string, owner *PublicKey) (*PublicKey, error) {
	if base.IsNil() {
		return nil, fmt.Errorf("create with seed: base is required")
	}
	if owner.IsNil() {
		return nil, fmt.Errorf("create with seed: owner is required")
	}
	if len(seed) > MaxSeedLength {
		return nil, fmt.Errorf("create with seed: seed is %d bytes but the limit is %d", len(seed), MaxSeedLength)
	}

	ownerBytes := owner.Bytes()
	if len(ownerBytes) >= len(PDAMarker) &&
		string(ownerBytes[len(ownerBytes)-len(PDAMarker):]) == PDAMarker {
		return nil, fmt.Errorf("create with seed: owner ends with %q, which is reserved for program derived addresses", PDAMarker)
	}

	h := sha256.New()
	h.Write(base.Bytes())
	h.Write([]byte(seed))
	h.Write(ownerBytes)

	return NewPublicKeyFromBytes(h.Sum(nil))
}
