package core

import (
	"crypto/sha256"
	"fmt"

	"github.com/andantan/svmlab/core/types"
)

// pda derives program derived addresses.
//
// It is a namespace like System and Sysvar: the derivation depends only on its
// arguments, so there is no state to hold and nothing to initialize.
type pda struct{}

var PDA = new(pda)

// Create hashes seeds, a program id, and the PDA marker into an address, and
// fails if the result lands on the ed25519 curve.
//
// That failure is the point rather than an edge case: a curve point is a
// public key somebody could hold the private key to, and a program derived
// address is only unsignable because the search below discards every seed
// that would produce one. Skipping the check would let a hash that happens to
// be a valid key stand in for a PDA, silently giving it an owner.
func (p *pda) Create(seeds [][]byte, programID *types.PublicKey) (*types.PublicKey, error) {
	if programID.IsNil() {
		return nil, fmt.Errorf("create program address: program id is required")
	}
	if len(seeds) > types.MaxSeeds {
		return nil, fmt.Errorf("create program address: %d seeds exceeds the limit of %d", len(seeds), types.MaxSeeds)
	}
	for i, seed := range seeds {
		if len(seed) > types.MaxSeedLength {
			return nil, fmt.Errorf("create program address: seed[%d] is %d bytes but the limit is %d", i, len(seed), types.MaxSeedLength)
		}
	}

	h := sha256.New()
	for _, seed := range seeds {
		h.Write(seed)
	}
	h.Write(programID.Bytes())
	h.Write([]byte(types.PDAMarker))
	sum := h.Sum(nil)

	if Ed25519.IsOnCurve(sum) {
		return nil, fmt.Errorf("create program address: derived address lies on the ed25519 curve")
	}

	return types.NewPublicKeyFromBytes(sum)
}

// Find appends a one-byte bump seed to the given seeds, starting at 255 and
// counting down, and returns the first address Create accepts.
//
// Counting down rather than up is only a convention, but it is the one the
// reference implementation and every explorer follow, so a different search
// order would find a valid PDA at the wrong bump and disagree with everyone
// else about which one is canonical.
func (p *pda) Find(seeds [][]byte, programID *types.PublicKey) (*types.PublicKey, uint8, error) {
	if len(seeds) > types.MaxSeeds-1 {
		return nil, 0, fmt.Errorf("find program address: %d seeds leaves no room for a bump seed", len(seeds))
	}

	withBump := make([][]byte, len(seeds)+1)
	copy(withBump, seeds)

	for bump := 255; bump >= 0; bump-- {
		withBump[len(seeds)] = []byte{byte(bump)}

		address, err := p.Create(withBump, programID)
		if err == nil {
			return address, uint8(bump), nil
		}
	}

	return nil, 0, fmt.Errorf("find program address: no bump seed in [0, 255] produced an off-curve address")
}
