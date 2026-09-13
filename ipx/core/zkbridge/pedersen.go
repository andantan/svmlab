package zkbridge

import "fmt"

// PedersenCommitmentLen and PedersenOpeningLen are both 32 bytes -- a
// compressed ristretto255 element and a scalar, confirmed against
// solana-go's own encryption/types.go rather than assumed from the
// generic "everything on this curve is 32 bytes" pattern (true here, but
// not universally -- an ElGamalCiphertext is 64).
const (
	PedersenCommitmentLen = 32
	PedersenOpeningLen    = 32
)

// PedersenCommit commits to amount with a fresh random opening, returning
// (commitment, opening).
func PedersenCommit(amount uint64) (commitment, opening []byte, err error) {
	out, err := invoke("pedersen_commit", Scalar(amount))
	if err != nil {
		return nil, nil, err
	}
	if len(out) != PedersenCommitmentLen+PedersenOpeningLen {
		return nil, nil, fmt.Errorf("zkbridge: pedersen_commit returned %d bytes, want %d", len(out), PedersenCommitmentLen+PedersenOpeningLen)
	}
	return out[:PedersenCommitmentLen], out[PedersenCommitmentLen:], nil
}

// PedersenCommitWith commits to amount under the given opening.
func PedersenCommitWith(amount uint64, opening []byte) ([]byte, error) {
	if len(opening) != PedersenOpeningLen {
		return nil, fmt.Errorf("zkbridge: pedersen_commit_with: opening is %d bytes, want %d", len(opening), PedersenOpeningLen)
	}
	out, err := invoke("pedersen_commit_with", Scalar(amount), Bytes(opening))
	if err != nil {
		return nil, err
	}
	if len(out) != PedersenCommitmentLen {
		return nil, fmt.Errorf("zkbridge: pedersen_commit_with returned %d bytes, want %d", len(out), PedersenCommitmentLen)
	}
	return out, nil
}

// PedersenOpeningNewRand samples a fresh random Pedersen opening.
func PedersenOpeningNewRand() ([]byte, error) {
	out, err := invoke("pedersen_opening_new_rand")
	if err != nil {
		return nil, err
	}
	if len(out) != PedersenOpeningLen {
		return nil, fmt.Errorf("zkbridge: pedersen_opening_new_rand returned %d bytes, want %d", len(out), PedersenOpeningLen)
	}
	return out, nil
}
