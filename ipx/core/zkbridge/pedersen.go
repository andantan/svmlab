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

// PedersenCombineLoHiCommitments combines a lo and hi commitment (the two
// halves of an amount split at bitLength bits) into one commitment to the
// whole amount: lo + hi * 2^bitLength, done homomorphically.
func PedersenCombineLoHiCommitments(lo, hi []byte, bitLength uint8) ([]byte, error) {
	if len(lo) != PedersenCommitmentLen || len(hi) != PedersenCommitmentLen {
		return nil, fmt.Errorf("zkbridge: pedersen_combine_lo_hi_commitments: lo/hi are %d/%d bytes, want %d each", len(lo), len(hi), PedersenCommitmentLen)
	}
	out, err := invoke("pedersen_combine_lo_hi_commitments", Bytes(lo), Bytes(hi), Scalar(bitLength))
	if err != nil {
		return nil, err
	}
	if len(out) != PedersenCommitmentLen {
		return nil, fmt.Errorf("zkbridge: pedersen_combine_lo_hi_commitments returned %d bytes, want %d", len(out), PedersenCommitmentLen)
	}
	return out, nil
}

// PedersenCombineLoHiOpenings is PedersenCombineLoHiCommitments' opening
// counterpart: the opening of the combined commitment.
func PedersenCombineLoHiOpenings(lo, hi []byte, bitLength uint8) ([]byte, error) {
	if len(lo) != PedersenOpeningLen || len(hi) != PedersenOpeningLen {
		return nil, fmt.Errorf("zkbridge: pedersen_combine_lo_hi_openings: lo/hi are %d/%d bytes, want %d each", len(lo), len(hi), PedersenOpeningLen)
	}
	out, err := invoke("pedersen_combine_lo_hi_openings", Bytes(lo), Bytes(hi), Scalar(bitLength))
	if err != nil {
		return nil, err
	}
	if len(out) != PedersenOpeningLen {
		return nil, fmt.Errorf("zkbridge: pedersen_combine_lo_hi_openings returned %d bytes, want %d", len(out), PedersenOpeningLen)
	}
	return out, nil
}

// PedersenSubCommitments returns a - b, homomorphically.
func PedersenSubCommitments(a, b []byte) ([]byte, error) {
	if len(a) != PedersenCommitmentLen || len(b) != PedersenCommitmentLen {
		return nil, fmt.Errorf("zkbridge: pedersen_sub_commitments: inputs are %d/%d bytes, want %d each", len(a), len(b), PedersenCommitmentLen)
	}
	out, err := invoke("pedersen_sub_commitments", Bytes(a), Bytes(b))
	if err != nil {
		return nil, err
	}
	if len(out) != PedersenCommitmentLen {
		return nil, fmt.Errorf("zkbridge: pedersen_sub_commitments returned %d bytes, want %d", len(out), PedersenCommitmentLen)
	}
	return out, nil
}

// PedersenSubOpenings returns a - b, the opening of PedersenSubCommitments'
// result when applied to the same pair's openings.
func PedersenSubOpenings(a, b []byte) ([]byte, error) {
	if len(a) != PedersenOpeningLen || len(b) != PedersenOpeningLen {
		return nil, fmt.Errorf("zkbridge: pedersen_sub_openings: inputs are %d/%d bytes, want %d each", len(a), len(b), PedersenOpeningLen)
	}
	out, err := invoke("pedersen_sub_openings", Bytes(a), Bytes(b))
	if err != nil {
		return nil, err
	}
	if len(out) != PedersenOpeningLen {
		return nil, fmt.Errorf("zkbridge: pedersen_sub_openings returned %d bytes, want %d", len(out), PedersenOpeningLen)
	}
	return out, nil
}

// PedersenFeeDelta computes the commitment and opening of the fee
// "delta" a percentage-with-cap proof needs: how far the fee, computed as
// a ceiling of amount * feeRateBasisPoints / 10000, overshoots the exact
// product. transferCommitment/Opening commit to the full transfer amount
// and feeCommitment/Opening to the fee. Returns (commitment, opening).
func PedersenFeeDelta(transferCommitment, transferOpening, feeCommitment, feeOpening []byte, feeRateBasisPoints uint16) (commitment, opening []byte, err error) {
	if len(transferCommitment) != PedersenCommitmentLen || len(feeCommitment) != PedersenCommitmentLen {
		return nil, nil, fmt.Errorf("zkbridge: pedersen_fee_delta: commitments are %d/%d bytes, want %d each", len(transferCommitment), len(feeCommitment), PedersenCommitmentLen)
	}
	if len(transferOpening) != PedersenOpeningLen || len(feeOpening) != PedersenOpeningLen {
		return nil, nil, fmt.Errorf("zkbridge: pedersen_fee_delta: openings are %d/%d bytes, want %d each", len(transferOpening), len(feeOpening), PedersenOpeningLen)
	}
	out, err := invoke("pedersen_fee_delta",
		Bytes(transferCommitment), Bytes(transferOpening), Bytes(feeCommitment), Bytes(feeOpening), Scalar(feeRateBasisPoints))
	if err != nil {
		return nil, nil, err
	}
	if len(out) != PedersenCommitmentLen+PedersenOpeningLen {
		return nil, nil, fmt.Errorf("zkbridge: pedersen_fee_delta returned %d bytes, want %d", len(out), PedersenCommitmentLen+PedersenOpeningLen)
	}
	return out[:PedersenCommitmentLen], out[PedersenCommitmentLen:], nil
}
