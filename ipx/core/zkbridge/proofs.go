package zkbridge

import "fmt"

// Proof and context byte lengths below are confirmed against solana-go's
// own proofdata/proof_data.go POD struct definitions rather than derived
// from anything computable client-side -- each is a fixed-size #[repr(C)]
// Rust struct on the wasm side, and getting a length wrong here would
// silently truncate or misread a field rather than fail loudly.

// CiphertextCommitmentEqualityProofDataLen is
// context(pubkey 32 + ciphertext 64 + commitment 32 = 128) +
// proof(192) = 320.
const CiphertextCommitmentEqualityProofDataLen = 320

// ProveCiphertextCommitmentEquality proves that ciphertext (under the
// keypair's public key) and commitment (opened with opening) encode the
// same amount. Returns the full ProofData bytes (context || proof),
// solana-zk-sdk's own wire layout, ready to embed in a
// VerifyCiphertextCommitmentEquality instruction.
func ProveCiphertextCommitmentEquality(secretKey, publicKey, ciphertext, commitment, opening []byte, amount uint64) ([]byte, error) {
	kp, err := marshalElGamalKeypair(secretKey, publicKey)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) != ElGamalCiphertextLen {
		return nil, fmt.Errorf("zkbridge: prove ciphertext commitment equality: ciphertext is %d bytes, want %d", len(ciphertext), ElGamalCiphertextLen)
	}
	if len(commitment) != PedersenCommitmentLen {
		return nil, fmt.Errorf("zkbridge: prove ciphertext commitment equality: commitment is %d bytes, want %d", len(commitment), PedersenCommitmentLen)
	}
	if len(opening) != PedersenOpeningLen {
		return nil, fmt.Errorf("zkbridge: prove ciphertext commitment equality: opening is %d bytes, want %d", len(opening), PedersenOpeningLen)
	}

	out, err := invoke("proof_ciphertext_commitment_equality",
		Bytes(kp), Bytes(ciphertext), Bytes(commitment), Bytes(opening), Scalar(amount))
	if err != nil {
		return nil, err
	}
	if len(out) != CiphertextCommitmentEqualityProofDataLen {
		return nil, fmt.Errorf("zkbridge: proof_ciphertext_commitment_equality returned %d bytes, want %d", len(out), CiphertextCommitmentEqualityProofDataLen)
	}
	return out, nil
}

// BatchedGroupedCiphertext3HandlesValidityProofDataLen is
// context(3 pubkeys 96 + groupedLo 128 + groupedHi 128 = 352) +
// proof(192) = 544.
const BatchedGroupedCiphertext3HandlesValidityProofDataLen = 544

// ProveBatchedGroupedCiphertext3HandlesValidity proves that groupedLo and
// groupedHi are each valid encryptions of amountLo and amountHi under all
// three public keys (in order: source, destination, auditor for
// Transfer), with the given openings. Returns the full ProofData bytes
// (context || proof).
func ProveBatchedGroupedCiphertext3HandlesValidity(pubkeys, groupedLo, groupedHi []byte, amountLo, amountHi uint64, openingLo, openingHi []byte) ([]byte, error) {
	if len(pubkeys) != 3*ElGamalPubkeyLen {
		return nil, fmt.Errorf("zkbridge: prove batched grouped ciphertext 3 handles validity: pubkeys is %d bytes, want %d", len(pubkeys), 3*ElGamalPubkeyLen)
	}
	if len(groupedLo) != GroupedElGamalCiphertext3Len || len(groupedHi) != GroupedElGamalCiphertext3Len {
		return nil, fmt.Errorf("zkbridge: prove batched grouped ciphertext 3 handles validity: grouped lo/hi are %d/%d bytes, want %d each", len(groupedLo), len(groupedHi), GroupedElGamalCiphertext3Len)
	}
	if len(openingLo) != PedersenOpeningLen || len(openingHi) != PedersenOpeningLen {
		return nil, fmt.Errorf("zkbridge: prove batched grouped ciphertext 3 handles validity: openings lo/hi are %d/%d bytes, want %d each", len(openingLo), len(openingHi), PedersenOpeningLen)
	}

	out, err := invoke("proof_batched_grouped_ciphertext_3_handles_validity",
		Bytes(pubkeys), Bytes(groupedLo), Bytes(groupedHi), Scalar(amountLo), Scalar(amountHi), Bytes(openingLo), Bytes(openingHi))
	if err != nil {
		return nil, err
	}
	if len(out) != BatchedGroupedCiphertext3HandlesValidityProofDataLen {
		return nil, fmt.Errorf("zkbridge: proof_batched_grouped_ciphertext_3_handles_validity returned %d bytes, want %d", len(out), BatchedGroupedCiphertext3HandlesValidityProofDataLen)
	}
	return out, nil
}

// MaxRangeProofCommitments is the number of commitment slots a batched
// range proof context reserves; unused slots stay zero. Confirmed
// against solana-go's own MaxRangeProofCommitments.
const MaxRangeProofCommitments = 8

// BatchedRangeProofU128DataLen is context(8 commitments * 32 + 8 bit
// lengths * 1 = 264) + proof(736) = 1000. The context is always this
// fixed size regardless of how many of the (up to 8) slots the caller
// actually uses -- unused slots are zero, not omitted.
const BatchedRangeProofU128DataLen = 1000

// BatchedRangeProofU64DataLen is context 264 (the same fixed 8-slot
// BatchedRangeProofContext) + proof 672 = 936, confirmed against
// zk-sdk-pod's RANGE_PROOF_U64_LEN.
const BatchedRangeProofU64DataLen = 936

// ProveBatchedRangeProofU128 proves that each amounts[i] fits within
// bitLengths[i] bits and matches commitments[i] (opened with
// openings[i]), batched into one proof whose bit lengths must sum to
// 128. Returns the full ProofData bytes (context || proof); the context
// itself is always 264 bytes (8 fixed slots), whether n is 1 or 8.
func ProveBatchedRangeProofU128(commitments [][]byte, amounts []uint64, bitLengths []uint8, openings [][]byte) ([]byte, error) {
	return proveBatchedRange("proof_batched_range_u128", 128, BatchedRangeProofU128DataLen, commitments, amounts, bitLengths, openings)
}

// ProveBatchedRangeProofU64 is ProveBatchedRangeProofU128's 64-bit
// counterpart: the bit lengths must sum to exactly 64, and the result is
// the 936-byte ProofData a VerifyBatchedRangeProofU64 instruction
// carries. Confidential Withdraw uses it with a single 64-bit commitment
// to the remaining balance.
func ProveBatchedRangeProofU64(commitments [][]byte, amounts []uint64, bitLengths []uint8, openings [][]byte) ([]byte, error) {
	return proveBatchedRange("proof_batched_range_u64", 64, BatchedRangeProofU64DataLen, commitments, amounts, bitLengths, openings)
}

func proveBatchedRange(export string, totalBits, dataLen int, commitments [][]byte, amounts []uint64, bitLengths []uint8, openings [][]byte) ([]byte, error) {
	n := len(commitments)
	if n == 0 || len(amounts) != n || len(bitLengths) != n || len(openings) != n {
		return nil, fmt.Errorf("zkbridge: prove batched range proof u%d: requires equal-length non-empty inputs, got %d commitments, %d amounts, %d bit lengths, %d openings",
			totalBits, n, len(amounts), len(bitLengths), len(openings))
	}
	if n > MaxRangeProofCommitments {
		return nil, fmt.Errorf("zkbridge: prove batched range proof u%d: supports at most %d commitments, got %d", totalBits, MaxRangeProofCommitments, n)
	}
	var sum int
	for _, bits := range bitLengths {
		sum += int(bits)
	}
	if sum != totalBits {
		return nil, fmt.Errorf("zkbridge: prove batched range proof u%d: bit lengths sum to %d, want %d", totalBits, sum, totalBits)
	}
	for i, c := range commitments {
		if len(c) != PedersenCommitmentLen {
			return nil, fmt.Errorf("zkbridge: prove batched range proof u%d: commitments[%d] is %d bytes, want %d", totalBits, i, len(c), PedersenCommitmentLen)
		}
	}
	for i, o := range openings {
		if len(o) != PedersenOpeningLen {
			return nil, fmt.Errorf("zkbridge: prove batched range proof u%d: openings[%d] is %d bytes, want %d", totalBits, i, len(o), PedersenOpeningLen)
		}
	}

	commitmentBytes := make([][]byte, n)
	copy(commitmentBytes, commitments)
	openingBytes := make([][]byte, n)
	copy(openingBytes, openings)

	out, err := invoke(export,
		Scalar(n), Concat(commitmentBytes), U64s(amounts), Bytes(bitLengths), Concat(openingBytes))
	if err != nil {
		return nil, err
	}
	if len(out) != dataLen {
		return nil, fmt.Errorf("zkbridge: %s returned %d bytes, want %d", export, len(out), dataLen)
	}
	return out, nil
}
