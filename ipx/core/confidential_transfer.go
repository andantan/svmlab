package core

import (
	"fmt"

	"github.com/andantan/svmlab/core/zkbridge"
)

// Transfer amount bit-split constants, confirmed against solana-go's own
// confidential/constants.go rather than picked to look plausible: the
// exact split (16 low bits, 32 high bits, leaving 48 total) is baked into
// what the deployed program's range proof verifier checks, not a choice
// this package is free to make differently.
const (
	// TransferBalanceBitLength is how many bits an account or mint
	// balance carries in the batched range proof.
	TransferBalanceBitLength = 64

	// TransferAmountLoBitLength is the low half of a transfer amount's
	// split.
	TransferAmountLoBitLength = 16
	// TransferAmountHiBitLength is the high half.
	TransferAmountHiBitLength = 32
	// TransferMaxAmount is the largest transfer amount the lo/hi split
	// can represent: 2^(16+32) - 1.
	TransferMaxAmount = 1<<(TransferAmountLoBitLength+TransferAmountHiBitLength) - 1

	// TransferPadBitLength is the headroom the batched range proof pads
	// with (a zero-amount, zero-bit-length-free commitment) so
	// balance + amount_lo + amount_hi + pad sums to exactly 128 bits,
	// the width BatchedRangeProofU128 covers.
	TransferPadBitLength = 128 - TransferBalanceBitLength - TransferAmountLoBitLength - TransferAmountHiBitLength
)

// auditorHandleIndex and sourceHandleIndex are a grouped 3-handle
// ciphertext's fixed key ordering for Transfer: [source, destination,
// auditor], confirmed against solana-go's own
// CiphertextValidityProofWithAuditorCiphertext usage.
const (
	sourceHandleIndex  = 0
	auditorHandleIndex = 2
)

func splitTransferAmount(amount uint64, loBits uint) (lo, hi uint64) {
	return amount & (1<<loBits - 1), amount >> loBits
}

// TransferProofs bundles everything extensions/confidential-transfer-account/
// transfer needs beyond its own Transfer instruction: the three proof-data
// byte blobs (each solana-zk-sdk's own context||proof wire layout, ready
// to embed in their respective zk_elgamal_proof VerifyProof instructions)
// and the two pieces Transfer's own instruction data carries directly.
type TransferProofs struct {
	// EqualityProof is CiphertextCommitmentEqualityProofData's bytes,
	// for VerifyCiphertextCommitmentEquality.
	EqualityProof []byte
	// ValidityProof is
	// BatchedGroupedCiphertext3HandlesValidityProofData's bytes, for
	// VerifyBatchedGroupedCiphertext3HandlesValidity.
	ValidityProof []byte
	// RangeProof is BatchedRangeProofU128Data's bytes, for
	// VerifyBatchedRangeProofU128.
	RangeProof []byte

	// AuditorCiphertextLo and AuditorCiphertextHi are the transfer
	// amount's lo/hi split, ElGamal-encrypted under the mint's auditor
	// key alone (or the identity key, if the mint has none) -- Transfer's
	// own transfer_amount_auditor_ciphertext_lo/hi fields.
	AuditorCiphertextLo []byte
	AuditorCiphertextHi []byte

	// NewSourceDecryptableAvailableBalance is source's new available
	// balance (currentAvailableBalance - transferAmount), AE-encrypted
	// under the caller's AeKey -- Transfer's own
	// new_source_decryptable_available_balance field.
	NewSourceDecryptableAvailableBalance []byte
}

// BuildTransferProofs computes everything a confidential Transfer needs
// to prove: that the lo/hi split of transferAmount is validly encrypted
// under the source, destination, and auditor ElGamal keys
// (BatchedGroupedCiphertext3HandlesValidity), that source's new available
// balance ciphertext (current minus this transfer) matches a fresh
// commitment to the plaintext remainder (CiphertextCommitmentEquality),
// and that the remainder and the lo/hi split all fit their bit widths,
// batched into one 128-bit range proof (source's new balance is what
// this last one actually keeps non-negative -- the reason Transfer can
// never overdraw an account despite the amount itself being encrypted).
//
// This calls the real solana-zk-sdk proof-generation code via
// core/zkbridge rather than a from-scratch port: see zkbridge's own doc
// comment for why. The orchestration itself (which values get committed,
// which get combined, in what order) is ported from solana-go's
// confidential/utils.go and confidential/transfer.go, function by
// function, against the same source this package already checks every
// other Token-2022 builder against.
//
// currentAvailableBalanceCiphertext is source's current available
// balance (the same ElGamalCiphertext ConfigureAccount's extension
// stores), and currentDecryptableAvailableBalance its AE encryption
// under aeKey -- decrypted here first to know the plaintext balance this
// server needs to check the spend against and to compute the new
// balance, since nothing about a confidential balance is otherwise
// readable server-side. auditorPublicKey may be nil for a mint with no
// auditor, in which case the identity key (32 zero bytes) stands in, the
// same convention InitializeConfidentialTransferMint's own MaybeNull
// auditor field uses.
func BuildTransferProofs(
	sourceSecretKey, sourcePublicKey, destinationPublicKey, auditorPublicKey []byte,
	currentAvailableBalanceCiphertext, currentDecryptableAvailableBalance, aeKey []byte,
	transferAmount uint64,
) (*TransferProofs, error) {
	if len(sourceSecretKey) != 32 || len(sourcePublicKey) != 32 {
		return nil, fmt.Errorf("build transfer proofs: source secret/public key must be 32 bytes each")
	}
	if len(destinationPublicKey) != 32 {
		return nil, fmt.Errorf("build transfer proofs: destination public key must be 32 bytes")
	}
	if auditorPublicKey != nil && len(auditorPublicKey) != 32 {
		return nil, fmt.Errorf("build transfer proofs: auditor public key must be 32 bytes when given")
	}

	currentBalance, err := DecryptAeAmount(aeKey, currentDecryptableAvailableBalance)
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: decrypt current balance: %w", err)
	}
	if transferAmount > TransferMaxAmount {
		return nil, fmt.Errorf("build transfer proofs: amount %d exceeds the maximum a confidential transfer can represent (%d)", transferAmount, uint64(TransferMaxAmount))
	}
	if transferAmount > currentBalance {
		return nil, fmt.Errorf("build transfer proofs: amount %d exceeds the current available balance %d", transferAmount, currentBalance)
	}

	auditorKey := make([]byte, 32)
	if auditorPublicKey != nil {
		copy(auditorKey, auditorPublicKey)
	}
	pubkeys := make([]byte, 0, 96)
	pubkeys = append(pubkeys, sourcePublicKey...)
	pubkeys = append(pubkeys, destinationPublicKey...)
	pubkeys = append(pubkeys, auditorKey...)

	amountLo, amountHi := splitTransferAmount(transferAmount, TransferAmountLoBitLength)

	openingLo, err := zkbridge.PedersenOpeningNewRand()
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: %w", err)
	}
	openingHi, err := zkbridge.PedersenOpeningNewRand()
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: %w", err)
	}

	groupedLo, err := zkbridge.GroupedElGamalEncrypt3(pubkeys, amountLo, openingLo)
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: %w", err)
	}
	groupedHi, err := zkbridge.GroupedElGamalEncrypt3(pubkeys, amountHi, openingHi)
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: %w", err)
	}

	validityProof, err := zkbridge.ProveBatchedGroupedCiphertext3HandlesValidity(pubkeys, groupedLo, groupedHi, amountLo, amountHi, openingLo, openingHi)
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: %w", err)
	}

	auditorCiphertextLo, err := zkbridge.GroupedCiphertext3ToElGamal(groupedLo, auditorHandleIndex)
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: %w", err)
	}
	auditorCiphertextHi, err := zkbridge.GroupedCiphertext3ToElGamal(groupedHi, auditorHandleIndex)
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: %w", err)
	}

	sourceCiphertextLo, err := zkbridge.GroupedCiphertext3ToElGamal(groupedLo, sourceHandleIndex)
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: %w", err)
	}
	sourceCiphertextHi, err := zkbridge.GroupedCiphertext3ToElGamal(groupedHi, sourceHandleIndex)
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: %w", err)
	}
	changeAmountCiphertext, err := zkbridge.ElGamalCombineLoHiCiphertexts(sourceCiphertextLo, sourceCiphertextHi, TransferAmountLoBitLength)
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: %w", err)
	}

	newBalance := currentBalance - transferAmount
	newBalanceCiphertext, err := zkbridge.ElGamalSubtractCiphertexts(currentAvailableBalanceCiphertext, changeAmountCiphertext)
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: %w", err)
	}

	finalBalanceCommitment, finalBalanceOpening, err := zkbridge.PedersenCommit(newBalance)
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: %w", err)
	}

	equalityProof, err := zkbridge.ProveCiphertextCommitmentEquality(sourceSecretKey, sourcePublicKey, newBalanceCiphertext, finalBalanceCommitment, finalBalanceOpening, newBalance)
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: %w", err)
	}

	loCommitment, err := zkbridge.PedersenCommitWith(amountLo, openingLo)
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: %w", err)
	}
	hiCommitment, err := zkbridge.PedersenCommitWith(amountHi, openingHi)
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: %w", err)
	}
	padCommitment, padOpening, err := zkbridge.PedersenCommit(0)
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: %w", err)
	}

	rangeProof, err := zkbridge.ProveBatchedRangeProofU128(
		[][]byte{finalBalanceCommitment, loCommitment, hiCommitment, padCommitment},
		[]uint64{newBalance, amountLo, amountHi, 0},
		[]uint8{TransferBalanceBitLength, TransferAmountLoBitLength, TransferAmountHiBitLength, TransferPadBitLength},
		[][]byte{finalBalanceOpening, openingLo, openingHi, padOpening},
	)
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: %w", err)
	}

	newSourceDecryptableAvailableBalance, err := EncryptAeAmount(aeKey, newBalance)
	if err != nil {
		return nil, fmt.Errorf("build transfer proofs: %w", err)
	}

	return &TransferProofs{
		EqualityProof:                        equalityProof,
		ValidityProof:                        validityProof,
		RangeProof:                           rangeProof,
		AuditorCiphertextLo:                  auditorCiphertextLo,
		AuditorCiphertextHi:                  auditorCiphertextHi,
		NewSourceDecryptableAvailableBalance: newSourceDecryptableAvailableBalance,
	}, nil
}
