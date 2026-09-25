package core

import (
	"fmt"

	"github.com/andantan/svmlab/core/zkbridge"
)

// WithdrawProofs is everything one confidential Withdraw needs beyond
// what the caller already holds: the two proofs (each to be verified into
// a context-state account of its own) and the source's new decryptable
// balance the instruction carries.
type WithdrawProofs struct {
	// EqualityProof is CiphertextCommitmentEqualityProofData's bytes, for
	// VerifyCiphertextCommitmentEquality -- proves the remaining-balance
	// ciphertext and a Pedersen commitment encode the same value.
	EqualityProof []byte
	// RangeProof is BatchedRangeProofU64Data's bytes, for
	// VerifyBatchedRangeProofU64 -- proves the remaining balance fits in
	// 64 bits, which is what stops a withdrawal exceeding the balance from
	// wrapping around to a huge remainder.
	RangeProof []byte

	// NewDecryptableAvailableBalance is the remaining balance
	// (currentAvailableBalance - withdrawAmount), AE-encrypted under the
	// caller's AeKey -- Withdraw's own new_decryptable_available_balance
	// field.
	NewDecryptableAvailableBalance []byte
}

// BuildWithdrawProofs builds the two proofs a confidential Withdraw
// requires, ported from solana-go's NewWithdrawProofData and run through
// the same wasm bridge BuildTransferProofs uses: the remaining-balance
// ciphertext (current available balance minus the plaintext amount,
// computed homomorphically), a fresh Pedersen commitment to that
// remainder, an equality proof tying the two together, and a 64-bit range
// proof over the commitment. The withdraw amount itself is public -- it
// leaves the confidential side as a plain balance -- so, unlike a
// transfer, there is nothing to encrypt for a destination or an auditor
// and no ciphertext-validity proof.
//
// currentAvailableBalanceCiphertext is the account's on-chain available
// balance, and currentDecryptableAvailableBalance its AE encryption under
// aeKey, decrypted here first to know the plaintext balance this server
// needs to check the withdrawal against.
func BuildWithdrawProofs(
	sourceSecretKey, sourcePublicKey []byte,
	currentAvailableBalanceCiphertext, currentDecryptableAvailableBalance, aeKey []byte,
	withdrawAmount uint64,
) (*WithdrawProofs, error) {
	if len(sourceSecretKey) != 32 || len(sourcePublicKey) != 32 {
		return nil, fmt.Errorf("build withdraw proofs: source secret/public key must be 32 bytes each")
	}

	currentBalance, err := DecryptAeAmount(aeKey, currentDecryptableAvailableBalance)
	if err != nil {
		return nil, fmt.Errorf("build withdraw proofs: decrypt current balance: %w", err)
	}
	if withdrawAmount > currentBalance {
		return nil, fmt.Errorf("build withdraw proofs: amount %d exceeds the current available balance %d", withdrawAmount, currentBalance)
	}
	remaining := currentBalance - withdrawAmount

	remainingCiphertext, err := zkbridge.ElGamalSubtractAmount(currentAvailableBalanceCiphertext, withdrawAmount)
	if err != nil {
		return nil, fmt.Errorf("build withdraw proofs: remaining balance ciphertext: %w", err)
	}
	commitment, opening, err := zkbridge.PedersenCommit(remaining)
	if err != nil {
		return nil, fmt.Errorf("build withdraw proofs: commit to remaining balance: %w", err)
	}

	equalityProof, err := zkbridge.ProveCiphertextCommitmentEquality(sourceSecretKey, sourcePublicKey, remainingCiphertext, commitment, opening, remaining)
	if err != nil {
		return nil, fmt.Errorf("build withdraw proofs: equality proof: %w", err)
	}
	rangeProof, err := zkbridge.ProveBatchedRangeProofU64([][]byte{commitment}, []uint64{remaining}, []uint8{TransferBalanceBitLength}, [][]byte{opening})
	if err != nil {
		return nil, fmt.Errorf("build withdraw proofs: range proof: %w", err)
	}

	newDecryptable, err := EncryptAeAmount(aeKey, remaining)
	if err != nil {
		return nil, fmt.Errorf("build withdraw proofs: encrypt new balance: %w", err)
	}

	return &WithdrawProofs{
		EqualityProof:                  equalityProof,
		RangeProof:                     rangeProof,
		NewDecryptableAvailableBalance: newDecryptable,
	}, nil
}
