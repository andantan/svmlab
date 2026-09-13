package core

import (
	"fmt"

	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
	"github.com/andantan/svmlab/core/zkbridge"
)

// ZkElgamalProofInstructionCloseContextState and the rest of this block
// are the top-level opcodes the ZkElgamalProof program accepts, confirmed
// against the interface crate's own ProofInstruction enum. VerifyPubkeyValidity,
// VerifyCiphertextCommitmentEquality, VerifyBatchedGroupedCiphertext3HandlesValidity,
// and VerifyBatchedRangeProofU128 are built out below -- everything
// extensions/confidential-transfer-account/{configure-account,transfer}
// need; the rest verify proofs no sub-instruction built in this codebase
// yet requires.
const (
	ZkElgamalProofInstructionCloseContextState uint8 = iota
	ZkElgamalProofInstructionVerifyZeroCiphertext
	ZkElgamalProofInstructionVerifyCiphertextCiphertextEquality
	ZkElgamalProofInstructionVerifyCiphertextCommitmentEquality
	ZkElgamalProofInstructionVerifyPubkeyValidity
	ZkElgamalProofInstructionVerifyPercentageWithCap
	ZkElgamalProofInstructionVerifyBatchedRangeProofU64
	ZkElgamalProofInstructionVerifyBatchedRangeProofU128
	ZkElgamalProofInstructionVerifyBatchedRangeProofU256
	ZkElgamalProofInstructionVerifyGroupedCiphertext2HandlesValidity
	ZkElgamalProofInstructionVerifyBatchedGroupedCiphertext2HandlesValidity
	ZkElgamalProofInstructionVerifyGroupedCiphertext3HandlesValidity
	ZkElgamalProofInstructionVerifyBatchedGroupedCiphertext3HandlesValidity
)

// zkElgamalProof is a namespace, the same shape System and Sysvar are:
// nothing about which proof to verify is state, so there is nothing to
// construct beyond the fixed program id.
type zkElgamalProof struct {
	id *types.PublicKey
}

// ZkElgamalProof builds instructions against the ZkElgamalProof program
// (ZkE1Gama1Proof11111111111111111111111111111), which Token-2022's
// ConfidentialTransfer family depends on to check the zero-knowledge
// proofs a caller supplies rather than checking them itself.
var ZkElgamalProof = &zkElgamalProof{id: ZkElgamalProofProgramID}

// VerifyPubkeyValidityInline builds a VerifyPubkeyValidity instruction
// carrying its proof data inline -- opcode 4, confirmed against the
// interface crate's ProofInstruction enum ordering -- rather than reading
// it from a separately funded context-state account. This is the shape
// extensions/confidential-transfer-account/configure-account expects
// when paired with it as the very next instruction in the same
// transaction (proof_instruction_offset = 1): no accounts at all, since
// the inline form carries everything the verifier needs in its own
// instruction data.
//
// elgamalPubkey is the account owner's ElGamal public key (the exact
// value the account's ConfidentialTransferAccount extension will store);
// proof is ProvePubkeyValidity's own 64-byte output, built against that
// same key. The two are concatenated as pubkey(32) || proof(64), the
// interface crate's own PubkeyValidityProofData wire layout (context
// struct then proof struct, with no length prefixes between them --
// bytemuck's Pod derive lays out fixed-size fields back to back).
func (z *zkElgamalProof) VerifyPubkeyValidityInline(elgamalPubkey, proof []byte) (*types.Instruction, error) {
	if len(elgamalPubkey) != 32 {
		return nil, fmt.Errorf("zk elgamal proof verify pubkey validity: elgamal pubkey is %d bytes, expected 32", len(elgamalPubkey))
	}
	if len(proof) != PubkeyValidityProofLen {
		return nil, fmt.Errorf("zk elgamal proof verify pubkey validity: proof is %d bytes, expected %d", len(proof), PubkeyValidityProofLen)
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyPubkeyValidity)
	data = codec.Binary.AppendBytes(data, elgamalPubkey)
	data = codec.Binary.AppendBytes(data, proof)

	return types.NewInstruction(z.id, types.NewAccounts(), data), nil
}

// VerifyCiphertextCommitmentEqualityInline builds a
// VerifyCiphertextCommitmentEquality instruction carrying its proof data
// inline -- opcode 3. proofData is
// zkbridge.ProveCiphertextCommitmentEquality's own output, solana-zk-sdk's
// CiphertextCommitmentEqualityProofData wire layout (context then proof,
// 320 bytes), packed directly rather than reassembled from parts since
// the wasm bridge already returns it in the exact form this instruction
// carries.
func (z *zkElgamalProof) VerifyCiphertextCommitmentEqualityInline(proofData []byte) (*types.Instruction, error) {
	if len(proofData) != zkbridge.CiphertextCommitmentEqualityProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify ciphertext commitment equality: proof data is %d bytes, expected %d", len(proofData), zkbridge.CiphertextCommitmentEqualityProofDataLen)
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyCiphertextCommitmentEquality)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, types.NewAccounts(), data), nil
}

// VerifyBatchedGroupedCiphertext3HandlesValidityInline builds a
// VerifyBatchedGroupedCiphertext3HandlesValidity instruction carrying its
// proof data inline -- opcode 10. proofData is
// zkbridge.ProveBatchedGroupedCiphertext3HandlesValidity's own output
// (544 bytes).
func (z *zkElgamalProof) VerifyBatchedGroupedCiphertext3HandlesValidityInline(proofData []byte) (*types.Instruction, error) {
	if len(proofData) != zkbridge.BatchedGroupedCiphertext3HandlesValidityProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify batched grouped ciphertext 3 handles validity: proof data is %d bytes, expected %d", len(proofData), zkbridge.BatchedGroupedCiphertext3HandlesValidityProofDataLen)
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyBatchedGroupedCiphertext3HandlesValidity)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, types.NewAccounts(), data), nil
}

// VerifyBatchedRangeProofU128Inline builds a VerifyBatchedRangeProofU128
// instruction carrying its proof data inline -- opcode 7. proofData is
// zkbridge.ProveBatchedRangeProofU128's own output (1000 bytes).
func (z *zkElgamalProof) VerifyBatchedRangeProofU128Inline(proofData []byte) (*types.Instruction, error) {
	if len(proofData) != zkbridge.BatchedRangeProofU128DataLen {
		return nil, fmt.Errorf("zk elgamal proof verify batched range proof u128: proof data is %d bytes, expected %d", len(proofData), zkbridge.BatchedRangeProofU128DataLen)
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyBatchedRangeProofU128)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, types.NewAccounts(), data), nil
}
