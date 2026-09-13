package core

import (
	"crypto/rand"
	"fmt"

	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
	"github.com/andantan/svmlab/core/zkbridge"
	"github.com/gtank/merlin"
	"github.com/gtank/ristretto255"
)

// Context-state account space, below, is confirmed against the interface
// crate's own ProofContextState<T> layout:
//
//	context_state_authority: Address (32) + proof_type: PodProofType (1) + context: T
//
// -- T being each proof type's own context-only struct (the proof itself
// never lives in the context-state account, only what a downstream
// consumer like ConfidentialTransferAccount's Transfer needs to read back
// later). These sizes were cross-checked against solana-go's own
// Example_contextState test output (space: 65 for PubkeyValidityProofContext).
const (
	// PubkeyValidityProofLen is the wire length of a PubkeyValidityProof: a
	// compressed ristretto255 element (Y, the sigma-protocol commitment)
	// followed by a scalar (z, the response), 32 bytes each.
	PubkeyValidityProofLen = 64

	// PubkeyValidityContextStateSpace is 32 + 1 + 32 (the ElGamal pubkey
	// alone).
	PubkeyValidityContextStateSpace = 65

	// CiphertextCommitmentEqualityContextStateSpace is 32 + 1 + 128
	// (pubkey 32 + ciphertext 64 + commitment 32).
	CiphertextCommitmentEqualityContextStateSpace = 161

	// BatchedGroupedCiphertext3HandlesValidityContextStateSpace is
	// 32 + 1 + 352 (3 pubkeys 96 + grouped-lo 128 + grouped-hi 128).
	BatchedGroupedCiphertext3HandlesValidityContextStateSpace = 385

	// BatchedRangeProofU128ContextStateSpace is 32 + 1 + 264 (8 fixed
	// commitment slots * 32 + 8 fixed bit-length slots * 1).
	BatchedRangeProofU128ContextStateSpace = 297

	// ZeroCiphertextContextStateSpace is 32 + 1 + 96 (pubkey 32 +
	// ciphertext 64).
	ZeroCiphertextContextStateSpace = 129

	// CiphertextCiphertextEqualityContextStateSpace is 32 + 1 + 192
	// (2 pubkeys 64 + 2 ciphertexts 128).
	CiphertextCiphertextEqualityContextStateSpace = 225

	// PercentageWithCapContextStateSpace is 32 + 1 + 104 (3 commitments 96
	// + max_value u64 8).
	PercentageWithCapContextStateSpace = 137

	// BatchedRangeProofU64ContextStateSpace and
	// BatchedRangeProofU256ContextStateSpace are the same 264-byte
	// BatchedRangeProofContext BatchedRangeProofU128ContextStateSpace
	// uses -- all three VerifyBatchedRangeProof{64,128,256} instructions
	// share one context struct (8 fixed commitment slots + 8 fixed
	// bit-length slots); only the proof itself, never stored in the
	// context-state account, varies with the bit length.
	BatchedRangeProofU64ContextStateSpace  = 297
	BatchedRangeProofU256ContextStateSpace = 297

	// GroupedCiphertext2HandlesValidityContextStateSpace is 32 + 1 + 160
	// (2 pubkeys 64 + a 2-handle grouped ciphertext 96).
	GroupedCiphertext2HandlesValidityContextStateSpace = 193

	// BatchedGroupedCiphertext2HandlesValidityContextStateSpace is
	// 32 + 1 + 256 (2 pubkeys 64 + grouped-lo 96 + grouped-hi 96).
	BatchedGroupedCiphertext2HandlesValidityContextStateSpace = 289

	// GroupedCiphertext3HandlesValidityContextStateSpace is 32 + 1 + 224
	// (3 pubkeys 96 + a 3-handle grouped ciphertext 128).
	GroupedCiphertext3HandlesValidityContextStateSpace = 257
)

// ProofData lengths below (context + proof, packed back to back) are
// confirmed against the interface crate's own proof_data structs and
// zk-sdk-pod's sigma_proofs.rs/range_proof.rs constants -- CIPHERTEXT_
// CIPHERTEXT_EQUALITY_PROOF_LEN, RANGE_PROOF_U64_LEN, and so on -- the
// same source CiphertextCommitmentEqualityProofDataLen and its two
// zkbridge-side siblings were confirmed against, just read directly here
// since no zkbridge prover exists yet for these eight.
const (
	// ZeroCiphertextProofDataLen is context 96 (pubkey 32 + ciphertext
	// 64) + proof 96.
	ZeroCiphertextProofDataLen = 192

	// CiphertextCiphertextEqualityProofDataLen is context 192 (2 pubkeys
	// 64 + 2 ciphertexts 128) + proof 224.
	CiphertextCiphertextEqualityProofDataLen = 416

	// PercentageWithCapProofDataLen is context 104 (3 commitments 96 +
	// max_value u64 8) + proof 256.
	PercentageWithCapProofDataLen = 360

	// BatchedRangeProofU64ProofDataLen is context 264 + proof 672.
	BatchedRangeProofU64ProofDataLen = 936

	// BatchedRangeProofU256ProofDataLen is context 264 + proof 800.
	BatchedRangeProofU256ProofDataLen = 1064

	// GroupedCiphertext2HandlesValidityProofDataLen is context 160
	// (2 pubkeys 64 + a 2-handle grouped ciphertext 96) + proof 160.
	GroupedCiphertext2HandlesValidityProofDataLen = 320

	// BatchedGroupedCiphertext2HandlesValidityProofDataLen is context 256
	// (2 pubkeys 64 + grouped-lo 96 + grouped-hi 96) + proof 160.
	BatchedGroupedCiphertext2HandlesValidityProofDataLen = 416

	// GroupedCiphertext3HandlesValidityProofDataLen is context 224
	// (3 pubkeys 96 + a 3-handle grouped ciphertext 128) + proof 192.
	GroupedCiphertext3HandlesValidityProofDataLen = 416
)

// zkTranscriptDomain is the fixed outer label every zk-elgamal-proof
// transcript is wrapped in, confirmed against zk-sdk's own lib.rs:
//
//	pub const TRANSCRIPT_DOMAIN: &[u8] = b"solana-zk-elgamal-proof-program-v1";
//
// This is not the same thing as a proof-specific label like
// "pubkey-validity-instruction" -- that is a second, separate dom-sep
// message appended after this one, not the argument merlin's own
// Transcript::new receives. An earlier version of this file collapsed
// the two into a single merlin.NewTranscript(specificLabel) call, which
// builds a transcript that verifies against itself (prover and verifier
// here agreed with each other) but not against the deployed program,
// since the actual bytes hashed into the transcript state differ from
// what new_zk_elgamal_transcript produces. Caught only by an actual
// on-chain VerifyPubkeyValidity failure (AlgebraicRelation) after local
// round-trip tests passed -- this class of transcript-shape bug is
// exactly what a self-consistent local prove/verify pair can never catch,
// since both sides make the same mistake.
const zkTranscriptDomain = "solana-zk-elgamal-proof-program-v1"

// pubkeyValidityTranscript rebuilds the exact Merlin transcript
// solana-zk-sdk's build_pubkey_validity_proof_data /
// PubkeyValidityProofData::verify_proof both construct, through the
// point ProvePubkeyValidity and VerifyPubkeyValidity diverge
// (append_point(b"Y", ...) happens after this returns, since the prover
// has to compute Y first and the verifier already has it).
//
// Confirmed against the interface crate's own transcript.rs,
// zk_elgamal_proof_program/pubkey_validity.rs, and
// sigma_proofs/pubkey_validity.rs rather than assumed from a generic
// sigma-protocol shape. The exact message sequence, in order:
//
//  1. Transcript::new_zk_elgamal_transcript(b"pubkey-validity-instruction")
//     itself expands to two dom-sep messages, not one:
//     merlin.NewTranscript(zkTranscriptDomain) appends dom-sep ->
//     zkTranscriptDomain as its own first message, and
//     new_zk_elgamal_transcript then appends a second, explicit
//     dom-sep -> "pubkey-validity-instruction" on top of that.
//  2. append_message(b"pubkey", pubkey_bytes) --
//     PubkeyValidityProof::hash_context_into_transcript, run before the
//     proof's own domain separator, not after.
//  3. append_message(b"dom-sep", b"pubkey-proof") --
//     pubkey_proof_domain_separator.
//
// Every one of these has to match byte for byte, or the challenge this
// derives disagrees with the one the deployed verifier recomputes even
// though the arithmetic around it is correct.
func pubkeyValidityTranscript(publicKey []byte) *merlin.Transcript {
	t := merlin.NewTranscript(zkTranscriptDomain)
	t.AppendMessage([]byte("dom-sep"), []byte("pubkey-validity-instruction"))
	t.AppendMessage([]byte("pubkey"), publicKey)
	t.AppendMessage([]byte("dom-sep"), []byte("pubkey-proof"))

	return t
}

// challengeScalar reads label's 64 challenge bytes from t and reduces them
// modulo the ristretto255 group order -- transcript.challenge_scalar's own
// two steps (challenge_bytes into a 64-byte buffer, then
// Scalar::from_bytes_mod_order_wide), which SetUniformBytes performs in
// one call since it takes the same wide input and applies the same
// reduction.
func challengeScalar(t *merlin.Transcript, label string) (*ristretto255.Scalar, error) {
	buf := t.ExtractBytes([]byte(label), 64)

	c, err := ristretto255.NewScalar().SetUniformBytes(buf)
	if err != nil {
		return nil, fmt.Errorf("challenge scalar: %w", err)
	}

	return c, nil
}

// ProvePubkeyValidity builds a PubkeyValidityProof: a sigma-protocol proof
// that the caller knows secretKey, the ElGamal secret key publicKey was
// derived from (public_key = secret_key^-1 * H, GenerateElGamalKey's own
// construction). This is what
// extensions/confidential-transfer-account/configure-account's
// proof_instruction_offset field requires alongside it in the same
// transaction -- without it the deployed program has no way to tell a
// real ElGamal public key from 32 arbitrary bytes.
//
// The proof itself: a random scalar y, a commitment Y = y*H, a
// Fiat-Shamir challenge c derived from a transcript seeded with publicKey
// (pubkeyValidityTranscript), and a response z = c*secretKey^-1 + y.
// Confirmed against the interface crate's PubkeyValidityProof::new --
// notably the response uses the secret's inverse, the same quantity
// public_key was built from, not the secret itself.
//
// The returned 64 bytes are Y (32 bytes, compressed) followed by z (32
// bytes) -- solana-zk-sdk's own PubkeyValidityProof wire layout, packed
// directly rather than through a Pod/bytemuck-style struct since Go has
// no equivalent to derive from.
func ProvePubkeyValidity(secretKey, publicKey []byte) ([]byte, error) {
	if len(secretKey) != 32 {
		return nil, fmt.Errorf("prove pubkey validity: secret key is %d bytes, expected 32", len(secretKey))
	}
	if len(publicKey) != 32 {
		return nil, fmt.Errorf("prove pubkey validity: public key is %d bytes, expected 32", len(publicKey))
	}

	s, err := ristretto255.NewScalar().SetCanonicalBytes(secretKey)
	if err != nil {
		return nil, fmt.Errorf("prove pubkey validity: secret key: %w", err)
	}

	pubkeyPoint, err := ristretto255.NewIdentityElement().SetCanonicalBytes(publicKey)
	if err != nil {
		return nil, fmt.Errorf("prove pubkey validity: public key: %w", err)
	}

	sInv := ristretto255.NewScalar().Invert(s)

	// public_key has to actually be secret_key^-1 * H, the one relationship
	// this proof exists to attest to -- checked here rather than left to
	// silently produce a proof that fails against the deployed verifier,
	// the same reason DeriveKeyFromBase58 checks a stored public key
	// against its secret instead of trusting the caller's pairing.
	recomputed := ristretto255.NewIdentityElement().ScalarMult(sInv, elgamalH)
	if recomputed.Equal(pubkeyPoint) != 1 {
		return nil, fmt.Errorf("prove pubkey validity: public key does not match secret_key^-1 * H")
	}

	transcript := pubkeyValidityTranscript(publicKey)

	var seed [64]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("prove pubkey validity: %w", err)
	}
	y, err := ristretto255.NewScalar().SetUniformBytes(seed[:])
	if err != nil {
		return nil, fmt.Errorf("prove pubkey validity: %w", err)
	}

	commitmentY := ristretto255.NewIdentityElement().ScalarMult(y, elgamalH)
	transcript.AppendMessage([]byte("Y"), commitmentY.Bytes())

	c, err := challengeScalar(transcript, "c")
	if err != nil {
		return nil, fmt.Errorf("prove pubkey validity: %w", err)
	}

	// z = c*s^-1 + y
	z := ristretto255.NewScalar().Add(ristretto255.NewScalar().Multiply(c, sInv), y)

	proof := make([]byte, 0, PubkeyValidityProofLen)
	proof = append(proof, commitmentY.Bytes()...)
	proof = append(proof, z.Bytes()...)

	return proof, nil
}

// VerifyPubkeyValidity checks a PubkeyValidityProof against publicKey
// exactly as the deployed zk_elgamal_proof program's verifier does: it
// rebuilds the same transcript, rederives the same challenge from proof's
// own Y, and checks z*H == Y + c*public_key.
//
// This never touches a cluster -- it exists so ProvePubkeyValidity's own
// output can be checked locally before a transaction ever carries it,
// the same role raw-byte TLV parsing has played throughout this API's
// devnet verification rather than trusting a builder's output blind.
func VerifyPubkeyValidity(publicKey, proof []byte) (bool, error) {
	if len(publicKey) != 32 {
		return false, fmt.Errorf("verify pubkey validity: public key is %d bytes, expected 32", len(publicKey))
	}
	if len(proof) != PubkeyValidityProofLen {
		return false, fmt.Errorf("verify pubkey validity: proof is %d bytes, expected %d", len(proof), PubkeyValidityProofLen)
	}

	pubkeyPoint, err := ristretto255.NewIdentityElement().SetCanonicalBytes(publicKey)
	if err != nil {
		return false, fmt.Errorf("verify pubkey validity: public key: %w", err)
	}

	commitmentY, err := ristretto255.NewIdentityElement().SetCanonicalBytes(proof[:32])
	if err != nil {
		return false, fmt.Errorf("verify pubkey validity: proof Y: %w", err)
	}

	z, err := ristretto255.NewScalar().SetCanonicalBytes(proof[32:64])
	if err != nil {
		return false, fmt.Errorf("verify pubkey validity: proof z: %w", err)
	}

	transcript := pubkeyValidityTranscript(publicKey)
	transcript.AppendMessage([]byte("Y"), commitmentY.Bytes())

	c, err := challengeScalar(transcript, "c")
	if err != nil {
		return false, fmt.Errorf("verify pubkey validity: %w", err)
	}

	lhs := ristretto255.NewIdentityElement().ScalarMult(z, elgamalH)
	rhs := ristretto255.NewIdentityElement().Add(commitmentY, ristretto255.NewIdentityElement().ScalarMult(c, pubkeyPoint))

	return lhs.Equal(rhs) == 1, nil
}

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

// ID returns the ZkElgamalProof program's own address -- the value a
// context-state account must be assigned to at creation so this program,
// rather than System, ends up owning it.
func (z *zkElgamalProof) ID() *types.PublicKey {
	return z.id
}

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

// contextStateAccounts builds the two extra accounts every Verify
// instruction takes on when asked to persist its context: the
// context-state account itself (writable, not a signer -- it must instead
// already exist, created by a System CreateAccount instruction earlier in
// the same transaction, owned by this program) and its declared owner
// (read-only, and not a signer either; only CloseContextState later
// requires that owner's signature).
func contextStateAccounts(contextStateAccount, contextStateAccountOwner *types.PublicKey) types.Accounts {
	return types.NewAccounts(
		types.NewWritableAccount(contextStateAccount),
		types.NewReadonlyAccount(contextStateAccountOwner),
	)
}

// VerifyPubkeyValidityContextState is VerifyPubkeyValidityInline's
// context-state counterpart: the same proof data, but with the account
// list telling the program to also persist the context (the ElGamal
// pubkey alone) into contextStateAccount for a later instruction --
// Transfer, here -- to read back by reference instead of needing the
// proof re-supplied inline. contextStateAccount must already exist,
// created earlier in the same transaction via System.CreateAccount with
// owner ZkElgamalProof.ID() and space PubkeyValidityContextStateSpace.
func (z *zkElgamalProof) VerifyPubkeyValidityContextState(elgamalPubkey, proof []byte, contextStateAccount, contextStateAccountOwner *types.PublicKey) (*types.Instruction, error) {
	if len(elgamalPubkey) != 32 {
		return nil, fmt.Errorf("zk elgamal proof verify pubkey validity (context state): elgamal pubkey is %d bytes, expected 32", len(elgamalPubkey))
	}
	if len(proof) != PubkeyValidityProofLen {
		return nil, fmt.Errorf("zk elgamal proof verify pubkey validity (context state): proof is %d bytes, expected %d", len(proof), PubkeyValidityProofLen)
	}
	if contextStateAccount.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify pubkey validity (context state): context state account is required")
	}
	if contextStateAccountOwner.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify pubkey validity (context state): context state account owner is required")
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyPubkeyValidity)
	data = codec.Binary.AppendBytes(data, elgamalPubkey)
	data = codec.Binary.AppendBytes(data, proof)

	return types.NewInstruction(z.id, contextStateAccounts(contextStateAccount, contextStateAccountOwner), data), nil
}

// VerifyCiphertextCommitmentEqualityContextState is
// VerifyCiphertextCommitmentEqualityInline's context-state counterpart.
// contextStateAccount must already exist, created earlier in the same
// transaction via System.CreateAccount with owner ZkElgamalProof.ID() and
// space CiphertextCommitmentEqualityContextStateSpace.
func (z *zkElgamalProof) VerifyCiphertextCommitmentEqualityContextState(proofData []byte, contextStateAccount, contextStateAccountOwner *types.PublicKey) (*types.Instruction, error) {
	if len(proofData) != zkbridge.CiphertextCommitmentEqualityProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify ciphertext commitment equality (context state): proof data is %d bytes, expected %d", len(proofData), zkbridge.CiphertextCommitmentEqualityProofDataLen)
	}
	if contextStateAccount.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify ciphertext commitment equality (context state): context state account is required")
	}
	if contextStateAccountOwner.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify ciphertext commitment equality (context state): context state account owner is required")
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyCiphertextCommitmentEquality)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, contextStateAccounts(contextStateAccount, contextStateAccountOwner), data), nil
}

// VerifyBatchedGroupedCiphertext3HandlesValidityContextState is
// VerifyBatchedGroupedCiphertext3HandlesValidityInline's context-state
// counterpart. contextStateAccount must already exist, created earlier in
// the same transaction via System.CreateAccount with owner
// ZkElgamalProof.ID() and space
// BatchedGroupedCiphertext3HandlesValidityContextStateSpace.
func (z *zkElgamalProof) VerifyBatchedGroupedCiphertext3HandlesValidityContextState(proofData []byte, contextStateAccount, contextStateAccountOwner *types.PublicKey) (*types.Instruction, error) {
	if len(proofData) != zkbridge.BatchedGroupedCiphertext3HandlesValidityProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify batched grouped ciphertext 3 handles validity (context state): proof data is %d bytes, expected %d", len(proofData), zkbridge.BatchedGroupedCiphertext3HandlesValidityProofDataLen)
	}
	if contextStateAccount.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify batched grouped ciphertext 3 handles validity (context state): context state account is required")
	}
	if contextStateAccountOwner.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify batched grouped ciphertext 3 handles validity (context state): context state account owner is required")
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyBatchedGroupedCiphertext3HandlesValidity)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, contextStateAccounts(contextStateAccount, contextStateAccountOwner), data), nil
}

// VerifyBatchedRangeProofU128ContextState is
// VerifyBatchedRangeProofU128Inline's context-state counterpart.
// contextStateAccount must already exist, created earlier in the same
// transaction via System.CreateAccount with owner ZkElgamalProof.ID() and
// space BatchedRangeProofU128ContextStateSpace.
func (z *zkElgamalProof) VerifyBatchedRangeProofU128ContextState(proofData []byte, contextStateAccount, contextStateAccountOwner *types.PublicKey) (*types.Instruction, error) {
	if len(proofData) != zkbridge.BatchedRangeProofU128DataLen {
		return nil, fmt.Errorf("zk elgamal proof verify batched range proof u128 (context state): proof data is %d bytes, expected %d", len(proofData), zkbridge.BatchedRangeProofU128DataLen)
	}
	if contextStateAccount.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify batched range proof u128 (context state): context state account is required")
	}
	if contextStateAccountOwner.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify batched range proof u128 (context state): context state account owner is required")
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyBatchedRangeProofU128)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, contextStateAccounts(contextStateAccount, contextStateAccountOwner), data), nil
}

// CloseContextState closes a proof context-state account and reclaims its
// rent lamports to destination. The context account's declared owner
// (contextStateAccountOwner, the same key passed as the second account to
// whichever VerifyXXXContextState instruction created it) must sign --
// this is the one context-state instruction that actually checks a
// signature, unlike the Verify step which only ever reads that key.
//
// Accounts, in order: the context account to close (writable), the
// lamports destination (writable), and the owner (signer). Confirmed
// against the interface crate's ProofInstruction::CloseContextState doc
// comment.
func (z *zkElgamalProof) CloseContextState(contextStateAccount, destination, contextStateAccountOwner *types.PublicKey) (*types.Instruction, error) {
	if contextStateAccount.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof close context state: context state account is required")
	}
	if destination.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof close context state: destination is required")
	}
	if contextStateAccountOwner.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof close context state: context state account owner is required")
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionCloseContextState)

	return types.NewInstruction(z.id, types.NewAccounts(
		types.NewWritableAccount(contextStateAccount),
		types.NewWritableAccount(destination),
		types.NewReadonlySignerAccount(contextStateAccountOwner),
	), data), nil
}

// VerifyZeroCiphertextInline builds a VerifyZeroCiphertext instruction carrying its proof data
// inline -- opcode ZkElgamalProofInstructionVerifyZeroCiphertext. proofData is the full ZeroCiphertextProofData wire
// bytes (context then proof, 192 bytes), packed by the caller exactly
// as the deployed program expects; unlike VerifyPubkeyValidityInline this
// package has no from-scratch prover for this proof type, so the caller
// supplies the finished blob rather than component parts.
func (z *zkElgamalProof) VerifyZeroCiphertextInline(proofData []byte) (*types.Instruction, error) {
	if len(proofData) != ZeroCiphertextProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify zero ciphertext: proof data is %d bytes, expected %d", len(proofData), ZeroCiphertextProofDataLen)
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyZeroCiphertext)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, types.NewAccounts(), data), nil
}

// VerifyZeroCiphertextContextState is VerifyZeroCiphertextInline's context-state counterpart.
// contextStateAccount must already exist, created earlier in the same
// transaction via System.CreateAccount with owner ZkElgamalProof.ID() and
// space ZeroCiphertextContextStateSpace.
func (z *zkElgamalProof) VerifyZeroCiphertextContextState(proofData []byte, contextStateAccount, contextStateAccountOwner *types.PublicKey) (*types.Instruction, error) {
	if len(proofData) != ZeroCiphertextProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify zero ciphertext (context state): proof data is %d bytes, expected %d", len(proofData), ZeroCiphertextProofDataLen)
	}
	if contextStateAccount.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify zero ciphertext (context state): context state account is required")
	}
	if contextStateAccountOwner.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify zero ciphertext (context state): context state account owner is required")
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyZeroCiphertext)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, contextStateAccounts(contextStateAccount, contextStateAccountOwner), data), nil
}

// VerifyCiphertextCiphertextEqualityInline builds a VerifyCiphertextCiphertextEquality instruction carrying its proof data
// inline -- opcode ZkElgamalProofInstructionVerifyCiphertextCiphertextEquality. proofData is the full CiphertextCiphertextEqualityProofData wire
// bytes (context then proof, 416 bytes), packed by the caller exactly
// as the deployed program expects; unlike VerifyPubkeyValidityInline this
// package has no from-scratch prover for this proof type, so the caller
// supplies the finished blob rather than component parts.
func (z *zkElgamalProof) VerifyCiphertextCiphertextEqualityInline(proofData []byte) (*types.Instruction, error) {
	if len(proofData) != CiphertextCiphertextEqualityProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify ciphertext ciphertext equality: proof data is %d bytes, expected %d", len(proofData), CiphertextCiphertextEqualityProofDataLen)
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyCiphertextCiphertextEquality)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, types.NewAccounts(), data), nil
}

// VerifyCiphertextCiphertextEqualityContextState is VerifyCiphertextCiphertextEqualityInline's context-state counterpart.
// contextStateAccount must already exist, created earlier in the same
// transaction via System.CreateAccount with owner ZkElgamalProof.ID() and
// space CiphertextCiphertextEqualityContextStateSpace.
func (z *zkElgamalProof) VerifyCiphertextCiphertextEqualityContextState(proofData []byte, contextStateAccount, contextStateAccountOwner *types.PublicKey) (*types.Instruction, error) {
	if len(proofData) != CiphertextCiphertextEqualityProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify ciphertext ciphertext equality (context state): proof data is %d bytes, expected %d", len(proofData), CiphertextCiphertextEqualityProofDataLen)
	}
	if contextStateAccount.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify ciphertext ciphertext equality (context state): context state account is required")
	}
	if contextStateAccountOwner.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify ciphertext ciphertext equality (context state): context state account owner is required")
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyCiphertextCiphertextEquality)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, contextStateAccounts(contextStateAccount, contextStateAccountOwner), data), nil
}

// VerifyPercentageWithCapInline builds a VerifyPercentageWithCap instruction carrying its proof data
// inline -- opcode ZkElgamalProofInstructionVerifyPercentageWithCap. proofData is the full PercentageWithCapProofData wire
// bytes (context then proof, 360 bytes), packed by the caller exactly
// as the deployed program expects; unlike VerifyPubkeyValidityInline this
// package has no from-scratch prover for this proof type, so the caller
// supplies the finished blob rather than component parts.
func (z *zkElgamalProof) VerifyPercentageWithCapInline(proofData []byte) (*types.Instruction, error) {
	if len(proofData) != PercentageWithCapProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify percentage with cap: proof data is %d bytes, expected %d", len(proofData), PercentageWithCapProofDataLen)
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyPercentageWithCap)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, types.NewAccounts(), data), nil
}

// VerifyPercentageWithCapContextState is VerifyPercentageWithCapInline's context-state counterpart.
// contextStateAccount must already exist, created earlier in the same
// transaction via System.CreateAccount with owner ZkElgamalProof.ID() and
// space PercentageWithCapContextStateSpace.
func (z *zkElgamalProof) VerifyPercentageWithCapContextState(proofData []byte, contextStateAccount, contextStateAccountOwner *types.PublicKey) (*types.Instruction, error) {
	if len(proofData) != PercentageWithCapProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify percentage with cap (context state): proof data is %d bytes, expected %d", len(proofData), PercentageWithCapProofDataLen)
	}
	if contextStateAccount.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify percentage with cap (context state): context state account is required")
	}
	if contextStateAccountOwner.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify percentage with cap (context state): context state account owner is required")
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyPercentageWithCap)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, contextStateAccounts(contextStateAccount, contextStateAccountOwner), data), nil
}

// VerifyBatchedRangeProofU64Inline builds a VerifyBatchedRangeProofU64 instruction carrying its proof data
// inline -- opcode ZkElgamalProofInstructionVerifyBatchedRangeProofU64. proofData is the full BatchedRangeProofU64ProofData wire
// bytes (context then proof, 936 bytes), packed by the caller exactly
// as the deployed program expects; unlike VerifyPubkeyValidityInline this
// package has no from-scratch prover for this proof type, so the caller
// supplies the finished blob rather than component parts.
func (z *zkElgamalProof) VerifyBatchedRangeProofU64Inline(proofData []byte) (*types.Instruction, error) {
	if len(proofData) != BatchedRangeProofU64ProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify batched range proof u64: proof data is %d bytes, expected %d", len(proofData), BatchedRangeProofU64ProofDataLen)
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyBatchedRangeProofU64)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, types.NewAccounts(), data), nil
}

// VerifyBatchedRangeProofU64ContextState is VerifyBatchedRangeProofU64Inline's context-state counterpart.
// contextStateAccount must already exist, created earlier in the same
// transaction via System.CreateAccount with owner ZkElgamalProof.ID() and
// space BatchedRangeProofU64ContextStateSpace.
func (z *zkElgamalProof) VerifyBatchedRangeProofU64ContextState(proofData []byte, contextStateAccount, contextStateAccountOwner *types.PublicKey) (*types.Instruction, error) {
	if len(proofData) != BatchedRangeProofU64ProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify batched range proof u64 (context state): proof data is %d bytes, expected %d", len(proofData), BatchedRangeProofU64ProofDataLen)
	}
	if contextStateAccount.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify batched range proof u64 (context state): context state account is required")
	}
	if contextStateAccountOwner.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify batched range proof u64 (context state): context state account owner is required")
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyBatchedRangeProofU64)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, contextStateAccounts(contextStateAccount, contextStateAccountOwner), data), nil
}

// VerifyBatchedRangeProofU256Inline builds a VerifyBatchedRangeProofU256 instruction carrying its proof data
// inline -- opcode ZkElgamalProofInstructionVerifyBatchedRangeProofU256. proofData is the full BatchedRangeProofU256ProofData wire
// bytes (context then proof, 1064 bytes), packed by the caller exactly
// as the deployed program expects; unlike VerifyPubkeyValidityInline this
// package has no from-scratch prover for this proof type, so the caller
// supplies the finished blob rather than component parts.
func (z *zkElgamalProof) VerifyBatchedRangeProofU256Inline(proofData []byte) (*types.Instruction, error) {
	if len(proofData) != BatchedRangeProofU256ProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify batched range proof u256: proof data is %d bytes, expected %d", len(proofData), BatchedRangeProofU256ProofDataLen)
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyBatchedRangeProofU256)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, types.NewAccounts(), data), nil
}

// VerifyBatchedRangeProofU256ContextState is VerifyBatchedRangeProofU256Inline's context-state counterpart.
// contextStateAccount must already exist, created earlier in the same
// transaction via System.CreateAccount with owner ZkElgamalProof.ID() and
// space BatchedRangeProofU256ContextStateSpace.
func (z *zkElgamalProof) VerifyBatchedRangeProofU256ContextState(proofData []byte, contextStateAccount, contextStateAccountOwner *types.PublicKey) (*types.Instruction, error) {
	if len(proofData) != BatchedRangeProofU256ProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify batched range proof u256 (context state): proof data is %d bytes, expected %d", len(proofData), BatchedRangeProofU256ProofDataLen)
	}
	if contextStateAccount.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify batched range proof u256 (context state): context state account is required")
	}
	if contextStateAccountOwner.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify batched range proof u256 (context state): context state account owner is required")
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyBatchedRangeProofU256)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, contextStateAccounts(contextStateAccount, contextStateAccountOwner), data), nil
}

// VerifyGroupedCiphertext2HandlesValidityInline builds a VerifyGroupedCiphertext2HandlesValidity instruction carrying its proof data
// inline -- opcode ZkElgamalProofInstructionVerifyGroupedCiphertext2HandlesValidity. proofData is the full GroupedCiphertext2HandlesValidityProofData wire
// bytes (context then proof, 320 bytes), packed by the caller exactly
// as the deployed program expects; unlike VerifyPubkeyValidityInline this
// package has no from-scratch prover for this proof type, so the caller
// supplies the finished blob rather than component parts.
func (z *zkElgamalProof) VerifyGroupedCiphertext2HandlesValidityInline(proofData []byte) (*types.Instruction, error) {
	if len(proofData) != GroupedCiphertext2HandlesValidityProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify grouped ciphertext2 handles validity: proof data is %d bytes, expected %d", len(proofData), GroupedCiphertext2HandlesValidityProofDataLen)
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyGroupedCiphertext2HandlesValidity)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, types.NewAccounts(), data), nil
}

// VerifyGroupedCiphertext2HandlesValidityContextState is VerifyGroupedCiphertext2HandlesValidityInline's context-state counterpart.
// contextStateAccount must already exist, created earlier in the same
// transaction via System.CreateAccount with owner ZkElgamalProof.ID() and
// space GroupedCiphertext2HandlesValidityContextStateSpace.
func (z *zkElgamalProof) VerifyGroupedCiphertext2HandlesValidityContextState(proofData []byte, contextStateAccount, contextStateAccountOwner *types.PublicKey) (*types.Instruction, error) {
	if len(proofData) != GroupedCiphertext2HandlesValidityProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify grouped ciphertext2 handles validity (context state): proof data is %d bytes, expected %d", len(proofData), GroupedCiphertext2HandlesValidityProofDataLen)
	}
	if contextStateAccount.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify grouped ciphertext2 handles validity (context state): context state account is required")
	}
	if contextStateAccountOwner.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify grouped ciphertext2 handles validity (context state): context state account owner is required")
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyGroupedCiphertext2HandlesValidity)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, contextStateAccounts(contextStateAccount, contextStateAccountOwner), data), nil
}

// VerifyBatchedGroupedCiphertext2HandlesValidityInline builds a VerifyBatchedGroupedCiphertext2HandlesValidity instruction carrying its proof data
// inline -- opcode ZkElgamalProofInstructionVerifyBatchedGroupedCiphertext2HandlesValidity. proofData is the full BatchedGroupedCiphertext2HandlesValidityProofData wire
// bytes (context then proof, 416 bytes), packed by the caller exactly
// as the deployed program expects; unlike VerifyPubkeyValidityInline this
// package has no from-scratch prover for this proof type, so the caller
// supplies the finished blob rather than component parts.
func (z *zkElgamalProof) VerifyBatchedGroupedCiphertext2HandlesValidityInline(proofData []byte) (*types.Instruction, error) {
	if len(proofData) != BatchedGroupedCiphertext2HandlesValidityProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify batched grouped ciphertext2 handles validity: proof data is %d bytes, expected %d", len(proofData), BatchedGroupedCiphertext2HandlesValidityProofDataLen)
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyBatchedGroupedCiphertext2HandlesValidity)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, types.NewAccounts(), data), nil
}

// VerifyBatchedGroupedCiphertext2HandlesValidityContextState is VerifyBatchedGroupedCiphertext2HandlesValidityInline's context-state counterpart.
// contextStateAccount must already exist, created earlier in the same
// transaction via System.CreateAccount with owner ZkElgamalProof.ID() and
// space BatchedGroupedCiphertext2HandlesValidityContextStateSpace.
func (z *zkElgamalProof) VerifyBatchedGroupedCiphertext2HandlesValidityContextState(proofData []byte, contextStateAccount, contextStateAccountOwner *types.PublicKey) (*types.Instruction, error) {
	if len(proofData) != BatchedGroupedCiphertext2HandlesValidityProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify batched grouped ciphertext2 handles validity (context state): proof data is %d bytes, expected %d", len(proofData), BatchedGroupedCiphertext2HandlesValidityProofDataLen)
	}
	if contextStateAccount.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify batched grouped ciphertext2 handles validity (context state): context state account is required")
	}
	if contextStateAccountOwner.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify batched grouped ciphertext2 handles validity (context state): context state account owner is required")
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyBatchedGroupedCiphertext2HandlesValidity)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, contextStateAccounts(contextStateAccount, contextStateAccountOwner), data), nil
}

// VerifyGroupedCiphertext3HandlesValidityInline builds a VerifyGroupedCiphertext3HandlesValidity instruction carrying its proof data
// inline -- opcode ZkElgamalProofInstructionVerifyGroupedCiphertext3HandlesValidity. proofData is the full GroupedCiphertext3HandlesValidityProofData wire
// bytes (context then proof, 416 bytes), packed by the caller exactly
// as the deployed program expects; unlike VerifyPubkeyValidityInline this
// package has no from-scratch prover for this proof type, so the caller
// supplies the finished blob rather than component parts.
func (z *zkElgamalProof) VerifyGroupedCiphertext3HandlesValidityInline(proofData []byte) (*types.Instruction, error) {
	if len(proofData) != GroupedCiphertext3HandlesValidityProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify grouped ciphertext3 handles validity: proof data is %d bytes, expected %d", len(proofData), GroupedCiphertext3HandlesValidityProofDataLen)
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyGroupedCiphertext3HandlesValidity)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, types.NewAccounts(), data), nil
}

// VerifyGroupedCiphertext3HandlesValidityContextState is VerifyGroupedCiphertext3HandlesValidityInline's context-state counterpart.
// contextStateAccount must already exist, created earlier in the same
// transaction via System.CreateAccount with owner ZkElgamalProof.ID() and
// space GroupedCiphertext3HandlesValidityContextStateSpace.
func (z *zkElgamalProof) VerifyGroupedCiphertext3HandlesValidityContextState(proofData []byte, contextStateAccount, contextStateAccountOwner *types.PublicKey) (*types.Instruction, error) {
	if len(proofData) != GroupedCiphertext3HandlesValidityProofDataLen {
		return nil, fmt.Errorf("zk elgamal proof verify grouped ciphertext3 handles validity (context state): proof data is %d bytes, expected %d", len(proofData), GroupedCiphertext3HandlesValidityProofDataLen)
	}
	if contextStateAccount.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify grouped ciphertext3 handles validity (context state): context state account is required")
	}
	if contextStateAccountOwner.IsNil() {
		return nil, fmt.Errorf("zk elgamal proof verify grouped ciphertext3 handles validity (context state): context state account owner is required")
	}

	data := codec.Binary.AppendU8(nil, ZkElgamalProofInstructionVerifyGroupedCiphertext3HandlesValidity)
	data = codec.Binary.AppendBytes(data, proofData)

	return types.NewInstruction(z.id, contextStateAccounts(contextStateAccount, contextStateAccountOwner), data), nil
}
