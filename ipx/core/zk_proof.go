package core

import (
	"crypto/rand"
	"fmt"

	"github.com/gtank/merlin"
	"github.com/gtank/ristretto255"
)

// PubkeyValidityProofLen is the wire length of a PubkeyValidityProof: a
// compressed ristretto255 element (Y, the sigma-protocol commitment)
// followed by a scalar (z, the response), 32 bytes each.
const PubkeyValidityProofLen = 64

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
