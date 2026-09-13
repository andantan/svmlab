package core

import (
	"encoding/hex"
	"testing"

	"github.com/gtank/ristretto255"
)

// TestElgamalGeneratorG pins G against the well-known ristretto255 base
// point encoding, the one fixed reference value any test here can check
// itself against without a Solana-provided vector -- if this ever fails,
// the ristretto255 dependency itself changed shape, not this package.
func TestElgamalGeneratorG(t *testing.T) {
	const wantG = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"

	got := hex.EncodeToString(ristretto255.NewGeneratorElement().Bytes())
	if got != wantG {
		t.Fatalf("G = %s, want %s", got, wantG)
	}
}

// TestGenerateElGamalKeyRelationship checks the one property
// GenerateElGamalKey exists to establish: public_key = secret_key^-1 * H,
// not secret_key * G -- the exact mistake this package shipped once
// before catching it against solana-zk-sdk's own ElGamalPubkey::new.
func TestGenerateElGamalKeyRelationship(t *testing.T) {
	key, err := GenerateElGamalKey()
	if err != nil {
		t.Fatalf("GenerateElGamalKey: %v", err)
	}
	if len(key.SecretKey) != 32 {
		t.Fatalf("secret key is %d bytes, want 32", len(key.SecretKey))
	}
	if len(key.PublicKey) != 32 {
		t.Fatalf("public key is %d bytes, want 32", len(key.PublicKey))
	}

	s, err := ristretto255.NewScalar().SetCanonicalBytes(key.SecretKey)
	if err != nil {
		t.Fatalf("secret key: not a canonical scalar: %v", err)
	}
	sInv := ristretto255.NewScalar().Invert(s)
	want := ristretto255.NewIdentityElement().ScalarMult(sInv, elgamalH)

	got, err := ristretto255.NewIdentityElement().SetCanonicalBytes(key.PublicKey)
	if err != nil {
		t.Fatalf("public key: not a canonical element: %v", err)
	}
	if want.Equal(got) != 1 {
		t.Fatalf("public key does not equal secret_key^-1 * H")
	}
}

// TestGenerateElGamalKeyUnique guards against the random source silently
// degrading to a constant or low-entropy output -- two independently
// generated keys must never collide.
func TestGenerateElGamalKeyUnique(t *testing.T) {
	a, err := GenerateElGamalKey()
	if err != nil {
		t.Fatalf("GenerateElGamalKey: %v", err)
	}
	b, err := GenerateElGamalKey()
	if err != nil {
		t.Fatalf("GenerateElGamalKey: %v", err)
	}

	if hex.EncodeToString(a.SecretKey) == hex.EncodeToString(b.SecretKey) {
		t.Fatal("two independently generated secret keys are identical")
	}
	if hex.EncodeToString(a.PublicKey) == hex.EncodeToString(b.PublicKey) {
		t.Fatal("two independently generated public keys are identical")
	}
}

// TestPubkeyValidityProofRoundTrip is the sigma protocol's own soundness
// and completeness in miniature: a proof built for a real key pair must
// verify, and the same proof must fail against a public key or a byte it
// was not built for.
func TestPubkeyValidityProofRoundTrip(t *testing.T) {
	key, err := GenerateElGamalKey()
	if err != nil {
		t.Fatalf("GenerateElGamalKey: %v", err)
	}

	proof, err := ProvePubkeyValidity(key.SecretKey, key.PublicKey)
	if err != nil {
		t.Fatalf("ProvePubkeyValidity: %v", err)
	}
	if len(proof) != PubkeyValidityProofLen {
		t.Fatalf("proof is %d bytes, want %d", len(proof), PubkeyValidityProofLen)
	}

	ok, err := VerifyPubkeyValidity(key.PublicKey, proof)
	if err != nil {
		t.Fatalf("VerifyPubkeyValidity: %v", err)
	}
	if !ok {
		t.Fatal("a freshly built proof did not verify against its own public key")
	}

	other, err := GenerateElGamalKey()
	if err != nil {
		t.Fatalf("GenerateElGamalKey: %v", err)
	}
	ok, err = VerifyPubkeyValidity(other.PublicKey, proof)
	if err != nil {
		t.Fatalf("VerifyPubkeyValidity against a different public key: %v", err)
	}
	if ok {
		t.Fatal("a proof verified against a public key it was not built for")
	}

	for i := range proof {
		tampered := append([]byte{}, proof...)
		tampered[i] ^= 0xFF
		if ok, _ := VerifyPubkeyValidity(key.PublicKey, tampered); ok {
			t.Fatalf("a proof with byte %d flipped still verified", i)
		}
	}
}

// TestProvePubkeyValidityRejectsMismatch checks the guard
// ProvePubkeyValidity itself runs: passing a public key that is not
// secretKey^-1 * H has to fail before ever reaching the transcript, the
// same way a proof built against it would only fail later, silently,
// against the deployed verifier.
func TestProvePubkeyValidityRejectsMismatch(t *testing.T) {
	a, err := GenerateElGamalKey()
	if err != nil {
		t.Fatalf("GenerateElGamalKey: %v", err)
	}
	b, err := GenerateElGamalKey()
	if err != nil {
		t.Fatalf("GenerateElGamalKey: %v", err)
	}

	if _, err := ProvePubkeyValidity(a.SecretKey, b.PublicKey); err == nil {
		t.Fatal("expected an error proving validity for a mismatched key pair, got nil")
	}
}

// TestPubkeyValidityProofLengthValidation checks the boundary inputs
// ProvePubkeyValidity and VerifyPubkeyValidity both reject before ever
// touching ristretto255 decoding.
func TestPubkeyValidityProofLengthValidation(t *testing.T) {
	if _, err := ProvePubkeyValidity(make([]byte, 31), make([]byte, 32)); err == nil {
		t.Fatal("expected an error for a 31-byte secret key, got nil")
	}
	if _, err := ProvePubkeyValidity(make([]byte, 32), make([]byte, 31)); err == nil {
		t.Fatal("expected an error for a 31-byte public key, got nil")
	}
	if _, err := VerifyPubkeyValidity(make([]byte, 31), make([]byte, PubkeyValidityProofLen)); err == nil {
		t.Fatal("expected an error for a 31-byte public key, got nil")
	}
	if _, err := VerifyPubkeyValidity(make([]byte, 32), make([]byte, PubkeyValidityProofLen-1)); err == nil {
		t.Fatal("expected an error for a 63-byte proof, got nil")
	}
}
