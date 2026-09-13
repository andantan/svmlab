package core

import (
	"encoding/hex"
	"testing"

	"github.com/secure-io/siv-go"
)

// TestAesGcmSivRFC8452Vectors pins github.com/secure-io/siv-go itself
// against RFC 8452 Appendix C.1's first two AEAD_AES_128_GCM_SIV test
// vectors -- an unmaintained dependency chosen deliberately (see the
// session that added it) gets its correctness checked against the
// standard's own published values rather than trusted on reputation
// alone, the same reason TestElgamalGeneratorG pins ristretto255 against
// a known-good encoding instead of just trusting the import compiles.
func TestAesGcmSivRFC8452Vectors(t *testing.T) {
	cases := []struct {
		name      string
		key       string
		nonce     string
		plaintext string
		result    string
	}{
		{
			name:      "empty plaintext",
			key:       "01000000000000000000000000000000",
			nonce:     "030000000000000000000000",
			plaintext: "",
			result:    "dc20e2d83f25705bb49e439eca56de25",
		},
		{
			name:      "8-byte plaintext",
			key:       "01000000000000000000000000000000",
			nonce:     "030000000000000000000000",
			plaintext: "0100000000000000",
			result:    "b5d839330ac7b786578782fff6013b815b287c22493a364c",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := hex.DecodeString(tc.key)
			if err != nil {
				t.Fatalf("decode key: %v", err)
			}
			nonce, err := hex.DecodeString(tc.nonce)
			if err != nil {
				t.Fatalf("decode nonce: %v", err)
			}
			plaintext, err := hex.DecodeString(tc.plaintext)
			if err != nil {
				t.Fatalf("decode plaintext: %v", err)
			}
			want, err := hex.DecodeString(tc.result)
			if err != nil {
				t.Fatalf("decode result: %v", err)
			}

			aead, err := siv.NewGCM(key)
			if err != nil {
				t.Fatalf("siv.NewGCM: %v", err)
			}

			got := aead.Seal(nil, nonce, plaintext, nil)
			if hex.EncodeToString(got) != hex.EncodeToString(want) {
				t.Fatalf("Seal() = %x, want %x", got, want)
			}
		})
	}
}

// TestEncryptAeAmountRoundTrip checks EncryptAeAmount/DecryptAeAmount
// against each other for the one value this API actually sends,
// decryptable_zero_balance's zero, and a couple of others for coverage.
func TestEncryptAeAmountRoundTrip(t *testing.T) {
	key := make([]byte, AeKeyLen)
	for i := range key {
		key[i] = byte(i + 1)
	}

	for _, amount := range []uint64{0, 1, 1_000_000, ^uint64(0)} {
		ct, err := EncryptAeAmount(key, amount)
		if err != nil {
			t.Fatalf("EncryptAeAmount(%d): %v", amount, err)
		}
		if len(ct) != AeCiphertextLen {
			t.Fatalf("ciphertext is %d bytes, want %d", len(ct), AeCiphertextLen)
		}

		got, err := DecryptAeAmount(key, ct)
		if err != nil {
			t.Fatalf("DecryptAeAmount: %v", err)
		}
		if got != amount {
			t.Fatalf("round trip: got %d, want %d", got, amount)
		}
	}
}

// TestEncryptAeAmountNoncesDiffer guards against a fixed or reused nonce,
// which would make AES-GCM-SIV's ciphertext leak equality between two
// encryptions of the same amount -- each call has to draw its own.
func TestEncryptAeAmountNoncesDiffer(t *testing.T) {
	key := make([]byte, AeKeyLen)

	a, err := EncryptAeAmount(key, 0)
	if err != nil {
		t.Fatalf("EncryptAeAmount: %v", err)
	}
	b, err := EncryptAeAmount(key, 0)
	if err != nil {
		t.Fatalf("EncryptAeAmount: %v", err)
	}

	if hex.EncodeToString(a) == hex.EncodeToString(b) {
		t.Fatal("two encryptions of the same amount under the same key produced identical ciphertext")
	}
}

// TestAeKeySeedMessage pins AeKeySeedMessage's byte layout: the literal
// ASCII prefix "AeKey" (no length byte, no separator) followed by the
// 32-byte public seed exactly as given.
func TestAeKeySeedMessage(t *testing.T) {
	tokenAccount := make([]byte, 32)
	for i := range tokenAccount {
		tokenAccount[i] = byte(i)
	}

	msg, err := AeKeySeedMessage(tokenAccount)
	if err != nil {
		t.Fatalf("AeKeySeedMessage: %v", err)
	}
	if len(msg) != 5+32 {
		t.Fatalf("message is %d bytes, want %d", len(msg), 5+32)
	}
	if string(msg[:5]) != "AeKey" {
		t.Fatalf("message prefix = %q, want %q", msg[:5], "AeKey")
	}
	if !bytesEqual(msg[5:], tokenAccount) {
		t.Fatal("message suffix does not equal tokenAccount")
	}

	if _, err := AeKeySeedMessage(make([]byte, 31)); err == nil {
		t.Fatal("expected an error for a 31-byte token account, got nil")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestDeriveAeKeyFromSignature checks the shape of DeriveAeKeyFromSignature's
// output -- 16 bytes, deterministic, and rejecting the inputs upstream
// itself rejects -- without a Rust-side vector to pin against, since no
// published one exists for this specific derivation.
func TestDeriveAeKeyFromSignature(t *testing.T) {
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i + 1)
	}

	key, err := DeriveAeKeyFromSignature(sig)
	if err != nil {
		t.Fatalf("DeriveAeKeyFromSignature: %v", err)
	}
	if len(key) != AeKeyLen {
		t.Fatalf("key is %d bytes, want %d", len(key), AeKeyLen)
	}

	again, err := DeriveAeKeyFromSignature(sig)
	if err != nil {
		t.Fatalf("DeriveAeKeyFromSignature: %v", err)
	}
	if hex.EncodeToString(key) != hex.EncodeToString(again) {
		t.Fatal("two derivations from the same signature produced different keys")
	}

	sig2 := append([]byte{}, sig...)
	sig2[0] ^= 0xFF
	key2, err := DeriveAeKeyFromSignature(sig2)
	if err != nil {
		t.Fatalf("DeriveAeKeyFromSignature: %v", err)
	}
	if hex.EncodeToString(key) == hex.EncodeToString(key2) {
		t.Fatal("two different signatures produced the same key")
	}

	if _, err := DeriveAeKeyFromSignature(make([]byte, 63)); err == nil {
		t.Fatal("expected an error for a 63-byte signature, got nil")
	}
	if _, err := DeriveAeKeyFromSignature(make([]byte, 64)); err == nil {
		t.Fatal("expected an error for an all-zero signature, got nil")
	}
}

// TestDecryptAeAmountRejectsTamperedCiphertext checks that GCM-SIV's
// authentication actually runs -- a flipped byte anywhere has to fail
// decryption, not silently return a wrong amount.
func TestDecryptAeAmountRejectsTamperedCiphertext(t *testing.T) {
	key := make([]byte, AeKeyLen)
	ct, err := EncryptAeAmount(key, 42)
	if err != nil {
		t.Fatalf("EncryptAeAmount: %v", err)
	}

	for i := range ct {
		tampered := append([]byte{}, ct...)
		tampered[i] ^= 0xFF
		if _, err := DecryptAeAmount(key, tampered); err == nil {
			t.Fatalf("byte %d: tampered ciphertext decrypted without error", i)
		}
	}
}
