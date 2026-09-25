package zkbridge

import (
	"encoding/binary"
	"fmt"
)

// ElGamalPubkeyLen is 32 bytes; ElGamalCiphertextLen is 64 -- a Pedersen
// commitment (32) followed by a decrypt handle (32), confirmed against
// solana-go's own ElGamalCiphertext [64]byte type.
const (
	ElGamalPubkeyLen     = 32
	ElGamalCiphertextLen = 64
)

// marshalElGamalKeypair builds the wire form elgamal_* exports expect for
// a keypair argument: pubkey(32) || secret(32) -- confirmed against
// solana-go's own ElGamalKeypair.MarshalBinary, notably public key
// first, not secret first.
func marshalElGamalKeypair(secretKey, publicKey []byte) ([]byte, error) {
	if len(secretKey) != 32 {
		return nil, fmt.Errorf("zkbridge: secret key is %d bytes, want 32", len(secretKey))
	}
	if len(publicKey) != 32 {
		return nil, fmt.Errorf("zkbridge: public key is %d bytes, want 32", len(publicKey))
	}
	out := make([]byte, 0, 64)
	out = append(out, publicKey...)
	out = append(out, secretKey...)
	return out, nil
}

// ElGamalEncrypt encrypts amount under publicKey with a fresh random
// Pedersen opening.
func ElGamalEncrypt(publicKey []byte, amount uint64) ([]byte, error) {
	if len(publicKey) != ElGamalPubkeyLen {
		return nil, fmt.Errorf("zkbridge: elgamal_encrypt: public key is %d bytes, want %d", len(publicKey), ElGamalPubkeyLen)
	}
	out, err := invoke("elgamal_encrypt", Bytes(publicKey), Scalar(amount))
	if err != nil {
		return nil, err
	}
	if len(out) != ElGamalCiphertextLen {
		return nil, fmt.Errorf("zkbridge: elgamal_encrypt returned %d bytes, want %d", len(out), ElGamalCiphertextLen)
	}
	return out, nil
}

// ElGamalCombineLoHiCiphertexts computes lo + 2^bitLength·hi -- recombines
// a lo/hi split ciphertext pair, encrypted under the same key, back into
// one ciphertext of the full value.
func ElGamalCombineLoHiCiphertexts(lo, hi []byte, bitLength uint8) ([]byte, error) {
	if len(lo) != ElGamalCiphertextLen || len(hi) != ElGamalCiphertextLen {
		return nil, fmt.Errorf("zkbridge: elgamal_combine_lo_hi_ciphertexts: lo/hi are %d/%d bytes, want %d each", len(lo), len(hi), ElGamalCiphertextLen)
	}
	out, err := invoke("elgamal_combine_lo_hi_ciphertexts", Bytes(lo), Bytes(hi), Scalar(bitLength))
	if err != nil {
		return nil, err
	}
	if len(out) != ElGamalCiphertextLen {
		return nil, fmt.Errorf("zkbridge: elgamal_combine_lo_hi_ciphertexts returned %d bytes, want %d", len(out), ElGamalCiphertextLen)
	}
	return out, nil
}

// ElGamalSubtractCiphertexts homomorphically subtracts ciphertext b from
// ciphertext a -- both encrypted under the same public key.
func ElGamalSubtractCiphertexts(a, b []byte) ([]byte, error) {
	if len(a) != ElGamalCiphertextLen || len(b) != ElGamalCiphertextLen {
		return nil, fmt.Errorf("zkbridge: elgamal_sub_ciphertexts: inputs are %d and %d bytes, want %d each", len(a), len(b), ElGamalCiphertextLen)
	}
	out, err := invoke("elgamal_sub_ciphertexts", Bytes(a), Bytes(b))
	if err != nil {
		return nil, err
	}
	if len(out) != ElGamalCiphertextLen {
		return nil, fmt.Errorf("zkbridge: elgamal_sub_ciphertexts returned %d bytes, want %d", len(out), ElGamalCiphertextLen)
	}
	return out, nil
}

// ElGamalSubtractAmount subtracts a plaintext amount from a ciphertext
// homomorphically -- the ciphertext of (value - amount) under the same
// key, without decrypting. Confidential Withdraw uses it to derive the
// remaining-balance ciphertext the on-chain program will itself compute.
func ElGamalSubtractAmount(ciphertext []byte, amount uint64) ([]byte, error) {
	if len(ciphertext) != ElGamalCiphertextLen {
		return nil, fmt.Errorf("zkbridge: elgamal subtract amount: ciphertext is %d bytes, want %d", len(ciphertext), ElGamalCiphertextLen)
	}

	out, err := invoke("elgamal_sub_amount", Bytes(ciphertext), Scalar(amount))
	if err != nil {
		return nil, err
	}
	if len(out) != ElGamalCiphertextLen {
		return nil, fmt.Errorf("zkbridge: elgamal_sub_amount returned %d bytes, want %d", len(out), ElGamalCiphertextLen)
	}
	return out, nil
}

// ElGamalEncryptWith encrypts amount under publicKey with the given
// Pedersen opening, rather than a random one -- the ciphertext is then
// reproducible, and a proof can name the opening it was built with.
func ElGamalEncryptWith(publicKey []byte, amount uint64, opening []byte) ([]byte, error) {
	if len(publicKey) != ElGamalPubkeyLen {
		return nil, fmt.Errorf("zkbridge: elgamal encrypt with: public key is %d bytes, want %d", len(publicKey), ElGamalPubkeyLen)
	}
	if len(opening) != PedersenOpeningLen {
		return nil, fmt.Errorf("zkbridge: elgamal encrypt with: opening is %d bytes, want %d", len(opening), PedersenOpeningLen)
	}

	out, err := invoke("elgamal_encrypt_with", Bytes(publicKey), Scalar(amount), Bytes(opening))
	if err != nil {
		return nil, err
	}
	if len(out) != ElGamalCiphertextLen {
		return nil, fmt.Errorf("zkbridge: elgamal_encrypt_with returned %d bytes, want %d", len(out), ElGamalCiphertextLen)
	}
	return out, nil
}

// ElGamalDecryptU32 decrypts a ciphertext whose plaintext is known to fit
// in 32 bits, with the ElGamal secret key it was encrypted for. A
// ciphertext that does not decrypt to a 32-bit value under this key -- the
// wrong key, or a larger amount -- comes back as an error, not a wrong
// number.
func ElGamalDecryptU32(secretKey, ciphertext []byte) (uint64, error) {
	if len(secretKey) != 32 {
		return 0, fmt.Errorf("zkbridge: elgamal decrypt u32: secret key is %d bytes, want 32", len(secretKey))
	}
	if len(ciphertext) != ElGamalCiphertextLen {
		return 0, fmt.Errorf("zkbridge: elgamal decrypt u32: ciphertext is %d bytes, want %d", len(ciphertext), ElGamalCiphertextLen)
	}

	out, err := invoke("elgamal_decrypt_u32", Bytes(secretKey), Bytes(ciphertext))
	if err != nil {
		return 0, err
	}
	if len(out) != 8 {
		return 0, fmt.Errorf("zkbridge: elgamal_decrypt_u32 returned %d bytes, want 8", len(out))
	}
	return binary.LittleEndian.Uint64(out), nil
}

// ElGamalAddCiphertexts returns a + b. The wasm exports only subtraction, so
// this is a - (0 - b), with the all-zero ciphertext (the identity point in
// both halves) standing in for zero.
func ElGamalAddCiphertexts(a, b []byte) ([]byte, error) {
	negB, err := ElGamalSubtractCiphertexts(make([]byte, ElGamalCiphertextLen), b)
	if err != nil {
		return nil, err
	}
	return ElGamalSubtractCiphertexts(a, negB)
}
