package zkbridge

import "fmt"

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
