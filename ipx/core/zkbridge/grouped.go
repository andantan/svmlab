package zkbridge

import "fmt"

// GroupedElGamalCiphertext3Len is 128 bytes: one shared Pedersen
// commitment (32) plus three per-key decrypt handles (32 each) --
// confirmed against solana-go's own GroupedElGamalCiphertext3 [128]byte
// type.
const GroupedElGamalCiphertext3Len = 128

// GroupedElGamalEncrypt3 encrypts amount under all three public keys
// (in order) with the given Pedersen opening, so all three end up sharing
// one commitment and can each independently decrypt their own handle.
//
// pubkeys must be three 32-byte ElGamal public keys concatenated in
// order -- for Transfer, [source, destination, auditor].
func GroupedElGamalEncrypt3(pubkeys []byte, amount uint64, opening []byte) ([]byte, error) {
	if len(pubkeys) != 3*ElGamalPubkeyLen {
		return nil, fmt.Errorf("zkbridge: grouped_elgamal_3_encrypt_with: pubkeys is %d bytes, want %d", len(pubkeys), 3*ElGamalPubkeyLen)
	}
	if len(opening) != PedersenOpeningLen {
		return nil, fmt.Errorf("zkbridge: grouped_elgamal_3_encrypt_with: opening is %d bytes, want %d", len(opening), PedersenOpeningLen)
	}

	out, err := invoke("grouped_elgamal_3_encrypt_with", Bytes(pubkeys), Scalar(amount), Bytes(opening))
	if err != nil {
		return nil, err
	}
	if len(out) != GroupedElGamalCiphertext3Len {
		return nil, fmt.Errorf("zkbridge: grouped_elgamal_3_encrypt_with returned %d bytes, want %d", len(out), GroupedElGamalCiphertext3Len)
	}
	return out, nil
}

// GroupedCiphertext3ToElGamal extracts the single-key ElGamal ciphertext
// for the key at handleIndex (its position at encryption time, 0-2) from
// a grouped 3-handle ciphertext.
func GroupedCiphertext3ToElGamal(grouped []byte, handleIndex int) ([]byte, error) {
	if len(grouped) != GroupedElGamalCiphertext3Len {
		return nil, fmt.Errorf("zkbridge: grouped_ciphertext_3_to_elgamal: grouped ciphertext is %d bytes, want %d", len(grouped), GroupedElGamalCiphertext3Len)
	}
	if handleIndex < 0 || handleIndex > 2 {
		return nil, fmt.Errorf("zkbridge: grouped_ciphertext_3_to_elgamal: handle index %d out of range [0, 2]", handleIndex)
	}

	out, err := invoke("grouped_ciphertext_3_to_elgamal", Bytes(grouped), Scalar(handleIndex))
	if err != nil {
		return nil, err
	}
	if len(out) != ElGamalCiphertextLen {
		return nil, fmt.Errorf("zkbridge: grouped_ciphertext_3_to_elgamal returned %d bytes, want %d", len(out), ElGamalCiphertextLen)
	}
	return out, nil
}
