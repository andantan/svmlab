package core

import (
	"fmt"

	"github.com/andantan/svmlab/core/zkbridge"
)

// ConfidentialMintBurn extension state, confirmed against the interface
// crate's ConfidentialMintBurn struct: confidential_supply(64) +
// decryptable_supply(36) + supply_elgamal_pubkey(32) + pending_burn(64).
const confidentialMintBurnLen = 196

// ConfidentialMintBurnState is a mint's ConfidentialMintBurn extension.
type ConfidentialMintBurnState struct {
	ConfidentialSupply  []byte
	DecryptableSupply   []byte
	SupplyElGamalPubkey []byte
	PendingBurn         []byte
}

// DecodeConfidentialMintBurn reads a mint's ConfidentialMintBurn extension.
func DecodeConfidentialMintBurn(mintData []byte) (*ConfidentialMintBurnState, error) {
	raw := FindExtensionData(mintData, ExtensionTypeConfidentialMintBurn)
	if raw == nil {
		return nil, fmt.Errorf("mint does not carry the ConfidentialMintBurn extension")
	}
	if len(raw) != confidentialMintBurnLen {
		return nil, fmt.Errorf("confidential mint burn: %d bytes, expected %d", len(raw), confidentialMintBurnLen)
	}

	return &ConfidentialMintBurnState{
		ConfidentialSupply:  append([]byte(nil), raw[0:64]...),
		DecryptableSupply:   append([]byte(nil), raw[64:100]...),
		SupplyElGamalPubkey: append([]byte(nil), raw[100:132]...),
		PendingBurn:         append([]byte(nil), raw[132:196]...),
	}, nil
}

// mint amount handle order, confirmed against MintProofContext: the grouped
// 3-handle ciphertext is [destination, supply, auditor].
const (
	mintSupplyHandleIndex  = 1
	mintAuditorHandleIndex = 2
)

// MintProofs is TransferProofs' counterpart for ConfidentialMint: three proof
// blobs plus the values the Mint instruction itself carries.
type MintProofs struct {
	// EqualityProof is CiphertextCommitmentEqualityProofData's bytes: the
	// mint's new supply ciphertext (old supply plus this amount) matches a
	// fresh commitment to the new supply.
	EqualityProof []byte
	// ValidityProof is BatchedGroupedCiphertext3HandlesValidityProofData's
	// bytes over [destination, supply, auditor].
	ValidityProof []byte
	// RangeProof is BatchedRangeProofU128Data's bytes over the new supply
	// (64 bits), amount lo (16), amount hi (32) and padding (16).
	RangeProof []byte

	AuditorCiphertextLo []byte
	AuditorCiphertextHi []byte

	// NewDecryptableSupply is the new supply AE-encrypted under the supply
	// AE key -- Mint's own new_decryptable_supply field.
	NewDecryptableSupply []byte
}

// BuildMintProofs proves one confidential mint of mintAmount to a
// destination account: the amount's lo/hi split is validly encrypted under
// the destination, supply and auditor keys, the mint's new confidential
// supply (current plus the amount, computed with the supply handle) equals a
// fresh commitment, and that new supply and the split fit their bit widths.
//
// Ported from the token-2022 proof-generation crate's mint_split_proof_data.
// currentSupplyCiphertext is the mint's confidential_supply and
// currentDecryptableSupply its AE cache, decrypted under supplyAeKey to know
// the plaintext supply. auditorPublicKey may be nil for a mint with no
// auditor (the identity key stands in).
func BuildMintProofs(
	supplySecretKey, supplyPublicKey, destinationPublicKey, auditorPublicKey []byte,
	currentSupplyCiphertext, currentDecryptableSupply, supplyAeKey []byte,
	mintAmount uint64,
) (*MintProofs, error) {
	wrap := func(err error) error { return fmt.Errorf("build mint proofs: %w", err) }

	if len(supplySecretKey) != 32 || len(supplyPublicKey) != 32 {
		return nil, fmt.Errorf("build mint proofs: supply secret/public key must be 32 bytes each")
	}
	if len(destinationPublicKey) != 32 {
		return nil, fmt.Errorf("build mint proofs: destination public key must be 32 bytes")
	}
	if auditorPublicKey != nil && len(auditorPublicKey) != 32 {
		return nil, fmt.Errorf("build mint proofs: auditor public key must be 32 bytes when given")
	}
	if mintAmount > TransferMaxAmount {
		return nil, fmt.Errorf("build mint proofs: amount %d exceeds the maximum a confidential mint can represent (%d)", mintAmount, uint64(TransferMaxAmount))
	}

	currentSupply, err := DecryptAeAmount(supplyAeKey, currentDecryptableSupply)
	if err != nil {
		return nil, wrap(fmt.Errorf("decrypt current supply (wrong supply_ae_key, or the decryptable supply is stale): %w", err))
	}
	newSupply := currentSupply + mintAmount
	if newSupply < currentSupply {
		return nil, fmt.Errorf("build mint proofs: supply %d plus %d overflows 64 bits", currentSupply, mintAmount)
	}

	auditorKey := make([]byte, 32)
	if auditorPublicKey != nil {
		copy(auditorKey, auditorPublicKey)
	}
	pubkeys := make([]byte, 0, 96)
	pubkeys = append(pubkeys, destinationPublicKey...)
	pubkeys = append(pubkeys, supplyPublicKey...)
	pubkeys = append(pubkeys, auditorKey...)

	amountLo, amountHi := splitTransferAmount(mintAmount, TransferAmountLoBitLength)

	openingLo, err := zkbridge.PedersenOpeningNewRand()
	if err != nil {
		return nil, wrap(err)
	}
	openingHi, err := zkbridge.PedersenOpeningNewRand()
	if err != nil {
		return nil, wrap(err)
	}
	groupedLo, err := zkbridge.GroupedElGamalEncrypt3(pubkeys, amountLo, openingLo)
	if err != nil {
		return nil, wrap(err)
	}
	groupedHi, err := zkbridge.GroupedElGamalEncrypt3(pubkeys, amountHi, openingHi)
	if err != nil {
		return nil, wrap(err)
	}

	validityProof, err := zkbridge.ProveBatchedGroupedCiphertext3HandlesValidity(pubkeys, groupedLo, groupedHi, amountLo, amountHi, openingLo, openingHi)
	if err != nil {
		return nil, wrap(err)
	}

	auditorCiphertextLo, err := zkbridge.GroupedCiphertext3ToElGamal(groupedLo, mintAuditorHandleIndex)
	if err != nil {
		return nil, wrap(err)
	}
	auditorCiphertextHi, err := zkbridge.GroupedCiphertext3ToElGamal(groupedHi, mintAuditorHandleIndex)
	if err != nil {
		return nil, wrap(err)
	}

	supplyCiphertextLo, err := zkbridge.GroupedCiphertext3ToElGamal(groupedLo, mintSupplyHandleIndex)
	if err != nil {
		return nil, wrap(err)
	}
	supplyCiphertextHi, err := zkbridge.GroupedCiphertext3ToElGamal(groupedHi, mintSupplyHandleIndex)
	if err != nil {
		return nil, wrap(err)
	}
	addedSupply, err := zkbridge.ElGamalCombineLoHiCiphertexts(supplyCiphertextLo, supplyCiphertextHi, TransferAmountLoBitLength)
	if err != nil {
		return nil, wrap(err)
	}
	newSupplyCiphertext, err := zkbridge.ElGamalAddCiphertexts(currentSupplyCiphertext, addedSupply)
	if err != nil {
		return nil, wrap(err)
	}

	newSupplyCommitment, newSupplyOpening, err := zkbridge.PedersenCommit(newSupply)
	if err != nil {
		return nil, wrap(err)
	}
	equalityProof, err := zkbridge.ProveCiphertextCommitmentEquality(supplySecretKey, supplyPublicKey, newSupplyCiphertext, newSupplyCommitment, newSupplyOpening, newSupply)
	if err != nil {
		return nil, wrap(err)
	}

	loCommitment, err := zkbridge.PedersenCommitWith(amountLo, openingLo)
	if err != nil {
		return nil, wrap(err)
	}
	hiCommitment, err := zkbridge.PedersenCommitWith(amountHi, openingHi)
	if err != nil {
		return nil, wrap(err)
	}
	padCommitment, padOpening, err := zkbridge.PedersenCommit(0)
	if err != nil {
		return nil, wrap(err)
	}
	rangeProof, err := zkbridge.ProveBatchedRangeProofU128(
		[][]byte{newSupplyCommitment, loCommitment, hiCommitment, padCommitment},
		[]uint64{newSupply, amountLo, amountHi, 0},
		[]uint8{TransferBalanceBitLength, TransferAmountLoBitLength, TransferAmountHiBitLength, TransferPadBitLength},
		[][]byte{newSupplyOpening, openingLo, openingHi, padOpening},
	)
	if err != nil {
		return nil, wrap(err)
	}

	newDecryptableSupply, err := EncryptAeAmount(supplyAeKey, newSupply)
	if err != nil {
		return nil, wrap(err)
	}

	return &MintProofs{
		EqualityProof:        equalityProof,
		ValidityProof:        validityProof,
		RangeProof:           rangeProof,
		AuditorCiphertextLo:  auditorCiphertextLo,
		AuditorCiphertextHi:  auditorCiphertextHi,
		NewDecryptableSupply: newDecryptableSupply,
	}, nil
}

// BurnProofs is TransferProofs for ConfidentialBurn: the same three proof
// blobs and auditor ciphertexts, with the source's new decryptable available
// balance in place of a destination-side value.
type BurnProofs = TransferProofs

// BuildBurnProofs proves one confidential burn of burnAmount from a source
// account. The shape is a Transfer's with the mint's supply ElGamal key
// standing where the destination's would: the amount's lo/hi split is
// encrypted under [source, supply, auditor] (confirmed against
// BurnProofContext), the source's remaining balance is proven equal to a
// fresh commitment, and the remainder and the split are range-proven. So this
// reuses BuildTransferProofs rather than repeating it.
func BuildBurnProofs(
	sourceSecretKey, sourcePublicKey, supplyPublicKey, auditorPublicKey []byte,
	currentAvailableBalanceCiphertext, currentDecryptableAvailableBalance, aeKey []byte,
	burnAmount uint64,
) (*BurnProofs, error) {
	proofs, err := BuildTransferProofs(
		sourceSecretKey, sourcePublicKey, supplyPublicKey, auditorPublicKey,
		currentAvailableBalanceCiphertext, currentDecryptableAvailableBalance, aeKey,
		burnAmount,
	)
	if err != nil {
		return nil, fmt.Errorf("build burn proofs: %w", err)
	}

	return proofs, nil
}

// BuildRotateSupplyProof builds the proof one RotateSupplyElGamalPubkey
// needs: that the mint's confidential supply ciphertext (under its current
// supply key) and the same supply re-encrypted under newSupplyPublicKey
// encode the same value. It returns the CiphertextCiphertextEquality
// proof data, ready for VerifyCiphertextCiphertextEquality.
//
// The supply is recovered by decrypting the current ciphertext with the
// current supply secret key, which only works for a supply that fits in 32
// bits. The program compares the proof's first ciphertext byte for byte with
// the mint's confidential_supply, and its first pubkey with the mint's supply
// key, so the proof goes stale if the supply changes before the rotation
// lands.
func BuildRotateSupplyProof(supplySecretKey, supplyPublicKey, newSupplyPublicKey, currentSupplyCiphertext []byte) (proof []byte, supply uint64, err error) {
	wrap := func(err error) error { return fmt.Errorf("build rotate supply proof: %w", err) }

	supply, err = zkbridge.ElGamalDecryptU32(supplySecretKey, currentSupplyCiphertext)
	if err != nil {
		return nil, 0, wrap(fmt.Errorf("decrypt the current supply (wrong supply secret key, or more than 32 bits): %w", err))
	}
	opening, err := zkbridge.PedersenOpeningNewRand()
	if err != nil {
		return nil, 0, wrap(err)
	}
	newCiphertext, err := zkbridge.ElGamalEncryptWith(newSupplyPublicKey, supply, opening)
	if err != nil {
		return nil, 0, wrap(err)
	}
	proof, err = zkbridge.ProveCiphertextCiphertextEquality(supplySecretKey, supplyPublicKey, newSupplyPublicKey, currentSupplyCiphertext, newCiphertext, opening, supply)
	if err != nil {
		return nil, 0, wrap(err)
	}

	return proof, supply, nil
}
