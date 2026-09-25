package core

import (
	"fmt"

	"github.com/andantan/svmlab/core/types"
	"github.com/andantan/svmlab/core/zkbridge"
)

const (
	// FeeAmountLoBitLength and FeeAmountHiBitLength split a transfer fee
	// the same way a transfer amount is split (16 + 32 bits), confirmed
	// against solana-go's own confidential/constants.go.
	FeeAmountLoBitLength = 16
	FeeAmountHiBitLength = 32

	// MaxFeeBasisPoints is 100%: a fee rate is out of 10000.
	MaxFeeBasisPoints = 10_000

	// feeDeltaBitLength is the width of the rounding delta and of its
	// complement in the range proof, and netAmountBitLength the width of
	// the amount left after the fee. Together with the balance (64), the
	// amount split (16 + 32), and the fee split (16 + 32) they sum to the
	// 256 bits BatchedRangeProofU256 covers: 64+16+32+16+16+16+32+64.
	feeDeltaBitLength  = 16
	netAmountBitLength = 64
)

// TransferWithFeeProofs is everything one confidential TransferWithFee
// needs beyond what the caller already holds: the five proofs (each to be
// verified into a context-state account of its own) and the three values
// the instruction itself carries.
type TransferWithFeeProofs struct {
	// EqualityProof is CiphertextCommitmentEqualityProofData's bytes, for
	// VerifyCiphertextCommitmentEquality (the source's new balance).
	EqualityProof []byte
	// TransferAmountValidityProof is
	// BatchedGroupedCiphertext3HandlesValidityProofData's bytes, for the
	// transfer amount encrypted under [source, destination, auditor].
	TransferAmountValidityProof []byte
	// PercentageWithCapProof is PercentageWithCapProofData's bytes, for
	// VerifyPercentageWithCap: the fee is the transfer amount times the
	// rate, rounded up, capped at the maximum fee.
	PercentageWithCapProof []byte
	// FeeValidityProof is BatchedGroupedCiphertext2HandlesValidityProofData's
	// bytes, for the fee encrypted under [destination, withdraw withheld
	// authority].
	FeeValidityProof []byte
	// RangeProof is BatchedRangeProofU256Data's bytes, for
	// VerifyBatchedRangeProofU256.
	RangeProof []byte

	AuditorCiphertextLo []byte
	AuditorCiphertextHi []byte

	// NewSourceDecryptableAvailableBalance is the source's new available
	// balance, AE-encrypted under the caller's AeKey.
	NewSourceDecryptableAvailableBalance []byte

	// Fee is the fee this transfer charges, in base units -- informational,
	// not part of any instruction: it is committed to inside the proofs.
	Fee uint64
}

// calculateTransferFee is the fee an amount incurs at rate basis points:
// the ceiling of amount * rate / 10000, capped at maximumFee, along with
// the rounding delta (how far fee * 10000 overshoots the exact product; 0
// when the cap applies). Ported from solana-go's calculateFee and the
// capping step in TransferWithFeeSplitProofData.
func calculateTransferFee(amount uint64, feeRateBasisPoints uint16, maximumFee uint64) (fee, delta uint64) {
	numerator := amount * uint64(feeRateBasisPoints)
	fee = (numerator + MaxFeeBasisPoints - 1) / MaxFeeBasisPoints
	delta = fee*MaxFeeBasisPoints - numerator
	if maximumFee < fee {
		fee, delta = maximumFee, 0
	}
	return fee, delta
}

// BuildTransferWithFeeProofs builds the five proofs a confidential
// TransferWithFee requires, ported step for step from solana-go's
// TransferWithFeeSplitProofData and run through the same wasm bridge
// BuildTransferProofs uses. It is BuildTransferProofs plus the fee: the
// fee is computed from feeRateBasisPoints and maximumFee, split lo/hi,
// encrypted for the destination and the mint's withdraw withheld
// authority, and proven correct by a percentage-with-cap proof; and the
// range proof widens to 256 bits to also cover the fee's pieces and the
// net amount (transfer amount minus fee).
//
// feeRateBasisPoints and maximumFee must be the transfer fee currently in
// effect on the mint -- the deployed program recomputes the fee from its
// own TransferFeeConfig for the current epoch and rejects a proof built
// for different parameters.
func BuildTransferWithFeeProofs(
	sourceSecretKey, sourcePublicKey, destinationPublicKey, auditorPublicKey, withdrawWithheldAuthorityPublicKey []byte,
	currentAvailableBalanceCiphertext, currentDecryptableAvailableBalance, aeKey []byte,
	transferAmount uint64, feeRateBasisPoints uint16, maximumFee uint64,
) (*TransferWithFeeProofs, error) {
	if len(sourceSecretKey) != 32 || len(sourcePublicKey) != 32 {
		return nil, fmt.Errorf("build transfer with fee proofs: source secret/public key must be 32 bytes each")
	}
	if len(destinationPublicKey) != 32 {
		return nil, fmt.Errorf("build transfer with fee proofs: destination public key must be 32 bytes")
	}
	if auditorPublicKey != nil && len(auditorPublicKey) != 32 {
		return nil, fmt.Errorf("build transfer with fee proofs: auditor public key must be 32 bytes when given")
	}
	if len(withdrawWithheldAuthorityPublicKey) != 32 {
		return nil, fmt.Errorf("build transfer with fee proofs: withdraw withheld authority public key must be 32 bytes")
	}
	if feeRateBasisPoints > MaxFeeBasisPoints {
		return nil, fmt.Errorf("build transfer with fee proofs: fee rate %d exceeds %d basis points", feeRateBasisPoints, MaxFeeBasisPoints)
	}

	currentBalance, err := DecryptAeAmount(aeKey, currentDecryptableAvailableBalance)
	if err != nil {
		return nil, fmt.Errorf("build transfer with fee proofs: decrypt current balance: %w", err)
	}
	if transferAmount > TransferMaxAmount {
		return nil, fmt.Errorf("build transfer with fee proofs: amount %d exceeds the maximum a confidential transfer can represent (%d)", transferAmount, uint64(TransferMaxAmount))
	}
	if transferAmount > currentBalance {
		return nil, fmt.Errorf("build transfer with fee proofs: amount %d exceeds the current available balance %d", transferAmount, currentBalance)
	}

	fee, claimedDelta := calculateTransferFee(transferAmount, feeRateBasisPoints, maximumFee)
	if fee > transferAmount {
		return nil, fmt.Errorf("build transfer with fee proofs: fee %d exceeds the transfer amount %d", fee, transferAmount)
	}
	netAmount := transferAmount - fee

	wrap := func(err error) error { return fmt.Errorf("build transfer with fee proofs: %w", err) }

	// --- the transfer amount and the source's new balance, exactly as in
	// BuildTransferProofs ---
	auditorKey := make([]byte, 32)
	if auditorPublicKey != nil {
		copy(auditorKey, auditorPublicKey)
	}
	pubkeys := make([]byte, 0, 96)
	pubkeys = append(pubkeys, sourcePublicKey...)
	pubkeys = append(pubkeys, destinationPublicKey...)
	pubkeys = append(pubkeys, auditorKey...)

	amountLo, amountHi := splitTransferAmount(transferAmount, TransferAmountLoBitLength)
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
	auditorCiphertextLo, err := zkbridge.GroupedCiphertext3ToElGamal(groupedLo, auditorHandleIndex)
	if err != nil {
		return nil, wrap(err)
	}
	auditorCiphertextHi, err := zkbridge.GroupedCiphertext3ToElGamal(groupedHi, auditorHandleIndex)
	if err != nil {
		return nil, wrap(err)
	}
	sourceCiphertextLo, err := zkbridge.GroupedCiphertext3ToElGamal(groupedLo, sourceHandleIndex)
	if err != nil {
		return nil, wrap(err)
	}
	sourceCiphertextHi, err := zkbridge.GroupedCiphertext3ToElGamal(groupedHi, sourceHandleIndex)
	if err != nil {
		return nil, wrap(err)
	}
	changeAmountCiphertext, err := zkbridge.ElGamalCombineLoHiCiphertexts(sourceCiphertextLo, sourceCiphertextHi, TransferAmountLoBitLength)
	if err != nil {
		return nil, wrap(err)
	}

	newBalance := currentBalance - transferAmount
	newBalanceCiphertext, err := zkbridge.ElGamalSubtractCiphertexts(currentAvailableBalanceCiphertext, changeAmountCiphertext)
	if err != nil {
		return nil, wrap(err)
	}
	finalBalanceCommitment, finalBalanceOpening, err := zkbridge.PedersenCommit(newBalance)
	if err != nil {
		return nil, wrap(err)
	}
	equalityProof, err := zkbridge.ProveCiphertextCommitmentEquality(sourceSecretKey, sourcePublicKey, newBalanceCiphertext, finalBalanceCommitment, finalBalanceOpening, newBalance)
	if err != nil {
		return nil, wrap(err)
	}

	// --- the fee: split, encrypted for [destination, withdraw withheld
	// authority], and proven valid ---
	feeLo, feeHi := splitTransferAmount(fee, FeeAmountLoBitLength)
	feePubkeys := make([]byte, 0, 64)
	feePubkeys = append(feePubkeys, destinationPublicKey...)
	feePubkeys = append(feePubkeys, withdrawWithheldAuthorityPublicKey...)

	feeOpeningLo, err := zkbridge.PedersenOpeningNewRand()
	if err != nil {
		return nil, wrap(err)
	}
	feeOpeningHi, err := zkbridge.PedersenOpeningNewRand()
	if err != nil {
		return nil, wrap(err)
	}
	feeGroupedLo, err := zkbridge.GroupedElGamalEncrypt2(feePubkeys, feeLo, feeOpeningLo)
	if err != nil {
		return nil, wrap(err)
	}
	feeGroupedHi, err := zkbridge.GroupedElGamalEncrypt2(feePubkeys, feeHi, feeOpeningHi)
	if err != nil {
		return nil, wrap(err)
	}
	feeValidityProof, err := zkbridge.ProveBatchedGroupedCiphertext2HandlesValidity(feePubkeys, feeGroupedLo, feeGroupedHi, feeLo, feeHi, feeOpeningLo, feeOpeningHi)
	if err != nil {
		return nil, wrap(err)
	}

	// --- commitments to the whole transfer amount and the whole fee ---
	transferLoCommitment, err := zkbridge.PedersenCommitWith(amountLo, openingLo)
	if err != nil {
		return nil, wrap(err)
	}
	transferHiCommitment, err := zkbridge.PedersenCommitWith(amountHi, openingHi)
	if err != nil {
		return nil, wrap(err)
	}
	transferCommitment, err := zkbridge.PedersenCombineLoHiCommitments(transferLoCommitment, transferHiCommitment, TransferAmountLoBitLength)
	if err != nil {
		return nil, wrap(err)
	}
	transferOpening, err := zkbridge.PedersenCombineLoHiOpenings(openingLo, openingHi, TransferAmountLoBitLength)
	if err != nil {
		return nil, wrap(err)
	}

	feeLoCommitment, err := zkbridge.PedersenCommitWith(feeLo, feeOpeningLo)
	if err != nil {
		return nil, wrap(err)
	}
	feeHiCommitment, err := zkbridge.PedersenCommitWith(feeHi, feeOpeningHi)
	if err != nil {
		return nil, wrap(err)
	}
	feeCommitment, err := zkbridge.PedersenCombineLoHiCommitments(feeLoCommitment, feeHiCommitment, FeeAmountLoBitLength)
	if err != nil {
		return nil, wrap(err)
	}
	feeOpening, err := zkbridge.PedersenCombineLoHiOpenings(feeOpeningLo, feeOpeningHi, FeeAmountLoBitLength)
	if err != nil {
		return nil, wrap(err)
	}

	// net = transfer amount - fee, as a commitment.
	netCommitment, err := zkbridge.PedersenSubCommitments(transferCommitment, feeCommitment)
	if err != nil {
		return nil, wrap(err)
	}
	netOpening, err := zkbridge.PedersenSubOpenings(transferOpening, feeOpening)
	if err != nil {
		return nil, wrap(err)
	}

	// The three combined commitments must each equal a direct commitment to
	// the whole value under the combined opening. A mismatch here means the
	// lo/hi recombination or the subtraction went wrong, which would only
	// surface later as a range or percentage proof the deployed program
	// rejects -- so it is checked here, where the cause is still visible.
	for _, c := range []struct {
		name       string
		value      uint64
		opening    []byte
		commitment []byte
	}{
		{"transfer amount", transferAmount, transferOpening, transferCommitment},
		{"fee", fee, feeOpening, feeCommitment},
		{"net amount", netAmount, netOpening, netCommitment},
	} {
		direct, err := zkbridge.PedersenCommitWith(c.value, c.opening)
		if err != nil {
			return nil, wrap(err)
		}
		if string(direct) != string(c.commitment) {
			return nil, fmt.Errorf("build transfer with fee proofs: combined %s commitment does not match a direct commitment to %d", c.name, c.value)
		}
	}

	// --- the percentage-with-cap proof ---
	claimedDeltaCommitment, claimedDeltaOpening, err := zkbridge.PedersenCommit(claimedDelta)
	if err != nil {
		return nil, wrap(err)
	}
	deltaCommitment, deltaOpening, err := zkbridge.PedersenFeeDelta(transferCommitment, transferOpening, feeCommitment, feeOpening, feeRateBasisPoints)
	if err != nil {
		return nil, wrap(err)
	}
	percentageProof, err := zkbridge.ProvePercentageWithCap(
		feeCommitment, feeOpening, fee,
		deltaCommitment, deltaOpening, claimedDelta,
		claimedDeltaCommitment, claimedDeltaOpening, maximumFee,
	)
	if err != nil {
		return nil, wrap(err)
	}

	// --- the 256-bit range proof over eight commitments ---
	claimedComplement := uint64(MaxFeeBasisPoints-1) - claimedDelta
	zeroOpening := make([]byte, zkbridge.PedersenOpeningLen)
	maxSubOneCommitment, err := zkbridge.PedersenCommitWith(MaxFeeBasisPoints-1, zeroOpening)
	if err != nil {
		return nil, wrap(err)
	}
	complementCommitment, err := zkbridge.PedersenSubCommitments(maxSubOneCommitment, claimedDeltaCommitment)
	if err != nil {
		return nil, wrap(err)
	}
	complementOpening, err := zkbridge.PedersenSubOpenings(zeroOpening, claimedDeltaOpening)
	if err != nil {
		return nil, wrap(err)
	}

	rangeProof, err := zkbridge.ProveBatchedRangeProofU256(
		[][]byte{finalBalanceCommitment, transferLoCommitment, transferHiCommitment, claimedDeltaCommitment, complementCommitment, feeLoCommitment, feeHiCommitment, netCommitment},
		[]uint64{newBalance, amountLo, amountHi, claimedDelta, claimedComplement, feeLo, feeHi, netAmount},
		[]uint8{TransferBalanceBitLength, TransferAmountLoBitLength, TransferAmountHiBitLength, feeDeltaBitLength, feeDeltaBitLength, FeeAmountLoBitLength, FeeAmountHiBitLength, netAmountBitLength},
		[][]byte{finalBalanceOpening, openingLo, openingHi, claimedDeltaOpening, complementOpening, feeOpeningLo, feeOpeningHi, netOpening},
	)
	if err != nil {
		return nil, wrap(err)
	}

	newSourceDecryptableAvailableBalance, err := EncryptAeAmount(aeKey, newBalance)
	if err != nil {
		return nil, wrap(err)
	}

	return &TransferWithFeeProofs{
		EqualityProof:                        equalityProof,
		TransferAmountValidityProof:          validityProof,
		PercentageWithCapProof:               percentageProof,
		FeeValidityProof:                     feeValidityProof,
		RangeProof:                           rangeProof,
		AuditorCiphertextLo:                  auditorCiphertextLo,
		AuditorCiphertextHi:                  auditorCiphertextHi,
		NewSourceDecryptableAvailableBalance: newSourceDecryptableAvailableBalance,
		Fee:                                  fee,
	}, nil
}

// ConfidentialTransferMintAuditor returns the auditor ElGamal public key a
// mint's ConfidentialTransferMint extension names, or nil when the mint
// carries the extension with no auditor (the field is all zero bytes).
// Layout confirmed against InitializeMintData: authority(32) +
// auto_approve(1) + auditor(32).
func ConfidentialTransferMintAuditor(mintData []byte) ([]byte, error) {
	raw := FindExtensionData(mintData, ExtensionTypeConfidentialTransferMint)
	if raw == nil {
		return nil, fmt.Errorf("mint does not carry the ConfidentialTransferMint extension")
	}
	if len(raw) != 65 {
		return nil, fmt.Errorf("confidential transfer mint: %d bytes, expected 65", len(raw))
	}
	auditor := raw[33:65]
	for _, b := range auditor {
		if b != 0 {
			return append([]byte(nil), auditor...), nil
		}
	}

	return nil, nil
}

// ConfidentialTransferFeeWithdrawAuthority returns the ElGamal public key
// a mint's ConfidentialTransferFeeConfig extension encrypts withheld fees
// under. Layout confirmed against ConfidentialTransferFeeConfig: authority
// (32) + withdraw_withheld_authority_elgamal_pubkey (32) +
// harvest_to_mint_enabled (1) + withheld_amount (64).
func ConfidentialTransferFeeWithdrawAuthority(mintData []byte) ([]byte, error) {
	raw := FindExtensionData(mintData, ExtensionTypeConfidentialTransferFeeConfig)
	if raw == nil {
		return nil, fmt.Errorf("mint does not carry the ConfidentialTransferFeeConfig extension")
	}
	if len(raw) != 129 {
		return nil, fmt.Errorf("confidential transfer fee config: %d bytes, expected 129", len(raw))
	}

	return append([]byte(nil), raw[32:64]...), nil
}

// ConfidentialTransferFeeAuthority returns the authority a mint's
// ConfidentialTransferFeeConfig extension names -- who may enable or
// disable harvesting to the mint -- or nil when the extension carries none
// (the field is all zero bytes). Layout confirmed against
// ConfidentialTransferFeeConfig: authority(32) first.
func ConfidentialTransferFeeAuthority(mintData []byte) (*types.PublicKey, error) {
	raw := FindExtensionData(mintData, ExtensionTypeConfidentialTransferFeeConfig)
	if raw == nil {
		return nil, fmt.Errorf("mint does not carry the ConfidentialTransferFeeConfig extension")
	}
	if len(raw) != 129 {
		return nil, fmt.Errorf("confidential transfer fee config: %d bytes, expected 129", len(raw))
	}
	for _, b := range raw[:32] {
		if b != 0 {
			return types.NewPublicKeyFromBytes(raw[:32])
		}
	}

	return nil, nil
}

// WithdrawWithheldProof is what withdrawing a mint's withheld confidential
// fees needs beyond what the caller already holds: the equality proof (to
// be verified into a context-state account) and the destination's new
// decryptable balance the instruction itself carries.
type WithdrawWithheldProof struct {
	// EqualityProof is CiphertextCiphertextEqualityProofData's bytes, for
	// VerifyCiphertextCiphertextEquality.
	EqualityProof []byte

	// NewDecryptableAvailableBalance is the destination's available balance
	// once the withheld amount is added to it, AE-encrypted under the
	// destination's AeKey -- WithdrawWithheldTokensFromMint's own
	// new_decryptable_available_balance field.
	NewDecryptableAvailableBalance []byte

	// Amount is the withheld amount being withdrawn, decrypted here.
	Amount uint64
}

// BuildWithdrawWithheldFromMintProof builds the proof one
// WithdrawWithheldTokensFromMint needs: that the mint's withheld-amount
// ciphertext (encrypted under the withdraw authority's ElGamal key) and the
// same amount re-encrypted under the destination account's ElGamal key
// encode the same value. The deployed program then adds the second
// ciphertext to the destination's available balance and zeroes the mint's.
//
// withheldCiphertext is the mint's on-chain withheld amount, which the
// program compares byte for byte against the proof's own first ciphertext;
// destinationDecryptableBalance and aeKey are the destination account's
// current AE ciphertext and key, used to work out the new decryptable
// balance. The withheld amount must fit in 32 bits, the most ElGamal
// decryption here recovers.
func BuildWithdrawWithheldFromMintProof(
	withdrawSecretKey, withdrawPublicKey, destinationPublicKey []byte,
	withheldCiphertext, destinationDecryptableBalance, aeKey []byte,
) (*WithdrawWithheldProof, error) {
	wrap := func(err error) error { return fmt.Errorf("build withdraw withheld proof: %w", err) }

	amount, err := zkbridge.ElGamalDecryptU32(withdrawSecretKey, withheldCiphertext)
	if err != nil {
		return nil, wrap(fmt.Errorf("decrypt the withheld amount (wrong withdraw authority key, or more than 32 bits): %w", err))
	}

	currentBalance, err := DecryptAeAmount(aeKey, destinationDecryptableBalance)
	if err != nil {
		return nil, wrap(fmt.Errorf("decrypt the destination's current balance: %w", err))
	}

	opening, err := zkbridge.PedersenOpeningNewRand()
	if err != nil {
		return nil, wrap(err)
	}
	destinationCiphertext, err := zkbridge.ElGamalEncryptWith(destinationPublicKey, amount, opening)
	if err != nil {
		return nil, wrap(err)
	}
	proof, err := zkbridge.ProveCiphertextCiphertextEquality(withdrawSecretKey, withdrawPublicKey, destinationPublicKey, withheldCiphertext, destinationCiphertext, opening, amount)
	if err != nil {
		return nil, wrap(err)
	}

	newDecryptable, err := EncryptAeAmount(aeKey, currentBalance+amount)
	if err != nil {
		return nil, wrap(err)
	}

	return &WithdrawWithheldProof{
		EqualityProof:                  proof,
		NewDecryptableAvailableBalance: newDecryptable,
		Amount:                         amount,
	}, nil
}

// ConfidentialTransferFeeWithheldAmount returns the ciphertext a mint's
// ConfidentialTransferFeeConfig extension holds as its withheld amount --
// what harvest gathers there and WithdrawWithheldTokensFromMint pays out.
// Layout confirmed against ConfidentialTransferFeeConfig: withheld_amount is
// the last 64 bytes of 129.
func ConfidentialTransferFeeWithheldAmount(mintData []byte) ([]byte, error) {
	raw := FindExtensionData(mintData, ExtensionTypeConfidentialTransferFeeConfig)
	if raw == nil {
		return nil, fmt.Errorf("mint does not carry the ConfidentialTransferFeeConfig extension")
	}
	if len(raw) != 129 {
		return nil, fmt.Errorf("confidential transfer fee config: %d bytes, expected 129", len(raw))
	}

	return append([]byte(nil), raw[65:129]...), nil
}

// ConfidentialTransferAccountKeys returns a token account's own ElGamal
// public key and its current decryptable available balance, both read from
// its ConfidentialTransferAccount extension. Layout confirmed against
// ConfidentialTransferAccount: elgamal_pubkey at 1..33 (after the approved
// byte) and decryptable_available_balance at 225..261.
func ConfidentialTransferAccountKeys(accountData []byte) (elgamalPubkey, decryptableAvailableBalance []byte, err error) {
	raw := FindExtensionData(accountData, ExtensionTypeConfidentialTransferAccount)
	if raw == nil {
		return nil, nil, fmt.Errorf("account does not carry the ConfidentialTransferAccount extension")
	}
	if len(raw) != 295 {
		return nil, nil, fmt.Errorf("confidential transfer account: %d bytes, expected 295", len(raw))
	}

	return append([]byte(nil), raw[1:33]...), append([]byte(nil), raw[225:261]...), nil
}

// BuildWithdrawWithheldFromAccountsProof is BuildWithdrawWithheldFromMintProof
// for WithdrawWithheldTokensFromAccounts: the ciphertext being withdrawn is
// the sum of every source account's own withheld amount
// (ConfidentialTransferFeeAmount), which the deployed program adds up
// itself and compares with the proof's first ciphertext. The sum must fit
// in 32 bits.
func BuildWithdrawWithheldFromAccountsProof(
	withdrawSecretKey, withdrawPublicKey, destinationPublicKey []byte,
	sourceWithheldCiphertexts [][]byte,
	destinationDecryptableBalance, aeKey []byte,
) (*WithdrawWithheldProof, error) {
	if len(sourceWithheldCiphertexts) == 0 {
		return nil, fmt.Errorf("build withdraw withheld proof: at least one source account is required")
	}

	sum := sourceWithheldCiphertexts[0]
	for _, ct := range sourceWithheldCiphertexts[1:] {
		var err error
		if sum, err = zkbridge.ElGamalAddCiphertexts(sum, ct); err != nil {
			return nil, fmt.Errorf("build withdraw withheld proof: sum source ciphertexts: %w", err)
		}
	}

	return BuildWithdrawWithheldFromMintProof(withdrawSecretKey, withdrawPublicKey, destinationPublicKey, sum, destinationDecryptableBalance, aeKey)
}

// ConfidentialTransferFeeAmountWithheld returns a token account's withheld
// confidential fee ciphertext, the whole 64-byte ConfidentialTransferFeeAmount
// extension.
func ConfidentialTransferFeeAmountWithheld(accountData []byte) ([]byte, error) {
	raw := FindExtensionData(accountData, ExtensionTypeConfidentialTransferFeeAmount)
	if raw == nil {
		return nil, fmt.Errorf("account does not carry the ConfidentialTransferFeeAmount extension")
	}
	if len(raw) != 64 {
		return nil, fmt.Errorf("confidential transfer fee amount: %d bytes, expected 64", len(raw))
	}

	return append([]byte(nil), raw...), nil
}
