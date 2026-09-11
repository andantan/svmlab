package core

import (
	"fmt"

	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
)

// Associated Token Account instruction discriminants.
//
// The program predates the discriminant byte: its original instruction is the
// empty payload, and later ones were added by giving them a leading byte the
// empty one cannot have. That is why Create is zero bytes rather than the byte
// zero, and it is the reason the two cases below are not symmetric.
const (
	ATAInstructionCreateIdempotent uint8 = 1
	ATAInstructionRecoverNested    uint8 = 2
)

// ata builds instructions for the program that owns the canonical
// token account of a wallet and mint pair.
//
// It is a namespace like System and PDA rather than a value like token: the
// program id is fixed by the runtime, and unlike a token program there is no
// second deployment of it to select between.
type ata struct{}

var ATA = new(ata)

// ID is the Associated Token Account program id.
func (_ *ata) ID() *types.PublicKey {
	return AssociatedTokenProgramID
}

// Derive returns the associated token address for a wallet and mint, together
// with the bump seed that produced it.
//
// The token program is a seed rather than a constant, so one wallet has
// different associated accounts for classic Token and Token-2022 over
// otherwise identical mints. Getting that wrong derives a real address that
// simply is not the one anybody else will look at.
//
// This is what an associated account is for: the address follows from the pair
// rather than from a key somebody generated, so anyone holding a wallet and a
// mint can recompute it without being told. A keypair token account has no
// such property, which is why its address has to be remembered.
func (_ *ata) Derive(wallet, mint, tokenProgramID *types.PublicKey) (*types.PublicKey, uint8, error) {
	if wallet.IsNil() {
		return nil, 0, fmt.Errorf("ata derive: wallet is required")
	}
	if mint.IsNil() {
		return nil, 0, fmt.Errorf("ata derive: mint is required")
	}
	if tokenProgramID.IsNil() {
		return nil, 0, fmt.Errorf("ata derive: token program is required")
	}

	return PDA.Find([][]byte{
		wallet.Bytes(),
		tokenProgramID.Bytes(),
		mint.Bytes(),
	}, AssociatedTokenProgramID)
}

// Create funds and initializes the associated token account for a wallet and
// mint.
//
// It carries no instruction data at all. Everything the program needs is in
// the account list, and it derives the address itself and compares, so a
// caller cannot direct the funds somewhere else by passing a different one.
//
// The account being created does not sign, which is the difference from
// System CreateAccount and the whole reason a program derived address exists:
// it has no private key to sign with, so the program signs for it. That also
// means no keypair has to be generated or kept.
//
// Creating one that already exists fails. CreateIdempotent is the variant for
// when that is not known in advance.
func (_ *ata) Create(payer, wallet, mint, tokenProgramID *types.PublicKey) (*types.Instruction, error) {
	accounts, err := ataAccounts("ata create", payer, wallet, mint, tokenProgramID)
	if err != nil {
		return nil, err
	}

	return types.NewInstruction(AssociatedTokenProgramID, accounts, nil), nil
}

// CreateIdempotent does what Create does, and succeeds instead of failing when
// the account is already there.
//
// This is the safe one to prepend to a transfer. Checking first and creating
// only if absent leaves a window in which somebody else creates it, and the
// plain Create would then fail the whole transaction over an account that
// exists and is correct.
func (_ *ata) CreateIdempotent(payer, wallet, mint, tokenProgramID *types.PublicKey) (*types.Instruction, error) {
	accounts, err := ataAccounts("ata create idempotent", payer, wallet, mint, tokenProgramID)
	if err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, ATAInstructionCreateIdempotent)

	return types.NewInstruction(AssociatedTokenProgramID, accounts, data), nil
}

// RecoverNested moves tokens out of a nested associated token account and
// closes it, both in the same instruction.
//
// A nested account exists when an associated account was mistakenly treated
// as if it were a wallet: deriving from it as the "wallet" seed produces a
// real address, the same way any wallet's does, and something funded and
// initialized it there instead of at the actual owner's associated account
// for that mint. This is the recovery for that mistake alone; it is not a
// close instruction for an ordinary associated account, which close-account
// already covers.
//
// Three addresses are derived, none of them a request field, the same
// discipline every other ATA instruction follows: ownerAccount is wallet's
// associated account for ownerMint (the one mistaken for a wallet), nested
// is ownerAccount's own associated account for nestedMint (the mistake
// itself), and destination is wallet's real associated account for
// nestedMint, which is where nested's balance ends up. wallet signs, since
// closing nested pays its reclaimed lamports there and only the real owner
// may authorize that.
func (_ *ata) RecoverNested(wallet, ownerMint, nestedMint, tokenProgramID *types.PublicKey) (*types.Instruction, error) {
	if wallet.IsNil() {
		return nil, fmt.Errorf("ata recover nested: wallet is required")
	}
	if ownerMint.IsNil() {
		return nil, fmt.Errorf("ata recover nested: owner mint is required")
	}
	if nestedMint.IsNil() {
		return nil, fmt.Errorf("ata recover nested: nested mint is required")
	}
	if ownerMint.Equal(nestedMint) {
		return nil, fmt.Errorf("ata recover nested: owner mint and nested mint are the same account")
	}
	if tokenProgramID.IsNil() {
		return nil, fmt.Errorf("ata recover nested: token program is required")
	}

	ownerAccount, _, err := ATA.Derive(wallet, ownerMint, tokenProgramID)
	if err != nil {
		return nil, fmt.Errorf("ata recover nested: owner account: %w", err)
	}
	nested, _, err := ATA.Derive(ownerAccount, nestedMint, tokenProgramID)
	if err != nil {
		return nil, fmt.Errorf("ata recover nested: nested account: %w", err)
	}
	destination, _, err := ATA.Derive(wallet, nestedMint, tokenProgramID)
	if err != nil {
		return nil, fmt.Errorf("ata recover nested: destination account: %w", err)
	}

	data := codec.Binary.AppendU8(nil, ATAInstructionRecoverNested)

	accounts := types.NewAccounts(
		types.NewWritableAccount(nested),
		types.NewReadonlyAccount(nestedMint),
		types.NewWritableAccount(destination),
		types.NewReadonlyAccount(ownerAccount),
		types.NewReadonlyAccount(ownerMint),
		types.NewWritableSignerAccount(wallet),
		types.NewReadonlyAccount(tokenProgramID),
	)

	return types.NewInstruction(AssociatedTokenProgramID, accounts, data), nil
}

// ataAccounts lays out the account list both creates share.
//
// The order is the instruction's entire interface, since neither create sends
// any data: payer, the derived account, the wallet it belongs to, the mint,
// then the two programs it invokes.
func ataAccounts(op string, payer, wallet, mint, tokenProgramID *types.PublicKey) (types.Accounts, error) {
	if payer.IsNil() {
		return nil, fmt.Errorf("%s: payer is required", op)
	}
	if wallet.IsNil() {
		return nil, fmt.Errorf("%s: wallet is required", op)
	}
	if mint.IsNil() {
		return nil, fmt.Errorf("%s: mint is required", op)
	}
	if tokenProgramID.IsNil() {
		return nil, fmt.Errorf("%s: token program is required", op)
	}

	account, _, err := ATA.Derive(wallet, mint, tokenProgramID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return types.NewAccounts(
		types.NewWritableSignerAccount(payer),
		types.NewWritableAccount(account),
		types.NewReadonlyAccount(wallet),
		types.NewReadonlyAccount(mint),
		types.NewReadonlyAccount(SystemProgramID),
		types.NewReadonlyAccount(tokenProgramID),
	), nil
}
