package core

import (
	"fmt"

	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
)

// System Program instruction discriminants.
//
// The leading u32 selects the operation, in the role an EVM four-byte selector
// plays. It is an index into a fixed list rather than a hash of a signature,
// so it carries no type information and cannot be recovered from a name.
const (
	SystemInstructionCreateAccount         uint32 = 0
	SystemInstructionAssign                uint32 = 1
	SystemInstructionTransfer              uint32 = 2
	SystemInstructionCreateAccountWithSeed uint32 = 3
	SystemInstructionAllocate              uint32 = 8
	SystemInstructionAllocateWithSeed      uint32 = 9
	SystemInstructionAssignWithSeed        uint32 = 10
	SystemInstructionTransferWithSeed      uint32 = 11
)

const (
	// SystemAccountSpace is a plain wallet: lamports and no data.
	SystemAccountSpace uint64 = 0

	// MaxPermittedDataLength is the largest data size an account may be
	// created with, which the runtime enforces rather than merely charging
	// rent for.
	MaxPermittedDataLength uint64 = 10 << 20
)

// system builds instructions for the program that owns every account not yet
// assigned elsewhere.
//
// It has no EVM counterpart because the EVM builds these operations into the
// protocol. Moving ether is a transaction field, and creating an account is a
// side effect of being sent funds. Here both are ordinary instructions to an
// ordinary program, which is why a transfer is a call rather than a value.
//
// The program id is the same on every Solana cluster, so it is captured once
// via Init rather than threaded through every call the way a per-chain address
// would be.
type system struct {
	id *types.PublicKey
}

var System = new(system)

// Init records the System Program id, read from config at startup.
func (s *system) Init(id *types.PublicKey) {
	s.id = id
}

// ID is the System Program id, which callers need when it is not the program
// being invoked but the value being passed, as the owner of a new account is.
func (s *system) ID() *types.PublicKey {
	return s.id
}

// Transfer moves lamports from one account to another.
//
// The sender signs and is debited, so it is a writable signer; the recipient is
// only credited, so it is writable but does not sign.
//
// A transfer to an account that does not exist creates it, but the runtime
// requires the resulting balance to reach the rent-exempt minimum, currently
// 890880 lamports for an empty account. A smaller amount to a new address fails
// rather than creating a dust account.
func (s *system) Transfer(from, to *types.PublicKey, lamports uint64) (*types.Instruction, error) {
	if s.id.IsNil() {
		return nil, fmt.Errorf("system: not initialized")
	}
	if from.IsNil() {
		return nil, fmt.Errorf("system transfer: sender is required")
	}
	if to.IsNil() {
		return nil, fmt.Errorf("system transfer: recipient is required")
	}
	if from.Equal(to) {
		return nil, fmt.Errorf("system transfer: sender and recipient are the same account")
	}

	data := codec.Binary.AppendU32(nil, SystemInstructionTransfer)
	data = codec.Binary.AppendU64(data, lamports)

	return types.NewInstruction(s.id, types.NewAccounts(
		types.NewWritableSignerAccount(from),
		types.NewWritableAccount(to),
	), data), nil
}

// CreateAccount funds a new account, sizes its data, and assigns it an owner.
//
// The new account signs as well as the funder, which is the part that surprises
// anyone coming from the EVM: an address does not exist until someone with its
// private key authorizes its creation. That is why a program derived address,
// having no private key, cannot be created this way and needs its owning
// program to sign for it instead.
//
// Lamports must cover the rent-exempt minimum for the requested space, or the
// runtime rejects the instruction.
func (s *system) CreateAccount(from, newAccount, owner *types.PublicKey, lamports, space uint64) (*types.Instruction, error) {
	if s.id.IsNil() {
		return nil, fmt.Errorf("system: not initialized")
	}
	if from.IsNil() {
		return nil, fmt.Errorf("system create account: funder is required")
	}
	if newAccount.IsNil() {
		return nil, fmt.Errorf("system create account: new account is required")
	}
	if owner.IsNil() {
		return nil, fmt.Errorf("system create account: owner is required")
	}
	if space > MaxPermittedDataLength {
		return nil, fmt.Errorf("system create account: %d bytes exceeds the %d byte limit", space, MaxPermittedDataLength)
	}

	data := codec.Binary.AppendU32(nil, SystemInstructionCreateAccount)
	data = codec.Binary.AppendU64(data, lamports)
	data = codec.Binary.AppendU64(data, space)
	data = codec.Binary.AppendBytes(data, owner.Bytes())

	return types.NewInstruction(s.id, types.NewAccounts(
		types.NewWritableSignerAccount(from),
		types.NewWritableSignerAccount(newAccount),
	), data), nil
}

// Allocate reserves data space on an existing account owned by the System
// Program.
func (s *system) Allocate(account *types.PublicKey, space uint64) (*types.Instruction, error) {
	if s.id.IsNil() {
		return nil, fmt.Errorf("system: not initialized")
	}
	if account.IsNil() {
		return nil, fmt.Errorf("system allocate: account is required")
	}
	if space > MaxPermittedDataLength {
		return nil, fmt.Errorf("system allocate: %d bytes exceeds the %d byte limit", space, MaxPermittedDataLength)
	}

	data := codec.Binary.AppendU32(nil, SystemInstructionAllocate)
	data = codec.Binary.AppendU64(data, space)

	return types.NewInstruction(s.id, types.NewAccounts(
		types.NewWritableSignerAccount(account),
	), data), nil
}

// Assign hands ownership of an account to another program.
//
// Only the owning program may write an account's data, so this is the step that
// puts an account under a program's control. Ownership here is a field on the
// account rather than a mapping the program keeps, which is the inverse of an
// EVM contract holding balances for its users in its own storage.
func (s *system) Assign(account, owner *types.PublicKey) (*types.Instruction, error) {
	if s.id.IsNil() {
		return nil, fmt.Errorf("system: not initialized")
	}
	if account.IsNil() {
		return nil, fmt.Errorf("system assign: account is required")
	}
	if owner.IsNil() {
		return nil, fmt.Errorf("system assign: owner is required")
	}

	data := codec.Binary.AppendU32(nil, SystemInstructionAssign)
	data = codec.Binary.AppendBytes(data, owner.Bytes())

	return types.NewInstruction(s.id, types.NewAccounts(
		types.NewWritableSignerAccount(account),
	), data), nil
}

// CreateAccountWithSeed funds a new account at an address derived from a base
// key, a seed, and the owner.
//
// The new account does not sign, which is the whole difference from
// CreateAccount: nobody holds a secret for a derived address, so there is no
// signature it could produce. Base signs in its place, which means whoever
// controls base controls every address derived from it.
//
// The address is derived here rather than taken as an argument. The runtime
// recomputes it and rejects the instruction if it disagrees, so accepting one
// from a caller would only add a way to be wrong.
func (s *system) CreateAccountWithSeed(from, base *types.PublicKey, seed string, owner *types.PublicKey, lamports, space uint64) (*types.Instruction, error) {
	if s.id.IsNil() {
		return nil, fmt.Errorf("system: not initialized")
	}
	if from.IsNil() {
		return nil, fmt.Errorf("system create account with seed: funder is required")
	}
	if space > MaxPermittedDataLength {
		return nil, fmt.Errorf("system create account with seed: %d bytes exceeds the %d byte limit", space, MaxPermittedDataLength)
	}

	derived, err := types.CreateWithSeed(base, seed, owner)
	if err != nil {
		return nil, fmt.Errorf("system create account with seed: %w", err)
	}

	data := codec.Binary.AppendU32(nil, SystemInstructionCreateAccountWithSeed)
	data = codec.Binary.AppendBytes(data, base.Bytes())
	data = codec.Binary.AppendString(data, seed)
	data = codec.Binary.AppendU64(data, lamports)
	data = codec.Binary.AppendU64(data, space)
	data = codec.Binary.AppendBytes(data, owner.Bytes())

	return types.NewInstruction(s.id, types.NewAccounts(
		types.NewWritableSignerAccount(from),
		types.NewWritableAccount(derived),
		types.NewReadonlySignerAccount(base),
	), data), nil
}

// TransferWithSeed moves lamports out of a seed-derived account.
//
// The sender is debited without signing, since base signs for it. That is what
// makes a derived address usable as a holding account: it can be funded by
// anyone and spent only by whoever holds the base key.
//
// The owner is the one the address was derived for, not a new one. It has to
// be the System Program for the transfer itself to be legal, since only the
// owning program may debit an account.
func (s *system) TransferWithSeed(base *types.PublicKey, seed string, owner, to *types.PublicKey, lamports uint64) (*types.Instruction, error) {
	if s.id.IsNil() {
		return nil, fmt.Errorf("system: not initialized")
	}
	if to.IsNil() {
		return nil, fmt.Errorf("system transfer with seed: recipient is required")
	}

	derived, err := types.CreateWithSeed(base, seed, owner)
	if err != nil {
		return nil, fmt.Errorf("system transfer with seed: %w", err)
	}
	if derived.Equal(to) {
		return nil, fmt.Errorf("system transfer with seed: sender and recipient are the same account")
	}

	data := codec.Binary.AppendU32(nil, SystemInstructionTransferWithSeed)
	data = codec.Binary.AppendU64(data, lamports)
	data = codec.Binary.AppendString(data, seed)
	data = codec.Binary.AppendBytes(data, owner.Bytes())

	return types.NewInstruction(s.id, types.NewAccounts(
		types.NewWritableAccount(derived),
		types.NewReadonlySignerAccount(base),
		types.NewWritableAccount(to),
	), data), nil
}

// AllocateWithSeed reserves data space on a seed-derived account.
//
// The owner is the one the address was derived for. Allocation still requires
// the account to be System-owned, so this is the step taken before assigning
// it away, on an address that was derived for its eventual owner from the
// start.
func (s *system) AllocateWithSeed(base *types.PublicKey, seed string, owner *types.PublicKey, space uint64) (*types.Instruction, error) {
	if s.id.IsNil() {
		return nil, fmt.Errorf("system: not initialized")
	}
	if space > MaxPermittedDataLength {
		return nil, fmt.Errorf("system allocate with seed: %d bytes exceeds the %d byte limit", space, MaxPermittedDataLength)
	}

	derived, err := types.CreateWithSeed(base, seed, owner)
	if err != nil {
		return nil, fmt.Errorf("system allocate with seed: %w", err)
	}

	data := codec.Binary.AppendU32(nil, SystemInstructionAllocateWithSeed)
	data = codec.Binary.AppendBytes(data, base.Bytes())
	data = codec.Binary.AppendString(data, seed)
	data = codec.Binary.AppendU64(data, space)
	data = codec.Binary.AppendBytes(data, owner.Bytes())

	return types.NewInstruction(s.id, types.NewAccounts(
		types.NewWritableAccount(derived),
		types.NewReadonlySignerAccount(base),
	), data), nil
}

// AssignWithSeed hands a seed-derived account to the program it was derived
// for.
//
// One owner serves two purposes here, which is the part worth reading twice:
// it is both the new owner and the owner the address is derived from. So an
// account can only be assigned to the program its address already encodes, and
// the usual flow is to derive for the target program first, fund that address
// to bring it into existence, then allocate and assign.
func (s *system) AssignWithSeed(base *types.PublicKey, seed string, owner *types.PublicKey) (*types.Instruction, error) {
	if s.id.IsNil() {
		return nil, fmt.Errorf("system: not initialized")
	}

	derived, err := types.CreateWithSeed(base, seed, owner)
	if err != nil {
		return nil, fmt.Errorf("system assign with seed: %w", err)
	}

	data := codec.Binary.AppendU32(nil, SystemInstructionAssignWithSeed)
	data = codec.Binary.AppendBytes(data, base.Bytes())
	data = codec.Binary.AppendString(data, seed)
	data = codec.Binary.AppendBytes(data, owner.Bytes())

	return types.NewInstruction(s.id, types.NewAccounts(
		types.NewWritableAccount(derived),
		types.NewReadonlySignerAccount(base),
	), data), nil
}
