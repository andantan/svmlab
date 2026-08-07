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
	SystemInstructionCreateAccount uint32 = 0
	SystemInstructionAssign        uint32 = 1
	SystemInstructionTransfer      uint32 = 2
	SystemInstructionAllocate      uint32 = 8
)

type systemProgram struct {
	id *types.PublicKey
}

// SystemProgram builds instructions for the program that owns every account
// not yet assigned elsewhere.
//
// It has no EVM counterpart because the EVM builds these operations into the
// protocol. Moving ether is a transaction field, and creating an account is a
// side effect of being sent funds. Here both are ordinary instructions to an
// ordinary program, which is why a transfer is a call rather than a value.
var SystemProgram = func() *systemProgram {
	id, err := types.NewPublicKeyFromBase58(types.SystemProgramID)
	if err != nil {
		panic(fmt.Sprintf("core: invalid system program id: %v", err))
	}

	return &systemProgram{id: id}
}()

func (p *systemProgram) ID() *types.PublicKey {
	return p.id
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
func (p *systemProgram) Transfer(from, to *types.PublicKey, lamports uint64) (*types.Instruction, error) {
	if from.IsNil() {
		return nil, fmt.Errorf("system transfer: sender is required")
	}
	if to.IsNil() {
		return nil, fmt.Errorf("system transfer: recipient is required")
	}
	if from.Equal(to) {
		return nil, fmt.Errorf("system transfer: sender and recipient are the same account")
	}

	data := codec.Bincode.AppendU32(nil, SystemInstructionTransfer)
	data = codec.Bincode.AppendU64(data, lamports)

	return types.NewInstruction(p.id, []*types.Account{
		types.NewWritableSignerAccount(from),
		types.NewWritableAccount(to),
	}, data), nil
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
func (p *systemProgram) CreateAccount(from, newAccount, owner *types.PublicKey, lamports, space uint64) (*types.Instruction, error) {
	if from.IsNil() {
		return nil, fmt.Errorf("system create account: funder is required")
	}
	if newAccount.IsNil() {
		return nil, fmt.Errorf("system create account: new account is required")
	}
	if owner.IsNil() {
		return nil, fmt.Errorf("system create account: owner is required")
	}

	data := codec.Bincode.AppendU32(nil, SystemInstructionCreateAccount)
	data = codec.Bincode.AppendU64(data, lamports)
	data = codec.Bincode.AppendU64(data, space)
	data = codec.Bincode.AppendBytes(data, owner.Bytes())

	return types.NewInstruction(p.id, []*types.Account{
		types.NewWritableSignerAccount(from),
		types.NewWritableSignerAccount(newAccount),
	}, data), nil
}

// Allocate reserves data space on an existing account owned by the System
// Program.
func (p *systemProgram) Allocate(account *types.PublicKey, space uint64) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("system allocate: account is required")
	}

	data := codec.Bincode.AppendU32(nil, SystemInstructionAllocate)
	data = codec.Bincode.AppendU64(data, space)

	return types.NewInstruction(p.id, []*types.Account{
		types.NewWritableSignerAccount(account),
	}, data), nil
}

// Assign hands ownership of an account to another program.
//
// Only the owning program may write an account's data, so this is the step that
// puts an account under a program's control. Ownership here is a field on the
// account rather than a mapping the program keeps, which is the inverse of an
// EVM contract holding balances for its users in its own storage.
func (p *systemProgram) Assign(account, owner *types.PublicKey) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("system assign: account is required")
	}
	if owner.IsNil() {
		return nil, fmt.Errorf("system assign: owner is required")
	}

	data := codec.Bincode.AppendU32(nil, SystemInstructionAssign)
	data = codec.Bincode.AppendBytes(data, owner.Bytes())

	return types.NewInstruction(p.id, []*types.Account{
		types.NewWritableSignerAccount(account),
	}, data), nil
}
