package core

import (
	"fmt"

	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
)

const (
	// RecordInstructionInitialize and the rest of this block are the
	// discriminators the Record program accepts, confirmed against its own
	// RecordInstruction::unpack.
	RecordInstructionInitialize uint8 = iota
	RecordInstructionWrite
	RecordInstructionSetAuthority
	RecordInstructionCloseAccount
	RecordInstructionReallocate
)

// RecordAccountHeaderLen is the 33 bytes a record account keeps ahead of the
// data it holds: a 1-byte version and the 32-byte authority. Everything
// written lives after it, so a proof written at offset 0 starts at byte 33
// of the account -- which is the offset a verify-from-account instruction
// has to name.
const RecordAccountHeaderLen = 33

// record is a namespace, the same shape ZkElgamalProof is: nothing about
// which record account to touch is state, so there is nothing to construct
// beyond the fixed program id.
type record struct {
	id *types.PublicKey
}

// Record builds instructions against the SPL Record program
// (recr1L3PCGKLbckBqMNcJhuuyU1zgo8nBhfLVsJNwr5).
var Record = &record{id: RecordProgramID}

// ID returns the Record program's own address -- the owner a record
// account must be given at creation, since only this program can write its
// data.
func (r *record) ID() *types.PublicKey {
	return r.id
}

// AccountSpace is the space a record account holding dataLength bytes
// needs: the 33-byte header plus the data.
func (r *record) AccountSpace(dataLength uint64) uint64 {
	return RecordAccountHeaderLen + dataLength
}

// Initialize marks a freshly created record account as a record and names
// its authority. The authority does not sign here, which is why this has to
// land in the same transaction as the System CreateAccount that made the
// account: an uninitialized record account can be initialized by anyone,
// with any authority they like.
//
// Accounts: [record(writable), authority(readonly)]. Confirmed against the
// Record program's own instruction builders.
func (r *record) Initialize(recordAccount, authority *types.PublicKey) (*types.Instruction, error) {
	if recordAccount.IsNil() {
		return nil, fmt.Errorf("record initialize: record account is required")
	}
	if authority.IsNil() {
		return nil, fmt.Errorf("record initialize: authority is required")
	}

	data := codec.Binary.AppendU8(nil, RecordInstructionInitialize)

	return types.NewInstruction(r.id, types.NewAccounts(
		types.NewWritableAccount(recordAccount),
		types.NewReadonlyAccount(authority),
	), data), nil
}

// Write copies data into the record at offset (counted from the end of the
// 33-byte header, not from the start of the account). It fails if that would
// run past the end of the account, so a record must be created (or
// reallocated) large enough first.
//
// Data is [1] + offset(u64) + length(u32) + bytes; accounts are
// [record(writable), authority(signer)].
func (r *record) Write(recordAccount, authority *types.PublicKey, offset uint64, bytes []byte) (*types.Instruction, error) {
	if recordAccount.IsNil() {
		return nil, fmt.Errorf("record write: record account is required")
	}
	if authority.IsNil() {
		return nil, fmt.Errorf("record write: authority is required")
	}
	if len(bytes) == 0 {
		return nil, fmt.Errorf("record write: nothing to write")
	}

	data := codec.Binary.AppendU8(nil, RecordInstructionWrite)
	data = codec.Binary.AppendU64(data, offset)
	data = codec.Binary.AppendU32(data, uint32(len(bytes)))
	data = codec.Binary.AppendBytes(data, bytes)

	return types.NewInstruction(r.id, types.NewAccounts(
		types.NewWritableAccount(recordAccount),
		types.NewReadonlySignerAccount(authority),
	), data), nil
}

// SetAuthority hands the record to newAuthority. Accounts:
// [record(writable), current authority(signer), new authority(readonly)].
func (r *record) SetAuthority(recordAccount, authority, newAuthority *types.PublicKey) (*types.Instruction, error) {
	if recordAccount.IsNil() {
		return nil, fmt.Errorf("record set authority: record account is required")
	}
	if authority.IsNil() {
		return nil, fmt.Errorf("record set authority: authority is required")
	}
	if newAuthority.IsNil() {
		return nil, fmt.Errorf("record set authority: new authority is required")
	}

	data := codec.Binary.AppendU8(nil, RecordInstructionSetAuthority)

	return types.NewInstruction(r.id, types.NewAccounts(
		types.NewWritableAccount(recordAccount),
		types.NewReadonlySignerAccount(authority),
		types.NewReadonlyAccount(newAuthority),
	), data), nil
}

// CloseAccount drains the record's lamports into receiver, which removes the
// account once the transaction ends. Accounts: [record(writable),
// authority(signer), receiver(writable)] -- the receiver is writable in the
// Record program's own builder even though its doc comment lists it as
// read-only, since it gains lamports.
func (r *record) CloseAccount(recordAccount, authority, receiver *types.PublicKey) (*types.Instruction, error) {
	if recordAccount.IsNil() {
		return nil, fmt.Errorf("record close account: record account is required")
	}
	if authority.IsNil() {
		return nil, fmt.Errorf("record close account: authority is required")
	}
	if receiver.IsNil() {
		return nil, fmt.Errorf("record close account: receiver is required")
	}

	data := codec.Binary.AppendU8(nil, RecordInstructionCloseAccount)

	return types.NewInstruction(r.id, types.NewAccounts(
		types.NewWritableAccount(recordAccount),
		types.NewReadonlySignerAccount(authority),
		types.NewWritableAccount(receiver),
	), data), nil
}

// Reallocate grows the record to hold dataLength bytes (excluding the
// header); it does nothing if the account is already that large. The
// account must already hold enough lamports for the larger size, since this
// instruction does not fund it. Accounts: [record(writable), authority
// (signer)].
func (r *record) Reallocate(recordAccount, authority *types.PublicKey, dataLength uint64) (*types.Instruction, error) {
	if recordAccount.IsNil() {
		return nil, fmt.Errorf("record reallocate: record account is required")
	}
	if authority.IsNil() {
		return nil, fmt.Errorf("record reallocate: authority is required")
	}

	data := codec.Binary.AppendU8(nil, RecordInstructionReallocate)
	data = codec.Binary.AppendU64(data, dataLength)

	return types.NewInstruction(r.id, types.NewAccounts(
		types.NewWritableAccount(recordAccount),
		types.NewReadonlySignerAccount(authority),
	), data), nil
}
