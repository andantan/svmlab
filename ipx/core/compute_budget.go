package core

import (
	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
)

// Compute Budget instruction discriminants.
//
// Borsh-serialized, unlike Token and System's own hand-rolled bincode: the
// discriminant is still one byte, but it comes from deriving on an enum
// rather than being assigned by hand, and every field after it is Borsh's
// own fixed-width little-endian encoding for the type — indistinguishable
// from this project's own u32/u64 append on the wire, so nothing here reads
// differently for it.
//
// Unused (0) is a reserved discriminant, not a builder: it is what
// RequestUnits used to occupy before compute unit pricing moved to the two
// Set* instructions below, and the deployed program still holds the slot
// so a later discriminant is never renumbered onto it.
const (
	ComputeBudgetInstructionUnused uint8 = iota
	ComputeBudgetInstructionRequestHeapFrame
	ComputeBudgetInstructionSetComputeUnitLimit
	ComputeBudgetInstructionSetComputeUnitPrice
	ComputeBudgetInstructionSetLoadedAccountsDataSizeLimit
)

// computeBudget builds instructions for the program that sets resource
// limits and priority fees for the transaction carrying it.
//
// It is a namespace like System and PDA rather than a value like token:
// there is exactly one Compute Budget program, fixed by the runtime, with
// nothing to select between.
type computeBudget struct{}

var ComputeBudget = new(computeBudget)

// ID is the Compute Budget program id.
func (_ *computeBudget) ID() *types.PublicKey {
	return ComputeBudgetProgramID
}

// SetComputeUnitLimit caps how many compute units the transaction carrying
// it may consume.
//
// It takes no accounts at all. There is nothing here for an authority to
// gate: the limit only ever affects the transaction it rides in, and
// setting it too low fails that same transaction with a compute-budget-
// exceeded error rather than anyone else's.
func (_ *computeBudget) SetComputeUnitLimit(units uint32) *types.Instruction {
	data := codec.Binary.AppendU8(nil, ComputeBudgetInstructionSetComputeUnitLimit)
	data = codec.Binary.AppendU32(data, units)

	return types.NewInstruction(ComputeBudgetProgramID, types.NewAccounts(), data)
}

// RequestHeapFrame resizes the heap available to the transaction carrying
// it, in bytes.
//
// It takes no accounts, the same as the other Compute Budget instructions:
// there is nobody to gate a value that only ever affects the transaction it
// rides in. The default heap is 32KiB per instruction invocation; a program
// that allocates more than that fails with an out-of-memory error unless
// something in the same transaction requests a larger frame first.
func (_ *computeBudget) RequestHeapFrame(bytes uint32) *types.Instruction {
	data := codec.Binary.AppendU8(nil, ComputeBudgetInstructionRequestHeapFrame)
	data = codec.Binary.AppendU32(data, bytes)

	return types.NewInstruction(ComputeBudgetProgramID, types.NewAccounts(), data)
}

// SetComputeUnitPrice sets the priority fee for the transaction carrying it,
// in micro-lamports per compute unit.
//
// It takes no accounts, the same as SetComputeUnitLimit: there is nobody to
// gate a value that only ever prices the transaction it rides in. The
// runtime multiplies this by whatever compute the transaction actually
// consumes — bounded by SetComputeUnitLimit when one is present, or by the
// per-transaction default otherwise — to get the priority fee on top of the
// base signature fee.
func (_ *computeBudget) SetComputeUnitPrice(microLamports uint64) *types.Instruction {
	data := codec.Binary.AppendU8(nil, ComputeBudgetInstructionSetComputeUnitPrice)
	data = codec.Binary.AppendU64(data, microLamports)

	return types.NewInstruction(ComputeBudgetProgramID, types.NewAccounts(), data)
}

// SetLoadedAccountsDataSizeLimit caps the total byte size of every account
// the transaction carrying it loads, across all its instructions and any
// CPIs they make.
//
// bytes must be non-zero — the runtime rejects zero outright as
// InvalidLoadedAccountsDataSizeLimit, since a transaction that may load
// nothing cannot load its own instructions' accounts either. It takes no
// accounts itself, the same as every other Compute Budget instruction:
// there is nobody to gate a value that only ever bounds the transaction it
// rides in. Left unset, legacy and v0 transactions default to 64MiB; a
// value here only ever lowers that ceiling, since the runtime clamps
// anything larger back down to it.
func (_ *computeBudget) SetLoadedAccountsDataSizeLimit(bytes uint32) *types.Instruction {
	data := codec.Binary.AppendU8(nil, ComputeBudgetInstructionSetLoadedAccountsDataSizeLimit)
	data = codec.Binary.AppendU32(data, bytes)

	return types.NewInstruction(ComputeBudgetProgramID, types.NewAccounts(), data)
}
