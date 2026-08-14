package types

import (
	"fmt"
	"strings"

	"github.com/andantan/svmlab/core/codec"
)

// MaxAccountIndex is the highest account an instruction can point at, since
// indexes are single bytes. A message may therefore carry at most 256 keys,
// well below what the short-vec length prefix could express.
const MaxAccountIndex = 0xff

// Instruction is a single call to a program.
//
// It is the closest thing to an EVM message call, but the resemblance is
// shallow. There is no value field, because moving lamports is itself an
// instruction to the System Program rather than a property of the call. There
// is no gas limit, because compute is budgeted per transaction rather than
// per call. And Data has no ABI: an EVM calldata payload begins with a
// four-byte selector derived from a canonical function signature, whereas
// this is an opaque byte string whose layout each program defines for itself.
// The nearest thing to a convention is the leading u32 discriminant the
// native programs use, or the eight-byte hash Anchor prepends.
type Instruction struct {
	ProgramID *PublicKey
	Accounts  []*Account
	Data      []byte
}

func NewInstruction(programID *PublicKey, accounts []*Account, data []byte) *Instruction {
	return &Instruction{
		ProgramID: programID,
		Accounts:  accounts,
		Data:      data,
	}
}

type Instructions []*Instruction

func NewInstructions(ixs ...*Instruction) Instructions {
	return ixs
}

// Append returns a new Instructions with ix added after the existing ones.
func (i Instructions) Append(ix *Instruction) Instructions {
	return append(append(Instructions{}, i...), ix)
}

// Prepend returns a new Instructions with ix added before the existing ones.
//
// A durable-nonce transaction's first instruction must consume the nonce, so
// this is how that instruction gets there.
func (i Instructions) Prepend(ix *Instruction) Instructions {
	return append(Instructions{ix}, i...)
}

func (i *Instruction) IsNil() bool {
	if i == nil || i.ProgramID.IsNil() {
		return true
	}

	return false
}

func (i *Instruction) String() string {
	accounts := make([]string, len(i.Accounts))
	for n, a := range i.Accounts {
		accounts[n] = a.String()
	}

	return fmt.Sprintf("%s(%s) data=%x", i.ProgramID, strings.Join(accounts, ", "), i.Data)
}

// CompiledInstruction is an Instruction with every public key replaced by its
// position in the enclosing message's account list.
//
// The indirection is what keeps a transaction small. A key is 32 bytes, and a
// transaction has 1232 bytes to work with, so repeating the fee payer and the
// System Program across several instructions would be costly. Listing every
// key once at the top of the message and pointing at it with a single byte
// costs 31 bytes less per repeat.
//
// This form is also the only one that exists on the wire. An Instruction
// cannot be serialized on its own, because an index has no meaning without
// the message that defines it.
type CompiledInstruction struct {
	ProgramIDIndex uint8
	AccountIndexes []uint8
	Data           []byte
}

func NewCompiledInstruction(programIDIndex uint8, accountIndexes []uint8, data []byte) *CompiledInstruction {
	return &CompiledInstruction{
		ProgramIDIndex: programIDIndex,
		AccountIndexes: accountIndexes,
		Data:           data,
	}
}

func (i *CompiledInstruction) IsNil() bool {
	if i == nil {
		return true
	}

	return false
}

// Serialize writes the instruction in the layout a message expects:
//
//	u8         program id index
//	short-vec  number of account indexes
//	[u8]       account indexes
//	short-vec  data length
//	[u8]       data
func (i *CompiledInstruction) Serialize() ([]byte, error) {
	out := codec.Binary.AppendU8(nil, i.ProgramIDIndex)

	out, err := codec.Binary.AppendShortVecLen(out, len(i.AccountIndexes))
	if err != nil {
		return nil, fmt.Errorf("instruction account indexes: %w", err)
	}
	out = codec.Binary.AppendBytes(out, i.AccountIndexes)

	out, err = codec.Binary.AppendShortVecLen(out, len(i.Data))
	if err != nil {
		return nil, fmt.Errorf("instruction data: %w", err)
	}
	out = codec.Binary.AppendBytes(out, i.Data)

	return out, nil
}

// DeserializeCompiledInstruction reads one instruction and returns the
// remaining input, so a caller can walk a message's instruction list.
func DeserializeCompiledInstruction(src []byte) (*CompiledInstruction, []byte, error) {
	programIDIndex, src, err := codec.Binary.ReadU8(src)
	if err != nil {
		return nil, nil, fmt.Errorf("instruction program id index: %w", err)
	}

	n, size, err := codec.Binary.ReadShortVecLen(src)
	if err != nil {
		return nil, nil, fmt.Errorf("instruction account indexes: %w", err)
	}
	indexes, src, err := codec.Binary.ReadBytes(src[size:], n)
	if err != nil {
		return nil, nil, fmt.Errorf("instruction account indexes: %w", err)
	}

	n, size, err = codec.Binary.ReadShortVecLen(src)
	if err != nil {
		return nil, nil, fmt.Errorf("instruction data: %w", err)
	}
	data, src, err := codec.Binary.ReadBytes(src[size:], n)
	if err != nil {
		return nil, nil, fmt.Errorf("instruction data: %w", err)
	}

	return NewCompiledInstruction(programIDIndex, indexes, data), src, nil
}

func (i *CompiledInstruction) String() string {
	return fmt.Sprintf("program=%d accounts=%v data=%x", i.ProgramIDIndex, i.AccountIndexes, i.Data)
}
