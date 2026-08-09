package types

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/andantan/svmlab/core/codec"
)

// MessageHeaderLength is the fixed three-byte prefix of a legacy message.
const MessageHeaderLength = 3

// MaxAccountKeys is the number of keys a message can hold, bounded by the
// single-byte indexes instructions use to reference them.
const MaxAccountKeys = MaxAccountIndex + 1

// MessageHeader records how the account list is partitioned.
//
// The list is sorted so that the four privilege classes form contiguous runs,
// and these three counts are enough to recover the boundaries. No per-key
// flags are stored, which is why the ordering is load-bearing rather than
// cosmetic: shuffle the keys and every privilege silently changes.
//
//	                                    signer  writable
//	[0, numRequiredSignatures - numReadonlySigned)   yes     yes
//	[.., numRequiredSignatures)                      yes     no
//	[.., len - numReadonlyUnsigned)                  no      yes
//	[.., len)                                        no      no
type MessageHeader struct {
	NumRequiredSignatures       uint8
	NumReadonlySignedAccounts   uint8
	NumReadonlyUnsignedAccounts uint8
}

// Message is the part of a transaction that gets signed.
//
// It plays the role RLP-encoded transaction fields play on an EVM chain, with
// one structural difference: the account list is hoisted to the top and every
// instruction refers to it by index. That is what lets several instructions
// share a fee payer or a program id without repeating 32 bytes each time.
//
// Signing covers these bytes directly. There is no keccak256 step, because
// ed25519 hashes internally as part of signing.
type Message struct {
	Header          MessageHeader
	AccountKeys     []*PublicKey
	RecentBlockhash *Hash
	Instructions    []*CompiledInstruction
}

// NewMessage compiles instructions into a signable message.
//
// The work here is ordering. Every account any instruction touches, plus every
// program it invokes, is gathered into one list, deduplicated, and sorted into
// the four privilege runs the header describes. Instruction operands are then
// rewritten as indexes into that list.
//
// Three rules govern the result:
//
//   - The fee payer is index 0 and is always a writable signer. It pays, so
//     its balance changes, and the runtime looks for it at a fixed position.
//   - A key appearing more than once is listed once with the union of its
//     privileges, since an instruction that needed a privilege fails without
//     it.
//   - A program id is added as a read-only non-signer. It is invoked, not
//     modified, and a program marked writable would be rejected.
//
// The message expires with the blockhash. NewNonceMessage builds one that does
// not.
func NewMessage(feePayer *PublicKey, recentBlockhash *Hash, instructions []*Instruction) (*Message, error) {
	return newMessage(feePayer, recentBlockhash, instructions)
}

// NewNonceMessage compiles a message that never expires, built against the
// value a durable nonce account stores.
//
// It exists as its own constructor because a message has one blockhash field
// and nothing in it marks which kind of value is there. Passing a nonce to
// NewMessage would work and read as a lie, so the two are named apart even
// though the compiled bytes differ only in what that field holds.
//
// The advance is a separate parameter rather than the caller's first
// instruction, because the runtime only accepts a nonce transaction whose
// first instruction consumes the nonce. Taking it here puts that rule in the
// signature. What the instruction actually is stays unknown to this layer,
// which serializes what it is given and knows nothing about programs.
func NewNonceMessage(feePayer *PublicKey, nonce *Hash, advance *Instruction, instructions []*Instruction) (*Message, error) {
	if advance.IsNil() {
		return nil, fmt.Errorf("message: the nonce advance instruction is required")
	}

	return newMessage(feePayer, nonce, append([]*Instruction{advance}, instructions...))
}

func newMessage(feePayer *PublicKey, recentBlockhash *Hash, instructions []*Instruction) (*Message, error) {
	if feePayer.IsNil() {
		return nil, fmt.Errorf("message: fee payer is required")
	}
	if recentBlockhash.IsNil() {
		return nil, fmt.Errorf("message: recent blockhash is required")
	}
	if len(instructions) == 0 {
		return nil, fmt.Errorf("message: at least one instruction is required")
	}

	// Seeded first so that the dedupe below treats the fee payer as the
	// earliest entry, letting a later reference to the same key merge into it
	// instead of creating a second one.
	referenced := []*Account{NewWritableSignerAccount(feePayer)}
	for n, ix := range instructions {
		if ix.IsNil() {
			return nil, fmt.Errorf("message: instruction[%d] is nil", n)
		}
		for j, a := range ix.Accounts {
			if a.IsNil() {
				return nil, fmt.Errorf("message: instruction[%d].account[%d] is nil", n, j)
			}
			referenced = append(referenced, a)
		}
		referenced = append(referenced, NewReadonlyAccount(ix.ProgramID))
	}

	// Repeated keys collapse into one entry carrying the union of their
	// privileges, so an account passed read-only to one instruction and
	// writable to another ends up writable once.
	//
	// The map is keyed by the base58 string rather than by the key itself
	// because PublicKey is a pointer, so using it directly would compare
	// addresses and treat two pointers to the same key as different accounts.
	seen := make(map[string]*Account, len(referenced))
	accounts := make([]*Account, 0, len(referenced))
	for _, a := range referenced {
		key := a.PublicKey.Base58()
		if existing, ok := seen[key]; ok {
			existing.Merge(a)
			continue
		}

		// Copied so that merging never mutates an Account the caller still
		// holds a reference to through its instruction.
		cp := NewAccount(a.PublicKey, a.IsSigner, a.IsWritable)
		seen[key] = cp
		accounts = append(accounts, cp)
	}

	// The fee payer is pulled out so the sort cannot move it, then put back at
	// index 0.
	payer := accounts[0]
	accounts = accounts[1:]

	// Within a privilege class, keys are ordered by their raw bytes rather
	// than by when they were first referenced. This is not an arbitrary
	// tie-break: the reference implementation accumulates keys in a
	// BTreeMap<Pubkey, _>, so byte order is what it produces.
	//
	// Note that the sort runs after the merge above, so a key is placed by the
	// union of its privileges rather than by whichever combination happened to
	// appear first. solana-go sorts before deduplicating and therefore orders
	// such a key differently. Both messages execute, since the runtime reads
	// the header and does not require a canonical key order, but the bytes
	// differ, and co-signers of one transaction must produce identical bytes
	// for their signatures to agree.
	sort.Slice(accounts, func(i, j int) bool {
		if r1, r2 := accounts[i].Rank(), accounts[j].Rank(); r1 != r2 {
			return r1 < r2
		}

		return bytes.Compare(accounts[i].PublicKey.Bytes(), accounts[j].PublicKey.Bytes()) < 0
	})

	accounts = append([]*Account{payer}, accounts...)

	if len(accounts) > MaxAccountKeys {
		return nil, fmt.Errorf("message: %d account keys exceeds the limit of %d", len(accounts), MaxAccountKeys)
	}

	keys := make([]*PublicKey, len(accounts))
	index := make(map[string]uint8, len(accounts))
	var header MessageHeader
	for i, a := range accounts {
		keys[i] = a.PublicKey
		index[a.PublicKey.Base58()] = uint8(i)

		switch a.Rank() {
		case RankWritableSigner:
			header.NumRequiredSignatures++
		case RankReadonlySigner:
			header.NumRequiredSignatures++
			header.NumReadonlySignedAccounts++
		case RankReadonlyNonSigner:
			header.NumReadonlyUnsignedAccounts++
		}
	}

	compiled := make([]*CompiledInstruction, len(instructions))
	for n, ix := range instructions {
		programIDIndex, ok := index[ix.ProgramID.Base58()]
		if !ok {
			return nil, fmt.Errorf("message: instruction[%d] program %s missing from account list", n, ix.ProgramID)
		}

		indexes := make([]uint8, len(ix.Accounts))
		for j, a := range ix.Accounts {
			i, ok := index[a.PublicKey.Base58()]
			if !ok {
				return nil, fmt.Errorf("message: instruction[%d].account[%d] %s missing from account list", n, j, a.PublicKey)
			}
			indexes[j] = i
		}

		compiled[n] = NewCompiledInstruction(programIDIndex, indexes, ix.Data)
	}

	return &Message{
		Header:          header,
		AccountKeys:     keys,
		RecentBlockhash: recentBlockhash,
		Instructions:    compiled,
	}, nil
}

func (m *Message) IsNil() bool {
	if m == nil || m.RecentBlockhash.IsNil() {
		return true
	}

	return false
}

// NumSigners is how many signatures the transaction must carry.
func (m *Message) NumSigners() int {
	return int(m.Header.NumRequiredSignatures)
}

// Signers returns the account keys that must sign, which are the leading
// entries of the list.
func (m *Message) Signers() []*PublicKey {
	return m.AccountKeys[:m.NumSigners()]
}

// IsSigner reports whether the key at i must sign.
func (m *Message) IsSigner(i int) bool {
	return i < int(m.Header.NumRequiredSignatures)
}

// IsWritable reports whether the key at i may be modified.
//
// It is derived from position and the header counts, since the wire format
// stores no per-key flag.
func (m *Message) IsWritable(i int) bool {
	signers := int(m.Header.NumRequiredSignatures)
	if i < signers {
		return i < signers-int(m.Header.NumReadonlySignedAccounts)
	}

	return i < len(m.AccountKeys)-int(m.Header.NumReadonlyUnsignedAccounts)
}

// Serialize writes the bytes that get signed:
//
//	u8         number of required signatures
//	u8         number of read-only signed accounts
//	u8         number of read-only unsigned accounts
//	short-vec  number of account keys
//	[32]byte   account keys
//	[32]byte   recent blockhash
//	short-vec  number of instructions
//	...        compiled instructions
func (m *Message) Serialize() ([]byte, error) {
	out := codec.Binary.AppendU8(nil, m.Header.NumRequiredSignatures)
	out = codec.Binary.AppendU8(out, m.Header.NumReadonlySignedAccounts)
	out = codec.Binary.AppendU8(out, m.Header.NumReadonlyUnsignedAccounts)

	out, err := codec.Binary.AppendShortVecLen(out, len(m.AccountKeys))
	if err != nil {
		return nil, fmt.Errorf("message account keys: %w", err)
	}
	for i, k := range m.AccountKeys {
		if k.IsNil() {
			return nil, fmt.Errorf("message: account key[%d] is nil", i)
		}
		out = codec.Binary.AppendBytes(out, k.Bytes())
	}

	out = codec.Binary.AppendBytes(out, m.RecentBlockhash.Bytes())

	out, err = codec.Binary.AppendShortVecLen(out, len(m.Instructions))
	if err != nil {
		return nil, fmt.Errorf("message instructions: %w", err)
	}
	for i, ix := range m.Instructions {
		raw, err := ix.Serialize()
		if err != nil {
			return nil, fmt.Errorf("message instruction[%d]: %w", i, err)
		}
		out = codec.Binary.AppendBytes(out, raw)
	}

	return out, nil
}

// DeserializeMessage parses a serialized legacy message.
//
// A versioned message is rejected rather than misread. Version 0 sets the high
// bit of the first byte, which cannot occur in a legacy message because a
// signature count of 128 or more would exceed the account limit.
func DeserializeMessage(raw []byte) (*Message, error) {
	if len(raw) > 0 && raw[0]&0x80 != 0 {
		return nil, fmt.Errorf("message: versioned message (v%d) is not supported", raw[0]&0x7f)
	}

	numRequiredSignatures, raw, err := codec.Binary.ReadU8(raw)
	if err != nil {
		return nil, fmt.Errorf("message header: %w", err)
	}
	numReadonlySigned, raw, err := codec.Binary.ReadU8(raw)
	if err != nil {
		return nil, fmt.Errorf("message header: %w", err)
	}
	numReadonlyUnsigned, raw, err := codec.Binary.ReadU8(raw)
	if err != nil {
		return nil, fmt.Errorf("message header: %w", err)
	}

	n, size, err := codec.Binary.ReadShortVecLen(raw)
	if err != nil {
		return nil, fmt.Errorf("message account keys: %w", err)
	}
	raw = raw[size:]

	keys := make([]*PublicKey, n)
	for i := range keys {
		var b []byte
		b, raw, err = codec.Binary.ReadBytes(raw, PublicKeyLength)
		if err != nil {
			return nil, fmt.Errorf("message account key[%d]: %w", i, err)
		}
		if keys[i], err = NewPublicKeyFromBytes(b); err != nil {
			return nil, fmt.Errorf("message account key[%d]: %w", i, err)
		}
	}

	b, raw, err := codec.Binary.ReadBytes(raw, HashLength)
	if err != nil {
		return nil, fmt.Errorf("message recent blockhash: %w", err)
	}
	blockhash, err := NewHashFromBytes(b)
	if err != nil {
		return nil, fmt.Errorf("message recent blockhash: %w", err)
	}

	n, size, err = codec.Binary.ReadShortVecLen(raw)
	if err != nil {
		return nil, fmt.Errorf("message instructions: %w", err)
	}
	raw = raw[size:]

	instructions := make([]*CompiledInstruction, n)
	for i := range instructions {
		if instructions[i], raw, err = DeserializeCompiledInstruction(raw); err != nil {
			return nil, fmt.Errorf("message instruction[%d]: %w", i, err)
		}
	}

	if len(raw) != 0 {
		return nil, fmt.Errorf("message: %d trailing bytes", len(raw))
	}

	return &Message{
		Header: MessageHeader{
			NumRequiredSignatures:       numRequiredSignatures,
			NumReadonlySignedAccounts:   numReadonlySigned,
			NumReadonlyUnsignedAccounts: numReadonlyUnsigned,
		},
		AccountKeys:     keys,
		RecentBlockhash: blockhash,
		Instructions:    instructions,
	}, nil
}

func (m *Message) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "header{sig=%d roSigned=%d roUnsigned=%d} blockhash=%s\n",
		m.Header.NumRequiredSignatures,
		m.Header.NumReadonlySignedAccounts,
		m.Header.NumReadonlyUnsignedAccounts,
		m.RecentBlockhash)

	for i, k := range m.AccountKeys {
		signer, writable := "-", "-"
		if m.IsSigner(i) {
			signer = "s"
		}
		if m.IsWritable(i) {
			writable = "w"
		}
		fmt.Fprintf(&sb, "  [%d] %s[%s%s]\n", i, k, signer, writable)
	}

	for i, ix := range m.Instructions {
		fmt.Fprintf(&sb, "  ix[%d] %s\n", i, ix)
	}

	return sb.String()
}
