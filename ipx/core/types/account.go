package types

import "fmt"

// Account privilege ranks, in the order a message must list its keys.
const (
	RankWritableSigner    = 0 // sw
	RankReadonlySigner    = 1 // s-
	RankWritableNonSigner = 2 // -w
	RankReadonlyNonSigner = 3 // --
)

// Account declares one account an instruction touches, and with what
// privileges.
//
// This is a reference to an account, not the account itself. It carries no
// balance, owner, or data, only the key and what the instruction intends to
// do with it. The on-chain state behind the key is a separate type, named
// AccountInfo after the getAccountInfo method that returns it.
//
// The nearest EVM equivalent is an EIP-2930 access list entry, but the two
// differ in a way that matters. An access list is optional and buys a gas
// discount; omitting it only costs more gas. An account list is mandatory,
// and an account left out makes the transaction fail outright.
//
// The reason is Sealevel, the parallel runtime. Transactions that write to
// disjoint accounts execute concurrently, which requires knowing what each
// one will touch before running it. An EVM chain executes sequentially and
// can discover accessed state as it goes; Solana cannot schedule at all
// without the declaration up front.
//
// IsSigner and IsWritable have no EVM counterpart:
//
//   - EVM has exactly one implicit signer, tx.origin. A Solana transaction
//     may require several, and each is named here rather than recovered from
//     the signature, since ed25519 offers no recovery.
//   - EVM treats all state as writable. An account marked read-only here
//     cannot be modified, and the runtime rejects an instruction that tries.
type Account struct {
	PublicKey  *PublicKey
	IsSigner   bool
	IsWritable bool
}

func NewAccount(k *PublicKey, isSigner, isWritable bool) *Account {
	return &Account{
		PublicKey:  k,
		IsSigner:   isSigner,
		IsWritable: isWritable,
	}
}

type Accounts []*Account

func NewAccounts(accs ...*Account) Accounts {
	return accs
}

// NewWritableSignerAccount describes an account that both authorizes the
// instruction and is modified by it, as the sender of a transfer is.
func NewWritableSignerAccount(k *PublicKey) *Account {
	return NewAccount(k, true, true)
}

// NewReadonlySignerAccount describes an account that authorizes the
// instruction without being modified, as an authority or delegate is.
func NewReadonlySignerAccount(k *PublicKey) *Account {
	return NewAccount(k, true, false)
}

// NewWritableAccount describes an account modified without signing, as
// the recipient of a transfer is.
func NewWritableAccount(k *PublicKey) *Account {
	return NewAccount(k, false, true)
}

// NewReadonlyAccount describes an account only read, as an invoked
// program or a sysvar is.
func NewReadonlyAccount(k *PublicKey) *Account {
	return NewAccount(k, false, false)
}

func (m *Account) IsNil() bool {
	if m == nil || m.PublicKey.IsNil() {
		return true
	}

	return false
}

// Rank returns the account's position class in a compiled message.
//
// A message lists its keys grouped by privilege, most privileged first, and
// the header records how many fall into each group. Sorting by this value is
// what produces that layout.
func (m *Account) Rank() int {
	switch {
	case m.IsSigner && m.IsWritable:
		return RankWritableSigner
	case m.IsSigner:
		return RankReadonlySigner
	case m.IsWritable:
		return RankWritableNonSigner
	default:
		return RankReadonlyNonSigner
	}
}

// Merge raises this account's privileges to include the other's.
//
// One account may appear in several instructions of the same transaction with
// different privileges, but the compiled message lists it once. The union is
// the correct resolution: a key needed as a signer anywhere must sign, and a
// key written anywhere must be writable, or the instruction that needed the
// privilege fails.
//
// Taking the intersection, or simply keeping the first occurrence, would
// produce a message that serializes cleanly and then fails on chain.
func (m *Account) Merge(o *Account) {
	m.IsSigner = m.IsSigner || o.IsSigner
	m.IsWritable = m.IsWritable || o.IsWritable
}

// Equal compares the account key and both privileges.
func (m *Account) Equal(o *Account) bool {
	return m.PublicKey.Equal(o.PublicKey) &&
		m.IsSigner == o.IsSigner &&
		m.IsWritable == o.IsWritable
}

func (m *Account) String() string {
	signer, writable := "-", "-"
	if m.IsSigner {
		signer = "s"
	}
	if m.IsWritable {
		writable = "w"
	}

	return fmt.Sprintf("%s[%s%s]", m.PublicKey, signer, writable)
}
