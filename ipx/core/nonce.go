package core

import (
	"fmt"

	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
)

// NonceAccountSpace is the size of a durable nonce account.
//
// The layout is fixed, so unlike most program state this is a constant rather
// than something read off a live account:
//
//	version    u32     which Versions variant
//	state      u32     which State variant
//	authority  [32]    who may advance, withdraw, or reassign
//	nonce      [32]    the stored blockhash
//	fee        u64     lamports per signature when it was stored
const NonceAccountSpace uint64 = 80

// Nonce account enum variants, each a bincode variant index rather than a tag
// the data describes itself with.
const (
	NonceVersionLegacy  uint32 = 0
	NonceVersionCurrent uint32 = 1

	NonceStateUninitialized uint32 = 0
	NonceStateInitialized   uint32 = 1
)

// NonceAccount is the state stored in a durable nonce account.
//
// Nonce is the field the whole feature exists for: a transaction may carry it
// in place of a recent blockhash, and then it never expires. That is the
// opposite of what an EVM nonce does. There a nonce is a per-account counter
// whose job is to prevent replay; here expiry is what is being removed, and
// replay is prevented by the stored value advancing.
type NonceAccount struct {
	Version              uint32
	State                uint32
	Authority            *types.PublicKey
	Nonce                *types.Hash
	LamportsPerSignature uint64
}

// Initialized reports whether the account holds a usable nonce.
//
// An account created at the right size but never initialized reads as all
// zeros, which is a legitimate intermediate state rather than corruption: the
// bytes are allocated before anything writes them.
func (n *NonceAccount) Initialized() bool {
	return n.State == NonceStateInitialized
}

// DeserializeNonceAccount parses the 80 bytes a nonce account holds.
//
// Every field is read even when the state is uninitialized, since the account
// is zero-filled to its full size either way and reporting zeros is more
// honest than pretending the fields are absent.
func DeserializeNonceAccount(raw []byte) (*NonceAccount, error) {
	if uint64(len(raw)) != NonceAccountSpace {
		return nil, fmt.Errorf("nonce account: %d bytes but expected %d", len(raw), NonceAccountSpace)
	}

	version, raw, err := codec.Binary.ReadU32(raw)
	if err != nil {
		return nil, fmt.Errorf("nonce account version: %w", err)
	}
	state, raw, err := codec.Binary.ReadU32(raw)
	if err != nil {
		return nil, fmt.Errorf("nonce account state: %w", err)
	}

	b, raw, err := codec.Binary.ReadBytes(raw, types.PublicKeyLength)
	if err != nil {
		return nil, fmt.Errorf("nonce account authority: %w", err)
	}
	authority, err := types.NewPublicKeyFromBytes(b)
	if err != nil {
		return nil, fmt.Errorf("nonce account authority: %w", err)
	}

	if b, raw, err = codec.Binary.ReadBytes(raw, types.HashLength); err != nil {
		return nil, fmt.Errorf("nonce account nonce: %w", err)
	}
	nonce, err := types.NewHashFromBytes(b)
	if err != nil {
		return nil, fmt.Errorf("nonce account nonce: %w", err)
	}

	fee, _, err := codec.Binary.ReadU64(raw)
	if err != nil {
		return nil, fmt.Errorf("nonce account fee calculator: %w", err)
	}

	return &NonceAccount{
		Version:              version,
		State:                state,
		Authority:            authority,
		Nonce:                nonce,
		LamportsPerSignature: fee,
	}, nil
}

// Nonce instruction discriminants, which continue the System Program's list:
// a nonce account is System-owned, so its instructions are System's.
const (
	SystemInstructionAdvanceNonceAccount    uint32 = 4
	SystemInstructionWithdrawNonceAccount   uint32 = 5
	SystemInstructionInitializeNonceAccount uint32 = 6
	SystemInstructionAuthorizeNonceAccount  uint32 = 7
	SystemInstructionUpgradeNonceAccount    uint32 = 12
)

// InitializeNonceAccount turns an existing System-owned account of the right
// size into a durable nonce account, storing the current blockhash as its
// first nonce.
//
// The nonce account is writable but does not sign. It has already been created
// by then, and nothing about initializing it needs its authority: the account
// simply gains the authority named here.
func (s *system) InitializeNonceAccount(nonce, authority *types.PublicKey) (*types.Instruction, error) {
	if s.id.IsNil() {
		return nil, fmt.Errorf("system: not initialized")
	}
	if Sysvar.RecentBlockhashes().IsNil() || Sysvar.Rent().IsNil() {
		return nil, fmt.Errorf("sysvar: not initialized")
	}
	if nonce.IsNil() {
		return nil, fmt.Errorf("nonce initialize: nonce account is required")
	}
	if authority.IsNil() {
		return nil, fmt.Errorf("nonce initialize: authority is required")
	}

	data := codec.Binary.AppendU32(nil, SystemInstructionInitializeNonceAccount)
	data = codec.Binary.AppendBytes(data, authority.Bytes())

	return types.NewInstruction(s.id, types.NewAccounts(
		types.NewWritableAccount(nonce),
		types.NewReadonlyAccount(Sysvar.RecentBlockhashes()),
		types.NewReadonlyAccount(Sysvar.Rent()),
	), data), nil
}

// AdvanceNonceAccount replaces the stored nonce with the current blockhash.
//
// This is what stops a durable nonce from being replayed: a transaction built
// against a nonce is only valid while that value is stored, and advancing it
// is the first instruction such a transaction runs, so it consumes the nonce
// it was built for.
func (s *system) AdvanceNonceAccount(nonce, authority *types.PublicKey) (*types.Instruction, error) {
	if s.id.IsNil() {
		return nil, fmt.Errorf("system: not initialized")
	}
	if Sysvar.RecentBlockhashes().IsNil() {
		return nil, fmt.Errorf("sysvar: not initialized")
	}
	if nonce.IsNil() {
		return nil, fmt.Errorf("nonce advance: nonce account is required")
	}
	if authority.IsNil() {
		return nil, fmt.Errorf("nonce advance: authority is required")
	}

	data := codec.Binary.AppendU32(nil, SystemInstructionAdvanceNonceAccount)

	return types.NewInstruction(s.id, types.NewAccounts(
		types.NewWritableAccount(nonce),
		types.NewReadonlyAccount(Sysvar.RecentBlockhashes()),
		types.NewReadonlySignerAccount(authority),
	), data), nil
}

// WithdrawNonceAccount moves lamports out of a nonce account.
//
// Taking the whole balance closes the account, and the runtime refuses that
// while the stored nonce is still the current blockhash: a transaction built
// against it could otherwise be left with nowhere to advance. Taking less
// requires what remains to stay rent exempt.
//
// The authority signs, except on an account that was sized but never
// initialized, where the account itself is the only thing that can authorize
// the withdrawal.
func (s *system) WithdrawNonceAccount(nonce, authority, to *types.PublicKey, lamports uint64) (*types.Instruction, error) {
	if s.id.IsNil() {
		return nil, fmt.Errorf("system: not initialized")
	}
	if Sysvar.RecentBlockhashes().IsNil() || Sysvar.Rent().IsNil() {
		return nil, fmt.Errorf("sysvar: not initialized")
	}
	if nonce.IsNil() {
		return nil, fmt.Errorf("nonce withdraw: nonce account is required")
	}
	if authority.IsNil() {
		return nil, fmt.Errorf("nonce withdraw: authority is required")
	}
	if to.IsNil() {
		return nil, fmt.Errorf("nonce withdraw: recipient is required")
	}

	data := codec.Binary.AppendU32(nil, SystemInstructionWithdrawNonceAccount)
	data = codec.Binary.AppendU64(data, lamports)

	return types.NewInstruction(s.id, types.NewAccounts(
		types.NewWritableAccount(nonce),
		types.NewWritableAccount(to),
		types.NewReadonlyAccount(Sysvar.RecentBlockhashes()),
		types.NewReadonlyAccount(Sysvar.Rent()),
		types.NewReadonlySignerAccount(authority),
	), data), nil
}

// AuthorizeNonceAccount hands the right to advance and withdraw to another
// key.
//
// Only the current authority can do this, and nothing else about the account
// changes: the stored nonce stays as it was, so transactions already built
// against it remain valid.
func (s *system) AuthorizeNonceAccount(nonce, authority, newAuthority *types.PublicKey) (*types.Instruction, error) {
	if s.id.IsNil() {
		return nil, fmt.Errorf("system: not initialized")
	}
	if nonce.IsNil() {
		return nil, fmt.Errorf("nonce authorize: nonce account is required")
	}
	if authority.IsNil() {
		return nil, fmt.Errorf("nonce authorize: authority is required")
	}
	if newAuthority.IsNil() {
		return nil, fmt.Errorf("nonce authorize: new authority is required")
	}

	data := codec.Binary.AppendU32(nil, SystemInstructionAuthorizeNonceAccount)
	data = codec.Binary.AppendBytes(data, newAuthority.Bytes())

	return types.NewInstruction(s.id, types.NewAccounts(
		types.NewWritableAccount(nonce),
		types.NewReadonlySignerAccount(authority),
	), data), nil
}

// UpgradeNonceAccount migrates a Legacy nonce account to the current version.
//
// Accounts created now are already current, so this exists for ones predating
// the change. Nothing signs: the migration is not a privileged operation, only
// a rewrite of how the same state is stored.
func (s *system) UpgradeNonceAccount(nonce *types.PublicKey) (*types.Instruction, error) {
	if s.id.IsNil() {
		return nil, fmt.Errorf("system: not initialized")
	}
	if nonce.IsNil() {
		return nil, fmt.Errorf("nonce upgrade: nonce account is required")
	}

	data := codec.Binary.AppendU32(nil, SystemInstructionUpgradeNonceAccount)

	return types.NewInstruction(s.id, types.NewAccounts(
		types.NewWritableAccount(nonce),
	), data), nil
}
