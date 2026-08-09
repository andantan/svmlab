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
