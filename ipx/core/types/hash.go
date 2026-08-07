package types

import (
	"bytes"
	"fmt"

	"github.com/mr-tron/base58"
)

const (
	HashLength       = 32
	HashBase58Length = 44
)

// Hash is a 32-byte value identifying a block or a cluster genesis.
//
// Its main use is as the recent blockhash a transaction carries, which is
// what stops a transaction from being replayed. That job belongs to an
// account nonce on an EVM chain, and the two behave very differently:
//
//   - A nonce is a counter owned by the sender, so a signed transaction stays
//     valid indefinitely until the nonce is consumed. A blockhash is produced
//     by the cluster and expires roughly 150 slots after it was issued, about
//     a minute, after which the transaction is rejected and must be rebuilt.
//   - A nonce serializes transactions from one sender. A blockhash does not,
//     so several transactions from the same signer may share one blockhash and
//     land in any order.
//
// This is why building, signing, and sending have to happen close together,
// and why a fee payer cannot presign a batch far in advance without moving to
// a durable nonce account.
type Hash struct {
	Hash [HashLength]byte

	bytes  []byte
	base58 string
}

func NewHash(h [HashLength]byte) *Hash {
	return &Hash{
		Hash: h,
	}
}

func NewHashFromBytes(b []byte) (*Hash, error) {
	if len(b) != HashLength {
		return nil, fmt.Errorf("hash must be %d bytes but got: %d", HashLength, len(b))
	}

	return &Hash{
		Hash: [HashLength]byte(b),
	}, nil
}

// NewHashFromBase58 parses a hash in the form the RPC layer returns it, as
// with getLatestBlockhash and getGenesisHash.
func NewHashFromBase58(s string) (*Hash, error) {
	b, err := base58.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base58 hash: %w", err)
	}

	h, err := NewHashFromBytes(b)
	if err != nil {
		return nil, err
	}
	h.base58 = s

	return h, nil
}

func (h *Hash) IsNil() bool {
	if h == nil {
		return true
	}

	return false
}

func (h *Hash) Bytes() []byte {
	if h.bytes == nil {
		h.bytes = h.Hash[:]
	}

	return h.bytes
}

// Base58 returns the hash string. Solana renders hashes in base58 rather
// than the 0x-prefixed hex an EVM chain uses.
func (h *Hash) Base58() string {
	if h.base58 == "" {
		h.base58 = base58.Encode(h.Bytes())
	}

	return h.base58
}

func (h *Hash) String() string {
	return h.Base58()
}

func (h *Hash) Equal(o *Hash) bool {
	return bytes.Equal(h.Bytes(), o.Bytes())
}

// IsZero reports whether every byte is zero, which is how an unset blockhash
// appears in a message that has not been assigned one yet.
func (h *Hash) IsZero() bool {
	return h.Hash == [HashLength]byte{}
}
