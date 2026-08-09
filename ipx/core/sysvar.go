package core

import (
	"github.com/andantan/svmlab/core/types"
)

// sysvar holds the accounts the runtime keeps cluster state in.
//
// These are not programs. Nothing is invoked at them, and no instruction names
// one as its program id: they are passed as ordinary read-only accounts to
// instructions that need to read the state they hold. Sealevel is the reason
// they have to be passed at all, since an instruction can only touch accounts
// it declared in advance, so even the current rent parameters have to be
// listed like any other account.
//
// The EVM has no equivalent because a contract reads block state through
// opcodes such as BLOCKHASH and TIMESTAMP, with nothing to declare.
type sysvar struct {
	recentBlockhashes *types.PublicKey
	rent              *types.PublicKey
}

var Sysvar = new(sysvar)

// Init records the sysvar addresses, read from config at startup.
func (s *sysvar) Init(recentBlockhashes, rent *types.PublicKey) {
	s.recentBlockhashes = recentBlockhashes
	s.rent = rent
}

// RecentBlockhashes is the account holding the cluster's recent blockhashes.
//
// The address never changes; its contents change every slot. The nonce
// instructions need it because each has to know the current blockhash:
// initialize stores it, advance replaces the stored one with it, and withdraw
// refuses to close an account whose stored nonce is still that value.
//
// The runtime only checks that the account at that position is this exact
// address and then reads the blockhash from the processing context rather than
// from the account data. So a wrong address fails the instruction even though
// nothing would have been read out of it, which matters here because the 1 in
// B1ockHashes is a digit: base58 has no lowercase L, and the misspelling
// decodes to a perfectly valid different address.
func (s *sysvar) RecentBlockhashes() *types.PublicKey {
	return s.recentBlockhashes
}

// Rent is the account holding the current rent parameters.
func (s *sysvar) Rent() *types.PublicKey {
	return s.rent
}
