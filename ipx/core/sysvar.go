package core

import (
	"github.com/andantan/svmlab/core/types"
)

// The sysvar addresses, kept apart from the program ids because a sysvar is
// not a program.
//
// Nothing is invoked at one, and no instruction names one as its program id:
// they are passed as ordinary read-only accounts to instructions that need the
// state they hold. Sealevel is why they have to be passed at all, since an
// instruction can only touch accounts it declared in advance, so even the
// current rent parameters have to be listed like any other account.
//
// The EVM has no equivalent because a contract reads block state through
// opcodes such as BLOCKHASH and TIMESTAMP, with nothing to declare.
//
// The 1 in B1ockHashes is a digit. base58 has no lowercase L, so the
// misspelling decodes to a perfectly valid different address, which is the
// kind of mistake this being a constant rather than a config line prevents.
const (
	RecentBlockhashesSysvarAddress = "SysvarRecentB1ockHashes11111111111111111111"
	RentSysvarAddress              = "SysvarRent111111111111111111111111111111111"

	// InstructionsSysvarAddress holds the currently executing transaction's
	// own instructions, readable mid-execution -- the mechanism a proof
	// instruction placed as a sibling (rather than pre-verified into a
	// context-state account) is found through:
	// extensions/confidential-transfer-account/configure-account's
	// proof_instruction_offset names a relative position, and this
	// account is what the program reads that neighboring instruction's
	// data from.
	InstructionsSysvarAddress = "Sysvar1nstructions1111111111111111111111111"
)

var (
	RecentBlockhashesSysvarID = types.MustPublicKeyFromBase58(RecentBlockhashesSysvarAddress)
	RentSysvarID              = types.MustPublicKeyFromBase58(RentSysvarAddress)
	InstructionsSysvarID      = types.MustPublicKeyFromBase58(InstructionsSysvarAddress)
)

// sysvar is a namespace rather than state, since the addresses it hands back
// are fixed by the runtime and there is nothing to initialize.
type sysvar struct{}

var Sysvar = new(sysvar)

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
// nothing would have been read out of it.
func (_ *sysvar) RecentBlockhashes() *types.PublicKey {
	return RecentBlockhashesSysvarID
}

// Rent is the account holding the current rent parameters.
func (_ *sysvar) Rent() *types.PublicKey {
	return RentSysvarID
}

// Instructions is the account a program reads the currently executing
// transaction's own instructions from -- see InstructionsSysvarAddress.
func (_ *sysvar) Instructions() *types.PublicKey {
	return InstructionsSysvarID
}
