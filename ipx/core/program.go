package core

import (
	"github.com/andantan/svmlab/core/types"
)

// The program addresses, which are the same on every Solana cluster and every
// SVM chain.
//
// These were config once, which was a mistake worth naming. A program id here
// is not a deployment address the way an EVM utility contract's is. The
// builtins are dispatched by the runtime on exactly these bytes, so a chain
// that moved the System Program would not be a chain with different settings;
// it would not run Solana programs at all. The SPL programs are ordinary BPF
// programs and could in principle sit elsewhere, but the variation that
// actually exists is Token versus Token-2022 on the same cluster, which is a
// choice per request rather than per chain.
//
// So the only thing configuring them bought was a way to get one wrong. Every
// one of these is valid base58 in every plausible typo, which means a wrong
// address parses, builds, signs, and fails on the cluster with an error about
// the account rather than about the letter that was changed.
//
// They are collected in one block for that reason: these are values checked by
// reading them against the official list, and that is easier done once here
// than in eight places next to the builders that use them.
const (
	// SystemProgramAddress owns every account not yet assigned elsewhere and
	// is what moves lamports, creates accounts, and keeps durable nonces.
	SystemProgramAddress = "11111111111111111111111111111111"

	// ComputeBudgetProgramAddress sets the compute unit limit and price for
	// the transaction carrying it, which is how a priority fee is expressed.
	ComputeBudgetProgramAddress = "ComputeBudget111111111111111111111111111111"

	// TokenProgramAddress is the original SPL Token program.
	TokenProgramAddress = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

	// Token2022ProgramAddress is the extension-capable successor. It is a
	// separate program at a separate address rather than an upgrade, so both
	// are live at once and a mint belongs to exactly one of them.
	Token2022ProgramAddress = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"

	// AssociatedTokenProgramAddress creates the canonical token account for a
	// wallet and mint. The token program is one of the seeds that address is
	// derived from, so Token and Token-2022 give a wallet different associated
	// accounts for otherwise identical mints.
	AssociatedTokenProgramAddress = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"

	// MemoProgramAddress attaches a UTF-8 note to a transaction, which is how
	// an exchange deposit tag travels when there is no calldata to put it in.
	MemoProgramAddress = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"

	// StakeProgramAddress delegates stake to a validator's vote account.
	StakeProgramAddress = "Stake11111111111111111111111111111111111111"

	// VoteProgramAddress holds the account a validator votes through, which is
	// the account stake is delegated to rather than the validator's identity.
	VoteProgramAddress = "Vote111111111111111111111111111111111111111"

	// ZkElgamalProofProgramAddress verifies the zero-knowledge proofs
	// Token-2022's ConfidentialTransfer family depends on -- a
	// PubkeyValidityProof, a range proof, an equality proof -- without
	// itself knowing anything about tokens. Token-2022 only ever names
	// this as an account a proof-carrying instruction points at
	// (proof_instruction_offset, or a context-state account this program
	// wrote), never as the program an instruction is sent to the way
	// System or Token-2022 itself is.
	ZkElgamalProofProgramAddress = "ZkE1Gama1Proof11111111111111111111111111111"
)

// The same addresses decoded once at startup.
//
// Everything in core and above uses these rather than the strings, so the
// base58 decode happens once per process instead of once per instruction, and
// a typo in the block above panics on the first line of main rather than
// surfacing as a rejected transaction.
var (
	SystemProgramID          = types.MustPublicKeyFromBase58(SystemProgramAddress)
	ComputeBudgetProgramID   = types.MustPublicKeyFromBase58(ComputeBudgetProgramAddress)
	TokenProgramID           = types.MustPublicKeyFromBase58(TokenProgramAddress)
	Token2022ProgramID       = types.MustPublicKeyFromBase58(Token2022ProgramAddress)
	AssociatedTokenProgramID = types.MustPublicKeyFromBase58(AssociatedTokenProgramAddress)
	MemoProgramID            = types.MustPublicKeyFromBase58(MemoProgramAddress)
	StakeProgramID           = types.MustPublicKeyFromBase58(StakeProgramAddress)
	VoteProgramID            = types.MustPublicKeyFromBase58(VoteProgramAddress)
	ZkElgamalProofProgramID  = types.MustPublicKeyFromBase58(ZkElgamalProofProgramAddress)
)
