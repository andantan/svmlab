package core

import (
	"fmt"

	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
)

const (
	// ElGamalRegistryInstructionCreateRegistry and the next are the
	// discriminators the registry program accepts, confirmed against its own
	// RegistryInstruction::unpack.
	ElGamalRegistryInstructionCreateRegistry uint8 = iota
	ElGamalRegistryInstructionUpdateRegistry
)

const (
	// ElGamalRegistryAccountLen is owner(32) + elgamal_pubkey(32), confirmed
	// against ELGAMAL_REGISTRY_ACCOUNT_LEN.
	ElGamalRegistryAccountLen = 64

	// ElGamalRegistrySeed is the fixed first seed of a registry's address.
	ElGamalRegistrySeed = "elgamal-registry"
)

// elgamalRegistry is a namespace, the same shape Record is.
type elgamalRegistry struct {
	id *types.PublicKey
}

// ElGamalRegistry builds instructions against the ElGamal registry program
// (regVYJW7tcT8zipN5YiBvHsvR5jXW1uLFxaHSbugABg).
var ElGamalRegistry = &elgamalRegistry{id: ElGamalRegistryProgramID}

// ID returns the registry program's own address.
func (r *elgamalRegistry) ID() *types.PublicKey {
	return r.id
}

// Address derives a wallet's registry account, a PDA of the registry program
// with seeds ["elgamal-registry", wallet]. The program creates it itself, so
// it never has to exist beforehand.
func (r *elgamalRegistry) Address(wallet *types.PublicKey) (*types.PublicKey, uint8, error) {
	if wallet.IsNil() {
		return nil, 0, fmt.Errorf("elgamal registry address: wallet is required")
	}

	return PDA.Find([][]byte{[]byte(ElGamalRegistrySeed), wallet.Bytes()}, r.id)
}

// Create builds CreateRegistry, which creates wallet's registry account and
// records the ElGamal public key a PubkeyValidity proof, verified beforehand
// into pubkeyValidityContext, certifies. The wallet signs.
//
// Confirmed against the registry crate's own create_registry and
// process_create_registry_account: data is [0] + proof offset (i8, 0 = context
// state account); accounts are [registry(writable), wallet(signer, readonly),
// system program(readonly), pubkey-validity context state(readonly)].
func (r *elgamalRegistry) Create(wallet, pubkeyValidityContext *types.PublicKey) (*types.Instruction, error) {
	if pubkeyValidityContext.IsNil() {
		return nil, fmt.Errorf("elgamal registry create: pubkey validity context state account is required")
	}
	registry, _, err := r.Address(wallet)
	if err != nil {
		return nil, fmt.Errorf("elgamal registry create: %w", err)
	}

	data := codec.Binary.AppendU8(nil, ElGamalRegistryInstructionCreateRegistry)
	data = codec.Binary.AppendU8(data, 0) // proof_instruction_offset: 0 = context state account

	return types.NewInstruction(r.id, types.NewAccounts(
		types.NewWritableAccount(registry),
		types.NewReadonlySignerAccount(wallet),
		types.NewReadonlyAccount(SystemProgramID),
		types.NewReadonlyAccount(pubkeyValidityContext),
	), data), nil
}

// Update builds UpdateRegistry, which replaces the ElGamal public key in
// wallet's registry account with the one a PubkeyValidity proof, verified
// beforehand into pubkeyValidityContext, certifies. Token accounts already
// configured keep the key they were configured with.
//
// Accounts are [registry(writable), pubkey-validity context state(readonly),
// owner(signer, readonly)]; data is [1] + proof offset (i8, 0).
func (r *elgamalRegistry) Update(wallet, pubkeyValidityContext *types.PublicKey) (*types.Instruction, error) {
	if pubkeyValidityContext.IsNil() {
		return nil, fmt.Errorf("elgamal registry update: pubkey validity context state account is required")
	}
	registry, _, err := r.Address(wallet)
	if err != nil {
		return nil, fmt.Errorf("elgamal registry update: %w", err)
	}

	data := codec.Binary.AppendU8(nil, ElGamalRegistryInstructionUpdateRegistry)
	data = codec.Binary.AppendU8(data, 0)

	return types.NewInstruction(r.id, types.NewAccounts(
		types.NewWritableAccount(registry),
		types.NewReadonlyAccount(pubkeyValidityContext),
		types.NewReadonlySignerAccount(wallet),
	), data), nil
}
