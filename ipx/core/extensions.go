package core

import (
	"fmt"
	"math/big"

	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
)

// ExtensionType discriminants, as Reallocate's instruction data encodes
// them: a little-endian u16 each, unlike every Token opcode above, which is
// a single byte. This is the full account-layout enum, mint-only variants
// included, since Reallocate's own validation is what rejects naming one
// that does not belong to an account rather than anything checked here.
const (
	ExtensionTypeUninitialized ExtensionType = iota
	ExtensionTypeTransferFeeConfig
	ExtensionTypeTransferFeeAmount
	ExtensionTypeMintCloseAuthority
	ExtensionTypeConfidentialTransferMint
	ExtensionTypeConfidentialTransferAccount
	ExtensionTypeDefaultAccountState
	ExtensionTypeImmutableOwner
	ExtensionTypeMemoTransfer
	ExtensionTypeNonTransferable
	ExtensionTypeInterestBearingConfig
	ExtensionTypeCpiGuard
	ExtensionTypePermanentDelegate
	ExtensionTypeNonTransferableAccount
	ExtensionTypeTransferHook
	ExtensionTypeTransferHookAccount
	ExtensionTypeConfidentialTransferFeeConfig
	ExtensionTypeConfidentialTransferFeeAmount
	ExtensionTypeMetadataPointer
	ExtensionTypeTokenMetadata
	ExtensionTypeGroupPointer
	ExtensionTypeTokenGroup
	ExtensionTypeGroupMemberPointer
	ExtensionTypeTokenGroupMember
	ExtensionTypeConfidentialMintBurn
	ExtensionTypeScaledUiAmount
	ExtensionTypePausable
	ExtensionTypePausableAccount
	ExtensionTypePermissionedBurn
)

// ExtensionType is Token-2022's own u16, not one of this project's u8
// opcodes: it selects a TLV record layout rather than an instruction.
type ExtensionType uint16

// extensionTypeNames maps the name a caller writes to the value Reallocate
// sends on the wire, so a request carries "immutable_owner" rather than a
// bare number nothing documents.
var extensionTypeNames = map[string]ExtensionType{
	"transfer_fee_config":              ExtensionTypeTransferFeeConfig,
	"transfer_fee_amount":              ExtensionTypeTransferFeeAmount,
	"mint_close_authority":             ExtensionTypeMintCloseAuthority,
	"confidential_transfer_mint":       ExtensionTypeConfidentialTransferMint,
	"confidential_transfer_account":    ExtensionTypeConfidentialTransferAccount,
	"default_account_state":            ExtensionTypeDefaultAccountState,
	"immutable_owner":                  ExtensionTypeImmutableOwner,
	"memo_transfer":                    ExtensionTypeMemoTransfer,
	"non_transferable":                 ExtensionTypeNonTransferable,
	"interest_bearing_config":          ExtensionTypeInterestBearingConfig,
	"cpi_guard":                        ExtensionTypeCpiGuard,
	"permanent_delegate":               ExtensionTypePermanentDelegate,
	"non_transferable_account":         ExtensionTypeNonTransferableAccount,
	"transfer_hook":                    ExtensionTypeTransferHook,
	"transfer_hook_account":            ExtensionTypeTransferHookAccount,
	"confidential_transfer_fee_config": ExtensionTypeConfidentialTransferFeeConfig,
	"confidential_transfer_fee_amount": ExtensionTypeConfidentialTransferFeeAmount,
	"metadata_pointer":                 ExtensionTypeMetadataPointer,
	"token_metadata":                   ExtensionTypeTokenMetadata,
	"group_pointer":                    ExtensionTypeGroupPointer,
	"token_group":                      ExtensionTypeTokenGroup,
	"group_member_pointer":             ExtensionTypeGroupMemberPointer,
	"token_group_member":               ExtensionTypeTokenGroupMember,
	"confidential_mint_burn":           ExtensionTypeConfidentialMintBurn,
	"scaled_ui_amount":                 ExtensionTypeScaledUiAmount,
	"pausable":                         ExtensionTypePausable,
	"pausable_account":                 ExtensionTypePausableAccount,
	"permissioned_burn":                ExtensionTypePermissionedBurn,
}

// ParseExtensionType resolves a caller-supplied name to its wire value.
// Uninitialized (0) is deliberately not resolvable here: it is a sentinel
// meaning "no extension" in the account layout, never a real value to
// request room for.
func ParseExtensionType(name string) (ExtensionType, error) {
	et, ok := extensionTypeNames[name]
	if !ok {
		return 0, fmt.Errorf("extension type: %q is not a recognized extension name", name)
	}

	return et, nil
}

// extensionTypeDataLen is the byte size of each extension's own TLV payload
// (the 4-byte type+length header is not counted), confirmed by reading every
// extension's struct definition in solana-program/token-2022's interface
// crate one at a time.
//
// Unlike an existing account's size, which GetAccountDataSize always answers
// by asking the deployed program directly rather than assuming client-side,
// a mint being created has no equivalent on-chain instruction at all:
// GetAccountDataSize only ever answers "how big does an account need to be
// to hold this mint", never "how big does this mint itself need to be" — a
// different question the interface crate does not expose a return-data
// instruction for. Sizing a mint with extensions before create-mint has to
// happen client-side or not at all, which is what this table is for.
//
// ExtensionTypeTokenMetadata is deliberately absent: name, symbol, uri, and
// additional_metadata are all variable-length Borsh strings/lists, so this
// extension has no fixed size to record here at all — it can only ever be
// computed from the actual field values a request carries, which is its own
// endpoint's job, not this table's.
var extensionTypeDataLen = map[ExtensionType]int{
	ExtensionTypeTransferFeeConfig:             108, // mint
	ExtensionTypeTransferFeeAmount:             8,   // account
	ExtensionTypeMintCloseAuthority:            32,  // mint
	ExtensionTypeConfidentialTransferMint:      65,  // mint
	ExtensionTypeConfidentialTransferAccount:   295, // account
	ExtensionTypeDefaultAccountState:           1,   // mint
	ExtensionTypeImmutableOwner:                0,   // account
	ExtensionTypeMemoTransfer:                  1,   // account
	ExtensionTypeNonTransferable:               0,   // mint
	ExtensionTypeInterestBearingConfig:         52,  // mint
	ExtensionTypeCpiGuard:                      1,   // account
	ExtensionTypePermanentDelegate:             32,  // mint
	ExtensionTypeNonTransferableAccount:        0,   // account
	ExtensionTypeTransferHook:                  64,  // mint
	ExtensionTypeTransferHookAccount:           1,   // account
	ExtensionTypeConfidentialTransferFeeConfig: 129, // mint
	ExtensionTypeConfidentialTransferFeeAmount: 64,  // account
	ExtensionTypeMetadataPointer:               64,  // mint
	ExtensionTypeGroupPointer:                  64,  // mint
	ExtensionTypeTokenGroup:                    80,  // mint
	ExtensionTypeGroupMemberPointer:            64,  // mint
	ExtensionTypeTokenGroupMember:              72,  // mint
	ExtensionTypeConfidentialMintBurn:          196, // mint
	ExtensionTypeScaledUiAmount:                56,  // mint
	ExtensionTypePausable:                      33,  // mint
	ExtensionTypePausableAccount:               0,   // account
}

// mintOnlyExtensionTypes is which of the keys in extensionTypeDataLen may
// actually appear on a mint, as opposed to only a token account. This is
// exactly the categorization GetAccountDataSize's own ExtensionTypeMismatch
// check enforces on chain for an account; a mint has no equivalent
// instruction to enforce it for, so CalculateMintExtensionsLen checks it
// here instead.
var mintOnlyExtensionTypes = map[ExtensionType]bool{
	ExtensionTypeTransferFeeConfig:             true,
	ExtensionTypeMintCloseAuthority:            true,
	ExtensionTypeConfidentialTransferMint:      true,
	ExtensionTypeDefaultAccountState:           true,
	ExtensionTypeNonTransferable:               true,
	ExtensionTypeInterestBearingConfig:         true,
	ExtensionTypePermanentDelegate:             true,
	ExtensionTypeTransferHook:                  true,
	ExtensionTypeConfidentialTransferFeeConfig: true,
	ExtensionTypeMetadataPointer:               true,
	ExtensionTypeGroupPointer:                  true,
	ExtensionTypeTokenGroup:                    true,
	ExtensionTypeGroupMemberPointer:            true,
	ExtensionTypeTokenGroupMember:              true,
	ExtensionTypeConfidentialMintBurn:          true,
	ExtensionTypeScaledUiAmount:                true,
	ExtensionTypePausable:                      true,
}

// CalculateMintExtensionsLen returns the total byte size a mint needs to
// hold every named extension, computed client-side from
// extensionTypeDataLen since no on-chain instruction answers this question
// (see the table's own doc comment). The 1-byte AccountType marker is
// included once, and only when the list is non-empty: a mint carrying no
// extension at all stays exactly MintSpace, with no marker byte at all,
// the same way a bare token account stays exactly TokenAccountSpace.
//
// ExtensionTypeTokenMetadata is rejected here, not silently skipped: its
// size cannot be known without the actual name/symbol/uri content, which
// belongs to a dedicated endpoint of its own, not this general-purpose
// calculator.
func CalculateMintExtensionsLen(extensionTypes []ExtensionType) (uint64, error) {
	if len(extensionTypes) == 0 {
		return MintSpace, nil
	}

	total := uint64(0)
	for _, et := range extensionTypes {
		if et == ExtensionTypeTokenMetadata {
			return 0, fmt.Errorf("extension type: token_metadata is variable-length and not supported by this calculator; its size depends on the actual name/symbol/uri content")
		}
		if !mintOnlyExtensionTypes[et] {
			return 0, fmt.Errorf("extension type: %d is a token-account extension, not a mint extension", et)
		}

		total += 4 + uint64(extensionTypeDataLen[et])
	}

	// An extended mint is not left at its own 82-byte layout: it is padded
	// out to a holder account's 165-byte length first, the same length a
	// token account's own extensions start from, and only then does the
	// one-byte AccountType marker and this account's own TLV region begin.
	// This is not a choice a mint's extensions get to skip, and missing it
	// once already cost a live devnet attempt an InvalidAccountData: the
	// account came back exactly 83 bytes short (165 - 82) of what the
	// program actually required.
	return TokenAccountSpace + 1 + total, nil
}

// Reallocate checks whether account is already large enough to hold every
// named extension type, and grows it if not.
//
// This is the general tool for adding an extension to a token account
// after it was created without one — a mint cannot use it at all, since a
// mint's extension list is fixed forever at InitializeMint2 and there is no
// instruction that reopens it. extensionTypes carries no length prefix on
// the wire: it is encoded as however many u16 values fit the rest of the
// instruction data, so passing zero of them is valid syntax that simply
// asks the program to confirm the account is already big enough for
// nothing new.
//
// rentPayer funds whatever the resize costs and is a distinct role from
// owner, the same separation every other rent-payer/authority pair in this
// API keeps: owner authorizes the account being touched, rentPayer covers
// what that costs, and they need not be the same key.
func (t *token) Reallocate(account, rentPayer, owner *types.PublicKey, signers []*types.PublicKey, extensionTypes []ExtensionType) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("token reallocate: account is required")
	}
	if rentPayer.IsNil() {
		return nil, fmt.Errorf("token reallocate: rent payer is required")
	}
	if err := validateAuthority("token reallocate", owner, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionReallocate)
	for _, et := range extensionTypes {
		data = codec.Binary.AppendU16(data, uint16(et))
	}

	accounts := types.NewAccounts(
		types.NewWritableAccount(account),
		types.NewWritableSignerAccount(rentPayer),
		types.NewReadonlyAccount(SystemProgramID),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, owner, signers), data), nil
}

// InitializeMintCloseAuthority attaches the MintCloseAuthority extension to
// mint, naming who may later close it via CloseAccount -- without this
// extension a mint can never be closed at all, since the base layout has no
// close-authority field of its own the way a token account does.
//
// This is a standalone top-level opcode (22), not a sub-instruction under a
// family the way TransferFeeExtension's members are, and it carries no
// second discriminant byte. closeAuthority is COption<Pubkey> on the wire --
// a single tag byte, the key itself following only when present, the same
// appendPubkeyOption encoding InitializeTransferFeeConfig's authorities use
// -- confirmed against the interface crate's pack_pubkey_option rather than
// assumed from the type name.
//
// closeAuthority may be left nil to skip the extension. Unlike leaving
// transferFeeConfigAuthority empty above, upstream also exposes
// AuthorityType::CloseMint through the plain SetAuthority instruction, so a
// close authority can still be granted or replaced later even if none was
// set here -- not yet built.
//
// Like every mint extension, this can only run after create-mint has
// allocated the account and before initialize-mint2 commits it; there is no
// path back into an already-initialized mint.
func (t *token) InitializeMintCloseAuthority(mint, closeAuthority *types.PublicKey) (*types.Instruction, error) {
	if mint.IsNil() {
		return nil, fmt.Errorf("token initialize mint close authority: mint is required")
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionInitializeMintCloseAuthority)
	data = appendPubkeyOption(data, closeAuthority)

	return types.NewInstruction(t.id, types.NewAccounts(
		types.NewWritableAccount(mint),
	), data), nil
}

// Token-2022 extension sub-instructions.
//
// Every extension-family top-level opcode above (26–46, excluding the
// standalone ones already built — InitializeMintCloseAuthority,
// InitializeNonTransferableMint, InitializePermanentDelegate,
// WithdrawExcessLamports, UnwrapLamports, Reallocate) carries a second byte
// selecting one of these, the same two-level shape TransferFeeExtension
// itself uses: TokenInstructionTransferFeeExtension (26) picks the family,
// TransferFeeInstructionSetTransferFee (5) picks the operation inside it.
// None of these are built yet; declared for reference the same way the
// opcodes above were, confirmed against solana-program/token-2022's
// interface crate one family at a time rather than guessed.
const (
	// TransferFeeInstructionInitializeTransferFeeConfig and the rest of
	// this block are sub-instructions under
	// TokenInstructionTransferFeeExtension (26).
	TransferFeeInstructionInitializeTransferFeeConfig uint8 = iota
	TransferFeeInstructionTransferCheckedWithFee
	TransferFeeInstructionWithdrawWithheldTokensFromMint
	TransferFeeInstructionWithdrawWithheldTokensFromAccounts
	TransferFeeInstructionHarvestWithheldTokensToMint
	TransferFeeInstructionSetTransferFee
)

const (
	// ConfidentialTransferInstructionInitializeMint and the rest of this
	// block are sub-instructions under
	// TokenInstructionConfidentialTransferExtension (27).
	ConfidentialTransferInstructionInitializeMint uint8 = iota
	ConfidentialTransferInstructionUpdateMint
	ConfidentialTransferInstructionConfigureAccount
	ConfidentialTransferInstructionApproveAccount
	ConfidentialTransferInstructionEmptyAccount
	ConfidentialTransferInstructionDeposit
	ConfidentialTransferInstructionWithdraw
	ConfidentialTransferInstructionTransfer
	ConfidentialTransferInstructionApplyPendingBalance
	ConfidentialTransferInstructionEnableConfidentialCredits
	ConfidentialTransferInstructionDisableConfidentialCredits
	ConfidentialTransferInstructionEnableNonConfidentialCredits
	ConfidentialTransferInstructionDisableNonConfidentialCredits
	ConfidentialTransferInstructionTransferWithFee
	ConfidentialTransferInstructionConfigureAccountWithRegistry
)

const (
	// DefaultAccountStateInstructionInitialize and Update are
	// sub-instructions under TokenInstructionDefaultAccountStateExtension
	// (28).
	DefaultAccountStateInstructionInitialize uint8 = iota
	DefaultAccountStateInstructionUpdate
)

const (
	// MemoTransferInstructionEnable and Disable are sub-instructions under
	// TokenInstructionMemoTransferExtension (30). The upstream enum is
	// itself named RequiredMemoTransfersInstruction, not
	// MemoTransferInstruction, despite the opcode's own name.
	MemoTransferInstructionEnable uint8 = iota
	MemoTransferInstructionDisable
)

const (
	// InterestBearingMintInstructionInitialize and UpdateRate are
	// sub-instructions under TokenInstructionInterestBearingMintExtension
	// (33).
	InterestBearingMintInstructionInitialize uint8 = iota
	InterestBearingMintInstructionUpdateRate
)

const (
	// CpiGuardInstructionEnable and Disable are sub-instructions under
	// TokenInstructionCpiGuardExtension (34).
	CpiGuardInstructionEnable uint8 = iota
	CpiGuardInstructionDisable
)

const (
	// TransferHookInstructionInitialize and Update are sub-instructions
	// under TokenInstructionTransferHookExtension (36).
	TransferHookInstructionInitialize uint8 = iota
	TransferHookInstructionUpdate
)

const (
	// ConfidentialTransferFeeInstructionInitializeConfidentialTransferFeeConfig
	// and the rest of this block are sub-instructions under
	// TokenInstructionConfidentialTransferFeeExtension (37).
	ConfidentialTransferFeeInstructionInitializeConfidentialTransferFeeConfig uint8 = iota
	ConfidentialTransferFeeInstructionWithdrawWithheldTokensFromMint
	ConfidentialTransferFeeInstructionWithdrawWithheldTokensFromAccounts
	ConfidentialTransferFeeInstructionHarvestWithheldTokensToMint
	ConfidentialTransferFeeInstructionEnableHarvestToMint
	ConfidentialTransferFeeInstructionDisableHarvestToMint
)

const (
	// MetadataPointerInstructionInitialize and Update are sub-instructions
	// under TokenInstructionMetadataPointerExtension (39). This is
	// Token-2022's own metadata-pointer config, distinct from the
	// spl-token-metadata-interface instructions (Initialize, UpdateField,
	// RemoveKey, UpdateAuthority, Emit) that the pointer's target account
	// implements separately, with its own 8-byte SHA256-derived
	// discriminators rather than this simple sequential-byte scheme.
	MetadataPointerInstructionInitialize uint8 = iota
	MetadataPointerInstructionUpdate
)

const (
	// GroupPointerInstructionInitialize and Update are sub-instructions
	// under TokenInstructionGroupPointerExtension (40).
	GroupPointerInstructionInitialize uint8 = iota
	GroupPointerInstructionUpdate
)

const (
	// GroupMemberPointerInstructionInitialize and Update are
	// sub-instructions under TokenInstructionGroupMemberPointerExtension
	// (41).
	GroupMemberPointerInstructionInitialize uint8 = iota
	GroupMemberPointerInstructionUpdate
)

// TokenGroup (21) and TokenGroupMember (23) are not sub-instructions of any
// TokenInstruction opcode at all, unlike everything else in this block:
// GroupPointer/GroupMemberPointer only ever point at an account holding
// them, and that account's own instructions come from a separate program
// interface, spl-token-group-interface, with its own discriminator scheme
// -- not yet researched or declared here.

const (
	// ConfidentialMintBurnInstructionInitializeMint and the rest of this
	// block are sub-instructions under
	// TokenInstructionConfidentialMintBurnExtension (42).
	ConfidentialMintBurnInstructionInitializeMint uint8 = iota
	ConfidentialMintBurnInstructionRotateSupplyElGamalPubkey
	ConfidentialMintBurnInstructionUpdateDecryptableSupply
	ConfidentialMintBurnInstructionMint
	ConfidentialMintBurnInstructionBurn
	ConfidentialMintBurnInstructionApplyPendingBurn
)

const (
	// ScaledUiAmountMintInstructionInitialize and UpdateMultiplier are
	// sub-instructions under TokenInstructionScaledUiAmountExtension (43).
	// The upstream enum is named ScaledUiAmountMintInstruction.
	ScaledUiAmountMintInstructionInitialize uint8 = iota
	ScaledUiAmountMintInstructionUpdateMultiplier
)

const (
	// PausableInstructionInitialize / Pause, and Resume are sub-instructions
	// under TokenInstructionPausableExtension (44).
	PausableInstructionInitialize uint8 = iota
	PausableInstructionPause
	PausableInstructionResume
)

const (
	// PermissionedBurnInstructionInitialize and the rest of this block are
	// sub-instructions under TokenInstructionPermissionedBurnExtension
	// (46).
	PermissionedBurnInstructionInitialize uint8 = iota
	PermissionedBurnInstructionBurn
	PermissionedBurnInstructionBurnChecked
	PermissionedBurnInstructionConfidentialBurn
)

// ExistingExtensionTypes walks the TLV region of an extended mint or token
// account and returns which extension types are already present.
//
// A mint gets padded out to a holder account's length before its own TLV
// region starts, so both layouts put that region at the identical offset —
// TokenAccountTypeOffset plus the one-byte type tag — and one walk serves
// both. Each record is a 4-byte header, a 2-byte ExtensionType followed by
// a 2-byte length, then that many bytes of the extension's own data; a type
// of Uninitialized (0) marks the first unused slot and ends the walk, the
// same way the deployed program itself stops, since nothing is ever written
// after that point. Reallocate needs this list to ask GetAccountDataSize
// for what the account should become — its own current size plus whatever
// new extension is being added — rather than only the size a bare account
// with just the new extension would need.
func ExistingExtensionTypes(data []byte) []ExtensionType {
	if uint64(len(data)) <= TokenAccountTypeOffset {
		return nil
	}

	var exts []ExtensionType
	rest := data[TokenAccountTypeOffset+1:]
	for len(rest) >= 4 {
		rawType, tail, err := codec.Binary.ReadU16(rest)
		if err != nil {
			break
		}
		et := ExtensionType(rawType)
		if et == ExtensionTypeUninitialized {
			break
		}

		length, tail, err := codec.Binary.ReadU16(tail)
		if err != nil {
			break
		}
		if uint64(len(tail)) < uint64(length) {
			break
		}

		exts = append(exts, et)
		rest = tail[length:]
	}

	return exts
}

// FindExtensionData walks the same TLV region ExistingExtensionTypes does
// and returns the raw payload bytes of the first record matching want, or
// nil if data carries no extensions at all or none of that type. The
// header itself (the 2-byte type and 2-byte length) is not included in
// what is returned, only the length bytes that follow it.
func FindExtensionData(data []byte, want ExtensionType) []byte {
	if uint64(len(data)) <= TokenAccountTypeOffset {
		return nil
	}

	rest := data[TokenAccountTypeOffset+1:]
	for len(rest) >= 4 {
		rawType, tail, err := codec.Binary.ReadU16(rest)
		if err != nil {
			break
		}
		et := ExtensionType(rawType)
		if et == ExtensionTypeUninitialized {
			break
		}

		length, tail, err := codec.Binary.ReadU16(tail)
		if err != nil {
			break
		}
		if uint64(len(tail)) < uint64(length) {
			break
		}

		if et == want {
			return tail[:length]
		}
		rest = tail[length:]
	}

	return nil
}

// TransferFee is one of the two rates a TransferFeeConfig extension keeps
// side by side -- Epoch is when this one takes effect, not when it was set.
type TransferFee struct {
	Epoch                  uint64
	MaximumFee             uint64
	TransferFeeBasisPoints uint16
}

// TransferFeeConfig is the TransferFeeConfig extension's own decoded state,
// read back from a mint's TLV data rather than assumed. The two authority
// fields are stored as a plain 32-byte key with an all-zero sentinel for
// absent, MaybeNull<Address>'s own account-storage form -- not the 1-byte
// tag InitializeTransferFeeConfig's instruction data uses to set them, and
// not the 4-byte-tag COption an older account layout (a mint's own
// mint/freeze authority) uses either. Three different encodings for
// "optional public key" exist across this API depending on exactly where
// the bytes live, and this is the account-storage one.
type TransferFeeConfig struct {
	TransferFeeConfigAuthority *types.PublicKey
	WithdrawWithheldAuthority  *types.PublicKey
	WithheldAmount             uint64
	OlderTransferFee           TransferFee
	NewerTransferFee           TransferFee
}

// EffectiveTransferFee picks whichever of OlderTransferFee/NewerTransferFee
// actually applies at epoch, the same comparison the deployed program's own
// get_epoch_fee makes: NewerTransferFee governs once epoch has reached the
// one it is stamped with, and OlderTransferFee governs everything before
// that. There is no third case — a rate set by SetTransferFee always lands
// as NewerTransferFee with epoch+1 as its own epoch, never sooner.
func (c *TransferFeeConfig) EffectiveTransferFee(epoch uint64) TransferFee {
	if epoch >= c.NewerTransferFee.Epoch {
		return c.NewerTransferFee
	}

	return c.OlderTransferFee
}

// CalculateFee reproduces calculate_epoch_fee exactly: the fee
// TransferCheckedWithFee must be sent with is not a range this checks
// against, it is a value the deployed program recomputes itself and
// requires byte-for-byte, failing the whole transfer as FeeMismatch over a
// single lamport of difference. Getting this formula right client-side is
// what lets a caller send a transfer that lands on the first try instead of
// guessing.
func (c *TransferFeeConfig) CalculateFee(epoch, amount uint64) uint64 {
	rate := c.EffectiveTransferFee(epoch)
	if rate.TransferFeeBasisPoints == 0 {
		return 0
	}

	// (amount * basisPoints), rounded up when dividing by 10,000 — ceiling
	// division on integers too large for u64 to multiply directly, which is
	// exactly why the upstream calculation itself widens to u128 first.
	numerator := uint64(rate.TransferFeeBasisPoints)
	product := new(big.Int).Mul(big.NewInt(int64(amount)), big.NewInt(int64(numerator)))
	divisor := big.NewInt(10_000)
	quotient, remainder := new(big.Int).QuoRem(product, divisor, new(big.Int))
	if remainder.Sign() != 0 {
		quotient.Add(quotient, big.NewInt(1))
	}

	fee := quotient.Uint64()
	if fee > rate.MaximumFee {
		return rate.MaximumFee
	}

	return fee
}

// DecodeTransferFeeConfig parses the TransferFeeConfig extension out of a
// mint's raw account data, or reports that the mint does not carry it at
// all -- the same distinction FindExtensionData's nil return already
// makes, surfaced here as an error instead of a silent zero value, since a
// mint with no TransferFeeConfig has no fee to compute and calling this at
// all was the caller's own mistake.
func DecodeTransferFeeConfig(mintData []byte) (*TransferFeeConfig, error) {
	raw := FindExtensionData(mintData, ExtensionTypeTransferFeeConfig)
	if raw == nil {
		return nil, fmt.Errorf("transfer fee config: mint does not carry the TransferFeeConfig extension")
	}
	if len(raw) != 108 {
		return nil, fmt.Errorf("transfer fee config: %d bytes, expected 108", len(raw))
	}

	readMaybeNullAddress := func(b []byte) *types.PublicKey {
		for _, v := range b {
			if v != 0 {
				key, _ := types.NewPublicKeyFromBytes(b)
				return key
			}
		}
		return nil
	}
	readTransferFee := func(b []byte) TransferFee {
		epoch, rest, _ := codec.Binary.ReadU64(b)
		maximumFee, rest, _ := codec.Binary.ReadU64(rest)
		basisPoints, _, _ := codec.Binary.ReadU16(rest)
		return TransferFee{Epoch: epoch, MaximumFee: maximumFee, TransferFeeBasisPoints: basisPoints}
	}

	transferFeeConfigAuthority := readMaybeNullAddress(raw[0:32])
	withdrawWithheldAuthority := readMaybeNullAddress(raw[32:64])
	withheldAmount, _, err := codec.Binary.ReadU64(raw[64:72])
	if err != nil {
		return nil, fmt.Errorf("transfer fee config: withheld_amount: %w", err)
	}

	return &TransferFeeConfig{
		TransferFeeConfigAuthority: transferFeeConfigAuthority,
		WithdrawWithheldAuthority:  withdrawWithheldAuthority,
		WithheldAmount:             withheldAmount,
		OlderTransferFee:           readTransferFee(raw[72:90]),
		NewerTransferFee:           readTransferFee(raw[90:108]),
	}, nil
}

// DecodeMintCloseAuthority reads the MintCloseAuthority extension's
// close_authority off mint. Like TransferFeeConfig's two authority fields,
// this is MaybeNull<Address> on the wire: a plain 32-byte field, all-zero
// meaning None, not a separate length-tagged COption -- confirmed against
// the interface crate's struct definition rather than assumed from
// TransferFeeConfig's pattern.
//
// A nil return with a nil error means the extension is present but
// close_authority was never set (or was cleared) -- the mint can never be
// closed until set-authority/close-mint/replace names one.
func DecodeMintCloseAuthority(mintData []byte) (*types.PublicKey, error) {
	raw := FindExtensionData(mintData, ExtensionTypeMintCloseAuthority)
	if raw == nil {
		return nil, fmt.Errorf("mint close authority: mint does not carry the MintCloseAuthority extension")
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("mint close authority: %d bytes, expected 32", len(raw))
	}

	for _, v := range raw {
		if v != 0 {
			return types.NewPublicKeyFromBytes(raw)
		}
	}

	return nil, nil
}

// GetAccountDataSize asks the program for the exact byte size an account
// would need to hold mint plus every named extension type — the same
// authority Reallocate itself defers to, asked directly rather than
// recomputed client-side.
//
// This is a return-data instruction, not a state change: nothing about
// mint or any other account is written. It exists to be simulated, never
// sent. extensionTypes carries no length prefix on the wire, the same as
// Reallocate's own list: it is encoded as however many u16 values fit the
// rest of the instruction data, so passing zero of them asks for the bare
// size a Token-2022 account with no extensions needs.
//
// Reimplementing this program's own size table client-side was tried and
// set aside: every extension's TLV payload size can be read once from its
// struct definition, but a hardcoded copy of that table drifts the moment
// the deployed program adds a field or changes a layout, the same reason a
// rent-exemption minimum is always asked of the cluster rather than
// assumed. Asking here instead means Reallocate's own rent math never goes
// stale.
func (t *token) GetAccountDataSize(mint *types.PublicKey, extensionTypes []ExtensionType) (*types.Instruction, error) {
	if mint.IsNil() {
		return nil, fmt.Errorf("token get account data size: mint is required")
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionGetAccountDataSize)
	for _, et := range extensionTypes {
		data = codec.Binary.AppendU16(data, uint16(et))
	}

	return types.NewInstruction(t.id, types.NewAccounts(
		types.NewReadonlyAccount(mint),
	), data), nil
}

// InitializeTransferFeeConfig attaches the TransferFeeConfig extension to
// mint, fixing the fee rate every TransferCheckedWithFee withholds and who
// may later change it or withdraw what accumulates.
//
// This can only ever run in the narrow window every mint extension shares:
// after create-mint has allocated the account (sized to include this
// extension) and before initialize-mint2 locks the extension list forever.
// There is no path back into an already-initialized mint — no Reallocate
// equivalent exists for mints at all, only for token accounts.
//
// transferFeeConfigAuthority and withdrawWithheldAuthority are independent
// roles: the first may call SetTransferFee later, the second may withdraw
// what WithdrawWithheldTokensFromMint/FromAccounts moves. Either may be nil
// to permanently forgo that capability, which InitializeMint2's own mint
// and freeze authorities cannot do without a mint close authority. Despite
// the COption name upstream gives both, this is instruction data, not
// account data: each is a single tag byte, the key itself following only
// when present, confirmed against the interface crate's own pack_pubkey_option
// rather than assumed from the account-layout COption the rules above warn
// about — that one pads a four-byte tag whether or not the key is present,
// which would shift and truncate a real key here.
func (t *token) InitializeTransferFeeConfig(mint, transferFeeConfigAuthority, withdrawWithheldAuthority *types.PublicKey, transferFeeBasisPoints uint16, maximumFee uint64) (*types.Instruction, error) {
	if mint.IsNil() {
		return nil, fmt.Errorf("token initialize transfer fee config: mint is required")
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionTransferFeeExtension)
	data = codec.Binary.AppendU8(data, TransferFeeInstructionInitializeTransferFeeConfig)
	data = appendPubkeyOption(data, transferFeeConfigAuthority)
	data = appendPubkeyOption(data, withdrawWithheldAuthority)
	data = codec.Binary.AppendU16(data, transferFeeBasisPoints)
	data = codec.Binary.AppendU64(data, maximumFee)

	return types.NewInstruction(t.id, types.NewAccounts(
		types.NewWritableAccount(mint),
	), data), nil
}

// SetTransferFee changes the rate InitializeTransferFeeConfig fixed,
// authorized by transferFeeConfigAuthority rather than mint's own mint or
// freeze authority — a fee-rate change is not a supply or freeze decision.
//
// The new rate is not immediate. The program keeps an older and a newer
// rate side by side, each stamped with the epoch it takes effect at: what
// this call sets becomes the newer rate, effective at the start of the
// next epoch, while whatever was already active keeps applying until then.
// That delay is enforced on chain, not something this builder or its
// caller can skip — nobody can be charged a rate they were not already
// able to see coming.
func (t *token) SetTransferFee(mint, transferFeeConfigAuthority *types.PublicKey, signers []*types.PublicKey, transferFeeBasisPoints uint16, maximumFee uint64) (*types.Instruction, error) {
	if mint.IsNil() {
		return nil, fmt.Errorf("token set transfer fee: mint is required")
	}
	if err := validateAuthority("token set transfer fee", transferFeeConfigAuthority, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionTransferFeeExtension)
	data = codec.Binary.AppendU8(data, TransferFeeInstructionSetTransferFee)
	data = codec.Binary.AppendU16(data, transferFeeBasisPoints)
	data = codec.Binary.AppendU64(data, maximumFee)

	accounts := types.NewAccounts(
		types.NewWritableAccount(mint),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, transferFeeConfigAuthority, signers), data), nil
}

// TransferCheckedWithFee is TransferChecked plus a fee: source's owner or
// delegate signs the same way, decimals is verified against mint's own the
// same way, and the only difference is fee, which the program withholds
// into destination's TransferFeeAmount extension rather than crediting the
// full amount across. fee is not computed here or on chain from mint's own
// TransferFeeConfig rate — the caller states it, and the program's own
// check is that it does not exceed what that rate and cap would allow, not
// that it matches exactly.
//
// The account order matches TransferChecked's own: source, mint, then
// destination, with authority (and any multisig signers) appended last.
func (t *token) TransferCheckedWithFee(source, mint, destination, authority *types.PublicKey, signers []*types.PublicKey, amount uint64, decimals uint8, fee uint64) (*types.Instruction, error) {
	if source.IsNil() {
		return nil, fmt.Errorf("token transfer checked with fee: source is required")
	}
	if mint.IsNil() {
		return nil, fmt.Errorf("token transfer checked with fee: mint is required")
	}
	if destination.IsNil() {
		return nil, fmt.Errorf("token transfer checked with fee: destination is required")
	}
	if source.Equal(destination) {
		return nil, fmt.Errorf("token transfer checked with fee: source and destination are the same account")
	}
	if err := validateAuthority("token transfer checked with fee", authority, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionTransferFeeExtension)
	data = codec.Binary.AppendU8(data, TransferFeeInstructionTransferCheckedWithFee)
	data = codec.Binary.AppendU64(data, amount)
	data = codec.Binary.AppendU8(data, decimals)
	data = codec.Binary.AppendU64(data, fee)

	accounts := types.NewAccounts(
		types.NewWritableAccount(source),
		types.NewReadonlyAccount(mint),
		types.NewWritableAccount(destination),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}

// HarvestWithheldTokensToMint sweeps whatever each of sources has withheld
// in its own TransferFeeAmount extension into mint's TransferFeeConfig
// withheld_amount, in one instruction covering however many sources are
// named.
//
// This is permissionless: no authority signs, since moving a balance
// between two places it can already only ever sit -- an account's own
// withheld fees, or the mint's -- needs nobody's permission, only the mint
// they all agree on. It is also the only step in the withheld-fee
// lifecycle that works this way; getting a balance out of the mint (or
// straight out of the accounts, bypassing the mint) is
// WithdrawWithheldTokensFromMint/FromAccounts's job instead, and those do
// require withdraw_withheld_authority's signature.
func (t *token) HarvestWithheldTokensToMint(mint *types.PublicKey, sources []*types.PublicKey) (*types.Instruction, error) {
	if mint.IsNil() {
		return nil, fmt.Errorf("token harvest withheld tokens to mint: mint is required")
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("token harvest withheld tokens to mint: at least one source is required")
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionTransferFeeExtension)
	data = codec.Binary.AppendU8(data, TransferFeeInstructionHarvestWithheldTokensToMint)

	accounts := types.NewAccounts(types.NewWritableAccount(mint))
	for i, source := range sources {
		if source.IsNil() {
			return nil, fmt.Errorf("token harvest withheld tokens to mint: sources[%d] is required", i)
		}
		accounts = append(accounts, types.NewWritableAccount(source))
	}

	return types.NewInstruction(t.id, accounts, data), nil
}

// WithdrawWithheldTokensFromMint moves mint's own TransferFeeConfig
// withheld_amount out to destination as real tokens, authorized by
// withdraw_withheld_authority rather than mint's own mint or freeze
// authority.
//
// This is the counterpart HarvestWithheldTokensToMint's permissionless
// sweep feeds: harvesting only ever moves a balance into the mint, never
// out of it, so getting it out from there to somewhere spendable is this
// instruction's job alone, and it is the one step in the whole withheld-fee
// lifecycle that actually requires a signature.
func (t *token) WithdrawWithheldTokensFromMint(mint, destination, withdrawWithheldAuthority *types.PublicKey, signers []*types.PublicKey) (*types.Instruction, error) {
	if mint.IsNil() {
		return nil, fmt.Errorf("token withdraw withheld tokens from mint: mint is required")
	}
	if destination.IsNil() {
		return nil, fmt.Errorf("token withdraw withheld tokens from mint: destination is required")
	}
	if err := validateAuthority("token withdraw withheld tokens from mint", withdrawWithheldAuthority, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionTransferFeeExtension)
	data = codec.Binary.AppendU8(data, TransferFeeInstructionWithdrawWithheldTokensFromMint)

	accounts := types.NewAccounts(
		types.NewWritableAccount(mint),
		types.NewWritableAccount(destination),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, withdrawWithheldAuthority, signers), data), nil
}

// WithdrawWithheldTokensFromAccounts moves whatever each of sources has
// withheld in its own TransferFeeAmount extension straight to destination,
// bypassing the mint's own TransferFeeConfig withheld_amount entirely --
// the shortcut HarvestWithheldTokensToMint does not take, since harvesting
// only ever moves a balance into the mint, never out to somewhere
// spendable.
//
// mint itself is read-only here: it is named only so the program can
// confirm every source actually belongs to it, never written to. Unlike
// HarvestWithheldTokensToMint this does require withdraw_withheld_authority
// to sign, the same authority WithdrawWithheldTokensFromMint answers to,
// since real tokens are leaving the accounts entirely rather than settling
// into a shared pool anyone could later account for.
//
// The account order is fixed by the program, authority (and any multisig
// signers) before the source list, not after: mint, destination, authority
// block, then every source in the order given.
func (t *token) WithdrawWithheldTokensFromAccounts(mint, destination, withdrawWithheldAuthority *types.PublicKey, signers []*types.PublicKey, sources []*types.PublicKey) (*types.Instruction, error) {
	if mint.IsNil() {
		return nil, fmt.Errorf("token withdraw withheld tokens from accounts: mint is required")
	}
	if destination.IsNil() {
		return nil, fmt.Errorf("token withdraw withheld tokens from accounts: destination is required")
	}
	if err := validateAuthority("token withdraw withheld tokens from accounts", withdrawWithheldAuthority, signers); err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("token withdraw withheld tokens from accounts: at least one source is required")
	}
	if len(sources) > 255 {
		return nil, fmt.Errorf("token withdraw withheld tokens from accounts: %d sources exceeds the 255 a single u8 count can carry", len(sources))
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionTransferFeeExtension)
	data = codec.Binary.AppendU8(data, TransferFeeInstructionWithdrawWithheldTokensFromAccounts)
	data = codec.Binary.AppendU8(data, uint8(len(sources)))

	accounts := types.NewAccounts(
		types.NewReadonlyAccount(mint),
		types.NewWritableAccount(destination),
	)
	accounts = appendAuthority(accounts, withdrawWithheldAuthority, signers)
	for i, source := range sources {
		if source.IsNil() {
			return nil, fmt.Errorf("token withdraw withheld tokens from accounts: sources[%d] is required", i)
		}
		accounts = append(accounts, types.NewWritableAccount(source))
	}

	return types.NewInstruction(t.id, accounts, data), nil
}

// appendMaybeNullAddress writes a fixed 32-byte field, all-zero for nil --
// MaybeNull<Address>'s wire encoding, confirmed against the nullable
// crate's own doc comment: the zero address is the sentinel for None, not
// a separate length-tagged option. Unlike appendPubkeyOption's 1-byte-tag
// COption encoding (InitializeTransferFeeConfig's authorities), this field
// is always exactly 32 bytes long whether or not a key is present -- using
// the wrong one shifts and truncates every field after it.
func appendMaybeNullAddress(dst []byte, k *types.PublicKey) []byte {
	if k.IsNil() {
		return append(dst, make([]byte, types.PublicKeyLength)...)
	}

	return codec.Binary.AppendBytes(dst, k.Bytes())
}

// appendMaybeNull32 is appendMaybeNullAddress's non-Address counterpart,
// for a fixed 32-byte MaybeNull<T> field that is not itself a Solana
// address -- ElGamal public keys carried by the ConfidentialTransfer
// family, which are 32-byte curve points sharing the same on-wire length
// as an address but not its type.
func appendMaybeNull32(dst []byte, v []byte) []byte {
	if len(v) == 0 {
		return append(dst, make([]byte, 32)...)
	}

	return codec.Binary.AppendBytes(dst, v)
}

// InitializeConfidentialTransferMint attaches the ConfidentialTransferMint
// extension to mint, naming who may later reconfigure it and approve new
// confidential accounts (authority), whether new accounts need that
// approval before use (autoApproveNewAccounts), and an optional auditor
// key that can decrypt any confidential transfer amount
// (auditorElGamalPubkey).
//
// This is opcode 27 sub 0 (ConfidentialTransferInstructionInitializeMint).
// Unlike InitializeTransferFeeConfig's two authorities, which use the
// 1-byte-tag COption encoding, both optional fields here are MaybeNull:
// authority is a fixed 32-byte field (appendMaybeNullAddress, all-zero for
// nil) and auditorElGamalPubkey is the same shape but not an address
// (appendMaybeNull32) -- confirmed against the interface crate's
// InitializeMintData struct rather than assumed from
// InitializeTransferFeeConfig's pattern. auditorElGamalPubkey, when given,
// must be exactly 32 bytes: a compressed Ristretto point, not a Solana
// address, and this package has no ElGamal implementation to derive one
// from a keypair -- callers supply the raw 32 bytes themselves.
//
// Like every mint extension, this can only run after create-mint has
// allocated the account and before initialize-mint2 commits it; there is
// no path back into an already-initialized mint.
func (t *token) InitializeConfidentialTransferMint(mint, authority *types.PublicKey, autoApproveNewAccounts bool, auditorElGamalPubkey []byte) (*types.Instruction, error) {
	if mint.IsNil() {
		return nil, fmt.Errorf("token initialize confidential transfer mint: mint is required")
	}
	if auditorElGamalPubkey != nil && len(auditorElGamalPubkey) != 32 {
		return nil, fmt.Errorf("token initialize confidential transfer mint: auditor elgamal pubkey is %d bytes, expected 32", len(auditorElGamalPubkey))
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionConfidentialTransferExtension)
	data = codec.Binary.AppendU8(data, ConfidentialTransferInstructionInitializeMint)
	data = appendMaybeNullAddress(data, authority)
	if autoApproveNewAccounts {
		data = codec.Binary.AppendU8(data, 1)
	} else {
		data = codec.Binary.AppendU8(data, 0)
	}
	data = appendMaybeNull32(data, auditorElGamalPubkey)

	return types.NewInstruction(t.id, types.NewAccounts(
		types.NewWritableAccount(mint),
	), data), nil
}

// UpdateConfidentialTransferMint changes InitializeConfidentialTransferMint's
// two adjustable fields -- autoApproveNewAccounts and auditorElGamalPubkey
// -- authorized by whoever InitializeConfidentialTransferMint named as
// authority, exactly the same as SetTransferFee is authorized by
// transferFeeConfigAuthority rather than mint's own mint or freeze
// authority.
//
// This is opcode 27 sub 1 (ConfidentialTransferInstructionUpdateMint), and
// unlike InitializeMint carries no authority field in its own data at
// all -- upstream's UpdateMintData is only { auto_approve_new_accounts,
// auditor_elgamal_pubkey }. authority itself is never reassignable through
// this instruction: it is proven by signing as an account here, the same
// role SetTransferFee's transferFeeConfigAuthority plays, not a value this
// call can hand to someone else. Both fields overwrite whatever
// InitializeConfidentialTransferMint set, with no way to leave one
// unchanged -- passing the same value back is how a caller keeps it as is.
//
// Confirmed against the interface crate's update_mint: no zero-knowledge
// proof or context-state account is needed, the same as InitializeMint --
// of ConfidentialTransfer's 15 sub-instructions, only these two are pure
// data instructions with no ElGamal math required on this server's side.
func (t *token) UpdateConfidentialTransferMint(mint, authority *types.PublicKey, signers []*types.PublicKey, autoApproveNewAccounts bool, auditorElGamalPubkey []byte) (*types.Instruction, error) {
	if mint.IsNil() {
		return nil, fmt.Errorf("token update confidential transfer mint: mint is required")
	}
	if err := validateAuthority("token update confidential transfer mint", authority, signers); err != nil {
		return nil, err
	}
	if auditorElGamalPubkey != nil && len(auditorElGamalPubkey) != 32 {
		return nil, fmt.Errorf("token update confidential transfer mint: auditor elgamal pubkey is %d bytes, expected 32", len(auditorElGamalPubkey))
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionConfidentialTransferExtension)
	data = codec.Binary.AppendU8(data, ConfidentialTransferInstructionUpdateMint)
	if autoApproveNewAccounts {
		data = codec.Binary.AppendU8(data, 1)
	} else {
		data = codec.Binary.AppendU8(data, 0)
	}
	data = appendMaybeNull32(data, auditorElGamalPubkey)

	accounts := types.NewAccounts(
		types.NewWritableAccount(mint),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}

// ConfigureAccount attaches the ConfidentialTransferAccount extension to
// account, the token-account-side counterpart to
// InitializeConfidentialTransferMint -- mint has to already carry
// ConfidentialTransferMint (see initialize), the same way a token account
// belongs to a mint everywhere else in this API.
//
// This is opcode 27 sub 2 (ConfidentialTransferInstructionConfigureAccount),
// and unlike the two mint-side sub-instructions it needs a zero-knowledge
// proof: the program has to be convinced elgamalPubkey (baked into
// decryptableZeroBalance's own key material, but not itself a field this
// instruction's data carries) has a known secret key before letting an
// account claim it, or anyone could configure an account against a
// public key they do not control. This builder only ever produces the
// inline/sibling-instruction form -- proofInstructionOffset names where
// the accompanying VerifyPubkeyValidity instruction sits relative to this
// one in the same transaction (1 for immediately after), never a
// pre-verified context-state account, since this package has no
// context-state lifecycle (create, verify into, close) built at all.
//
// decryptableZeroBalance is always an encryption of zero (a freshly
// configured account has no balance yet) -- EncryptAeAmount(aeKey, 0),
// under an AeKey the caller derives themselves, the same reason
// auditorElGamalPubkey and proof are always caller-supplied bytes rather
// than something this package derives from a signature it never holds.
//
// Confirmed against the interface crate's own accounts list: token
// account (writable), mint (readonly), the sysvar::instructions account
// (readonly, standing in for the proof account this offset form always
// names), then authority -- the same shape resolveProofLocation's
// instruction-offset branch builds, not its context-state branch.
func (t *token) ConfigureAccount(account, mint, authority *types.PublicKey, signers []*types.PublicKey, decryptableZeroBalance []byte, maximumPendingBalanceCreditCounter uint64, proofInstructionOffset int8) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("token configure account: account is required")
	}
	if mint.IsNil() {
		return nil, fmt.Errorf("token configure account: mint is required")
	}
	if err := validateAuthority("token configure account", authority, signers); err != nil {
		return nil, err
	}
	if len(decryptableZeroBalance) != AeCiphertextLen {
		return nil, fmt.Errorf("token configure account: decryptable zero balance is %d bytes, expected %d", len(decryptableZeroBalance), AeCiphertextLen)
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionConfidentialTransferExtension)
	data = codec.Binary.AppendU8(data, ConfidentialTransferInstructionConfigureAccount)
	data = codec.Binary.AppendBytes(data, decryptableZeroBalance)
	data = codec.Binary.AppendU64(data, maximumPendingBalanceCreditCounter)
	data = codec.Binary.AppendU8(data, uint8(proofInstructionOffset))

	accounts := types.NewAccounts(
		types.NewWritableAccount(account),
		types.NewReadonlyAccount(mint),
		types.NewReadonlyAccount(Sysvar.Instructions()),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}

// ApproveAccount flips account's ConfidentialTransferAccount.approved
// flag, authorized by whoever InitializeConfidentialTransferMint or
// UpdateConfidentialTransferMint named as mint's authority -- the same
// role ConfigureAccount itself has no say over, since
// auto_approve_new_accounts on that mint being false is exactly what
// makes an unapproved account unusable until this runs.
//
// This is opcode 27 sub 3 (ConfidentialTransferInstructionApproveAccount),
// and unlike ConfigureAccount it carries no data at all beyond the two
// discriminant bytes and needs no zero-knowledge proof -- confirmed
// against the interface crate's own approve_account: `&()` for data, no
// sysvar::instructions account, just [account(writable), mint(readonly),
// authority(+multisig)].
func (t *token) ApproveAccount(account, mint, authority *types.PublicKey, signers []*types.PublicKey) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("token approve account: account is required")
	}
	if mint.IsNil() {
		return nil, fmt.Errorf("token approve account: mint is required")
	}
	if err := validateAuthority("token approve account", authority, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionConfidentialTransferExtension)
	data = codec.Binary.AppendU8(data, ConfidentialTransferInstructionApproveAccount)

	accounts := types.NewAccounts(
		types.NewWritableAccount(account),
		types.NewReadonlyAccount(mint),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}

// Deposit moves amount from account's ordinary public balance into its
// ConfidentialTransferAccount pending balance, encrypted along the way --
// the entry point into the confidential side from a plain SPL balance,
// the same direction Withdraw (not yet built) reverses.
//
// This is opcode 27 sub 5 (ConfidentialTransferInstructionDeposit), and
// unlike ConfigureAccount it needs no zero-knowledge proof: the amount is
// still public at this instant (it is leaving the public balance, which
// anyone can already see), so there is nothing to prove about it yet --
// only Transfer, which moves an already-confidential amount, needs a
// range proof that it is non-negative. Confirmed against the interface
// crate's own deposit(): accounts are
// [token_account(writable), mint(readonly), authority(+multisig)], data
// is amount(u64) + decimals(u8), the same decimals-checks-against-mint
// shape every other *Checked instruction in this codebase uses.
func (t *token) Deposit(account, mint, authority *types.PublicKey, signers []*types.PublicKey, amount uint64, decimals uint8) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("token deposit: account is required")
	}
	if mint.IsNil() {
		return nil, fmt.Errorf("token deposit: mint is required")
	}
	if err := validateAuthority("token deposit", authority, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionConfidentialTransferExtension)
	data = codec.Binary.AppendU8(data, ConfidentialTransferInstructionDeposit)
	data = codec.Binary.AppendU64(data, amount)
	data = codec.Binary.AppendU8(data, decimals)

	accounts := types.NewAccounts(
		types.NewWritableAccount(account),
		types.NewReadonlyAccount(mint),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}

// ApplyPendingBalance moves whatever Deposit and incoming Transfers have
// accumulated in account's encrypted pending balance into its available
// balance, the one Transfer and Withdraw actually spend from. Nothing
// received since account's last apply can be spent until this runs.
//
// This is opcode 27 sub 8 (ConfidentialTransferInstructionApplyPendingBalance),
// and needs no zero-knowledge proof -- the program does the pending-into-
// available ElGamal addition itself; nothing here is asserted about a
// value the caller alone knows. newDecryptableAvailableBalance is the
// caller's own bookkeeping catching up to that addition: an AE encryption
// (EncryptAeAmount) of what the available balance becomes once this
// lands, under the same AeKey ConfigureAccount's decryptable_zero_balance
// used, so the account's own cheap-to-read cache stays in sync with the
// ElGamal ciphertext the program actually updates.
//
// expectedPendingBalanceCreditCounter is how many pending-balance credits
// (deposits and incoming transfers) landed since account's last apply --
// the program rejects a mismatched count rather than silently applying a
// different set of credits than the caller believes it is catching up
// on. Confirmed against the interface crate's own apply_pending_balance:
// accounts are just [token_account(writable), authority(+multisig)], no
// mint account at all, unlike Deposit.
func (t *token) ApplyPendingBalance(account, authority *types.PublicKey, signers []*types.PublicKey, expectedPendingBalanceCreditCounter uint64, newDecryptableAvailableBalance []byte) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("token apply pending balance: account is required")
	}
	if err := validateAuthority("token apply pending balance", authority, signers); err != nil {
		return nil, err
	}
	if len(newDecryptableAvailableBalance) != AeCiphertextLen {
		return nil, fmt.Errorf("token apply pending balance: new decryptable available balance is %d bytes, expected %d", len(newDecryptableAvailableBalance), AeCiphertextLen)
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionConfidentialTransferExtension)
	data = codec.Binary.AppendU8(data, ConfidentialTransferInstructionApplyPendingBalance)
	data = codec.Binary.AppendU64(data, expectedPendingBalanceCreditCounter)
	data = codec.Binary.AppendBytes(data, newDecryptableAvailableBalance)

	accounts := types.NewAccounts(
		types.NewWritableAccount(account),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}

// ConfidentialTransfer moves amount confidentially from source to destination,
// neither the amount nor either account's resulting balance ever
// appearing in plaintext on chain. This is opcode 27 sub 7
// (ConfidentialTransferInstructionTransfer), and unlike every other
// sub-instruction this package builds, it depends on three separate
// zero-knowledge proofs landing alongside it in the same transaction, in
// a fixed order right after it: equality, then ciphertext validity, then
// the range proof (BuildTransferProofs computes all three, along with
// the two values this instruction's own data carries).
//
// newSourceDecryptableAvailableBalance, transferAmountAuditorCiphertextLo,
// and transferAmountAuditorCiphertextHi are BuildTransferProofs's own
// NewSourceDecryptableAvailableBalance, AuditorCiphertextLo, and
// AuditorCiphertextHi fields, packed here rather than recomputed --
// this builder only assembles bytes it is given, the same separation of
// concerns every other builder in this package keeps between "compute
// the value" and "encode the instruction."
//
// Confirmed against the interface crate's own inner_transfer: accounts
// are [source(writable), mint(readonly), destination(writable),
// sysvar::instructions(readonly) -- always included, since this package
// only ever builds the inline proof-offset form, never a context-state
// account -- authority(+multisig)]. Every proof_instruction_offset is
// fixed at 1: source's own equality proof comes first among the three
// followups, but Transfer itself always leads, so all three offsets are
// relative to the same instruction and share the same value.
func (t *token) ConfidentialTransfer(source, mint, destination, authority *types.PublicKey, signers []*types.PublicKey, newSourceDecryptableAvailableBalance, transferAmountAuditorCiphertextLo, transferAmountAuditorCiphertextHi []byte) (*types.Instruction, error) {
	if source.IsNil() {
		return nil, fmt.Errorf("token transfer: source is required")
	}
	if mint.IsNil() {
		return nil, fmt.Errorf("token transfer: mint is required")
	}
	if destination.IsNil() {
		return nil, fmt.Errorf("token transfer: destination is required")
	}
	if err := validateAuthority("token transfer", authority, signers); err != nil {
		return nil, err
	}
	if len(newSourceDecryptableAvailableBalance) != AeCiphertextLen {
		return nil, fmt.Errorf("token transfer: new source decryptable available balance is %d bytes, expected %d", len(newSourceDecryptableAvailableBalance), AeCiphertextLen)
	}
	if len(transferAmountAuditorCiphertextLo) != 64 {
		return nil, fmt.Errorf("token transfer: transfer amount auditor ciphertext lo is %d bytes, expected 64", len(transferAmountAuditorCiphertextLo))
	}
	if len(transferAmountAuditorCiphertextHi) != 64 {
		return nil, fmt.Errorf("token transfer: transfer amount auditor ciphertext hi is %d bytes, expected 64", len(transferAmountAuditorCiphertextHi))
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionConfidentialTransferExtension)
	data = codec.Binary.AppendU8(data, ConfidentialTransferInstructionTransfer)
	data = codec.Binary.AppendBytes(data, newSourceDecryptableAvailableBalance)
	data = codec.Binary.AppendBytes(data, transferAmountAuditorCiphertextLo)
	data = codec.Binary.AppendBytes(data, transferAmountAuditorCiphertextHi)
	data = codec.Binary.AppendU8(data, 1) // equality_proof_instruction_offset
	data = codec.Binary.AppendU8(data, 1) // ciphertext_validity_proof_instruction_offset
	data = codec.Binary.AppendU8(data, 1) // range_proof_instruction_offset

	accounts := types.NewAccounts(
		types.NewWritableAccount(source),
		types.NewReadonlyAccount(mint),
		types.NewWritableAccount(destination),
		types.NewReadonlyAccount(Sysvar.Instructions()),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}
