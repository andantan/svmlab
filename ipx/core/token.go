package core

import (
	"fmt"

	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
)

// SPL Token instruction discriminants.
//
// The leading byte selects the operation, where the System Program uses a u32.
// Both are indexes into a fixed list rather than hashes of a signature, so the
// width is the only difference, but it is one a builder cannot get wrong twice:
// writing a u32 here shifts every following field by three bytes.
//
// The gaps are Token-2022 opcodes. They are left out rather than guessed at,
// since an opcode the deployed program does not implement fails as
// InvalidInstruction with nothing to say which byte was wrong.
const (
	TokenInstructionInitializeMint uint8 = iota
	TokenInstructionInitializeAccount
	TokenInstructionInitializeMultisig
	TokenInstructionTransfer
	TokenInstructionApprove
	TokenInstructionRevoke
	TokenInstructionSetAuthority
	TokenInstructionMintTo
	TokenInstructionBurn
	TokenInstructionCloseAccount
	TokenInstructionFreezeAccount
	TokenInstructionThawAccount
	TokenInstructionTransferChecked
	TokenInstructionApproveChecked
	TokenInstructionMintToChecked
	TokenInstructionBurnChecked
	TokenInstructionInitializeAccount2
	TokenInstructionSyncNative
	TokenInstructionInitializeAccount3
	TokenInstructionInitializeMultisig2
	TokenInstructionInitializeMint2
	TokenInstructionGetAccountDataSize
	TokenInstructionInitializeImmutableOwner
	TokenInstructionAmountToUiAmount
	TokenInstructionUiAmountToAmount
)

// Authority types SetAuthority accepts, a u8 selecting which of an account's
// roles is being handed over.
//
// Which ones are valid depends on what the account is: the first two belong to
// a mint and the last two to a token account, and the program rejects the
// wrong pairing rather than silently ignoring it.
const (
	TokenAuthorityMintTokens uint8 = iota
	TokenAuthorityFreezeAccount
	TokenAuthorityAccountOwner
	TokenAuthorityCloseAccount
)

// NativeMintAddress is the mint that stands in for SOL itself.
//
// SOL is not an SPL token, so anything that takes a token account cannot take a
// wallet. Wrapping is the bridge: a token account of this mint holds lamports
// directly, and its balance is whatever its lamports are beyond the rent
// reserve, which is why SyncNative exists and why no other mint needs it.
const NativeMintAddress = "So11111111111111111111111111111111111111112"

var NativeMintID = types.MustPublicKeyFromBase58(NativeMintAddress)

// TokenAccountSpace is the size of an SPL Token holder account, confirmed
// against a live holder's account.
//
// The layout is fixed:
//
//	mint             [32]           which mint these units belong to
//	owner            [32]           who may move them
//	amount           u64            balance, in base units
//	delegate         COption<[32]>  4 + 32, who else may move some
//	state            u8             uninitialized, initialized, or frozen
//	is_native        COption<u64>   4 + 8, rent reserve when this holds wSOL
//	delegated_amount u64            how much the delegate may move
//	close_authority  COption<[32]>  4 + 32, who may close beyond the owner
const TokenAccountSpace uint64 = 165

// Token account states, a u8 rather than the bool a mint uses, because an
// account has a third state a mint does not.
const (
	TokenAccountStateUninitialized uint8 = 0
	TokenAccountStateInitialized   uint8 = 1
	TokenAccountStateFrozen        uint8 = 2
)

// TokenAccount is the state stored in an SPL Token holder account.
//
// This is where an ERC-20 balance mapping went. Instead of the contract keeping
// a map from address to balance, each holder gets an account of their own, and
// the mint keeps only the total. That is what makes Sealevel able to run two
// transfers of the same token in parallel: they touch different accounts, so
// nothing has to serialize them.
//
// Owner is not the account's owner in the runtime sense. The runtime owner is
// the Token Program, which is what lets it write the data; Owner here is the
// wallet the Token Program will accept a signature from.
type TokenAccount struct {
	Mint            *types.PublicKey
	Owner           *types.PublicKey
	Amount          uint64
	Delegate        *types.PublicKey
	State           uint8
	IsNative        bool
	RentReserve     uint64
	DelegatedAmount uint64
	CloseAuthority  *types.PublicKey
}

// Initialized reports whether the account holds usable state.
func (a *TokenAccount) Initialized() bool {
	return a.State != TokenAccountStateUninitialized
}

// Frozen reports whether the mint's freeze authority has suspended this
// account.
//
// A frozen account rejects transfer, burn, and approve until thawed. Its
// balance is untouched, which is why this is a state rather than a zeroing.
func (a *TokenAccount) Frozen() bool {
	return a.State == TokenAccountStateFrozen
}

// Delegated reports how much a delegate may still move.
//
// The two fields have to be read together: DelegatedAmount is left behind when
// a delegation is revoked, so a non-zero amount with no delegate means nothing.
func (a *TokenAccount) Delegated() uint64 {
	if a.Delegate.IsNil() {
		return 0
	}

	return a.DelegatedAmount
}

// DeserializeTokenAccount parses the 165 bytes a token account holds.
func DeserializeTokenAccount(raw []byte) (*TokenAccount, error) {
	if uint64(len(raw)) != TokenAccountSpace {
		return nil, fmt.Errorf("token account: %d bytes but expected %d", len(raw), TokenAccountSpace)
	}

	b, raw, err := codec.Binary.ReadBytes(raw, types.PublicKeyLength)
	if err != nil {
		return nil, fmt.Errorf("token account mint: %w", err)
	}
	mint, err := types.NewPublicKeyFromBytes(b)
	if err != nil {
		return nil, fmt.Errorf("token account mint: %w", err)
	}

	if b, raw, err = codec.Binary.ReadBytes(raw, types.PublicKeyLength); err != nil {
		return nil, fmt.Errorf("token account owner: %w", err)
	}
	owner, err := types.NewPublicKeyFromBytes(b)
	if err != nil {
		return nil, fmt.Errorf("token account owner: %w", err)
	}

	amount, raw, err := codec.Binary.ReadU64(raw)
	if err != nil {
		return nil, fmt.Errorf("token account amount: %w", err)
	}

	delegate, raw, err := readCOptionPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("token account delegate: %w", err)
	}

	state, raw, err := codec.Binary.ReadU8(raw)
	if err != nil {
		return nil, fmt.Errorf("token account state: %w", err)
	}
	if state > TokenAccountStateFrozen {
		return nil, fmt.Errorf("token account state is %d, expected 0, 1, or 2", state)
	}

	// is_native is a COption<u64> rather than a bool: the tag says whether this
	// account holds wrapped SOL, and the payload is the rent reserve that has
	// to stay behind when its balance is synced against its lamports.
	isNative, rentReserve, raw, err := readCOptionU64(raw)
	if err != nil {
		return nil, fmt.Errorf("token account is_native: %w", err)
	}

	delegatedAmount, raw, err := codec.Binary.ReadU64(raw)
	if err != nil {
		return nil, fmt.Errorf("token account delegated amount: %w", err)
	}

	closeAuthority, _, err := readCOptionPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("token account close authority: %w", err)
	}

	return &TokenAccount{
		Mint:            mint,
		Owner:           owner,
		Amount:          amount,
		Delegate:        delegate,
		State:           state,
		IsNative:        isNative,
		RentReserve:     rentReserve,
		DelegatedAmount: delegatedAmount,
		CloseAuthority:  closeAuthority,
	}, nil
}

// readCOptionU64 reads a 12-byte COption<u64>, reporting whether the tag said
// some as well as the value.
func readCOptionU64(src []byte) (bool, uint64, []byte, error) {
	b, src, err := codec.Binary.ReadCOption(src, 8)
	if err != nil {
		return false, 0, nil, err
	}
	if b == nil {
		return false, 0, src, nil
	}

	v, _, err := codec.Binary.ReadU64(b)
	if err != nil {
		return false, 0, nil, err
	}

	return true, v, src, nil
}

// MintSpace is the size of an SPL Token mint, confirmed against the USDC,
// USDT, and wSOL mints.
//
// The layout is fixed, so like a nonce account this is a constant rather than
// something read off a live account:
//
//	mint_authority       COption<[32]>  4 + 32, who may mint new supply
//	supply               u64            total minted, in base units
//	decimals             u8             where the UI places the point
//	is_initialized       bool           1 byte, 0 or 1
//	freeze_authority     COption<[32]>  4 + 32, who may freeze holders
//
// COption is not Rust's Option. Borsh would write a single tag byte; this is
// bincode's fixed-width encoding, where the tag is a u32 and the payload
// follows whether or not it is present. That is why the size is a constant at
// all: a mint with no freeze authority is the same 82 bytes as one with it.
const MintSpace uint64 = 82

// MaxMintDecimals is the largest decimals a mint may declare.
//
// The ceiling exists because a UI amount is a u64 divided by 10^decimals, and
// past this the divisor no longer fits. It is a display scale and nothing more:
// every instruction moves base units, so decimals never changes what a transfer
// does, only how it reads.
const MaxMintDecimals uint8 = 19

// Mint is the state stored in an SPL Token mint account.
//
// It is the closest thing Solana has to an ERC-20 contract, and the difference
// is what it does not hold: no balances and no allowances. Those live in
// separate token accounts owned by each holder, so a mint is only the supply,
// the decimals, and who may change them.
//
// MintAuthority and FreezeAuthority are nil when absent rather than zero, since
// a mint whose authority was removed is permanently different from one whose
// authority is the zero address, and the tag is what says which.
type Mint struct {
	MintAuthority   *types.PublicKey
	Supply          uint64
	Decimals        uint8
	IsInitialized   bool
	FreezeAuthority *types.PublicKey
}

// Mintable reports whether new supply can still be created.
//
// Removing the mint authority is how a supply is capped, and it cannot be
// undone: SetAuthority to none is one-way, so this answers a permanent
// question rather than a current one.
func (m *Mint) Mintable() bool {
	return !m.MintAuthority.IsNil()
}

// Freezable reports whether holders of this mint can have their accounts
// frozen.
//
// A freeze authority can only be set when the mint is initialized, so a mint
// that never had one can never gain one.
func (m *Mint) Freezable() bool {
	return !m.FreezeAuthority.IsNil()
}

// DeserializeMint parses the 82 bytes a mint account holds.
func DeserializeMint(raw []byte) (*Mint, error) {
	if uint64(len(raw)) != MintSpace {
		return nil, fmt.Errorf("mint: %d bytes but expected %d", len(raw), MintSpace)
	}

	mintAuthority, raw, err := readCOptionPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("mint authority: %w", err)
	}

	supply, raw, err := codec.Binary.ReadU64(raw)
	if err != nil {
		return nil, fmt.Errorf("mint supply: %w", err)
	}

	decimals, raw, err := codec.Binary.ReadU8(raw)
	if err != nil {
		return nil, fmt.Errorf("mint decimals: %w", err)
	}

	initialized, raw, err := codec.Binary.ReadU8(raw)
	if err != nil {
		return nil, fmt.Errorf("mint is_initialized: %w", err)
	}

	freezeAuthority, _, err := readCOptionPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("mint freeze authority: %w", err)
	}

	return &Mint{
		MintAuthority:   mintAuthority,
		Supply:          supply,
		Decimals:        decimals,
		IsInitialized:   initialized == 1,
		FreezeAuthority: freezeAuthority,
	}, nil
}

// readCOptionPublicKey reads a 36-byte COption<Pubkey>, returning nil when the
// tag says none.
func readCOptionPublicKey(src []byte) (*types.PublicKey, []byte, error) {
	b, src, err := codec.Binary.ReadCOption(src, types.PublicKeyLength)
	if err != nil {
		return nil, nil, err
	}
	if b == nil {
		return nil, src, nil
	}

	k, err := types.NewPublicKeyFromBytes(b)
	if err != nil {
		return nil, nil, err
	}

	return k, src, nil
}

// appendPubkeyOption writes an optional public key the way instruction data
// carries one: a single tag byte, and the key itself only when there is one.
//
// This is deliberately not the COption an account's data uses. There the tag is
// a u32 and the 32-byte payload is written whether or not it is present, which
// is what keeps a mint 82 bytes with or without a freeze authority. Instruction
// data has no fixed width to preserve, so the program packs None as one zero
// byte and nothing after it.
//
// Using the account layout here is not a harmless overshoot. The program reads
// one tag byte and then 32 bytes, so a four-byte tag leaves three zeros in
// front of the key, shifting it and dropping its last three bytes: the
// authority stored on chain is a different address than the caller named, and
// nothing fails to report it. The None case survives the mistake by accident,
// since the first of the four tag bytes is zero and the rest is ignored.
func appendPubkeyOption(dst []byte, k *types.PublicKey) []byte {
	if k.IsNil() {
		return codec.Binary.AppendU8(dst, 0)
	}

	dst = codec.Binary.AppendU8(dst, 1)

	return codec.Binary.AppendBytes(dst, k.Bytes())
}

// MultisigSpace is the size of an SPL Token multisig account.
//
// The layout is fixed at the maximum rather than sized to the signer count:
//
//	m               u8       how many signatures are required
//	n               u8       how many signers are enrolled
//	is_initialized  bool     1 byte, 0 or 1
//	signers         [32;11]  the enrolled keys, unused slots zeroed
//
// 3 + 11*32 = 355. Storing eleven slots whether or not they are used is what
// keeps this a constant, and it is why enrolling more than eleven is not a
// rent question but an impossible one.
const MultisigSpace uint64 = 355

// Multisig signer bounds, which the program enforces as 1 <= m <= n <= 11.
const (
	MinMultisigSigners = 1
	MaxMultisigSigners = 11
)

// Multisig is an SPL Token account that stands in for a single authority.
//
// Anywhere the Token Program takes an authority, it will take one of these
// instead, and then the named members sign in its place. That is the whole
// mechanism: there is no threshold logic in the mint or the token account, only
// an authority address that happens to be a multisig account rather than a
// wallet.
//
// This has no EVM counterpart at the protocol level. A Gnosis Safe is a
// contract that collects signatures and then calls onward; here the program
// itself counts signers on the transaction, so a multisig transfer is one
// instruction with several signing accounts rather than a call from a proxy.
type Multisig struct {
	M             uint8
	N             uint8
	IsInitialized bool
	Signers       []*types.PublicKey
}

// Enrolled reports whether a key is one of the multisig's registered signers.
//
// Membership alone authorizes nothing: an enrolled key signing is only
// sufficient once at least M of them have, which is a count the caller checks
// against M separately, not something this account can answer about a single
// key.
func (ms *Multisig) Enrolled(key *types.PublicKey) bool {
	for _, s := range ms.Signers {
		if s.Equal(key) {
			return true
		}
	}

	return false
}

// RequireMultisigAuthority decodes account data as a multisig and checks that
// signers is enough of its enrolled members, given the account's owner as
// read from the cluster.
//
// This takes owner and data already fetched rather than an account or a
// cluster to fetch them from. core has no path to a live cluster — internal/rpc
// imports core for its decoders, so the reverse import would cycle — and
// reading is not what varies between callers here, only what to do with what
// was read.
func RequireMultisigAuthority(program, owner *types.PublicKey, data []byte, signers []*types.PublicKey) (*Multisig, error) {
	if !owner.Equal(program) {
		return nil, fmt.Errorf("owned by %s, not %s", owner, program)
	}

	multisig, err := DecodeMultisig(owner, data)
	if err != nil {
		return nil, err
	}
	if !multisig.IsInitialized {
		return nil, fmt.Errorf("not initialized")
	}
	if len(signers) < int(multisig.M) {
		return nil, fmt.Errorf("requires %d signers, %d were given", multisig.M, len(signers))
	}
	for _, s := range signers {
		if !multisig.Enrolled(s) {
			return nil, fmt.Errorf("%s is not enrolled", s)
		}
	}

	return multisig, nil
}

// DeserializeMultisig parses the 355 bytes a multisig account holds.
//
// Only the first N slots are returned. The remaining slots are present in the
// data and are usually zero, but they are not signers, and reporting them would
// suggest the zero address can authorize something.
func DeserializeMultisig(raw []byte) (*Multisig, error) {
	if uint64(len(raw)) != MultisigSpace {
		return nil, fmt.Errorf("multisig: %d bytes but expected %d", len(raw), MultisigSpace)
	}

	m, raw, err := codec.Binary.ReadU8(raw)
	if err != nil {
		return nil, fmt.Errorf("multisig m: %w", err)
	}

	n, raw, err := codec.Binary.ReadU8(raw)
	if err != nil {
		return nil, fmt.Errorf("multisig n: %w", err)
	}
	if n > MaxMultisigSigners {
		return nil, fmt.Errorf("multisig n is %d, and the limit is %d", n, MaxMultisigSigners)
	}

	initialized, raw, err := codec.Binary.ReadU8(raw)
	if err != nil {
		return nil, fmt.Errorf("multisig is_initialized: %w", err)
	}

	signers := make([]*types.PublicKey, 0, n)
	for i := range uint8(MaxMultisigSigners) {
		b, rest, err := codec.Binary.ReadBytes(raw, types.PublicKeyLength)
		if err != nil {
			return nil, fmt.Errorf("multisig signer[%d]: %w", i, err)
		}
		raw = rest

		if i >= n {
			continue
		}

		k, err := types.NewPublicKeyFromBytes(b)
		if err != nil {
			return nil, fmt.Errorf("multisig signer[%d]: %w", i, err)
		}
		signers = append(signers, k)
	}

	return &Multisig{
		M:             m,
		N:             n,
		IsInitialized: initialized == 1,
		Signers:       signers,
	}, nil
}

// TokenAccountTypeOffset is where an extended account records which layout
// precedes it, and the values it holds.
//
// Classic Token needs no such byte because size alone identifies an account: 82
// is a mint, 165 is a holder, 355 is a multisig. Token-2022 breaks that, since
// extensions make both a mint and a holder longer than 165, so it pads a mint
// out to the holder's length and writes a tag at the end of the padding. An
// extended account is therefore never exactly 165 bytes, which is what keeps
// the classic sizes unambiguous.
const (
	TokenAccountTypeOffset = TokenAccountSpace

	TokenAccountTypeUninitialized uint8 = 0
	TokenAccountTypeMint          uint8 = 1
	TokenAccountTypeAccount       uint8 = 2
)

// DecodeMint parses account data as a mint, given the program that owns it.
//
// Ownership is checked here rather than left to the caller because a mint and a
// holder account are both owned by a token program and both start with 32 bytes
// that parse as a public key. Nothing in the bytes says which one this is, so
// deciding it from the length and the type tag is the only thing standing
// between a holder account and a supply figure invented from its owner field.
func DecodeMint(owner *types.PublicKey, data []byte) (*Mint, error) {
	if _, err := TokenProgram(owner); err != nil {
		return nil, fmt.Errorf("mint: owned by %s, which is not a token program", owner)
	}

	base, err := tokenBaseData(data, MintSpace, TokenAccountTypeMint, "mint")
	if err != nil {
		return nil, err
	}

	return DeserializeMint(base)
}

// DecodeTokenAccount parses account data as a holder account, under the same
// rule as DecodeMint.
func DecodeTokenAccount(owner *types.PublicKey, data []byte) (*TokenAccount, error) {
	if _, err := TokenProgram(owner); err != nil {
		return nil, fmt.Errorf("token account: owned by %s, which is not a token program", owner)
	}

	base, err := tokenBaseData(data, TokenAccountSpace, TokenAccountTypeAccount, "token account")
	if err != nil {
		return nil, err
	}

	return DeserializeTokenAccount(base)
}

// DecodeMultisig parses account data as a multisig, given the program that
// owns it.
//
// Unlike a mint or a holder account, this needs no type-tag disambiguation:
// nothing attaches extensions to a multisig account, so it is exactly 355
// bytes on both Token and Token-2022 and DeserializeMultisig's own length
// check is the only one there is to make.
func DecodeMultisig(owner *types.PublicKey, data []byte) (*Multisig, error) {
	if _, err := TokenProgram(owner); err != nil {
		return nil, fmt.Errorf("multisig: owned by %s, which is not a token program", owner)
	}

	return DeserializeMultisig(data)
}

// tokenBaseData returns the fixed prefix a classic parser reads, rejecting data
// whose length or type tag says it is something else.
func tokenBaseData(data []byte, space uint64, want uint8, name string) ([]byte, error) {
	size := uint64(len(data))

	switch {
	case size == space:
		// A classic account, or an extended one that happens to carry no
		// extensions. Either way the layout is exactly the base.
		return data, nil

	case size <= TokenAccountTypeOffset:
		return nil, fmt.Errorf("%s: %d bytes, which is neither %d nor an extended account", name, size, space)

	case data[TokenAccountTypeOffset] != want:
		return nil, fmt.Errorf("%s: extended account is type %d, not %d", name, data[TokenAccountTypeOffset], want)

	default:
		return data[:space], nil
	}
}

// token builds instructions for an SPL Token program.
//
// Unlike System, this one carries its program id, because there are two live at
// once. Token-2022 is a separate deployment rather than a version of this one,
// and on the classic instruction surface the two are byte for byte the same:
// the same opcodes, the same account orders, the same account layouts. Only the
// address they are sent to differs.
//
// So the id is a field and the two programs are two values of the same type. It
// is still not configuration: both addresses are constants, and which one a
// caller wants is a property of the mint being operated on rather than of the
// cluster. A mint belongs to exactly one of them, and its runtime owner says
// which.
//
// What this does not cover is the part of Token-2022 that is genuinely new.
// Extensions change account sizes and add instructions of their own, so they
// need their own builders and their own parsers; this shares only the surface
// the two programs already agree on.
type token struct {
	id *types.PublicKey
}

var (
	Token     = &token{id: TokenProgramID}
	Token2022 = &token{id: Token2022ProgramID}
)

// TokenProgram selects the builder for a program id, so a handler can take the
// program from its request rather than branching on it.
func TokenProgram(id *types.PublicKey) (*token, error) {
	switch {
	case id.Equal(TokenProgramID):
		return Token, nil
	case id.Equal(Token2022ProgramID):
		return Token2022, nil
	default:
		return nil, fmt.Errorf("token program: %s is neither %s nor %s", id, TokenProgramID, Token2022ProgramID)
	}
}

// ID is the program id, which callers need when it is not the program being
// invoked but the value being passed, as the owner of a new mint is, and as a
// seed of an associated token address is.
func (t *token) ID() *types.PublicKey {
	return t.id
}

// appendAuthority adds the accounts that authorize an instruction.
//
// A single authority signs for itself. A multisig authority does not sign at
// all: the account is passed read-only and the enrolled members sign in its
// place, which is why the same instruction has a different signature count
// depending on nothing the instruction data says.
//
// The members are not checked against the account here. That would need the
// account read, and the program does the checking anyway; passing a key that
// is not enrolled fails on chain rather than producing a transaction that
// looks valid.
func appendAuthority(accounts types.Accounts, authority *types.PublicKey, signers []*types.PublicKey) types.Accounts {
	if len(signers) == 0 {
		return append(accounts, types.NewReadonlySignerAccount(authority))
	}

	accounts = append(accounts, types.NewReadonlyAccount(authority))
	for _, s := range signers {
		accounts = append(accounts, types.NewReadonlySignerAccount(s))
	}

	return accounts
}

// validateAuthority rejects the ways an authority can be malformed before the
// accounts are laid out.
func validateAuthority(op string, authority *types.PublicKey, signers []*types.PublicKey) error {
	if authority.IsNil() {
		return fmt.Errorf("%s: authority is required", op)
	}
	if len(signers) > MaxMultisigSigners {
		return fmt.Errorf("%s: %d multisig signers exceeds the limit of %d", op, len(signers), MaxMultisigSigners)
	}

	seen := make(map[string]bool, len(signers))
	for i, s := range signers {
		if s.IsNil() {
			return fmt.Errorf("%s: multisig signer[%d] is required", op, i)
		}
		// A repeated key signs once, so counting it twice would build a
		// transaction that satisfies m on paper and not on chain.
		if key := s.Base58(); seen[key] {
			return fmt.Errorf("%s: multisig signer[%d] %s is repeated", op, i, s)
		} else {
			seen[key] = true
		}
	}

	return nil
}

// InitializeMint turns an existing Token-owned account of the right size into
// a mint.
//
// This is the original variant: it takes the rent sysvar as a read-only
// account alongside mint, a parameter the program stopped reading once rent
// collection was disabled. InitializeMint2 drops it as dead weight in a
// transaction with a hard size limit; this exists only for compatibility
// with instruction data built against the original opcode.
//
// The mint does not sign. It has already been created by then, and nothing
// about initializing it needs its authority, which is exactly why creating and
// initializing have to travel in one transaction: between them the account is
// Token-owned, correctly sized, and initializable by anyone.
//
// A nil freezeAuthority means the mint can never freeze a holder, and that
// cannot be added later.
func (t *token) InitializeMint(mint, mintAuthority, freezeAuthority *types.PublicKey, decimals uint8) (*types.Instruction, error) {
	if mint.IsNil() {
		return nil, fmt.Errorf("token initialize mint: mint is required")
	}
	if mintAuthority.IsNil() {
		return nil, fmt.Errorf("token initialize mint: mint authority is required")
	}
	if decimals > MaxMintDecimals {
		return nil, fmt.Errorf("token initialize mint: %d decimals exceeds the limit of %d", decimals, MaxMintDecimals)
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionInitializeMint)
	data = codec.Binary.AppendU8(data, decimals)
	data = codec.Binary.AppendBytes(data, mintAuthority.Bytes())
	data = appendPubkeyOption(data, freezeAuthority)

	return types.NewInstruction(t.id, types.NewAccounts(
		types.NewWritableAccount(mint),
		types.NewReadonlyAccount(Sysvar.Rent()),
	), data), nil
}

// InitializeMint2 turns an existing Token-owned account of the right size into
// a mint.
//
// This is the 2 variant rather than the original because the only difference is
// that it does not take the rent sysvar. The program stopped needing it once
// rent collection was disabled, so passing it is thirty-two wasted bytes in a
// transaction with a hard size limit.
//
// The mint does not sign. It has already been created by then, and nothing
// about initializing it needs its authority, which is exactly why creating and
// initializing have to travel in one transaction: between them the account is
// Token-owned, correctly sized, and initializable by anyone.
//
// A nil freezeAuthority means the mint can never freeze a holder, and that
// cannot be added later.
func (t *token) InitializeMint2(mint, mintAuthority, freezeAuthority *types.PublicKey, decimals uint8) (*types.Instruction, error) {
	if mint.IsNil() {
		return nil, fmt.Errorf("token initialize mint: mint is required")
	}
	if mintAuthority.IsNil() {
		return nil, fmt.Errorf("token initialize mint: mint authority is required")
	}
	if decimals > MaxMintDecimals {
		return nil, fmt.Errorf("token initialize mint: %d decimals exceeds the limit of %d", decimals, MaxMintDecimals)
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionInitializeMint2)
	data = codec.Binary.AppendU8(data, decimals)
	data = codec.Binary.AppendBytes(data, mintAuthority.Bytes())
	data = appendPubkeyOption(data, freezeAuthority)

	return types.NewInstruction(t.id, types.NewAccounts(
		types.NewWritableAccount(mint),
	), data), nil
}

// InitializeAccount turns an existing Token-owned account of the right size
// into a holder account for one mint.
//
// This is the original variant: owner is passed as a read-only account rather
// than in the instruction data, and the rent sysvar rides alongside it.
// Neither is read for anything but its address; InitializeAccount3 drops both.
// This exists only for compatibility with the original opcode.
//
// As with a mint, the account does not sign and anyone may initialize it, so
// this belongs in the same transaction as its creation.
func (t *token) InitializeAccount(account, mint, owner *types.PublicKey) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("token initialize account: account is required")
	}
	if mint.IsNil() {
		return nil, fmt.Errorf("token initialize account: mint is required")
	}
	if owner.IsNil() {
		return nil, fmt.Errorf("token initialize account: owner is required")
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionInitializeAccount)

	return types.NewInstruction(t.id, types.NewAccounts(
		types.NewWritableAccount(account),
		types.NewReadonlyAccount(mint),
		types.NewReadonlyAccount(owner),
		types.NewReadonlyAccount(Sysvar.Rent()),
	), data), nil
}

// InitializeAccount2 turns an existing Token-owned account of the right size
// into a holder account for one mint.
//
// The 2 variant takes the owner in the instruction data rather than as an
// account, dropping the owner account InitializeAccount carries; the rent
// sysvar is still read. InitializeAccount3 drops that too. This exists only
// for compatibility with the original opcode.
//
// As with a mint, the account does not sign and anyone may initialize it, so
// this belongs in the same transaction as its creation.
func (t *token) InitializeAccount2(account, mint, owner *types.PublicKey) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("token initialize account: account is required")
	}
	if mint.IsNil() {
		return nil, fmt.Errorf("token initialize account: mint is required")
	}
	if owner.IsNil() {
		return nil, fmt.Errorf("token initialize account: owner is required")
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionInitializeAccount2)
	data = codec.Binary.AppendBytes(data, owner.Bytes())

	return types.NewInstruction(t.id, types.NewAccounts(
		types.NewWritableAccount(account),
		types.NewReadonlyAccount(mint),
		types.NewReadonlyAccount(Sysvar.Rent()),
	), data), nil
}

// InitializeAccount3 turns an existing Token-owned account of the right size
// into a holder account for one mint.
//
// The 3 variant takes the owner in the instruction data rather than as an
// account, which drops both the owner account and the rent sysvar. Neither was
// ever read for anything but its address.
//
// As with a mint, the account does not sign and anyone may initialize it, so
// this belongs in the same transaction as its creation.
func (t *token) InitializeAccount3(account, mint, owner *types.PublicKey) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("token initialize account: account is required")
	}
	if mint.IsNil() {
		return nil, fmt.Errorf("token initialize account: mint is required")
	}
	if owner.IsNil() {
		return nil, fmt.Errorf("token initialize account: owner is required")
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionInitializeAccount3)
	data = codec.Binary.AppendBytes(data, owner.Bytes())

	return types.NewInstruction(t.id, types.NewAccounts(
		types.NewWritableAccount(account),
		types.NewReadonlyAccount(mint),
	), data), nil
}

// InitializeMultisig turns an existing Token-owned account of the right size
// into a multisig, using the original opcode that carries the rent sysvar as
// a read-only account alongside the multisig. InitializeMultisig2 drops it as
// dead weight; this exists only for compatibility with the original opcode.
//
// The multisig does not sign, and neither do the signers being enrolled:
// this only records their addresses, the same way InitializeMint2 only
// records a mint authority without checking it against a signer. Nothing
// about becoming a registered signer needs proving here — that only matters
// once the multisig is actually used as an authority.
//
// m must be at least 1 and at most len(signers), and len(signers) must be at
// most MaxMultisigSigners: the program enforces 1 <= m <= n <= 11, and
// building an instruction that cannot pass that is caught here rather than
// on chain.
func (t *token) InitializeMultisig(multisig *types.PublicKey, m uint8, signers []*types.PublicKey) (*types.Instruction, error) {
	if multisig.IsNil() {
		return nil, fmt.Errorf("token initialize multisig: multisig is required")
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("token initialize multisig: at least one signer is required")
	}
	if len(signers) > MaxMultisigSigners {
		return nil, fmt.Errorf("token initialize multisig: %d signers exceeds the limit of %d", len(signers), MaxMultisigSigners)
	}
	if m < MinMultisigSigners || int(m) > len(signers) {
		return nil, fmt.Errorf("token initialize multisig: m must be between 1 and %d, got %d", len(signers), m)
	}

	seen := make(map[string]bool, len(signers))
	for i, s := range signers {
		if s.IsNil() {
			return nil, fmt.Errorf("token initialize multisig: signer[%d] is required", i)
		}
		if key := s.Base58(); seen[key] {
			return nil, fmt.Errorf("token initialize multisig: signer[%d] %s is repeated", i, s)
		} else {
			seen[key] = true
		}
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionInitializeMultisig)
	data = codec.Binary.AppendU8(data, m)

	accounts := types.NewAccounts(
		types.NewWritableAccount(multisig),
		types.NewReadonlyAccount(Sysvar.Rent()),
	)
	for _, s := range signers {
		accounts = append(accounts, types.NewReadonlyAccount(s))
	}

	return types.NewInstruction(t.id, accounts, data), nil
}

// InitializeMultisig2 turns an existing Token-owned account of the right
// size into a multisig.
//
// This is the 2 variant rather than the original because the only difference
// is that it does not take the rent sysvar, the same relationship
// InitializeMint2 has to InitializeMint.
func (t *token) InitializeMultisig2(multisig *types.PublicKey, m uint8, signers []*types.PublicKey) (*types.Instruction, error) {
	if multisig.IsNil() {
		return nil, fmt.Errorf("token initialize multisig: multisig is required")
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("token initialize multisig: at least one signer is required")
	}
	if len(signers) > MaxMultisigSigners {
		return nil, fmt.Errorf("token initialize multisig: %d signers exceeds the limit of %d", len(signers), MaxMultisigSigners)
	}
	if m < MinMultisigSigners || int(m) > len(signers) {
		return nil, fmt.Errorf("token initialize multisig: m must be between 1 and %d, got %d", len(signers), m)
	}

	seen := make(map[string]bool, len(signers))
	for i, s := range signers {
		if s.IsNil() {
			return nil, fmt.Errorf("token initialize multisig: signer[%d] is required", i)
		}
		if key := s.Base58(); seen[key] {
			return nil, fmt.Errorf("token initialize multisig: signer[%d] %s is repeated", i, s)
		} else {
			seen[key] = true
		}
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionInitializeMultisig2)
	data = codec.Binary.AppendU8(data, m)

	accounts := types.NewAccounts(
		types.NewWritableAccount(multisig),
	)
	for _, s := range signers {
		accounts = append(accounts, types.NewReadonlyAccount(s))
	}

	return types.NewInstruction(t.id, accounts, data), nil
}

// Transfer moves tokens between two accounts, the original opcode.
//
// Unlike TransferChecked, neither the mint nor its decimals is named or
// verified: the program trusts amount against whatever source's own mint and
// decimals turn out to be, which is exactly the failure mode the checked
// variant exists to catch. This is for compatibility with the original
// opcode; TransferChecked remains the normal public path.
func (t *token) Transfer(source, destination, authority *types.PublicKey, signers []*types.PublicKey, amount uint64) (*types.Instruction, error) {
	if source.IsNil() {
		return nil, fmt.Errorf("token transfer: source is required")
	}
	if destination.IsNil() {
		return nil, fmt.Errorf("token transfer: destination is required")
	}
	if source.Equal(destination) {
		return nil, fmt.Errorf("token transfer: source and destination are the same account")
	}
	if err := validateAuthority("token transfer", authority, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionTransfer)
	data = codec.Binary.AppendU64(data, amount)

	accounts := types.NewAccounts(
		types.NewWritableAccount(source),
		types.NewWritableAccount(destination),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}

// Approve grants a delegate spending rights over an account, the original
// opcode.
//
// Unlike ApproveChecked, neither the mint nor its decimals is named or
// verified. This is for compatibility with the original opcode;
// ApproveChecked remains the normal public path.
func (t *token) Approve(account, delegate, authority *types.PublicKey, signers []*types.PublicKey, amount uint64) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("token approve: account is required")
	}
	if delegate.IsNil() {
		return nil, fmt.Errorf("token approve: delegate is required")
	}
	if err := validateAuthority("token approve", authority, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionApprove)
	data = codec.Binary.AppendU64(data, amount)

	accounts := types.NewAccounts(
		types.NewWritableAccount(account),
		types.NewReadonlyAccount(delegate),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}

// MintTo creates new supply in a holder account, the original opcode.
//
// Unlike MintToChecked, decimals is neither named nor verified against the
// mint. The account list is otherwise identical: the mint is writable for
// the same reason — supply lives on it. This is for compatibility with the
// original opcode; MintToChecked remains the normal public path.
func (t *token) MintTo(mint, destination, authority *types.PublicKey, signers []*types.PublicKey, amount uint64) (*types.Instruction, error) {
	if mint.IsNil() {
		return nil, fmt.Errorf("token mint to: mint is required")
	}
	if destination.IsNil() {
		return nil, fmt.Errorf("token mint to: destination is required")
	}
	if err := validateAuthority("token mint to", authority, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionMintTo)
	data = codec.Binary.AppendU64(data, amount)

	accounts := types.NewAccounts(
		types.NewWritableAccount(mint),
		types.NewWritableAccount(destination),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}

// Burn destroys supply held by an account, the original opcode.
//
// Unlike BurnChecked, decimals is neither named nor verified against the
// mint. The account list is otherwise identical. This is for compatibility
// with the original opcode; BurnChecked remains the normal public path.
func (t *token) Burn(account, mint, authority *types.PublicKey, signers []*types.PublicKey, amount uint64) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("token burn: account is required")
	}
	if mint.IsNil() {
		return nil, fmt.Errorf("token burn: mint is required")
	}
	if err := validateAuthority("token burn", authority, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionBurn)
	data = codec.Binary.AppendU64(data, amount)

	accounts := types.NewAccounts(
		types.NewWritableAccount(account),
		types.NewWritableAccount(mint),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}

// TransferChecked moves tokens between two accounts of the same mint.
//
// It never sends to a wallet. Both ends are token accounts, and reaching a
// wallet means deriving or creating its associated account first, which is the
// step that has no ERC-20 counterpart: there, a transfer to an address that has
// never held the token just writes a new map entry.
//
// The checked variant takes the mint and the decimals it expects, and the
// program rejects the instruction if either disagrees with the account. That
// costs one more account key and removes the failure where a client formatted
// an amount against the wrong decimals and moved a thousand times too much.
func (t *token) TransferChecked(source, mint, destination, authority *types.PublicKey, signers []*types.PublicKey, amount uint64, decimals uint8) (*types.Instruction, error) {
	if source.IsNil() {
		return nil, fmt.Errorf("token transfer: source is required")
	}
	if mint.IsNil() {
		return nil, fmt.Errorf("token transfer: mint is required")
	}
	if destination.IsNil() {
		return nil, fmt.Errorf("token transfer: destination is required")
	}
	if source.Equal(destination) {
		return nil, fmt.Errorf("token transfer: source and destination are the same account")
	}
	if err := validateAuthority("token transfer", authority, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionTransferChecked)
	data = codec.Binary.AppendU64(data, amount)
	data = codec.Binary.AppendU8(data, decimals)

	accounts := types.NewAccounts(
		types.NewWritableAccount(source),
		types.NewReadonlyAccount(mint),
		types.NewWritableAccount(destination),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}

// MintToChecked creates new supply in a holder account.
//
// Only the mint authority can do this, and a mint whose authority was removed
// has a fixed supply forever. The mint is writable because the total supply
// lives on it, which is the one piece of state a mint keeps about balances.
func (t *token) MintToChecked(mint, destination, authority *types.PublicKey, signers []*types.PublicKey, amount uint64, decimals uint8) (*types.Instruction, error) {
	if mint.IsNil() {
		return nil, fmt.Errorf("token mint to: mint is required")
	}
	if destination.IsNil() {
		return nil, fmt.Errorf("token mint to: destination is required")
	}
	if err := validateAuthority("token mint to", authority, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionMintToChecked)
	data = codec.Binary.AppendU64(data, amount)
	data = codec.Binary.AppendU8(data, decimals)

	accounts := types.NewAccounts(
		types.NewWritableAccount(mint),
		types.NewWritableAccount(destination),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}

// BurnChecked destroys supply held by an account.
//
// The authority here is the account's owner or delegate rather than the mint's
// authority: burning spends a balance, so it is the holder's to authorize. The
// mint is still writable because the total supply comes down with it.
func (t *token) BurnChecked(account, mint, authority *types.PublicKey, signers []*types.PublicKey, amount uint64, decimals uint8) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("token burn: account is required")
	}
	if mint.IsNil() {
		return nil, fmt.Errorf("token burn: mint is required")
	}
	if err := validateAuthority("token burn", authority, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionBurnChecked)
	data = codec.Binary.AppendU64(data, amount)
	data = codec.Binary.AppendU8(data, decimals)

	accounts := types.NewAccounts(
		types.NewWritableAccount(account),
		types.NewWritableAccount(mint),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}

// CloseAccount reclaims a token account's rent.
//
// The account has to hold no tokens first, which is the whole reason this is
// worth doing rather than abandoning it: the balance is not swept, it has to be
// zero, and the lamports that come back are the rent-exempt reserve. A wrapped
// SOL account is the exception the program makes, since its balance is its
// lamports, and closing it is how SOL is unwrapped.
//
// There is no checked variant because there is no amount to check.
func (t *token) CloseAccount(account, destination, authority *types.PublicKey, signers []*types.PublicKey) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("token close account: account is required")
	}
	if destination.IsNil() {
		return nil, fmt.Errorf("token close account: destination is required")
	}
	if account.Equal(destination) {
		return nil, fmt.Errorf("token close account: account and destination are the same account")
	}
	if err := validateAuthority("token close account", authority, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionCloseAccount)

	accounts := types.NewAccounts(
		types.NewWritableAccount(account),
		types.NewWritableAccount(destination),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}

// ApproveChecked authorizes a delegate to move up to amount from an account,
// on behalf of its owner.
//
// The delegate is not a second owner. It may move at most amount and no more,
// the account's own owner can still move the whole balance regardless, and a
// second Approve replaces the delegation rather than adding to it — the
// program stores one delegate and one amount, not a list.
func (t *token) ApproveChecked(account, mint, delegate, authority *types.PublicKey, signers []*types.PublicKey, amount uint64, decimals uint8) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("token approve: account is required")
	}
	if mint.IsNil() {
		return nil, fmt.Errorf("token approve: mint is required")
	}
	if delegate.IsNil() {
		return nil, fmt.Errorf("token approve: delegate is required")
	}
	if err := validateAuthority("token approve", authority, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionApproveChecked)
	data = codec.Binary.AppendU64(data, amount)
	data = codec.Binary.AppendU8(data, decimals)

	accounts := types.NewAccounts(
		types.NewWritableAccount(account),
		types.NewReadonlyAccount(mint),
		types.NewReadonlyAccount(delegate),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}

// Revoke withdraws whatever delegation an account currently has.
//
// There is no delegate argument: the program clears whichever one is stored,
// so naming one would only be a way to get it wrong. An account with no
// delegate revokes cleanly too, since clearing an already-empty delegation is
// not an error the program raises.
func (t *token) Revoke(account, authority *types.PublicKey, signers []*types.PublicKey) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("token revoke: account is required")
	}
	if err := validateAuthority("token revoke", authority, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionRevoke)

	accounts := types.NewAccounts(
		types.NewWritableAccount(account),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}

// SetAuthority replaces or removes one of a mint's or a token account's four
// authorities.
//
// Which account is writable and which authority is being replaced are the same
// piece of information told twice — once as which account was passed, once as
// authorityType — and the program checks both agree rather than trusting
// either alone.
//
// A nil newAuthority clears the role rather than leaving it unchanged, and for
// mint_authority or freeze_authority that is permanent: neither can be set
// again once cleared. Nothing here distinguishes "the caller meant to clear
// it" from "the caller forgot to fill it in", which is why the endpoint above
// this has to ask for that distinction explicitly rather than reading it off
// an empty string.
func (t *token) SetAuthority(account *types.PublicKey, authorityType uint8, currentAuthority, newAuthority *types.PublicKey, signers []*types.PublicKey) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("token set authority: account is required")
	}
	if authorityType > TokenAuthorityCloseAccount {
		return nil, fmt.Errorf("token set authority: authority type is %d, expected 0 through %d", authorityType, TokenAuthorityCloseAccount)
	}
	if err := validateAuthority("token set authority", currentAuthority, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionSetAuthority)
	data = codec.Binary.AppendU8(data, authorityType)
	data = appendPubkeyOption(data, newAuthority)

	accounts := types.NewAccounts(
		types.NewWritableAccount(account),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, currentAuthority, signers), data), nil
}

// FreezeAccount suspends an account, so it rejects transfer, burn, and
// approve until thawed.
//
// Only a mint that was initialized with a freeze authority can be frozen at
// all; one initialized without it can never gain the capability afterward.
// The balance is untouched, since freezing is a state on the account rather
// than a change to what it holds.
func (t *token) FreezeAccount(account, mint, authority *types.PublicKey, signers []*types.PublicKey) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("token freeze account: account is required")
	}
	if mint.IsNil() {
		return nil, fmt.Errorf("token freeze account: mint is required")
	}
	if err := validateAuthority("token freeze account", authority, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionFreezeAccount)

	accounts := types.NewAccounts(
		types.NewWritableAccount(account),
		types.NewReadonlyAccount(mint),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}

// ThawAccount reverses FreezeAccount, letting transfer, burn, and approve
// resume against the account.
func (t *token) ThawAccount(account, mint, authority *types.PublicKey, signers []*types.PublicKey) (*types.Instruction, error) {
	if account.IsNil() {
		return nil, fmt.Errorf("token thaw account: account is required")
	}
	if mint.IsNil() {
		return nil, fmt.Errorf("token thaw account: mint is required")
	}
	if err := validateAuthority("token thaw account", authority, signers); err != nil {
		return nil, err
	}

	data := codec.Binary.AppendU8(nil, TokenInstructionThawAccount)

	accounts := types.NewAccounts(
		types.NewWritableAccount(account),
		types.NewReadonlyAccount(mint),
	)

	return types.NewInstruction(t.id, appendAuthority(accounts, authority, signers), data), nil
}

// CreateMint funds a new account and hands it to the Token Program, sized and
// owned correctly for a mint but not initialized.
//
// This is deliberately the low-level half only: initializing it is a separate
// call (InitializeMint2, or InitializeMint for the original opcode), and
// nothing stops somebody else from initializing it first in between with
// their own authority. A caller who wants that race closed belongs on a
// composite instead; this is for one who accepts it, e.g. because the two
// calls are already going to land in the same transaction some other way.
//
// The new mint signs, because creating an account requires the account itself
// to authorize it. That is the one place a mint's private key is ever needed:
// afterwards the mint authority governs it and the key that made it is spent.
//
// lamports has to cover rent exemption for MintSpace, which the caller reads
// from the cluster rather than assuming, since it is a cluster parameter.
func (t *token) CreateMint(payer, mint *types.PublicKey, lamports uint64) (*types.Instruction, error) {
	return System.CreateAccount(payer, mint, t.id, lamports, MintSpace)
}

// CreateAccount funds a new account and hands it to the Token Program, sized
// and owned correctly for a holder account but not initialized.
//
// This is deliberately the low-level half only: initializing it is a separate
// call (InitializeAccount3, or InitializeAccount/InitializeAccount2 for the
// original opcodes), and nothing stops somebody else from initializing it
// first in between, naming their own wallet as owner. A caller who wants that
// race closed belongs on a composite instead; this is for one who accepts it.
//
// This produces a plain keypair account rather than an associated one. The
// address is whatever key was generated for it, so nothing can rediscover it
// from the wallet and mint, which is what the associated token account exists
// to fix. It is still what to use when a wallet wants more than one account for
// the same mint, since the associated address is one per pair.
func (t *token) CreateAccount(payer, account *types.PublicKey, lamports uint64) (*types.Instruction, error) {
	return System.CreateAccount(payer, account, t.id, lamports, TokenAccountSpace)
}

// CreateMultisig funds a new account and hands it to the Token Program, sized
// and owned correctly for a multisig but not initialized.
//
// This is deliberately the low-level half only, the same as CreateMint and
// CreateAccount: initializing it is a separate call (InitializeMultisig2, or
// InitializeMultisig for the original opcode), and nothing stops somebody
// else from initializing it first in between with their own m and signers. A
// caller who wants that race closed should build the pair as two
// instructions in one transaction themselves.
//
// The new multisig signs, because creating an account requires the account
// itself to authorize it. That is the one place its private key is ever
// needed: afterwards it is only ever named as an authority, never signed for
// directly, and the key that made it is spent.
func (t *token) CreateMultisig(payer, multisig *types.PublicKey, lamports uint64) (*types.Instruction, error) {
	return System.CreateAccount(payer, multisig, t.id, lamports, MultisigSpace)
}
