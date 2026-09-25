package core

import (
	"encoding/binary"
	"fmt"

	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
)

// The token-metadata and token-group interfaces are not opcode-numbered like the
// rest of Token-2022: each instruction starts with an 8-byte discriminator, the
// first 8 bytes of SHA-256 over a fixed label ("spl_token_metadata_interface:
// initialize_account" and so on). Token-2022 implements both interfaces itself
// for the mints it owns. The values below were computed from the labels in the
// interface crates' own #[discriminator_hash_input] attributes.
var (
	tokenMetadataInitializeDiscriminator      = []byte{0xd2, 0xe1, 0x1e, 0xa2, 0x58, 0xb8, 0x4d, 0x8d}
	tokenMetadataUpdateFieldDiscriminator     = []byte{0xdd, 0xe9, 0x31, 0x2d, 0xb5, 0xca, 0xdc, 0xc8}
	tokenMetadataRemoveKeyDiscriminator       = []byte{0xea, 0x12, 0x20, 0x38, 0x59, 0x8d, 0x25, 0xb5}
	tokenMetadataUpdateAuthorityDiscriminator = []byte{0xd7, 0xe4, 0xa6, 0xe4, 0x54, 0x64, 0x56, 0x7b}
	tokenMetadataEmitDiscriminator            = []byte{0xfa, 0xa6, 0xb4, 0xfa, 0x0d, 0x0c, 0xb8, 0x46}

	tokenGroupInitializeDiscriminator       = []byte{0x79, 0x71, 0x6c, 0x27, 0x36, 0x33, 0x00, 0x04}
	tokenGroupUpdateMaxSizeDiscriminator    = []byte{0x6c, 0x25, 0xab, 0x8f, 0xf8, 0x1e, 0x12, 0x6e}
	tokenGroupUpdateAuthorityDiscriminator  = []byte{0xa1, 0x69, 0x58, 0x01, 0xed, 0xdd, 0xd8, 0xcb}
	tokenGroupInitializeMemberDiscriminator = []byte{0x98, 0x20, 0xde, 0xb0, 0xdf, 0xed, 0x74, 0x86}
)

// Field selectors of UpdateField's Field enum (a Borsh enum: one tag byte, and
// only Key carries a string).
const (
	TokenMetadataFieldName uint8 = iota
	TokenMetadataFieldSymbol
	TokenMetadataFieldUri
	TokenMetadataFieldKey
)

// TokenMetadata is the TokenMetadata extension's state, read back from a
// mint's TLV data: update_authority(32, all zero = none) + mint(32) + name +
// symbol + uri (each a Borsh string, u32 length then bytes) + additional
// metadata (u32 count, then key/value string pairs). It is variable length,
// which is why data-size cannot size a mint for it and why writing it costs
// rent as it grows.
type TokenMetadata struct {
	UpdateAuthority *types.PublicKey
	Mint            *types.PublicKey
	Name            string
	Symbol          string
	Uri             string
	Additional      [][2]string
}

// TokenMetadataDataLen is the length of the extension's data for the given
// contents, the TLV length field's value.
func TokenMetadataDataLen(name, symbol, uri string, additional [][2]string) int {
	n := 32 + 32 + 4 + len(name) + 4 + len(symbol) + 4 + len(uri) + 4
	for _, kv := range additional {
		n += 4 + len(kv[0]) + 4 + len(kv[1])
	}

	return n
}

// DecodeTokenMetadata reads a mint's TokenMetadata extension.
func DecodeTokenMetadata(mintData []byte) (*TokenMetadata, error) {
	raw := FindExtensionData(mintData, ExtensionTypeTokenMetadata)
	if raw == nil {
		return nil, fmt.Errorf("mint does not carry the TokenMetadata extension")
	}
	if len(raw) < 64 {
		return nil, fmt.Errorf("token metadata: %d bytes, expected at least 64", len(raw))
	}

	m := &TokenMetadata{}
	var err error
	if allZero(raw[:32]) {
		m.UpdateAuthority = nil
	} else if m.UpdateAuthority, err = types.NewPublicKeyFromBytes(raw[:32]); err != nil {
		return nil, err
	}
	if m.Mint, err = types.NewPublicKeyFromBytes(raw[32:64]); err != nil {
		return nil, err
	}

	rest := raw[64:]
	readString := func() (string, error) {
		if len(rest) < 4 {
			return "", fmt.Errorf("token metadata: truncated string length")
		}
		n := int(binary.LittleEndian.Uint32(rest[:4]))
		if len(rest) < 4+n {
			return "", fmt.Errorf("token metadata: truncated string")
		}
		s := string(rest[4 : 4+n])
		rest = rest[4+n:]
		return s, nil
	}
	if m.Name, err = readString(); err != nil {
		return nil, err
	}
	if m.Symbol, err = readString(); err != nil {
		return nil, err
	}
	if m.Uri, err = readString(); err != nil {
		return nil, err
	}
	if len(rest) < 4 {
		return nil, fmt.Errorf("token metadata: truncated additional metadata count")
	}
	count := int(binary.LittleEndian.Uint32(rest[:4]))
	rest = rest[4:]
	for i := 0; i < count; i++ {
		k, err := readString()
		if err != nil {
			return nil, err
		}
		v, err := readString()
		if err != nil {
			return nil, err
		}
		m.Additional = append(m.Additional, [2]string{k, v})
	}

	return m, nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// appendBorshString appends a Borsh string: u32 little-endian length, then the
// UTF-8 bytes.
func appendBorshString(dst []byte, s string) []byte {
	dst = codec.Binary.AppendU32(dst, uint32(len(s)))
	return append(dst, s...)
}

// InitializeTokenMetadata writes the TokenMetadata extension into mint --
// name, symbol and uri (the uri points at a JSON document, which is where the
// image lives) -- with updateAuthority (nil for none) allowed to change it
// later. Interface instruction Initialize; data is the discriminator then the
// three Borsh strings; accounts are [metadata(writable), update
// authority(readonly), mint(readonly), mint authority(signer)]. For
// Token-2022's own implementation the metadata account is the mint itself, so
// the mint needs a MetadataPointer pointing at itself, and it has to hold the
// rent for the bigger account before this runs: the program grows the account
// but does not pay for it.
func (t *token) InitializeTokenMetadata(mint, updateAuthority, mintAuthority *types.PublicKey, name, symbol, uri string) (*types.Instruction, error) {
	const label = "token metadata initialize"
	if mint.IsNil() {
		return nil, fmt.Errorf("%s: mint is required", label)
	}
	if mintAuthority.IsNil() {
		return nil, fmt.Errorf("%s: mint authority is required", label)
	}

	data := append([]byte(nil), tokenMetadataInitializeDiscriminator...)
	data = appendBorshString(data, name)
	data = appendBorshString(data, symbol)
	data = appendBorshString(data, uri)

	authority := updateAuthority
	if authority.IsNil() {
		authority = SystemProgramID // all zero bytes: no update authority
	}

	return types.NewInstruction(t.id, types.NewAccounts(
		types.NewWritableAccount(mint),
		types.NewReadonlyAccount(authority),
		types.NewReadonlyAccount(mint),
		types.NewReadonlySignerAccount(mintAuthority),
	), data), nil
}

// UpdateTokenMetadataField sets one field of mint's TokenMetadata: name,
// symbol, uri, or an additional key (field TokenMetadataFieldKey with key
// naming it). A new key is created, an existing one overwritten, and the
// account is resized to fit -- growing it needs rent the caller has to have
// put on the mint first. Interface instruction UpdateField; data is the
// discriminator, the Field enum (tag byte, then the key string for Key), then
// the value string; accounts are [metadata(writable), update
// authority(signer)].
func (t *token) UpdateTokenMetadataField(mint, updateAuthority *types.PublicKey, field uint8, key, value string) (*types.Instruction, error) {
	const label = "token metadata update field"
	if mint.IsNil() {
		return nil, fmt.Errorf("%s: mint is required", label)
	}
	if updateAuthority.IsNil() {
		return nil, fmt.Errorf("%s: update authority is required", label)
	}
	if field > TokenMetadataFieldKey {
		return nil, fmt.Errorf("%s: unknown field %d", label, field)
	}
	if field == TokenMetadataFieldKey && key == "" {
		return nil, fmt.Errorf("%s: key is required for an additional field", label)
	}

	data := append([]byte(nil), tokenMetadataUpdateFieldDiscriminator...)
	data = codec.Binary.AppendU8(data, field)
	if field == TokenMetadataFieldKey {
		data = appendBorshString(data, key)
	}
	data = appendBorshString(data, value)

	return types.NewInstruction(t.id, types.NewAccounts(
		types.NewWritableAccount(mint),
		types.NewReadonlySignerAccount(updateAuthority),
	), data), nil
}

// RemoveTokenMetadataKey deletes an additional key from mint's TokenMetadata
// (never name, symbol or uri). With idempotent set a missing key is not an
// error. Interface instruction RemoveKey; data is the discriminator, the
// idempotent flag (1 byte), then the key string; accounts are
// [metadata(writable), update authority(signer)].
func (t *token) RemoveTokenMetadataKey(mint, updateAuthority *types.PublicKey, key string, idempotent bool) (*types.Instruction, error) {
	const label = "token metadata remove key"
	if mint.IsNil() {
		return nil, fmt.Errorf("%s: mint is required", label)
	}
	if updateAuthority.IsNil() {
		return nil, fmt.Errorf("%s: update authority is required", label)
	}
	if key == "" {
		return nil, fmt.Errorf("%s: key is required", label)
	}

	data := append([]byte(nil), tokenMetadataRemoveKeyDiscriminator...)
	if idempotent {
		data = codec.Binary.AppendU8(data, 1)
	} else {
		data = codec.Binary.AppendU8(data, 0)
	}
	data = appendBorshString(data, key)

	return types.NewInstruction(t.id, types.NewAccounts(
		types.NewWritableAccount(mint),
		types.NewReadonlySignerAccount(updateAuthority),
	), data), nil
}

// UpdateTokenMetadataAuthority hands mint's TokenMetadata update authority to
// newAuthority, or clears it with nil -- permanently, since with none nobody can
// sign for it again. Interface instruction UpdateAuthority; data is the
// discriminator then the new authority (32 bytes, all zero = none); accounts
// are [metadata(writable), current update authority(signer)].
func (t *token) UpdateTokenMetadataAuthority(mint, updateAuthority, newAuthority *types.PublicKey) (*types.Instruction, error) {
	const label = "token metadata update authority"
	if mint.IsNil() {
		return nil, fmt.Errorf("%s: mint is required", label)
	}
	if updateAuthority.IsNil() {
		return nil, fmt.Errorf("%s: update authority is required", label)
	}

	data := append([]byte(nil), tokenMetadataUpdateAuthorityDiscriminator...)
	data = appendMaybeNullAddress(data, newAuthority)

	return types.NewInstruction(t.id, types.NewAccounts(
		types.NewWritableAccount(mint),
		types.NewReadonlySignerAccount(updateAuthority),
	), data), nil
}

// EmitTokenMetadata makes the program return mint's TokenMetadata as return
// data, optionally only the byte range [start, end). Interface instruction
// Emit; data is the discriminator then two Borsh Option<u64> (a tag byte, then
// the u64 when present); accounts are [metadata(readonly)]. It changes
// nothing, so it is only useful simulated.
func (t *token) EmitTokenMetadata(mint *types.PublicKey, start, end *uint64) (*types.Instruction, error) {
	if mint.IsNil() {
		return nil, fmt.Errorf("token metadata emit: mint is required")
	}

	data := append([]byte(nil), tokenMetadataEmitDiscriminator...)
	for _, v := range []*uint64{start, end} {
		if v == nil {
			data = codec.Binary.AppendU8(data, 0)
		} else {
			data = codec.Binary.AppendU8(data, 1)
			data = codec.Binary.AppendU64(data, *v)
		}
	}

	return types.NewInstruction(t.id, types.NewAccounts(types.NewReadonlyAccount(mint)), data), nil
}

// TokenGroup is the TokenGroup extension's state: update_authority(32, all zero
// = none) + mint(32) + size(u64, members so far) + max_size(u64).
type TokenGroup struct {
	UpdateAuthority *types.PublicKey
	Mint            *types.PublicKey
	Size            uint64
	MaxSize         uint64
}

// DecodeTokenGroup reads a mint's TokenGroup extension.
func DecodeTokenGroup(mintData []byte) (*TokenGroup, error) {
	raw := FindExtensionData(mintData, ExtensionTypeTokenGroup)
	if raw == nil {
		return nil, fmt.Errorf("mint does not carry the TokenGroup extension")
	}
	if len(raw) != 80 {
		return nil, fmt.Errorf("token group: %d bytes, expected 80", len(raw))
	}

	g := &TokenGroup{Size: binary.LittleEndian.Uint64(raw[64:72]), MaxSize: binary.LittleEndian.Uint64(raw[72:80])}
	var err error
	if !allZero(raw[:32]) {
		if g.UpdateAuthority, err = types.NewPublicKeyFromBytes(raw[:32]); err != nil {
			return nil, err
		}
	}
	if g.Mint, err = types.NewPublicKeyFromBytes(raw[32:64]); err != nil {
		return nil, err
	}

	return g, nil
}

// InitializeTokenGroup makes mint a group: updateAuthority (nil for none) may
// change it later and it holds at most maxSize members. Interface instruction
// InitializeGroup; data is the discriminator, the update authority (32, all
// zero = none), then max size (u64); accounts are [group(writable),
// mint(readonly), mint authority(signer)]. For Token-2022's own implementation
// the group account is the mint itself, which needs a GroupPointer pointing at
// itself and the rent for the bigger account before this runs.
func (t *token) InitializeTokenGroup(mint, updateAuthority, mintAuthority *types.PublicKey, maxSize uint64) (*types.Instruction, error) {
	const label = "token group initialize"
	if mint.IsNil() {
		return nil, fmt.Errorf("%s: mint is required", label)
	}
	if mintAuthority.IsNil() {
		return nil, fmt.Errorf("%s: mint authority is required", label)
	}

	data := append([]byte(nil), tokenGroupInitializeDiscriminator...)
	data = appendMaybeNullAddress(data, updateAuthority)
	data = codec.Binary.AppendU64(data, maxSize)

	return types.NewInstruction(t.id, types.NewAccounts(
		types.NewWritableAccount(mint),
		types.NewReadonlyAccount(mint),
		types.NewReadonlySignerAccount(mintAuthority),
	), data), nil
}

// UpdateTokenGroupMaxSize changes how many members the group may hold; it
// cannot go below the current size. Interface instruction UpdateGroupMaxSize;
// data is the discriminator then the max size (u64); accounts are
// [group(writable), update authority(signer)].
func (t *token) UpdateTokenGroupMaxSize(mint, updateAuthority *types.PublicKey, maxSize uint64) (*types.Instruction, error) {
	const label = "token group update max size"
	if mint.IsNil() {
		return nil, fmt.Errorf("%s: mint is required", label)
	}
	if updateAuthority.IsNil() {
		return nil, fmt.Errorf("%s: update authority is required", label)
	}

	data := append([]byte(nil), tokenGroupUpdateMaxSizeDiscriminator...)
	data = codec.Binary.AppendU64(data, maxSize)

	return types.NewInstruction(t.id, types.NewAccounts(
		types.NewWritableAccount(mint),
		types.NewReadonlySignerAccount(updateAuthority),
	), data), nil
}

// UpdateTokenGroupAuthority hands the group's update authority to newAuthority,
// or clears it with nil -- permanently. Interface instruction
// UpdateGroupAuthority; data is the discriminator then the new authority (32,
// all zero = none); accounts are [group(writable), current authority(signer)].
func (t *token) UpdateTokenGroupAuthority(mint, updateAuthority, newAuthority *types.PublicKey) (*types.Instruction, error) {
	const label = "token group update authority"
	if mint.IsNil() {
		return nil, fmt.Errorf("%s: mint is required", label)
	}
	if updateAuthority.IsNil() {
		return nil, fmt.Errorf("%s: update authority is required", label)
	}

	data := append([]byte(nil), tokenGroupUpdateAuthorityDiscriminator...)
	data = appendMaybeNullAddress(data, newAuthority)

	return types.NewInstruction(t.id, types.NewAccounts(
		types.NewWritableAccount(mint),
		types.NewReadonlySignerAccount(updateAuthority),
	), data), nil
}

// InitializeTokenGroupMember makes memberMint a member of the group held by
// groupMint, numbering it and counting it in the group's size. Interface
// instruction InitializeMember; no data beyond the discriminator; accounts are
// [member(writable), member mint(readonly), member mint authority(signer),
// group(writable), group update authority(signer)]. For Token-2022's own
// implementation the member account is the member mint and the group account
// the group mint; the member needs a GroupMemberPointer pointing at itself and
// the rent for the bigger account before this runs.
func (t *token) InitializeTokenGroupMember(memberMint, memberMintAuthority, groupMint, groupUpdateAuthority *types.PublicKey) (*types.Instruction, error) {
	const label = "token group initialize member"
	if memberMint.IsNil() || memberMintAuthority.IsNil() || groupMint.IsNil() || groupUpdateAuthority.IsNil() {
		return nil, fmt.Errorf("%s: member mint, member mint authority, group mint and group update authority are all required", label)
	}

	return types.NewInstruction(t.id, types.NewAccounts(
		types.NewWritableAccount(memberMint),
		types.NewReadonlyAccount(memberMint),
		types.NewReadonlySignerAccount(memberMintAuthority),
		types.NewWritableAccount(groupMint),
		types.NewReadonlySignerAccount(groupUpdateAuthority),
	), append([]byte(nil), tokenGroupInitializeMemberDiscriminator...)), nil
}
