package types

import (
	"fmt"
	"strings"

	"github.com/andantan/svmlab/core/codec"
)

// MaxTransactionSize is the serialized size a transaction must fit in.
//
// The limit comes from the network rather than from consensus: a transaction
// travels in a single UDP packet, and 1232 is what remains of the 1280-byte
// IPv6 minimum MTU after headers. Nothing splits a transaction across packets,
// so exceeding this makes it unsendable rather than merely expensive. It is
// the closest analogue to an EVM block gas limit, except that it bounds size
// rather than work and cannot be raised by paying more.
const MaxTransactionSize = 1232

// Transaction is a message plus the signatures authorizing it.
//
// Signature i belongs to account key i. That positional pairing is the whole
// mechanism: ed25519 offers no key recovery, so nothing can be learned about a
// signer from the signature itself, and the message's leading account keys are
// the only statement of who signed.
//
// The count is fixed by the message header before any signing happens, since
// the array length is part of the serialized bytes and every signer must sign
// the identical message.
type Transaction struct {
	Signatures []*Signature
	Message    *Message
}

// NewTransaction returns an unsigned transaction with one empty signature slot
// per required signer.
func NewTransaction(message *Message) (*Transaction, error) {
	if message.IsNil() {
		return nil, fmt.Errorf("transaction: message is required")
	}

	signatures := make([]*Signature, message.NumSigners())
	for i := range signatures {
		signatures[i] = NewEmptySignature()
	}

	return &Transaction{
		Signatures: signatures,
		Message:    message,
	}, nil
}

func (t *Transaction) IsNil() bool {
	if t == nil || t.Message.IsNil() {
		return true
	}

	return false
}

// SignerIndex reports which signature slot belongs to a key.
//
// Only the leading account keys sign, so a key present in the message but
// outside that range is an error rather than a missing entry: signing with it
// would overwrite another signer's slot.
func (t *Transaction) SignerIndex(k *PublicKey) (int, error) {
	for i, key := range t.Message.Signers() {
		if key.Equal(k) {
			return i, nil
		}
	}

	return 0, fmt.Errorf("transaction: %s is not a required signer", k)
}

// SetSignature stores a signature in the slot belonging to its signer.
func (t *Transaction) SetSignature(k *PublicKey, sig *Signature) error {
	i, err := t.SignerIndex(k)
	if err != nil {
		return err
	}
	t.Signatures[i] = sig

	return nil
}

// IsFullySigned reports whether every required slot has been filled.
//
// A partially signed transaction is a normal intermediate state: co-signers
// each fill their own slot, passing the same serialized bytes along, and only
// the complete result can be sent.
func (t *Transaction) IsFullySigned() bool {
	if len(t.Signatures) != t.Message.NumSigners() {
		return false
	}
	for _, sig := range t.Signatures {
		if sig.IsNil() || sig.IsZero() {
			return false
		}
	}

	return true
}

// ID returns the transaction id, which is the fee payer's signature.
//
// A transaction therefore has no id until it is signed. This differs from an
// EVM hash, which is the keccak256 of the encoded transaction and exists for
// any well-formed payload, signed or not.
func (t *Transaction) ID() (*Signature, error) {
	if len(t.Signatures) == 0 || t.Signatures[0].IsNil() || t.Signatures[0].IsZero() {
		return nil, fmt.Errorf("transaction: not signed")
	}

	return t.Signatures[0], nil
}

// Serialize writes the wire format:
//
//	short-vec  number of signatures
//	[64]byte   signatures
//	...        message
func (t *Transaction) Serialize() ([]byte, error) {
	if len(t.Signatures) != t.Message.NumSigners() {
		return nil, fmt.Errorf("transaction: %d signatures but the message requires %d",
			len(t.Signatures), t.Message.NumSigners())
	}

	out, err := codec.Binary.AppendShortVecLen(nil, len(t.Signatures))
	if err != nil {
		return nil, fmt.Errorf("transaction signatures: %w", err)
	}
	for i, sig := range t.Signatures {
		if sig.IsNil() {
			return nil, fmt.Errorf("transaction: signature[%d] is nil", i)
		}
		out = codec.Binary.AppendBytes(out, sig.Bytes())
	}

	message, err := t.Message.Serialize()
	if err != nil {
		return nil, fmt.Errorf("transaction message: %w", err)
	}
	out = codec.Binary.AppendBytes(out, message)

	if len(out) > MaxTransactionSize {
		return nil, fmt.Errorf("transaction: %d bytes exceeds the %d byte limit", len(out), MaxTransactionSize)
	}

	return out, nil
}

// IsVersionedTransaction peeks the byte that opens the message, just past the
// signature array, without otherwise reading it.
//
// A versioned message sets that byte's high bit; a legacy one cannot, since
// its own first byte is a signature count that DeserializeMessage bounds well
// below 128. The two callers that need this — DeserializeTransaction, to
// reject a version it does not model, and a signer placing a signature into a
// wire-format transaction it never parses into a *Message at all — both stop
// here rather than duplicating the peek.
func IsVersionedTransaction(raw []byte) (bool, error) {
	n, prefix, err := codec.Binary.ReadShortVecLen(raw)
	if err != nil {
		return false, fmt.Errorf("transaction signatures: %w", err)
	}

	messageStart := prefix + n*SignatureLength
	if len(raw) <= messageStart {
		return false, fmt.Errorf("transaction: %d bytes is too short for %d signatures and a message", len(raw), n)
	}

	return raw[messageStart]&0x80 != 0, nil
}

// IsFullySignedTransaction reports whether every signature slot in a
// serialized transaction is filled, reading only the signature array.
//
// Like IsVersionedTransaction, this answers a question about the wire format
// without parsing the message the signatures belong to. Sending and
// simulating both gate on this, and neither otherwise needs the message
// parsed either — only the raw bytes travel over RPC — so requiring a full
// legacy-only DeserializeTransaction first would reject a versioned
// transaction for a reason that has nothing to do with why either endpoint
// reads it.
func IsFullySignedTransaction(raw []byte) (bool, error) {
	n, prefix, err := codec.Binary.ReadShortVecLen(raw)
	if err != nil {
		return false, fmt.Errorf("transaction signatures: %w", err)
	}
	if len(raw) < prefix+n*SignatureLength {
		return false, fmt.Errorf("transaction: %d bytes is too short for %d signatures", len(raw), n)
	}

	for i := 0; i < n; i++ {
		start := prefix + i*SignatureLength
		zero := true
		for _, b := range raw[start : start+SignatureLength] {
			if b != 0 {
				zero = false
				break
			}
		}
		if zero {
			return false, nil
		}
	}

	return true, nil
}

// DecodeFullySignedTransaction decodes a base64 transaction and checks that
// every signature slot is filled, without parsing the message inside it. It
// returns raw bytes rather than a *Transaction because that type only
// models a legacy message — a versioned (v0) transaction has no
// Transaction to parse into, and this check has to pass for either.
func DecodeFullySignedTransaction(transaction string) ([]byte, error) {
	raw, err := codec.Base64.Decode(strings.TrimSpace(transaction))
	if err != nil {
		return nil, fmt.Errorf("transaction: invalid base64: %w", err)
	}

	fullySigned, err := IsFullySignedTransaction(raw)
	if err != nil {
		return nil, fmt.Errorf("transaction: %w", err)
	}
	if !fullySigned {
		return nil, fmt.Errorf("transaction: is not fully signed")
	}

	return raw, nil
}

// RefreshTransactionBlockhash replaces an unsigned transaction's recent
// blockhash in place, without parsing the message into a *Message.
//
// It works the same way SignRawTransaction locates a signer's slot: a
// blockhash sits at a fixed offset past the header and the account key
// list, whether the message is legacy or versioned, so finding it costs a
// header and two short-vec counts, not the instructions or address lookup
// tables that follow.
//
// The transaction must be unsigned. A signature commits to the exact
// message bytes it was produced over, so changing the blockhash after
// signing would leave every existing signature invalid without anything
// here able to tell — better to refuse a transaction carrying any signature
// than hand back one whose signatures silently stopped meaning anything.
func RefreshTransactionBlockhash(raw []byte, blockhash *Hash) ([]byte, error) {
	if blockhash.IsNil() {
		return nil, fmt.Errorf("transaction: blockhash is nil")
	}

	n, sigPrefixSize, err := codec.Binary.ReadShortVecLen(raw)
	if err != nil {
		return nil, fmt.Errorf("transaction signatures: %w", err)
	}
	sigSectionEnd := sigPrefixSize + n*SignatureLength
	if len(raw) < sigSectionEnd {
		return nil, fmt.Errorf("transaction: %d bytes is too short for %d signatures", len(raw), n)
	}
	for i := range n {
		start := sigPrefixSize + i*SignatureLength
		for _, b := range raw[start : start+SignatureLength] {
			if b != 0 {
				return nil, fmt.Errorf("transaction: already signed, refreshing the blockhash would invalidate every signature")
			}
		}
	}

	versioned, err := IsVersionedTransaction(raw)
	if err != nil {
		return nil, fmt.Errorf("transaction: %w", err)
	}

	message := raw[sigSectionEnd:]
	offset := 0
	if versioned {
		offset = 1
	}
	if len(message) < offset+MessageHeaderLength {
		return nil, fmt.Errorf("transaction: message is too short for a header")
	}

	keyCount, keyCountSize, err := codec.Binary.ReadShortVecLen(message[offset+MessageHeaderLength:])
	if err != nil {
		return nil, fmt.Errorf("transaction: account key count: %w", err)
	}

	keysStart := offset + MessageHeaderLength + keyCountSize
	keysEnd := keysStart + keyCount*PublicKeyLength
	blockhashEnd := keysEnd + HashLength
	if len(message) < blockhashEnd {
		return nil, fmt.Errorf("transaction: message is too short for a blockhash")
	}

	out := make([]byte, len(raw))
	copy(out, raw)
	copy(out[sigSectionEnd+keysEnd:], blockhash.Bytes())

	return out, nil
}

// ToLegacyTransaction returns raw in the legacy wire format.
//
// A legacy transaction comes back as it went in. A versioned (v0) one that
// declares no address lookup tables is the same transaction in a different
// envelope — a version byte in front, an empty table count behind, and
// nothing else between them — so it is rewritten rather than refused, which
// is what lets anything downstream take a *Transaction without modelling v0.
//
// One that does use a lookup table cannot be rewritten. Its instructions
// index accounts the message never lists: the keys those indexes stand for
// live only in tables held on chain, so resolving them means reading each
// table off the cluster, which is the address lookup table work this project
// has not done. Refusing is the honest answer, since dropping the section
// would leave every index past the static keys pointing somewhere else.
func ToLegacyTransaction(raw []byte) ([]byte, error) {
	versioned, err := IsVersionedTransaction(raw)
	if err != nil {
		return nil, err
	}
	if !versioned {
		return raw, nil
	}

	n, sigPrefixSize, err := codec.Binary.ReadShortVecLen(raw)
	if err != nil {
		return nil, fmt.Errorf("transaction signatures: %w", err)
	}
	sigSectionEnd := sigPrefixSize + n*SignatureLength
	if len(raw) < sigSectionEnd {
		return nil, fmt.Errorf("transaction: %d bytes is too short for %d signatures", len(raw), n)
	}
	message := raw[sigSectionEnd:]

	if v := message[0] & 0x7f; v != 0 {
		return nil, fmt.Errorf("transaction message: version %d is not supported", v)
	}

	rest := message[1:]
	if len(rest) < MessageHeaderLength {
		return nil, fmt.Errorf("transaction message: too short for a header")
	}
	rest = rest[MessageHeaderLength:]

	keyCount, size, err := codec.Binary.ReadShortVecLen(rest)
	if err != nil {
		return nil, fmt.Errorf("transaction message account keys: %w", err)
	}
	rest = rest[size:]
	if len(rest) < keyCount*PublicKeyLength+HashLength {
		return nil, fmt.Errorf("transaction message: too short for %d account keys and a blockhash", keyCount)
	}
	rest = rest[keyCount*PublicKeyLength+HashLength:]

	ixCount, size, err := codec.Binary.ReadShortVecLen(rest)
	if err != nil {
		return nil, fmt.Errorf("transaction message instructions: %w", err)
	}
	rest = rest[size:]
	for i := range ixCount {
		if _, rest, err = DeserializeCompiledInstruction(rest); err != nil {
			return nil, fmt.Errorf("transaction message instruction[%d]: %w", i, err)
		}
	}

	tables, size, err := codec.Binary.ReadShortVecLen(rest)
	if err != nil {
		return nil, fmt.Errorf("transaction message address lookup tables: %w", err)
	}
	if tables != 0 {
		return nil, fmt.Errorf(
			"transaction message: %d address lookup tables are not supported, since the accounts they hold are not in the message",
			tables)
	}
	if len(rest) != size {
		return nil, fmt.Errorf("transaction message: %d trailing bytes", len(rest)-size)
	}

	out := make([]byte, 0, sigSectionEnd+len(message)-1-size)
	out = append(out, raw[:sigSectionEnd]...)
	out = append(out, message[1:len(message)-size]...)

	return out, nil
}

// DeserializeTransaction parses the wire format.
func DeserializeTransaction(raw []byte) (*Transaction, error) {
	n, size, err := codec.Binary.ReadShortVecLen(raw)
	if err != nil {
		return nil, fmt.Errorf("transaction signatures: %w", err)
	}
	raw = raw[size:]

	signatures := make([]*Signature, n)
	for i := range signatures {
		var b []byte
		if b, raw, err = codec.Binary.ReadBytes(raw, SignatureLength); err != nil {
			return nil, fmt.Errorf("transaction signature[%d]: %w", i, err)
		}
		if signatures[i], err = NewSignature(b); err != nil {
			return nil, fmt.Errorf("transaction signature[%d]: %w", i, err)
		}
	}

	message, err := DeserializeMessage(raw)
	if err != nil {
		return nil, fmt.Errorf("transaction message: %w", err)
	}

	if len(signatures) != message.NumSigners() {
		return nil, fmt.Errorf("transaction: %d signatures but the message requires %d",
			len(signatures), message.NumSigners())
	}

	return &Transaction{
		Signatures: signatures,
		Message:    message,
	}, nil
}

func (t *Transaction) String() string {
	var sb strings.Builder
	for i, sig := range t.Signatures {
		state := sig.Base58()
		if sig.IsZero() {
			state = "<unsigned>"
		}
		_, _ = fmt.Fprintf(&sb, "sig[%d] %s %s\n", i, t.Message.AccountKeys[i], state)
	}
	sb.WriteString(t.Message.String())

	return sb.String()
}
