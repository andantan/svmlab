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

	out, err := codec.Bincode.AppendShortVecLen(nil, len(t.Signatures))
	if err != nil {
		return nil, fmt.Errorf("transaction signatures: %w", err)
	}
	for i, sig := range t.Signatures {
		if sig.IsNil() {
			return nil, fmt.Errorf("transaction: signature[%d] is nil", i)
		}
		out = codec.Bincode.AppendBytes(out, sig.Bytes())
	}

	message, err := t.Message.Serialize()
	if err != nil {
		return nil, fmt.Errorf("transaction message: %w", err)
	}
	out = codec.Bincode.AppendBytes(out, message)

	if len(out) > MaxTransactionSize {
		return nil, fmt.Errorf("transaction: %d bytes exceeds the %d byte limit", len(out), MaxTransactionSize)
	}

	return out, nil
}

// DeserializeTransaction parses the wire format.
func DeserializeTransaction(raw []byte) (*Transaction, error) {
	n, size, err := codec.Bincode.ReadShortVecLen(raw)
	if err != nil {
		return nil, fmt.Errorf("transaction signatures: %w", err)
	}
	raw = raw[size:]

	signatures := make([]*Signature, n)
	for i := range signatures {
		var b []byte
		if b, raw, err = codec.Bincode.ReadBytes(raw, SignatureLength); err != nil {
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
