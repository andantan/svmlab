package codec

import (
	"encoding/binary"
	"fmt"
	"math"
)

type binaryCodec struct{}

var Binary = new(binaryCodec)

const (
	// ShortVecMaxLen is the largest length a short-vec prefix can express.
	ShortVecMaxLen = math.MaxUint16

	// ShortVecMaxSize is the widest a short-vec prefix can be, since 16 bits
	// need three groups of seven.
	ShortVecMaxSize = 3
)

// The wire format Solana uses is bincode with one substitution: a sequence is
// prefixed by a compact-u16 rather than bincode's fixed u64 length. That saves
// seven bytes on every account list, instruction list, and instruction payload
// in a transaction, which matters against the 1232-byte packet limit.
//
// Everything else follows bincode: fixed-width integers, little endian, no
// tags, no padding, no field names. Compared to RLP the difference is that
// nothing here is self-describing. RLP encodes each item's own length, so a
// decoder can walk a payload it has never seen. A bincode payload is only
// meaningful to a reader that already knows the exact struct layout, which is
// why decoding below is written against Solana's specific message layout
// rather than as a general decoder.

// AppendU8 appends a single byte.
func (_ *binaryCodec) AppendU8(dst []byte, v uint8) []byte {
	return append(dst, v)
}

// AppendU32 appends a little-endian uint32.
//
// Instruction discriminants are u32, so this is what selects a System Program
// operation, in the role an EVM four-byte selector plays.
func (_ *binaryCodec) AppendU32(dst []byte, v uint32) []byte {
	return binary.LittleEndian.AppendUint32(dst, v)
}

// AppendU64 appends a little-endian uint64, the width of every lamport amount.
func (_ *binaryCodec) AppendU64(dst []byte, v uint64) []byte {
	return binary.LittleEndian.AppendUint64(dst, v)
}

// AppendBytes appends raw bytes with no length prefix, for fixed-width values
// such as a public key, a hash, or a signature.
func (_ *binaryCodec) AppendBytes(dst []byte, b []byte) []byte {
	return append(dst, b...)
}

// COption tag values.
//
// This is not Rust's Option. Borsh writes a single tag byte and omits the
// payload when absent; a COption writes a u32 tag and the payload follows
// either way. That fixed width is why an SPL Token mint is 82 bytes whether or
// not it has a freeze authority, and why every account layout that uses one is
// a constant rather than something measured.
const (
	COptionNone uint32 = 0
	COptionSome uint32 = 1
)

// AppendCOption appends a COption whose payload is size bytes.
//
// An absent value still writes its payload, zero-filled, because a reader
// advances by a fixed width and would otherwise fall out of step with every
// field after it.
func (c *binaryCodec) AppendCOption(dst []byte, b []byte, size int) []byte {
	if b == nil {
		dst = c.AppendU32(dst, COptionNone)
		return c.AppendBytes(dst, make([]byte, size))
	}

	dst = c.AppendU32(dst, COptionSome)
	return c.AppendBytes(dst, b)
}

// ReadCOption reads a COption whose payload is size bytes, returning nil when
// the tag says none.
//
// The payload is consumed either way. It is usually zero when absent, but
// nothing guarantees that, so the tag is the only thing that decides.
func (c *binaryCodec) ReadCOption(src []byte, size int) ([]byte, []byte, error) {
	tag, src, err := c.ReadU32(src)
	if err != nil {
		return nil, nil, err
	}

	b, src, err := c.ReadBytes(src, size)
	if err != nil {
		return nil, nil, err
	}

	switch tag {
	case COptionNone:
		return nil, src, nil
	case COptionSome:
		return b, src, nil
	default:
		return nil, nil, fmt.Errorf("COption tag is %d, expected %d or %d", tag, COptionNone, COptionSome)
	}
}

// AppendString appends a bincode string: a u64 length followed by raw UTF-8
// bytes.
//
// The length is a full u64 rather than the short-vec prefix used elsewhere.
// That substitution applies to the sequences a transaction is assembled from,
// meaning the account list, the instruction list, and an instruction's data,
// and not to fields inside an instruction payload, which stay plain bincode.
// A short-vec here would encode the same seed as different bytes, and the
// runtime would derive a different address from them.
func (c *binaryCodec) AppendString(dst []byte, s string) []byte {
	dst = c.AppendU64(dst, uint64(len(s)))

	return append(dst, s...)
}

// AppendShortVecLen appends a compact-u16 length prefix.
//
// The value is split into seven-bit groups, least significant first, and every
// group but the last carries a high continuation bit:
//
//	    0 -> 0x00
//	  127 -> 0x7f
//	  128 -> 0x80 0x01
//	16383 -> 0xff 0x7f
//	16384 -> 0x80 0x80 0x01
//	65535 -> 0xff 0xff 0x03
//
// Below 128 this is a single byte identical to the plain length, which is why
// a wrong implementation still works on short lists and only breaks once a
// transaction carries 128 or more accounts or instruction bytes.
func (_ *binaryCodec) AppendShortVecLen(dst []byte, n int) ([]byte, error) {
	if n < 0 || n > ShortVecMaxLen {
		return nil, fmt.Errorf("short-vec length must be 0..%d but got: %d", ShortVecMaxLen, n)
	}

	v := uint16(n)
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			return append(dst, b), nil
		}
		dst = append(dst, b|0x80)
	}
}

// ShortVecLenSize reports how many bytes AppendShortVecLen would write.
func (_ *binaryCodec) ShortVecLenSize(n int) (int, error) {
	if n < 0 || n > ShortVecMaxLen {
		return 0, fmt.Errorf("short-vec length must be 0..%d but got: %d", ShortVecMaxLen, n)
	}

	switch {
	case n < 0x80:
		return 1, nil
	case n < 0x4000:
		return 2, nil
	default:
		return 3, nil
	}
}

// ReadShortVecLen reads a compact-u16 prefix, returning the length and the
// number of bytes consumed.
//
// A non-canonical encoding is rejected: a length padded into more bytes than
// it needs decodes to the same number but serializes differently, and a
// transaction whose bytes do not round-trip has a different signature than the
// one the sender produced.
func (c *binaryCodec) ReadShortVecLen(src []byte) (int, int, error) {
	n, size := 0, 0
	for {
		if size >= len(src) {
			return 0, 0, fmt.Errorf("short-vec: unexpected end of input after %d bytes", size)
		}

		b := src[size]
		n |= int(b&0x7f) << (7 * size)
		size++

		if b&0x80 == 0 {
			break
		}
		if size == ShortVecMaxSize {
			return 0, 0, fmt.Errorf("short-vec: length exceeds %d bytes", ShortVecMaxSize)
		}
	}

	if n > ShortVecMaxLen {
		return 0, 0, fmt.Errorf("short-vec: length %d exceeds %d", n, ShortVecMaxLen)
	}

	want, err := c.ShortVecLenSize(n)
	if err != nil {
		return 0, 0, err
	}
	if size != want {
		return 0, 0, fmt.Errorf("short-vec: length %d encoded in %d bytes but requires %d", n, size, want)
	}

	return n, size, nil
}

// ReadU8 reads a single byte and returns the remaining input.
func (_ *binaryCodec) ReadU8(src []byte) (uint8, []byte, error) {
	if len(src) < 1 {
		return 0, nil, fmt.Errorf("binary: need 1 byte for u8 but got: %d", len(src))
	}

	return src[0], src[1:], nil
}

// ReadU32 reads a little-endian uint32 and returns the remaining input.
func (_ *binaryCodec) ReadU32(src []byte) (uint32, []byte, error) {
	if len(src) < 4 {
		return 0, nil, fmt.Errorf("binary: need 4 bytes for u32 but got: %d", len(src))
	}

	return binary.LittleEndian.Uint32(src), src[4:], nil
}

// ReadU64 reads a little-endian uint64 and returns the remaining input.
func (_ *binaryCodec) ReadU64(src []byte) (uint64, []byte, error) {
	if len(src) < 8 {
		return 0, nil, fmt.Errorf("binary: need 8 bytes for u64 but got: %d", len(src))
	}

	return binary.LittleEndian.Uint64(src), src[8:], nil
}

// ReadBytes reads n raw bytes and returns the remaining input.
func (_ *binaryCodec) ReadBytes(src []byte, n int) ([]byte, []byte, error) {
	if n < 0 {
		return nil, nil, fmt.Errorf("binary: negative read length: %d", n)
	}
	if len(src) < n {
		return nil, nil, fmt.Errorf("binary: need %d bytes but got: %d", n, len(src))
	}

	return src[:n], src[n:], nil
}
