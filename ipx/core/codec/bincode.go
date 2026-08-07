package codec

import (
	"encoding/binary"
	"fmt"
	"math"
)

type bincodeCodec struct{}

var Bincode = new(bincodeCodec)

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
func (c *bincodeCodec) AppendU8(dst []byte, v uint8) []byte {
	return append(dst, v)
}

// AppendU32 appends a little-endian uint32.
//
// Instruction discriminants are u32, so this is what selects a System Program
// operation, in the role an EVM four-byte selector plays.
func (c *bincodeCodec) AppendU32(dst []byte, v uint32) []byte {
	return binary.LittleEndian.AppendUint32(dst, v)
}

// AppendU64 appends a little-endian uint64, the width of every lamport amount.
func (c *bincodeCodec) AppendU64(dst []byte, v uint64) []byte {
	return binary.LittleEndian.AppendUint64(dst, v)
}

// AppendBytes appends raw bytes with no length prefix, for fixed-width values
// such as a public key, a hash, or a signature.
func (c *bincodeCodec) AppendBytes(dst []byte, b []byte) []byte {
	return append(dst, b...)
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
func (c *bincodeCodec) AppendShortVecLen(dst []byte, n int) ([]byte, error) {
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
func (c *bincodeCodec) ShortVecLenSize(n int) (int, error) {
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
func (c *bincodeCodec) ReadShortVecLen(src []byte) (int, int, error) {
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
func (c *bincodeCodec) ReadU8(src []byte) (uint8, []byte, error) {
	if len(src) < 1 {
		return 0, nil, fmt.Errorf("bincode: need 1 byte for u8 but got: %d", len(src))
	}

	return src[0], src[1:], nil
}

// ReadU32 reads a little-endian uint32 and returns the remaining input.
func (c *bincodeCodec) ReadU32(src []byte) (uint32, []byte, error) {
	if len(src) < 4 {
		return 0, nil, fmt.Errorf("bincode: need 4 bytes for u32 but got: %d", len(src))
	}

	return binary.LittleEndian.Uint32(src), src[4:], nil
}

// ReadU64 reads a little-endian uint64 and returns the remaining input.
func (c *bincodeCodec) ReadU64(src []byte) (uint64, []byte, error) {
	if len(src) < 8 {
		return 0, nil, fmt.Errorf("bincode: need 8 bytes for u64 but got: %d", len(src))
	}

	return binary.LittleEndian.Uint64(src), src[8:], nil
}

// ReadBytes reads n raw bytes and returns the remaining input.
func (c *bincodeCodec) ReadBytes(src []byte, n int) ([]byte, []byte, error) {
	if n < 0 {
		return nil, nil, fmt.Errorf("bincode: negative read length: %d", n)
	}
	if len(src) < n {
		return nil, nil, fmt.Errorf("bincode: need %d bytes but got: %d", n, len(src))
	}

	return src[:n], src[n:], nil
}
