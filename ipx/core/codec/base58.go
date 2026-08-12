package codec

import "fmt"

// Base58Alphabet is the Bitcoin base58 alphabet, which omits the visually
// ambiguous characters 0, O, I, and l.
const Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Invalid marks a byte that is not part of the base58 alphabet.
//
// 0xff is the sentinel rather than 0x00 because 0x00 is the legitimate value
// of '1', the character every all-zero account address is made of.
const base58Invalid = 0xff

// base58Index maps an ASCII byte to its base58 digit value, or base58Invalid
// if the byte is not part of the alphabet. It is the inverse of
// Base58Alphabet and must be regenerated if that constant ever changes.
//
// Note the gaps carved out of the otherwise contiguous ASCII runs: '0' (0x30),
// 'I' (0x49), 'O' (0x4F), and 'l' (0x6C) are excluded from the alphabet
// because they are easy to confuse with 'O', 'l', '0', and 'I'.
var base58Index = [256]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 0x00-0x0F
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 0x10-0x1F
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 0x20-0x2F  ' '..'/'
	0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 0x30-0x3F  '0'..'?'
	0xff, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0xff, 0x11, 0x12, 0x13, 0x14, 0x15, 0xff, // 0x40-0x4F  '@'..'O'
	0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, // 0x50-0x5F  'P'..'_'
	0xff, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0xff, 0x2c, 0x2d, 0x2e, // 0x60-0x6F  '`'..'o'
	0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xff, 0xff, 0xff, 0xff, 0xff, // 0x70-0x7F  'p'..DEL
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 0x80-0x8F
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 0x90-0x9F
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 0xA0-0xAF
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 0xB0-0xBF
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 0xC0-0xCF
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 0xD0-0xDF
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 0xE0-0xEF
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 0xF0-0xFF
}

type base58Codec struct{}

// Base58 encodes and decodes the Bitcoin base58 representation used
// throughout Solana for public keys, signatures, blockhashes, and
// transaction ids.
//
// The encoding is case-sensitive: unlike hex, two base58 strings differing
// only in case decode to different byte sequences.
var Base58 = new(base58Codec)

// Encode returns the base58 representation of b.
//
// Leading zero bytes are preserved as leading '1' characters, so the encoding
// stays length-stable for fixed-width values such as 32-byte public keys.
func (c *base58Codec) Encode(b []byte) string {
	// log(256)/log(58) ≈ 1.365; 138/100 is the conventional safe bound.
	size := len(b)*138/100 + 1
	buf := make([]byte, size)

	high := size - 1
	for _, v := range b {
		j := size - 1
		for carry := int(v); j > high || carry != 0; j-- {
			carry += 256 * int(buf[j])
			buf[j] = byte(carry % 58)
			carry /= 58
		}
		high = j
	}

	// Strip the zero padding the loop left at the front of buf.
	k := 0
	for k < size && buf[k] == 0 {
		k++
	}

	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}

	out := make([]byte, zeros+size-k)
	for i := range zeros {
		out[i] = Base58Alphabet[0]
	}
	for i, v := range buf[k:] {
		out[zeros+i] = Base58Alphabet[v]
	}

	return string(out)
}

// Decode parses a base58 string into its byte representation.
//
// Leading '1' characters decode back to leading zero bytes.
func (c *base58Codec) Decode(s string) ([]byte, error) {
	// log(58)/log(256) ≈ 0.7325; 733/1000 is the conventional safe bound.
	size := len(s)*733/1000 + 1
	buf := make([]byte, size)

	high := size - 1
	for i := range len(s) {
		v := base58Index[s[i]]
		if v == base58Invalid {
			return nil, fmt.Errorf("base58: invalid character %q at index %d", s[i], i)
		}

		j := size - 1
		for carry := int(v); j > high || carry != 0; j-- {
			carry += 58 * int(buf[j])
			buf[j] = byte(carry % 256)
			carry /= 256
		}
		high = j
	}

	k := 0
	for k < size && buf[k] == 0 {
		k++
	}

	zeros := 0
	for zeros < len(s) && s[zeros] == Base58Alphabet[0] {
		zeros++
	}

	out := make([]byte, zeros+size-k)
	copy(out[zeros:], buf[k:])

	return out, nil
}

// DecodeFixed parses a base58 string and asserts the decoded length, which is
// the common case for Solana's fixed-width types: 32-byte public keys and
// blockhashes, 64-byte signatures and expanded secret keys.
func (c *base58Codec) DecodeFixed(s string, n int) ([]byte, error) {
	b, err := c.Decode(s)
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, fmt.Errorf("base58: expected %d bytes but decoded %d", n, len(b))
	}

	return b, nil
}

// ToBase64 re-encodes a base58 string as base64, decoding and re-encoding
// rather than transliterating: the two alphabets share no digit values, so
// there is no shortcut between them, only the bytes underneath. This is what
// an external transaction handed over in base58 needs before it goes into
// this project's RPC calls, which take base64 the way the cluster itself
// does.
func (c *base58Codec) ToBase64(s string) (string, error) {
	b, err := c.Decode(s)
	if err != nil {
		return "", err
	}

	return Base64.Encode(b), nil
}
