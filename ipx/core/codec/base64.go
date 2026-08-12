package codec

import "encoding/base64"

type base64Codec struct{}

// Base64 wraps the standard encoding, unlike Base58: base64 already has a
// correct, well-tested implementation in the standard library, so nothing
// here is reimplemented. It exists so every codec is reached the same way,
// codec.X.Encode/Decode, rather than some call through this package and
// others reach into encoding/base64 directly.
var Base64 = new(base64Codec)

// Encode returns the standard (RFC 4648, padded) base64 representation of b.
//
// This is the encoding Solana's RPC layer uses for a transaction and for a
// message, as opposed to the base58 it uses for a public key, a signature, or
// a hash.
func (c *base64Codec) Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// Decode parses the standard (RFC 4648, padded) base64 representation.
func (c *base64Codec) Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// ToBase58 re-encodes a base64 string as base58, decoding and re-encoding
// rather than transliterating, the same as Base58.ToBase64 in the other
// direction. This is what a transaction built as base64 needs before it goes
// anywhere that names an address, a signature, or a hash — anything Solana
// itself renders in base58.
func (c *base64Codec) ToBase58(s string) (string, error) {
	b, err := c.Decode(s)
	if err != nil {
		return "", err
	}

	return Base58.Encode(b), nil
}
