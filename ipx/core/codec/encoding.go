package codec

import (
	"fmt"
	"strings"
)

// DecodeByName decodes s using the codec named by encoding, "base64" or
// "base58". It exists because more than one request body carries an
// explicit encoding field rather than a fixed one, and each needs the exact
// same "which codec, and what if the name is missing or wrong" handling.
//
// encoding has no default: base64 and base58 partially overlap in their
// alphabets, so guessing would decode to different bytes than the caller
// sent rather than failing outright.
func DecodeByName(encoding, s string) ([]byte, error) {
	switch strings.TrimSpace(encoding) {
	case "base64":
		return Base64.Decode(strings.TrimSpace(s))
	case "base58":
		return Base58.Decode(strings.TrimSpace(s))
	case "":
		return nil, fmt.Errorf(`encoding is required: "base64" or "base58"`)
	default:
		return nil, fmt.Errorf(`encoding: must be "base64" or "base58", got %q`, encoding)
	}
}
