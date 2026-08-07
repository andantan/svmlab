package types

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	UnitLamport = "lamport"
	UnitSol     = "sol"
)

const (
	// SolDecimals is the number of decimal places one SOL divides into.
	SolDecimals = 9

	// LamportsPerSol is the smallest unit count in one SOL.
	LamportsPerSol = 1_000_000_000
)

// Lamports are held in a uint64 rather than the big.Int an EVM balance needs.
//
// Wei has 18 decimals, so a single ether is 10^18 and an ordinary balance
// already exceeds what 64 bits can hold. A lamport has 9, and the entire SOL
// supply is on the order of 10^9 SOL, which is about 10^18 lamports. That
// leaves more than a factor of ten of headroom below 2^64, so every balance
// and every transfer fits.
//
// This is not a stylistic choice: the on-chain representation is a u64. An
// account's lamport field, the System Program's transfer argument, and the
// rent-exempt minimum are all u64, so arithmetic here must overflow exactly
// where the runtime would rather than silently exceeding it.

// LamportsToSol renders a lamport amount as a decimal SOL string, trimming
// trailing fractional zeros.
func LamportsToSol(lamports uint64) string {
	return formatScaledUint(lamports, SolDecimals)
}

// SolToLamports parses a decimal SOL string into lamports.
//
// It rejects an amount with more than nine decimal places rather than
// rounding it, since the discarded digits would be real value the caller
// believed they were sending.
func SolToLamports(sol string) (uint64, error) {
	out, err := ConvertUnitDecimal(sol, UnitSol, UnitLamport)
	if err != nil {
		return 0, err
	}

	return strconv.ParseUint(out, 10, 64)
}

// ConvertUnitDecimal converts a decimal amount between lamports and SOL.
//
// A negative amount is rejected: lamports are unsigned on chain, and no
// instruction can move a negative balance.
func ConvertUnitDecimal(amount, from, to string) (string, error) {
	var scale int
	switch from {
	case UnitLamport:
		scale = 0
	case UnitSol:
		scale = SolDecimals
	default:
		return "", fmt.Errorf("invalid unit: %s", from)
	}

	intPart, fracPart, _ := strings.Cut(amount, ".")
	if len(fracPart) > scale {
		return "", fmt.Errorf("amount: too many decimal places for %s", from)
	}

	digits := strings.TrimLeft(intPart+fracPart+strings.Repeat("0", scale-len(fracPart)), "0")
	if digits == "" {
		digits = "0"
	}

	// ParseUint rejects both a leading minus and any value past 2^64-1, so an
	// amount the chain could not represent fails here instead of wrapping.
	n, err := strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return "", fmt.Errorf("amount %q: %w", amount, err)
	}

	switch to {
	case UnitLamport:
		return strconv.FormatUint(n, 10), nil
	case UnitSol:
		return formatScaledUint(n, SolDecimals), nil
	default:
		return "", fmt.Errorf("invalid unit: %s", to)
	}
}

func formatScaledUint(value uint64, scale int) string {
	digits := strconv.FormatUint(value, 10)
	if scale == 0 {
		return digits
	}

	if len(digits) <= scale {
		return trimTrailingFractionZeros("0." + strings.Repeat("0", scale-len(digits)) + digits)
	}

	split := len(digits) - scale

	return trimTrailingFractionZeros(digits[:split] + "." + digits[split:])
}

func trimTrailingFractionZeros(s string) string {
	if !strings.Contains(s, ".") {
		return s
	}

	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	if s == "" {
		return "0"
	}

	return s
}
