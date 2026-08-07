package rpc

// Elem is one JSON-RPC call: the method, its params, and a pointer the result
// is decoded into.
//
// Keeping the result as a pointer rather than a return value is what lets a
// batch decode heterogeneous results in one round trip.
type Elem struct {
	Method string
	Params any
	Result any
}

type Elems []Elem

func (e *Elems) With(elem Elem) *Elems {
	*e = append(*e, elem)

	return e
}

func (e *Elems) Len() int {
	return len(*e)
}

func (e *Elems) GetMethod(i int) string {
	return (*e)[i].Method
}

func (e *Elems) GetParams(i int) any {
	return (*e)[i].Params
}

func (e *Elems) GetResult(i int) any {
	return (*e)[i].Result
}

// Commitment selects how settled a slot must be before the node answers.
//
// It occupies the place a block tag such as "latest" or "finalized" holds in an
// EVM call, but it is a confirmation level rather than a height, and it must be
// passed as a field of an options object rather than as a bare positional
// argument.
type Commitment string

const (
	// CommitmentProcessed is the node's most recent slot, which may still be
	// skipped by the cluster.
	CommitmentProcessed Commitment = "processed"

	// CommitmentConfirmed has a supermajority vote and is what a client
	// normally waits for.
	CommitmentConfirmed Commitment = "confirmed"

	// CommitmentFinalized is rooted and cannot be rolled back.
	CommitmentFinalized Commitment = "finalized"
)

func SOLGetGenesisHash(result *string) Elem {
	return Elem{Method: "getGenesisHash", Result: result}
}

func SOLGetHealth(result *string) Elem {
	return Elem{Method: "getHealth", Result: result}
}

func SOLGetVersion(result *map[string]any) Elem {
	return Elem{Method: "getVersion", Result: result}
}

func SOLGetSlot(c Commitment, result *uint64) Elem {
	return Elem{Method: "getSlot", Params: []any{options(c)}, Result: result}
}

func SOLGetBalance(pubkey string, c Commitment, result *Result[uint64]) Elem {
	return Elem{Method: "getBalance", Params: []any{pubkey, options(c)}, Result: result}
}

func SOLGetAccountInfo(pubkey string, c Commitment, result *Result[*AccountInfo]) Elem {
	return Elem{
		Method: "getAccountInfo",
		Params: []any{pubkey, map[string]any{"commitment": c, "encoding": "base64"}},
		Result: result,
	}
}

func SOLGetLatestBlockhash(c Commitment, result *Result[LatestBlockhash]) Elem {
	return Elem{Method: "getLatestBlockhash", Params: []any{options(c)}, Result: result}
}

func SOLGetMinimumBalanceForRentExemption(space uint64, c Commitment, result *uint64) Elem {
	return Elem{Method: "getMinimumBalanceForRentExemption", Params: []any{space, options(c)}, Result: result}
}

// SOLGetFeeForMessage prices a message rather than a transaction.
//
// The fee depends only on the signature count and any compute budget
// instructions, both of which live in the message, so it can be known before
// signing. There is no equivalent of estimateGas returning a number that later
// execution can exceed.
func SOLGetFeeForMessage(message string, c Commitment, result *Result[*uint64]) Elem {
	return Elem{Method: "getFeeForMessage", Params: []any{message, options(c)}, Result: result}
}

// SOLSendTransaction submits a fully signed transaction.
//
// skipPreflight turns off the node-side simulation that runs first. Leaving it
// on catches most failures before the transaction is broadcast, at the cost of
// a round trip.
func SOLSendTransaction(tx string, skipPreflight bool, c Commitment, result *string) Elem {
	return Elem{
		Method: "sendTransaction",
		Params: []any{tx, map[string]any{
			"encoding":            "base64",
			"skipPreflight":       skipPreflight,
			"preflightCommitment": c,
		}},
		Result: result,
	}
}

// SOLSimulateTransaction executes a transaction against the node's state
// without submitting it.
//
// This is the closest analogue to eth_call on a signed payload, and the logs it
// returns are the only account of why a program stopped: nothing here
// corresponds to a revert string.
func SOLSimulateTransaction(tx string, sigVerify bool, c Commitment, result *Result[SimulateValue]) Elem {
	return Elem{
		Method: "simulateTransaction",
		Params: []any{tx, map[string]any{
			"encoding":   "base64",
			"commitment": c,
			"sigVerify":  sigVerify,
		}},
		Result: result,
	}
}

func SOLGetSignatureStatuses(signatures []string, searchHistory bool, result *Result[[]*SignatureStatus]) Elem {
	return Elem{
		Method: "getSignatureStatuses",
		Params: []any{signatures, map[string]any{"searchTransactionHistory": searchHistory}},
		Result: result,
	}
}

// SOLRequestAirdrop funds an account on devnet or testnet. Mainnet rejects it.
func SOLRequestAirdrop(pubkey string, lamports uint64, c Commitment, result *string) Elem {
	return Elem{Method: "requestAirdrop", Params: []any{pubkey, lamports, options(c)}, Result: result}
}

func options(c Commitment) map[string]any {
	if c == "" {
		c = CommitmentConfirmed
	}

	return map[string]any{"commitment": c}
}
