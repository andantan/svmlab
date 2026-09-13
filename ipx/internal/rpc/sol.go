package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/andantan/svmlab/core"
	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
)

// Context is the slot a result was read at.
//
// Almost every state-reading method wraps its answer in this envelope, which
// has no EVM counterpart: there, the block a call was evaluated against is
// whatever tag the caller passed and is not echoed back. Here the node reports
// it, so a balance always arrives with the slot it was true at.
type Context struct {
	Slot       uint64 `json:"slot"`
	APIVersion string `json:"apiVersion,omitempty"`
}

// Result is the {context, value} envelope those methods return.
type Result[T any] struct {
	Context Context `json:"context"`
	Value   T       `json:"value"`
}

// AccountInfo is the on-chain state of an account, as returned by
// getAccountInfo. types.Account is the transaction-side reference to a key;
// this is what actually lives at it.
//
// Owner is the field an EVM chain has no room for. Every account names the
// program allowed to write it, and an ordinary wallet is owned by the System
// Program. Code and state are separate accounts rather than one contract, so
// Executable marks a program while Data holds bytes some other program
// interprets.
type AccountInfo struct {
	Lamports   uint64 `json:"lamports"`
	Owner      string `json:"owner"`
	Data       []any  `json:"data"`
	Executable bool   `json:"executable"`
	RentEpoch  any    `json:"rentEpoch"`
	Space      uint64 `json:"space"`
}

// Bytes decodes the account data, which arrives as [base64String, "base64"].
func (a *AccountInfo) Bytes() ([]byte, error) {
	if len(a.Data) == 0 {
		return nil, nil
	}

	encoded, ok := a.Data[0].(string)
	if !ok {
		return nil, fmt.Errorf("account data: expected a base64 string but got %T", a.Data[0])
	}

	return codec.Base64.Decode(encoded)
}

// Exists reports whether an account was found at the key: a nil receiver is
// the ordinary AccountInfo result for an address nobody has funded, not an
// error, so this is safe to call on the result before checking it any other
// way.
func (a *AccountInfo) Exists() bool {
	return a != nil
}

// CarriesData reports whether an account holds any data. The System Program's
// Transfer instruction (and CreateAccount's internal lamport move) rejects a
// `from` account outright if this is true, regardless of who owns it, so
// callers naming a funding or rent payer check it on its own rather than
// folding it into an ownership or existence check. A nil receiver carries no
// data.
func (a *AccountInfo) CarriesData() bool {
	return a.Exists() && a.Space != 0
}

// IsNonceAccount reports whether this account is shaped like a nonce
// account: owned by the System Program and sized for one. It does not check
// whether the account is initialized — the data still has to be
// deserialized for that.
func (a *AccountInfo) IsNonceAccount() bool {
	return a.Owner == core.System.ID().Base58() && a.Space == core.NonceAccountSpace
}

// NonceAccount decodes this account as a durable nonce account, returning a
// descriptive error if it does not exist, is not shaped like one, or exists
// but has not been initialized.
func (a *AccountInfo) NonceAccount() (*core.NonceAccount, error) {
	if !a.Exists() {
		return nil, fmt.Errorf("is not found")
	}
	if !a.IsNonceAccount() {
		return nil, fmt.Errorf("is not a nonce account")
	}

	data, err := a.Bytes()
	if err != nil {
		return nil, err
	}
	nonce, err := core.DeserializeNonceAccount(data)
	if err != nil {
		return nil, err
	}
	if !nonce.Initialized() {
		return nil, fmt.Errorf("is not initialized")
	}

	return nonce, nil
}

// KeyedAccount is an account together with the address it was found at.
//
// getAccountInfo takes the address as an argument and so does not repeat it;
// the listing methods return accounts nobody named in advance, which is the
// whole point of asking, so the address travels with each one.
type KeyedAccount struct {
	Pubkey  string       `json:"pubkey"`
	Account *AccountInfo `json:"account"`
}

// LatestBlockhash is a blockhash together with the last block height at which
// a transaction using it is still accepted.
//
// LastValidBlockHeight is what makes expiry checkable rather than guessed: a
// transaction is dead once the chain passes it, and it can then be rebuilt
// without risking a double send.
type LatestBlockhash struct {
	Blockhash            string `json:"blockhash"`
	LastValidBlockHeight uint64 `json:"lastValidBlockHeight"`
}

// SignatureStatus is what getSignatureStatuses reports for one signature.
//
// It replaces an EVM receipt, and the difference matters: a receipt exists only
// once a transaction is mined, whereas a status is nil while the signature is
// unknown, which includes both "not yet seen" and "expired without landing".
type SignatureStatus struct {
	Slot               uint64          `json:"slot"`
	Confirmations      *uint64         `json:"confirmations"`
	Err                json.RawMessage `json:"err"`
	ConfirmationStatus string          `json:"confirmationStatus"`
}

// Succeeded reports whether the transaction landed without error.
func (s *SignatureStatus) Succeeded() bool {
	return s != nil && !s.Failed()
}

// Failed reports whether the transaction landed but its execution failed.
//
// A failed transaction is still recorded on chain and still pays its fee, in
// the same way a reverted EVM transaction consumes gas.
func (s *SignatureStatus) Failed() bool {
	return s != nil && len(s.Err) > 0 && string(s.Err) != "null"
}

// SimulateValue is the outcome of simulateTransaction.
type SimulateValue struct {
	Err           json.RawMessage `json:"err"`
	Logs          []string        `json:"logs"`
	UnitsConsumed *uint64         `json:"unitsConsumed"`
	ReturnData    *ReturnData     `json:"returnData"`
}

// Failed reports whether the simulated execution failed.
func (v *SimulateValue) Failed() bool {
	return len(v.Err) > 0 && string(v.Err) != "null"
}

// DecodedReturnData decodes ReturnData's payload, or reports nil, nil when
// the simulated instruction never called sol_set_return_data at all — a
// program that returns nothing is not an error, so a caller distinguishes
// "no return data" from "empty return data" by nil-ness rather than length.
func (v *SimulateValue) DecodedReturnData() ([]byte, error) {
	if v.ReturnData == nil {
		return nil, nil
	}
	if v.ReturnData.Data[1] != "base64" {
		return nil, fmt.Errorf("simulate: return data encoding %q is not base64", v.ReturnData.Data[1])
	}

	return codec.Base64.Decode(v.ReturnData.Data[0])
}

// ReturnData is what a program last passed to sol_set_return_data during
// simulation, still in its wire shape: Data is a two-element
// [payload, encoding] pair rather than a plain string, mirroring how
// accountInfo encodes account data, so Encoding is checked instead of
// assumed.
type ReturnData struct {
	ProgramId string    `json:"programId"`
	Data      [2]string `json:"data"`
}

func (c *Client) GenesisHash(ctx context.Context) (string, error) {
	var result string
	err := c.Call(ctx, SOLGetGenesisHash(&result))

	return result, err
}

func (c *Client) Health(ctx context.Context) (string, error) {
	var result string
	err := c.Call(ctx, SOLGetHealth(&result))

	return result, err
}

func (c *Client) Version(ctx context.Context) (map[string]any, error) {
	var result map[string]any
	err := c.Call(ctx, SOLGetVersion(&result))

	return result, err
}

func (c *Client) Slot(ctx context.Context, commitment Commitment) (uint64, error) {
	var result uint64
	err := c.Call(ctx, SOLGetSlot(commitment, &result))

	return result, err
}

// EpochInfo is what the cluster reports about where it currently is, not
// wrapped in the usual Context envelope: unlike a balance or an account,
// there is no other slot this could be true "as of" -- it already is the
// slot-and-epoch reading itself.
type EpochInfo struct {
	Epoch        uint64 `json:"epoch"`
	SlotIndex    uint64 `json:"slotIndex"`
	SlotsInEpoch uint64 `json:"slotsInEpoch"`
	AbsoluteSlot uint64 `json:"absoluteSlot"`
}

func (c *Client) EpochInfo(ctx context.Context, commitment Commitment) (*EpochInfo, error) {
	var result EpochInfo
	err := c.Call(ctx, SOLGetEpochInfo(commitment, &result))

	return &result, err
}

func (c *Client) Balance(ctx context.Context, pubkey *types.PublicKey, commitment Commitment) (uint64, error) {
	var result Result[uint64]
	if err := c.Call(ctx, SOLGetBalance(pubkey.Base58(), commitment, &result)); err != nil {
		return 0, err
	}

	return result.Value, nil
}

// AccountInfo returns the account's state, or nil if no account exists at the
// key.
//
// A nil result is the ordinary answer for an address nobody has funded, and it
// is the only practical guard against a mistyped recipient: base58 carries no
// checksum, so a single dropped character can decode to a different valid
// address that no error can distinguish from an intended one.
func (c *Client) AccountInfo(ctx context.Context, pubkey *types.PublicKey, commitment Commitment) (*AccountInfo, error) {
	var result Result[*AccountInfo]
	if err := c.Call(ctx, SOLGetAccountInfo(pubkey.Base58(), commitment, &result)); err != nil {
		return nil, err
	}

	return result.Value, nil
}

// GetMultipleAccounts reads several accounts in one round trip, keyed by
// base58 rather than by *PublicKey: two different pointers to the same key
// would otherwise land as separate map entries, and a request naming the
// same account under two roles (from and fee_payer, say) is the ordinary
// case this exists to batch, not an edge case to special-case away.
//
// A pubkey named more than once is only asked of the cluster once, but the
// returned map still answers for every key passed in. A missing entry's
// value is nil, the ordinary AccountInfo answer for an address nobody has
// funded, not an error.
func (c *Client) GetMultipleAccounts(ctx context.Context, pubkeys []*types.PublicKey, commitment Commitment) (map[string]*AccountInfo, error) {
	unique := make([]string, 0, len(pubkeys))
	seen := make(map[string]bool, len(pubkeys))
	for _, pk := range pubkeys {
		key := pk.Base58()
		if !seen[key] {
			seen[key] = true
			unique = append(unique, key)
		}
	}

	var result Result[[]*AccountInfo]
	if err := c.Call(ctx, SOLGetMultipleAccounts(unique, commitment, &result)); err != nil {
		return nil, err
	}

	accounts := make(map[string]*AccountInfo, len(unique))
	for i, key := range unique {
		accounts[key] = result.Value[i]
	}

	return accounts, nil
}

// Exists reports whether an account has been created at the key.
func (c *Client) Exists(ctx context.Context, pubkey *types.PublicKey, commitment Commitment) (bool, error) {
	info, err := c.AccountInfo(ctx, pubkey, commitment)
	if err != nil {
		return false, err
	}

	return info != nil, nil
}

// LatestBlockhash returns a blockhash to build a transaction against, together
// with the block height at which it expires.
func (c *Client) LatestBlockhash(ctx context.Context, commitment Commitment) (*types.Hash, uint64, error) {
	var result Result[LatestBlockhash]
	if err := c.Call(ctx, SOLGetLatestBlockhash(commitment, &result)); err != nil {
		return nil, 0, err
	}

	hash, err := types.NewHashFromBase58(result.Value.Blockhash)
	if err != nil {
		return nil, 0, fmt.Errorf("latest blockhash: %w", err)
	}

	return hash, result.Value.LastValidBlockHeight, nil
}

// Mint reads a mint account and parses it, returning nil when nothing lives at
// the address.
//
// A missing account is not an error here, since asking whether a mint exists is
// a legitimate question and the caller can tell nil from a failure to answer.
func (c *Client) Mint(ctx context.Context, mint *types.PublicKey, commitment Commitment) (*core.Mint, error) {
	info, err := c.AccountInfo(ctx, mint, commitment)
	if err != nil || info == nil {
		return nil, err
	}

	owner, err := types.NewPublicKeyFromBase58(info.Owner)
	if err != nil {
		return nil, err
	}

	data, err := info.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to decode account data: %w", err)
	}

	return core.DecodeMint(owner, data)
}

// TokenAccount reads a holder account and parses it, under the same rule as
// Mint.
func (c *Client) TokenAccount(ctx context.Context, key *types.PublicKey, commitment Commitment) (*core.TokenAccount, error) {
	info, err := c.AccountInfo(ctx, key, commitment)
	if err != nil || info == nil {
		return nil, err
	}

	owner, err := types.NewPublicKeyFromBase58(info.Owner)
	if err != nil {
		return nil, err
	}

	data, err := info.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to decode account data: %w", err)
	}

	return core.DecodeTokenAccount(owner, data)
}

// TokenAccountsByMint lists a wallet's token accounts for one mint.
//
// There can be more than one. Only the associated address is unique per wallet
// and mint; any number of keypair accounts may hold the same token for the same
// owner, so this returns a list rather than an account.
func (c *Client) TokenAccountsByMint(ctx context.Context, owner, mint *types.PublicKey, commitment Commitment) ([]KeyedAccount, error) {
	return c.tokenAccountsByOwner(ctx, owner, map[string]any{"mint": mint.Base58()}, commitment)
}

// TokenAccountsByProgram lists every token account a wallet owns under one
// token program.
//
// The program has to be named because classic Token and Token-2022 are separate
// programs holding separate accounts, and a wallet may hold both. Asking for one
// says nothing about the other.
func (c *Client) TokenAccountsByProgram(ctx context.Context, owner, program *types.PublicKey, commitment Commitment) ([]KeyedAccount, error) {
	return c.tokenAccountsByOwner(ctx, owner, map[string]any{"programId": program.Base58()}, commitment)
}

func (c *Client) tokenAccountsByOwner(ctx context.Context, owner *types.PublicKey, filter map[string]any, commitment Commitment) ([]KeyedAccount, error) {
	var result Result[[]KeyedAccount]
	if err := c.Call(ctx, SOLGetTokenAccountsByOwner(owner.Base58(), filter, commitment, &result)); err != nil {
		return nil, err
	}

	return result.Value, nil
}

// MinimumBalanceForRentExemption is the balance an account of the given size
// must hold to persist.
//
// Below it the account is subject to removal, which is why a transfer creating
// an account has to meet this threshold. An EVM account has no such floor.
func (c *Client) MinimumBalanceForRentExemption(ctx context.Context, space uint64, commitment Commitment) (uint64, error) {
	var result uint64
	err := c.Call(ctx, SOLGetMinimumBalanceForRentExemption(space, commitment, &result))

	return result, err
}

func (c *Client) MinimumBalanceForRentExemptionSystem(ctx context.Context) (uint64, error) {
	return c.MinimumBalanceForRentExemption(ctx, core.SystemAccountSpace, CommitmentConfirmed)
}

func (c *Client) MinimumBalanceForRentExemptionMint(ctx context.Context) (uint64, error) {
	return c.MinimumBalanceForRentExemption(ctx, core.MintSpace, CommitmentConfirmed)
}

func (c *Client) MinimumBalanceForRentExemptionToken(ctx context.Context) (uint64, error) {
	return c.MinimumBalanceForRentExemption(ctx, core.TokenAccountSpace, CommitmentConfirmed)
}

func (c *Client) MinimumBalanceForRentExemptionMultisig(ctx context.Context) (uint64, error) {
	return c.MinimumBalanceForRentExemption(ctx, core.MultisigSpace, CommitmentConfirmed)
}

func (c *Client) MinimumBalanceForRentExemptionStake(ctx context.Context) (uint64, error) {
	return c.MinimumBalanceForRentExemption(ctx, core.StakeAccountSpace, CommitmentConfirmed)
}

func (c *Client) MinimumBalanceForRentExemptionVote(ctx context.Context) (uint64, error) {
	return c.MinimumBalanceForRentExemption(ctx, core.VoteAccountSpace, CommitmentConfirmed)
}

func (c *Client) MinimumBalanceForRentExemptionNonce(ctx context.Context) (uint64, error) {
	return c.MinimumBalanceForRentExemption(ctx, core.NonceAccountSpace, CommitmentConfirmed)
}

// FeeForMessage prices a message, or returns false if the blockhash it carries
// has already expired.
func (c *Client) FeeForMessage(ctx context.Context, message *types.Message, commitment Commitment) (uint64, bool, error) {
	raw, err := message.Serialize()
	if err != nil {
		return 0, false, fmt.Errorf("fee for message: %w", err)
	}

	var result Result[*uint64]
	if err = c.Call(ctx, SOLGetFeeForMessage(codec.Base64.Encode(raw), commitment, &result)); err != nil {
		return 0, false, err
	}
	if result.Value == nil {
		return 0, false, nil
	}

	return *result.Value, true, nil
}

// SimulateTransaction runs a transaction against the node's state without
// submitting it, returning the program logs either way.
func (c *Client) SimulateTransaction(ctx context.Context, tx *types.Transaction, sigVerify bool, commitment Commitment) (*SimulateValue, error) {
	raw, err := tx.Serialize()
	if err != nil {
		return nil, fmt.Errorf("simulate transaction: %w", err)
	}

	return c.SimulateRawTransaction(ctx, raw, sigVerify, commitment)
}

// SimulateRawTransaction is SimulateTransaction over bytes already on the
// wire, so it works on a versioned message too: nothing above the RPC call
// itself needs the message parsed, only the bytes it was given.
func (c *Client) SimulateRawTransaction(ctx context.Context, raw []byte, sigVerify bool, commitment Commitment) (*SimulateValue, error) {
	var result Result[SimulateValue]
	if err := c.Call(ctx, SOLSimulateTransaction(codec.Base64.Encode(raw), sigVerify, commitment, &result)); err != nil {
		return nil, err
	}

	return &result.Value, nil
}

// SimulateUnsignedTransaction simulates a transaction that carries no real
// signatures and no real recent blockhash — built purely to read whatever
// return data it produces, never to be sent. The node replaces the
// blockhash with its own current one and skips signature verification
// entirely, so raw needs only to be well-formed: the right number of empty
// signature slots for its account keys, and any 32 bytes where a blockhash
// goes.
func (c *Client) SimulateUnsignedTransaction(ctx context.Context, raw []byte, commitment Commitment) (*SimulateValue, error) {
	var result Result[SimulateValue]
	if err := c.Call(ctx, SOLSimulateTransactionReplaceBlockhash(codec.Base64.Encode(raw), commitment, &result)); err != nil {
		return nil, err
	}

	return &result.Value, nil
}

// SendTransaction broadcasts a signed transaction and returns its signature.
//
// The signature is known before sending, since it is already in the
// transaction, so the returned value confirms acceptance rather than
// identifying the transaction. Acceptance is not execution: the transaction
// still has to land in a block, which SignatureStatus reports.
func (c *Client) SendTransaction(ctx context.Context, tx *types.Transaction, skipPreflight bool, commitment Commitment) (*types.Signature, error) {
	raw, err := tx.Serialize()
	if err != nil {
		return nil, fmt.Errorf("send transaction: %w", err)
	}

	return c.SendRawTransaction(ctx, raw, skipPreflight, commitment)
}

// SendRawTransaction is SendTransaction over bytes already on the wire, so it
// works on a versioned message too: broadcasting only ever sends base64 bytes
// over RPC, and nothing here needs them parsed first.
func (c *Client) SendRawTransaction(ctx context.Context, raw []byte, skipPreflight bool, commitment Commitment) (*types.Signature, error) {
	var result string
	if err := c.Call(ctx, SOLSendTransaction(codec.Base64.Encode(raw), skipPreflight, commitment, &result)); err != nil {
		return nil, err
	}

	return types.NewSignatureFromBase58(result)
}

// SignatureStatus returns the status of one signature, or nil if the cluster
// has not seen it.
func (c *Client) SignatureStatus(ctx context.Context, sig *types.Signature, searchHistory bool) (*SignatureStatus, error) {
	statuses, err := c.SignatureStatuses(ctx, []*types.Signature{sig}, searchHistory)
	if err != nil {
		return nil, err
	}
	if len(statuses) == 0 {
		return nil, nil
	}

	return statuses[0], nil
}

func (c *Client) SignatureStatuses(ctx context.Context, sigs []*types.Signature, searchHistory bool) ([]*SignatureStatus, error) {
	encoded := make([]string, len(sigs))
	for i, sig := range sigs {
		encoded[i] = sig.Base58()
	}

	var result Result[[]*SignatureStatus]
	if err := c.Call(ctx, SOLGetSignatureStatuses(encoded, searchHistory, &result)); err != nil {
		return nil, err
	}

	return result.Value, nil
}

// RequestAirdrop funds an account on devnet or testnet.
func (c *Client) RequestAirdrop(ctx context.Context, pubkey *types.PublicKey, lamports uint64, commitment Commitment) (*types.Signature, error) {
	var result string
	if err := c.Call(ctx, SOLRequestAirdrop(pubkey.Base58(), lamports, commitment, &result)); err != nil {
		return nil, err
	}

	return types.NewSignatureFromBase58(result)
}

// WaitForConfirmation polls until the signature reaches the given commitment,
// the deadline passes, or the transaction fails.
//
// This is the counterpart to waiting for an EVM receipt, with one difference
// that shapes the loop: a transaction can simply never land, because its
// blockhash expires and the cluster forgets it. Polling forever would hang, so
// a timeout is a required argument rather than a convenience.
func (c *Client) WaitForConfirmation(ctx context.Context, sig *types.Signature, commitment Commitment, timeout time.Duration) (*SignatureStatus, error) {
	deadline := time.Now().Add(timeout)

	for {
		status, err := c.SignatureStatus(ctx, sig, false)
		if err != nil {
			return nil, err
		}
		if status != nil {
			if status.Failed() {
				return status, fmt.Errorf("transaction %s failed: %s", sig, string(status.Err))
			}
			if confirmedAtLeast(status.ConfirmationStatus, commitment) {
				return status, nil
			}
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout waiting for confirmation: %s", sig)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// confirmedAtLeast reports whether a reported status meets the requested
// commitment, ranking the three levels by how settled they are.
func confirmedAtLeast(status string, want Commitment) bool {
	rank := map[string]int{
		string(CommitmentProcessed): 1,
		string(CommitmentConfirmed): 2,
		string(CommitmentFinalized): 3,
	}

	if want == "" {
		want = CommitmentConfirmed
	}

	return rank[status] >= rank[string(want)]
}
