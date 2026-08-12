# SPL Token API Plan

## Scope

System Program work is complete. This document covers the original SPL Token Program:

```text
TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
```

The goal is to implement every instruction supported by that program, not just
the common mint / transfer path.

Token-2022 turned out to need less separation than this document first assumed.
On the classic instruction surface the two programs are byte for byte the same,
so `core.Token` and `core.Token2022` are two values of one type differing only
in the id they send to, and every builder below already works through either.
What stays a separate follow-up is the part that is genuinely new: extensions
change account sizes and add instructions of their own, so they need their own
builders and their own parsers. The base layouts still parse from the first 82
or 165 bytes, which was confirmed against live Token-2022 accounts.

Two other programs appear here as well, and the distinction matters even
though callers never see it. The Associated Token Account program

```text
ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL
```

Is what `create-ata` and everything derived from it actually invokes, and the
System Program supplies the `CreateAccount` half of every atomic create. Their
endpoints sit under `token/` because that is where a caller looks for them, so
each one below names the program its instructions belong to.

Endpoints that produce a transaction belong under:

```text
POST /svm/v2/transaction/token/...
```

Endpoints that only read and decode state are grouped by what they are asked
about rather than by which RPC method answers them:

```text
POST /svm/token/mint        what this mint is
POST /svm/token/account     what this token account holds
POST /svm/account/tokens    what this wallet holds
```

The first two describe a token, so they sit under `token`. The third describes
a wallet and belongs beside `account/balance` and `account/nonce`, since the
question is what one address controls and tokens are one answer among several.

The split against `/transaction/*` is by what comes back: those return
something to sign, these return what is already on chain. Putting a mint
decoder under `/transaction` because it concerns tokens would be the first
endpoint in either tree to break that.

Every state-changing endpoint should accept the existing optional
`nonce_account` field. When present, it uses the stored durable nonce as the
message blockhash and prepends `AdvanceNonceAccount`.

## Rules

- A mint is an 82-byte Token-Program-owned account. A token account is 165
  bytes. Both have to be rent exempt.
- Creating an empty account and initializing it must be one transaction. An
  uninitialized Token-owned account can otherwise be initialized by somebody
  else before its intended owner does it.
- Token amounts are base units (`u64`), not UI decimal strings. `decimals` is
  metadata on the mint. Checked variants take the expected decimals and should
  be the default public API.
- A token transfer moves balances between two *token accounts* of the same
  mint; it never sends directly to a wallet address. `create-ata` is the
  convenience path for a wallet recipient.
- An authority may be a single signer or an SPL multisig account. Request
  types should consistently take `authority` plus optional
  `multisig_signers`; when the latter is non-empty, authority itself does not
  sign and the named members do.
- The Token Program owns mint and token-account data. Do not offer a generic
  "set owner program" escape hatch.
- An authority field that the program declares `Option<Pubkey>` is absent when
  the request omits it, which follows `nonce_account`. `SetAuthority` is the
  exception: there an omitted authority is not "leave it alone" but "remove it
  permanently", so it requires an explicit flag rather than an empty string. A
  typo should not be able to end a mint's freeze authority forever.

## Complete Original SPL Token Instruction Set

The current upstream Token interface defines the following classic-program
opcodes. Gaps are Token-2022-only opcodes and must not be filled by guessing.

| Opcode | Instruction              | Endpoint                           | Priority                 |
|-------:|--------------------------|------------------------------------|--------------------------|
|      0 | InitializeMint           | `token/initialize-mint`            | compatibility            |
|      1 | InitializeAccount        | `token/initialize-account`         | compatibility            |
|      2 | InitializeMultisig       | `token/initialize-multisig`        | compatibility            |
|      3 | Transfer                 | `token/transfer`                   | compatibility            |
|      4 | Approve                  | `token/approve`                    | compatibility            |
|      5 | Revoke                   | `token/revoke`                     | core                     |
|      6 | SetAuthority             | `token/set-authority`              | core                     |
|      7 | MintTo                   | `token/mint-to`                    | compatibility            |
|      8 | Burn                     | `token/burn`                       | compatibility            |
|      9 | CloseAccount             | `token/close-account`              | core                     |
|     10 | FreezeAccount            | `token/freeze-account`             | admin                    |
|     11 | ThawAccount              | `token/thaw-account`               | admin                    |
|     12 | TransferChecked          | `token/transfer-checked`           | core default             |
|     13 | ApproveChecked           | `token/approve-checked`            | core default             |
|     14 | MintToChecked            | `token/mint-to-checked`            | core default             |
|     15 | BurnChecked              | `token/burn-checked`               | core default             |
|     16 | InitializeAccount2       | `token/initialize-account2`        | compatibility            |
|     17 | SyncNative               | `token/sync-native`                | wrapped SOL              |
|     18 | InitializeAccount3       | `token/initialize-account3`        | core default             |
|     19 | InitializeMultisig2      | `token/initialize-multisig2`       | preferred multisig       |
|     20 | InitializeMint2          | `token/initialize-mint2`           | core default             |
|     21 | GetAccountDataSize       | `token/account-data-size`          | read / return data       |
|     22 | InitializeImmutableOwner | `token/initialize-immutable-owner` | ATA compatibility        |
|     23 | AmountToUiAmount         | `token/amount-to-ui`               | read / return data       |
|     24 | UiAmountToAmount         | `token/ui-to-amount`               | read / return data       |
|     38 | WithdrawExcessLamports   | `token/withdraw-excess-lamports`   | recovery — unverified    |
|     45 | UnwrapLamports           | `token/unwrap-lamports`            | wrapped SOL — unverified |
|    255 | Batch                    | `token/batch`                      | last — unverified        |

Six of these have builders in `core` today, and none of them has an endpoint:

```text
 9  CloseAccount        confirmed against mainnet instructions
12  TransferChecked     confirmed against mainnet instructions
14  MintToChecked       account order from the spec, not yet seen on chain
15  BurnChecked         account order from the spec, not yet seen on chain
18  InitializeAccount3  confirmed against mainnet instructions
20  InitializeMint2     encoding checked by hand
```

`InitializeImmutableOwner` is intentionally a no-op in the classic Token
Program, but it remains necessary for compatibility with the Associated Token
Account flow. `Batch` is a Token Program instruction that serializes multiple
Token instructions inside one instruction; it is different from putting
multiple ordinary instructions in a Solana transaction.

Opcodes 0 through 24 are handled by the program binary deployed on every
cluster today. The last three are marked unverified because the interface crate
this table was read from is not the deployed program: an opcode can exist in
the source and still come back `InvalidInstruction` from the account the
endpoint would send it to. Each has to be sent once against a live cluster
before its endpoint is written, otherwise the result is a documented endpoint
that has never worked.

Sampling twelve mainnet transactions turned up 81 Token instructions across
seven opcodes — 3, 4, 9, 12, 17, 18, 21, and 22 — which confirms those are live
but says nothing either way about 38, 45, and 255. Absence from a sample that
small is not evidence, so they stay unverified until one is actually sent.

## Composite Convenience Endpoints

The instruction endpoints above are the complete low-level surface. These
builders are also needed because they remove unsafe intermediate states.

| Endpoint                      | Instructions in one transaction                        | Programs      | Why it exists                                                      |
|-------------------------------|--------------------------------------------------------|---------------|--------------------------------------------------------------------|
| `token/create-mint`           | System CreateAccount + InitializeMint2                 | System, Token | atomically create an 82-byte mint                                  |
| `token/create-account`        | System CreateAccount + InitializeAccount3              | System, Token | atomically create a 165-byte token account                         |
| `token/create-ata`            | Associated Token Account create                        | ATA           | derive and create the canonical token account for wallet + mint    |
| `token/create-ata-idempotent` | ATA idempotent create                                  | ATA           | safe when the ATA may already exist                                |
| `token/transfer-to-wallet`    | optional ATA create + TransferChecked                  | ATA, Token    | recipient may provide a wallet rather than a token-account address |
| `token/create-wrapped-sol`    | create token account + InitializeAccount3(native mint) | System, Token | create a wrapped SOL account                                       |
| `token/wrap-sol`              | System Transfer + SyncNative                           | System, Token | reflect deposited lamports as wrapped SOL                          |

For ordinary callers, expose `create-mint`, `create-ata`,
`transfer-checked`, `mint-to-checked`, and `close-account` prominently.
Keep the one-instruction endpoints available for learning and for composing
custom transactions.

## Implementation Order

Only ATA depends on both of the pieces below it; Token and PDA do not depend on
each other at all.

```text
PDA ─────────────┐
                 ├──> ATA
Token ───────────┘
```

Every endpoint in the first usable lifecycle works against a token account made
from an ordinary keypair, so none of it is blocked on PDA. PDA still comes
first because it is the smallest of the three and the only one nothing is
waiting on: one file, and afterward every remaining choice is open. Doing
Token first means designing `create-account` and then discovering, when ATA
arrives, that its neighbour is nearly the same endpoint for a reason worth
having settled earlier.

### 0. Program derived addresses — done

`core/ed25519.go` answers the one question a PDA turns on: whether 32 bytes
decompress as a curve point. No dependency was added for it. The standard
library does not expose the test and the curve libraries answer it inside
thousands of lines of scalar arithmetic nothing here needs, so the field
arithmetic is local and the predicate is the only thing exported.

`core/pda.go` sits on it with `Create` and `Find`. Checked against 2044 token
accounts pulled from mainnet blocks: 1655 are associated token accounts and
derive exactly, bumps included, and every account that did not match is one of the
seeds say should not.

### 1. Durable nonce, extracted — deferred

The nineteen System endpoints still each carry their own copy of the block that
resolves `nonce_account` and builds the two messages. The concern stands: every
Token endpoint that takes a nonce adds another copy, and the argument for
extracting before rather than after is only stronger as the count grows.

It is deferred rather than dropped. The Token request and response shapes are
still moving, and an extraction now would be shaped around a guess at them.
Revisit once the lifecycle endpoints in step 3 exist and the block's real
parameters are visible.

### 2. Shared token foundation — done

Done:

- `core.Token` and `core.Token2022`, two values of one type. The program id is
  a field rather than a constant, since the classic surface is identical and
  which program a caller wants follows from the mint rather than the cluster.
- `u8` opcode encoding, against the System Program's `u32`. The full classic
  opcode list, 0 through 24, with the Token-2022-only gaps left out.
- Parsers for Mint (82), TokenAccount (165), and Multisig (355). Mint and token
  account agree with what the RPC reports for USDC, USDT, and wSOL; wSOL is the
  one that exercises an absent `COption` in both fields. Multisig is unverified
  against a live account, since they are rare.
- `COption` moved to `codec`, where the tag is a `u32` and the payload is
  written whether or not it is present. That fixed width is why a mint is 82
  bytes with or without a freeze authority.
- Shared authority handling for a single signer and for multisig members,
  where the authority stops signing and the members sign in its place.
- `Token.CreateMint` and `Token.CreateAccount` emit the System create beside the
  initialize as one instruction pair.

- `DecodeMint` and `DecodeTokenAccount`, which take the owning program alongside
  the data. Ownership belongs with the parse rather than beside it: a mint and a
  holder account are both owned by a token program and both open with 32 bytes
  that read as a public key, so nothing in the data says which one it is.
  Deciding it from the length and the Token-2022 type tag is what stands between
  a holder account and a supply figure invented from its owner field.
- The read endpoints, all three of them:

  ```text
  /svm/token/mint        USDC, USDT, wSOL, and Token-2022 accounts confirmed
  /svm/token/account     confirmed, including a 170-byte extended account
  /svm/account/tokens    confirmed against both programs
  ```

  `/svm/account/tokens` queries classic Token and Token-2022 and merges the
  results, reporting the program on each entry. An earlier draft of this
  document argued the two must not be merged, on the grounds that no single
  instruction can touch accounts from both. That argument is about building a
  transaction and does not reach a read: the question here is what a wallet
  holds, the answer spans both programs, and the per-entry program keeps the
  distinction available to anything that has to act on it.

  Each mint is read once for its decimals and cached across the listing, since a
  wallet's accounts cluster on a few mints. A mint that cannot be read caches
  its absence too, so a dead mint costs one call rather than one per account.

  One limit belongs to the method rather than to us: a node drops large accounts
  from its secondary indexes and answers `getTokenAccountsByOwner` for them with
  an error, which currently surfaces as a 502.

This group has nothing pending.

### 3. First usable token lifecycle — done

```text
token/create-mint                 (CreateAccount + InitializeMint2)
token/create-account              (CreateAccount + InitializeAccount3)
token/mint-to-checked
token/transfer-checked
token/burn-checked
token/close-account
```

All six are live under `/svm/v2/transaction/token/`. `TransferChecked`,
`CloseAccount`, and `InitializeAccount3` were rebuilt from fifty instructions
taken off mainnet and match byte for byte with the account order included;
`MintToChecked` and `BurnChecked` have not been seen on chain yet, since the
sampled blocks held no mint or burn, so their account order is read from the
spec rather than confirmed — worth a live send before leaning on it.

The holder accounts here are ordinary keypairs, which is why this step could
come before ATA: the whole lifecycle can be walked end to end without a derived
address anywhere in it. That was the argument for ordering it first while PDA
was still unwritten. PDA is written now, and ATA is next — see the note there.

Every one of these takes a required `program` field naming the account to
send the instructions to (classic Token or Token-2022), not defaulted: a mint
belongs to exactly one of the two forever, and a default would make picking
wrong silent. It is an address rather than an enum of names because that is
what actually selects the program on chain — a third Token implementation
would need no code change here to be reachable.

`decimals` is taken from the request and checked against the mint rather than
filled in from it, on `mint-to-checked`, `transfer-checked`, and
`burn-checked`. Reading the mint to supply the value would defeat what the
checked variants exist for; comparing instead reports a wrong-decimals amount
as a 400 rather than as an on-chain failure.

Authorization splits along two different axes depending on what moves.
`mint-to-checked` checks the mint's own `mint_authority`, since minting
creates supply and only the mint can allow that. `transfer-checked` and
`burn-checked` instead check the account's `owner`, or its `delegate` for no
more than the delegated amount, since both spend a balance that belongs to
whoever holds it. `close-account` splits again: `owner` or `close_authority`,
never a delegate, because delegation covers spending a balance and closing
isn't spending one.

Every account read for one of these six is also checked against the
`program` field before it is decoded — the mint and, where applicable, the
token account's own owning program must equal what the request named, not
merely decode successfully — since a Token account decodes as a valid
Token-2022 layout's prefix and the mismatch would otherwise surface as an
on-chain `IncorrectProgramId` instead of a 400 with a reason.

`close-account`'s zero-balance rule carries one exception: a wrapped SOL
account's balance is its lamports rather than a token amount, and closing it
is how SOL is unwrapped, so `IsNative` skips the check rather than the
account being treated as still holding value.

Devnet walkthrough, exercised end to end including a durable nonce on
`mint-to-checked` against Token-2022:

```text
create mint (decimals 6)
→ create token account for wallet A
→ create token account for wallet B
→ mint 1,000,000 base units to A
→ transfer 250,000 base units A -> B
→ burn a small amount from B
→ drain B and close B's account
```

### 4. Associated token accounts — done

```text
token/create-ata
token/create-ata-idempotent
token/transfer-to-wallet
```

This is the ATA program rather than the Token program, so it has its own
`core.ATA` namespace on `AssociatedTokenProgramID`, and it was the first
consumer of `PDA.Find`. The derived address was already known to be right
before any of this was written — the same derivation matched 1655 live
associated accounts in step 0 — so what the endpoints had to confirm was the
instructions, not the address: no data at all for the plain create, one byte
for the idempotent one, both exactly as expected.

`transfer-to-wallet` ended up taking two wallet addresses, `account` and
`destination`, rather than an exact source account plus a destination wallet.
The first draft of it only derived the recipient's side, on the assumption
that a sender already knows their own token account. That assumption did not
survive contact with the endpoint's own reasoning: if not making the caller
compute an associated address is worth an endpoint for the recipient, it is
worth the same thing for the sender. A caller who *does* already hold an
exact token account address — an associated one or one from
`token/create-account` — has transfer-checked for that; this endpoint is
specifically for two wallets that have never had to think about where their
tokens live.

The two sides are not symmetric in what happens when the derived account is
missing. The destination's gets an idempotent create prepended, so the
transfer and the account both land in one transaction and neither creator
loses a race with the other. The source's is never created: an account
nobody has funded has no balance to send, so a missing one is reported as
having no associated account for the mint rather than being created empty
and immediately failing the transfer anyway.

No `token/close-ata` was needed. `token/close-account` already takes any
165-byte Token or Token-2022 account, and an associated account is that same
layout at a derived address; nothing about closing distinguishes how the
address came to exist.

### 5. Delegation and administration

```text
token/approve-checked
token/revoke
token/set-authority
token/freeze-account
token/thaw-account
```

Walk delegate allowance exhaustion, revocation, authority removal, and a frozen
account rejecting transfer / burn / approve until thawed. `freeze-account` and
`thaw-account` only work on a mint whose freeze authority was set when it was
initialized, so `create-mint` has to have offered that field by now.

### 6. Compatibility and multisig

```text
initialize-mint, initialize-account, initialize-multisig
initialize-account2, initialize-account3, initialize-multisig2
transfer, approve, mint-to, burn
initialize-immutable-owner
```

The `*2`, `*3`, and checked variants should share internal builders rather than
reimplement account order and serialization. What has to be confirmed is that
the encoded instruction data is byte exact, and the way to confirm it here is
to send one of each to devnet and read back how an explorer decodes it: an
account order that is wrong in a way the builder cannot see is still wrong in a
way the cluster can.

### 7. Native SOL, read-return-data, recovery, batch

```text
token/sync-native
token/create-wrapped-sol
token/wrap-sol
token/unwrap-lamports
token/account-data-size
token/amount-to-ui
token/ui-to-amount
token/withdraw-excess-lamports
token/batch
```

`unwrap-lamports`, `withdraw-excess-lamports`, and `batch` are the three
unverified opcodes, so this step begins by sending each one against a live
cluster and drops any that the deployed program rejects.

The three return-data instructions produce a value rather than a state change,
which a transaction-builder response has no field for. In the classic program
they are also nearly free to compute: the data size is a fixed 165 and the two
conversions are a shift of the decimal point by the mint's `decimals`. So build
them as ordinary builders and let a caller who wants the value run the result
through the existing `/svm/cluster/transaction/simulate`, rather than growing a
second response shape for three instructions that barely need one.

`token/batch` comes last because it needs a safe typed representation of nested
Token instructions and strict transaction-size checks.

## API Conventions

Amounts are decimal strings carrying raw base units:

```json
{
  "source": "source_token_account",
  "mint": "mint_account",
  "destination": "destination_token_account",
  "authority": "owner_or_delegate",
  "amount": "250000",
  "decimals": 6,
  "fee_payer": "fee_payer",
  "nonce_account": "optional_durable_nonce"
}
```

This matches what the System endpoints already do — every `amount`,
`lamports`, and `space` field there is a decimal string, because a `u64` past
2^53 does not survive a JSON number intact — so token amounts need no new
convention, only the same one.

Avoid receiving a UI amount in state-changing endpoints. A client converts UI
values using mint decimals first; the checked instruction independently
confirms that those decimals match on-chain. `ui-to-amount` exists for the
explicit conversion case.

Every response follows the existing v2 shape:

```text
transaction, message, recent_blockhash, account_keys, signers, fee,
nonce_authority (when nonce_account was used)
```

It should additionally return the selected Token Program id and typed operation
fields such as mint, source, destination, amount, decimals, and authority.

## Safety Checks

- Validate that every mint and token account belongs to the configured classic
  Token Program before building an operation.
- Decode involved accounts and verify their mint relationship before returning
  a transfer, mint, burn, freeze, or close transaction.
- Prefer checked variants in public examples and verify the supplied decimals
  from the decoded mint.
- Ensure a close of a non-native token account has zero token balance. Native
  accounts use the dedicated unwrap / close behavior.
- Verify a destination ATA matches the requested wallet, mint, and Token
  Program; do not treat an arbitrary token account as a wallet ATA. The check
  is to derive the address and compare, never to trust one the caller supplied
  under that name.
- Derive an ATA only through `FindProgramAddress`. A seed set whose first
  candidate is on the curve has no valid address at that bump, and taking it
  anyway produces a plausible base58 string that nothing can ever sign for.
- Preserve the existing signer and durable-nonce rules. A nonce authority is
  an additional signer, never a substitute for a token authority.
- For multisig, validate `1 <= m <= n <= 11`, deduplicate signer keys, and
  reject a request whose unique signer count cannot fit in its serialized
  transaction.

## Token-2022 Boundary

Token-2022 shares the base lifecycle but adds extension initialization and
extension-specific transfer, fee, metadata, confidential-transfer, and
authority rules. It cannot safely reuse fixed 82 / 165 byte assumptions.

After the classic program is complete, create a separate
`TOKEN_2022_API_PROPOSAL.md` that begins with extension-aware account sizing
and only then selects extensions to support. Do not point classic endpoints at
`TokenzQd...` as a shortcut.

## References

- Official Token Program instruction source:
  https://github.com/solana-program/token/blob/main/interface/src/instruction.rs
- Associated Token Account program source:
  https://github.com/solana-program/associated-token-account
- Program derived address derivation:
  https://solana.com/docs/core/pda
- Solana SPL Token basics:
  https://solana.com/docs/tokens/basics
- Solana token account creation guide:
  https://solana.com/pt/docs/tokens/basics/create-token-account

