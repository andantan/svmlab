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
System Program supplies the `CreateAccount` behind every `create-*`. Their
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

Every state-changing endpoint takes a required `recent_blockhash`, never
fetched server-side, and an optional `durable_nonce_account`. When the latter is
present, the message is built against the stored nonce instead, with
`AdvanceNonceAccount` prepended, and `recent_blockhash` only prices it.

## Rules

- A classic mint is an 82-byte Token-Program-owned account, a token account
  165, a multisig 355. Token-2022 accounts may be larger, with extension space
  past the base layout, so size checks are "at least" and only the base slice is
  decoded. All have to be rent exempt, and the rent-exempt minimum is always
  asked of the cluster, never assumed: a zero-byte account's minimum was 810624
  lamports on mainnet and 650240 on devnet on the same day, and neither matched
  the 890880 often quoted.
- Creating an account and initializing it are separate endpoints. An
  uninitialized Token-owned account can be initialized by somebody else before
  its intended owner does it, and this surface once closed that race by making
  `create-mint` and `create-account` bundle both. It no longer does: closing the
  race is the caller's choice, made by putting the two instructions in one
  transaction, not a property this low-level surface imposes. Every `create-*`
  is `System.CreateAccount` sized and owned for its layout, and every
  `initialize-*` is the one instruction that follows it.
- Token amounts are base units (`u64`), not UI decimal strings. `decimals` is
  metadata on the mint. Checked variants take the expected decimals and should
  be the default public API.
- A token transfer moves balances between two *token accounts* of the same
  mint; it never sends directly to a wallet address. `create-ata` then an
  exact-address transfer is the path for a wallet recipient.
- An authority may be a single signer or an SPL multisig account. Request types
  name the authority by the role it plays — `mint_authority`,
  `token_account_owner`, `source_token_account_authority`,
  `token_account_close_authority`, `freeze_authority` — never a bare
  `authority`, since several different authorities can bear on one account. The
  exceptions are the few instructions whose authority genuinely depends on the
  account's type (`withdraw-excess-lamports`). Every one also takes optional
  `multisig_signers`; when non-empty, the authority itself does not sign and the
  named members do.
- An endpoint does one thing. Where an instruction has an optional amount (all
  of it, or exactly this much), that becomes two paths — the base one with a
  required amount and `/max` without one — rather than one endpoint whose
  meaning changes with an empty field.
- The Token Program owns mint and token-account data. Do not offer a generic
  "set owner program" escape hatch.
- An optional public key is encoded **two different ways**, and they must not be
  confused. In **account data** it is a `COption`: a `u32` tag with the 32-byte
  payload always written, which is what makes a mint 82 bytes with or without a
  freeze authority. In **instruction data** it is a one-byte tag, with the key
  following only when the tag says there is one and `None` written as that
  single zero byte and nothing else.

  Sending the account form in instruction data is not a harmless overshoot.
  `unpack_pubkey_option` reads one tag byte and then 32 bytes, so three of the
  four tag bytes stay in front of the key: it shifts three bytes, loses its
  last three, and the program stores a valid-looking address nobody holds
  without reporting anything. This was shipped in `InitializeMint2` and
  `SetAuthority` and only caught after a `close_authority` written that way
  left an account nobody could close. `None` had been passing by accident,
  since the first of the four tag bytes is zero and the rest was ignored.

  `core.appendPubkeyOption` is the instruction-data form. `codec.Binary`'s
  `AppendCOption`/`ReadCOption` are the account-data form and belong only to
  the parsers.

  The same mistake was made a second time, with a `u64` instead of a key, in
  `UnwrapLamports`, whose amount is an `Option<u64>` with a one-byte tag.
  `AppendCOption` was reached for because it was the writer that existed, and
  it failed identically: `None` passed (its first tag byte is zero), while
  `Some(10000)` put three zero tag bytes in front of the amount, which the
  program read as `0x2710000000` and rejected as `InsufficientFunds` — a
  business-logic error that looked nothing like an encoding bug. The rule is
  the one above, not a pubkey-specific one: **an optional value in instruction
  data has a one-byte tag, whatever the value is.** `COption` belongs to account
  layouts only. Check this rule before writing any new builder with an optional
  field, and check the upstream doc comment, which states the tag width.
- Removing an authority is a separate endpoint from replacing it, never a
  request flag. An omitted `new_authority` must not be read as "remove it": for
  a mint or freeze authority that is permanent, and a field somebody forgot to
  fill in should not be indistinguishable from a deliberate removal. Hence
  `/replace` and `/clear` as distinct paths.

## Complete Original SPL Token Instruction Set

The upstream Token interface (`solana-program/token`, `interface/src/instruction.rs`)
defines these opcodes. Gaps are Token-2022-only opcodes; `core/token.go` declares
those too, for reference, but nothing here builds them.

| Opcode | Instruction              | Endpoint(s)                                   | Status                          |
|-------:|--------------------------|-----------------------------------------------|---------------------------------|
|      0 | InitializeMint           | `initialize-mint`                             | live                            |
|      1 | InitializeAccount        | `initialize-account`                          | live                            |
|      2 | InitializeMultisig       | `initialize-multisig`                         | live                            |
|      3 | Transfer                 | `transfer`, `transfer/max`                    | live                            |
|      4 | Approve                  | `approve`, `approve/max`                      | live                            |
|      5 | Revoke                   | `revoke`                                      | live                            |
|      6 | SetAuthority             | `set-authority/{mint,freeze,close}/{replace,clear}`, `set-authority/owner/replace` | live, devnet |
|      7 | MintTo                   | `mint-to`                                     | live                            |
|      8 | Burn                     | `burn`, `burn/max`                            | live                            |
|      9 | CloseAccount             | `close-account`                               | live, mainnet bytes             |
|     10 | FreezeAccount            | `freeze-account`                              | live, devnet                    |
|     11 | ThawAccount              | `thaw-account`                                | live, devnet                    |
|     12 | TransferChecked          | `transfer-checked`, `transfer-checked/max`, `transfer-from-ata`, `transfer-from-ata/max` | live, mainnet bytes |
|     13 | ApproveChecked           | `approve-checked`, `approve-checked/max`      | live                            |
|     14 | MintToChecked            | `mint-to-checked`                             | live, devnet incl. multisig     |
|     15 | BurnChecked              | `burn-checked`, `burn-checked/max`            | live, devnet                    |
|     16 | InitializeAccount2       | `initialize-account2`                         | live                            |
|     17 | SyncNative               | `sync-native`                                 | live, devnet (Token-2022)       |
|     18 | InitializeAccount3       | `initialize-account3`, `initialize-wrapped-sol` | live, mainnet bytes           |
|     19 | InitializeMultisig2      | `initialize-multisig2`                        | live, devnet                    |
|     20 | InitializeMint2          | `initialize-mint2`                            | live, devnet                    |
|     21 | GetAccountDataSize       | `account-data-size`                           | open                            |
|     22 | InitializeImmutableOwner | `initialize-immutable-owner`                  | live, devnet (Token-2022)       |
|     23 | AmountToUiAmount         | `amount-to-ui`                                | open                            |
|     24 | UiAmountToAmount         | `ui-to-amount`                                | open                            |
|     38 | WithdrawExcessLamports   | `withdraw-excess-lamports`                    | live, not yet sent              |
|     45 | UnwrapLamports           | `unwrap-lamports`, `unwrap-lamports/max`      | live, devnet (Token-2022)       |
|    255 | Batch                    | `batch`                                       | open, last                      |

"Mainnet bytes" means the builder's output was compared byte for byte, account
order included, against instructions taken off mainnet. "Devnet" means a
transaction was signed and sent and the account read back afterward; for the
instructions that carry an optional public key that meant comparing the stored
authority byte for byte against what the request named. That read-back is what
caught the three-byte shift in `InitializeMint2` described in the rules above,
which an earlier "encoding checked by hand" note had missed: the bytes matched
a layout, just not the one the program unpacks. Plain "live" means built and
served, not yet seen land.

`InitializeImmutableOwner` is a no-op in the classic Token Program, kept for
compatibility with the Associated Token Account flow, which calls it on every
account it creates regardless of program; in Token-2022 it attaches the real
extension. The endpoint currently accepts only Token-2022 for `program`. That
restriction rests on an earlier belief that classic Token has no handler for
the opcode, which the upstream doc comment contradicts, and should be lifted.
Either way it has to run before `InitializeAccount*`, since both programs fail
it on an account already initialized.

`Batch` serializes several Token instructions inside one instruction — a `u8`
account count, a `u8` data length, then the nested discriminator and data, per
entry — which is different from putting several ordinary instructions in one
Solana transaction.

The three at 38, 45, and 255 are in the interface crate, which is not the same
thing as the deployed program: an opcode can exist in the source and still come
back `InvalidInstruction` from the account an endpoint sends it to. Sampling
twelve mainnet transactions turned up 81 Token instructions across seven
opcodes — 3, 4, 9, 12, 17, 18, 21, and 22 — which said nothing either way about
the three. `UnwrapLamports` has since been sent: the devnet Token-2022 program
logs it by name, and both a full and a partial unwrap landed once the encoding
was right. It has not been sent to classic Token. `WithdrawExcessLamports` is
built and served on the strength of its opcode number and upstream account list
alone.

## Composite Convenience Endpoints — none, by decision

This section once listed builders that bundled several instructions into one
transaction to remove an unsafe intermediate state. None of them survived into
the v2 surface, and none will be added to it: a caller who wants two
instructions to land atomically builds them into one transaction, and a
composed convenience endpoint belongs to a later, higher-level API generation
rather than this low-level one. What each planned composite became:

| Planned composite             | Would have bundled                                     | What replaced it                                                          |
|-------------------------------|--------------------------------------------------------|---------------------------------------------------------------------------|
| `token/create-mint`           | System CreateAccount + InitializeMint2                 | `create-mint` (CreateAccount only) + `initialize-mint2`                   |
| `token/create-account`        | System CreateAccount + InitializeAccount3              | `create-kta` (CreateAccount only) + `initialize-account3`                 |
| `token/transfer-to-wallet`    | optional ATA create + TransferChecked, both sides derived | `transfer-from-ata`: source derived, never created; destination exact  |
| `token/create-wrapped-sol`    | create token account + InitializeAccount3(native mint) | `create-kta`/`create-ata` + `initialize-wrapped-sol`                      |
| `token/wrap-sol`              | System Transfer + SyncNative                           | `system/transfer` + `sync-native`                                         |

`create-ata` and `create-ata-idempotent` are the one exception in kind rather
than in principle: they are single ATA instructions, and it is the ATA program
itself, not this API, that creates and initializes the account inside one
instruction through its own CPIs, since a derived address has no private key to
sign a separate `CreateAccount` with.

`initialize-wrapped-sol` is not a composite either. It is `InitializeAccount3`
with `mint` fixed to the program's own native mint rather than taken from the
request, because that address is not something a caller should have to know:
classic Token's is the constant `So11111111111111111111111111111111111111112`,
and Token-2022's is a separate PDA of the Token-2022 program derived from the
seed `native-mint`, `9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP` — confirmed
when an account initialized against it came back from devnet parsed
`isNative: true`. A wrapped-SOL account under one program can never hold the
other's native mint.

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
derive exactly, bumps included, and every account that did not match is one the
seeds say should not.

### 1. Durable nonce, extracted — deferred

Every System and Token endpoint still carries its own copy of the block that
reads `durable_nonce_account` and builds the two messages (the real one against
the stored nonce, and one against `recent_blockhash` to price it), along with
the fee-payer balance check that follows. That is deliberate for now: the
refactor duplicates first and consolidates in a separate pass, so request and
response shapes could keep moving without dragging a shared helper along. They
have now settled across both programs, so this is a candidate for that
consolidation pass rather than something waiting on a shape to appear.

### 2. Shared token foundation — done

Done:

- `core.Token` and `core.Token2022`, two values of one type. The program id is
  a field rather than a constant, since the classic surface is identical and
  which program a caller wants follows from the mint rather than the cluster.
- `u8` opcode encoding, against the System Program's `u32`. The full opcode
  list, 0 through 46 plus 255, with the Token-2022-only ones declared for
  reference and not built.
- Parsers for Mint (82), TokenAccount (165), and Multisig (355). Mint and token
  account agree with what the RPC reports for USDC, USDT, and wSOL; wSOL is the
  one that exercises an absent `COption` in both fields. Multisig has since
  been confirmed against one created and initialized on devnet.
- `COption` moved to `codec`, where the tag is a `u32` and the payload is
  written whether or not it is present. That fixed width is why a mint is 82
  bytes with or without a freeze authority.
- Shared authority handling for a single signer and for multisig members,
  where the authority stops signing and the members sign in its place.
- `Token.CreateMint`, `Token.CreateAccount`, and `Token.CreateMultisig` emit the
  System create alone, sized and owned for the layout; initializing is the
  separate `Initialize*` builder. They once emitted both as one pair.
- `Token.NativeMint`, which returns the classic constant for Token and derives
  Token-2022's own PDA for Token-2022.

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
token/create-mint                 (CreateAccount only; see below)
token/create-kta                  (CreateAccount only; was token/create-account)
token/mint-to-checked
token/transfer-checked            (+/max)
token/burn-checked                (+/max)
token/close-account
```

All six are live under `/svm/v2/transaction/token/`. `TransferChecked`,
`CloseAccount`, and `InitializeAccount3` were rebuilt from fifty instructions
taken off mainnet and match byte for byte with the account order included.
`MintToChecked` and `BurnChecked` were missing from that sample and were first
confirmed by live devnet sends instead, `MintToChecked` including one whose
mint authority was a 2-of-3 multisig.

`create-mint` and `create-kta` shipped as composites that also initialized, and
were later cut down to `CreateAccount` alone (see the rules above);
`create-account` was renamed `create-kta`, a keypair token account, to set it
against `create-ata` and away from System's own `create-account`. The account
they create is initialized by `initialize-mint2`/`initialize-account3`, or
their older opcodes, as a separate call.

The holder accounts here are ordinary keypairs, which is why this step could
come before ATA: the whole lifecycle can be walked end to end without a derived
address anywhere in it. That was the argument for ordering it first while PDA
was still unwritten.

Every one of these, and everything after, takes a required `program` field naming the account to
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

Authorization splits along two different axes depending on what moves, and
the request field names which one: `mint-to-checked` takes `mint_authority`,
checked against the mint's own, since minting creates supply and only the mint
can allow that. `transfer-checked` and `burn-checked` take
`source_token_account_authority`/`token_account_authority`, checked against the
account's `owner` or its `delegate` for no more than the delegated amount, since
both spend a balance that belongs to whoever holds it. `close-account` splits
again: `token_account_close_authority`, checked against
`close_authority.unwrap_or(owner)`, never a delegate, because delegation covers
spending a balance and closing isn't spending one.

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
token/transfer-from-ata          (+/max; was token/transfer-to-wallet)
```

This is the ATA program rather than the Token program, so it has its own
`core.ATA` namespace on `AssociatedTokenProgramID`, and it was the first
consumer of `PDA.Find`. The derived address was already known to be right
before any of this was written — the same derivation matched 1655 live
associated accounts in step 0 — so what the endpoints had to confirm was the
instructions, not the address: no data at all for the plain create, one byte
for the idempotent one, both exactly as expected.

`transfer-from-ata` takes `owner` + `mint` and derives only the *source's*
associated account from them. The source is never created if missing, since an
account nobody has funded has no balance to send; that is reported as the owner
having no associated account for the mint. `destination_token_account` is an
exact address the caller already knows, keypair or associated, taken exactly as
`transfer-checked` takes it — nothing on the destination side is derived or
created.

It shipped first as `transfer-to-wallet`, which took two wallet addresses and
derived both sides, prepending an idempotent create for the destination's
associated account so the transfer and the account landed together. That made
it the one endpoint in Token v2 that quietly bundled a conditional create with a
transfer, so it was cut down to the one derivation only this endpoint offers —
the source lookup. A caller who wants the destination created first calls
`create-ata-idempotent` and then this, two calls rather than one endpoint doing
both silently.

No `token/close-ata` was needed. `token/close-account` already takes any
165-byte Token or Token-2022 account, and an associated account is that same
layout at a derived address; nothing about closing distinguishes how the
address came to exist.

### 5. Delegation and administration — done

Live:

```text
token/approve-checked
token/revoke
token/set-authority/mint/replace     token/set-authority/mint/clear
token/set-authority/freeze/replace   token/set-authority/freeze/clear
token/set-authority/owner/replace
token/set-authority/close/replace    token/set-authority/close/clear
token/freeze-account
token/thaw-account
```

`freeze-account` and `thaw-account` check the same precondition
`set-authority/freeze/*` does: the mint must have been initialized with a
freeze authority, which `create-mint` has offered since it was written, and
clearing that authority afterward is permanent, so a mint whose freeze
authority is gone can never freeze a holder again. The authority is the mint's
freeze authority, never the account's own owner or a delegate — freezing
suspends any account holding the mint, which is a different axis from who may
spend a given account's balance. Freezing an already-frozen account, or
thawing one that is not frozen, is rejected rather than silently allowed
through.

Verified end to end on devnet: created an associated account, froze it,
confirmed `frozen: true` through the read endpoint, confirmed a second freeze
is rejected, confirmed thaw with the wrong key is rejected, thawed it with the
mint's real freeze authority, confirmed `frozen: false`, confirmed a second
thaw is rejected. Both directions were signed and sent, not just built.

`approve-checked` grants a delegate up to an amount, and only the account's
owner may grant it. An existing delegate cannot re-delegate onward, since that
would let it hand the owner's balance to a third party the owner never chose.
A second approve replaces the delegation rather than adding to it, because the
program stores one delegate and one amount rather than a list, which is also
why reducing an allowance is another approve rather than a partial revoke.

`revoke` takes neither an amount nor a delegate. It clears whatever is stored,
so it is a deletion rather than a decrease, and naming the delegate would only
be a way to get it wrong. An account with no delegate revokes cleanly.

`set-authority` is seven endpoints rather than one, split by role and by
direction.

The four roles are separate endpoints because they differ in more than the
`u8` they encode: which account is read (a mint for the first two, a token
account for the last two), which key must sign, and whether the change can be
undone. One endpoint would have branched four ways internally to save a single
path.

Direction is a path segment rather than a request field. Clearing a mint or
freeze authority is permanent, and a `clear_authority` boolean makes a field
somebody forgot to fill in indistinguishable from a deliberate removal;
`/clear` has to be typed. `/replace` rather than `/new`, because three of the
four roles cannot be set from absent at all — a mint or freeze authority at
`None` has no signer left to change it, and an owner is never absent — so only
close authority ever starts empty.

Seven and not eight: `AccountOwner` has no clear variant. A token account's
owner is a plain `Pubkey` on chain rather than a `COption`, so there is no
representation for "no owner" to write, and the program rejects the attempt
rather than accepting a value it could not store.

The authority a `close` change requires is `close_authority.unwrap_or(owner)`,
the same rule `close-account` itself applies: a close authority **replaces**
the owner rather than joining it. Once set, the owner can neither close the
account nor take the role back — only the current close authority can hand it
on or clear it. This was implemented as owner-or-close-authority at first,
which let an owner ignore a handover they had made.

### 6. Compatibility and multisig — done

```text
initialize-mint, initialize-mint2
initialize-account, initialize-account2, initialize-account3
initialize-multisig, initialize-multisig2, create-multisig
transfer (+/max), approve (+/max), mint-to, burn (+/max)
initialize-immutable-owner
```

The `initialize-*` endpoints validate before building: the target must already
exist, be owned by `program`, be at least the base size, and still be
uninitialized. "At least" rather than "exactly" matters: all five
`initialize-mint*`/`initialize-account*` endpoints first shipped requiring an
exact 82 or 165 bytes, which rejected every Token-2022 account with extension
space appended, and decoded the whole buffer rather than the base slice.

The unchecked opcodes take no `mint` and no `decimals` at all, since the program
names and verifies neither; mint is still read off the account and reported in
the response, so a caller is not left blind about what moved. `transfer`,
`approve`, and `burn` have `/max` paths matching their checked counterparts.
`mint-to` has none: supply has no balance to sweep.

`create-multisig` is `CreateAccount` sized for 355 bytes, and the multisig it
initializes is permanent in both directions the classic program allows: its `m`
and enrolled signers can never be changed, and it can never be closed. Neither
program has an instruction for either, and unlike a mint, which Token-2022's
`MintCloseAuthority` makes closable, nothing adds one for a multisig.
Replacing a multisig means creating a new one and repointing whatever named the
old one through `set-authority`. The multisig endpoints take the account as
`multisig_account`, and the members enrolled as `signers`, which is a different
list from `multisig_signers` — the members signing *this* transaction on a
multisig's behalf. Enrolling a signer does not require their signature.

### 7. Native SOL, read-return-data, recovery, batch — partly done

```text
token/initialize-wrapped-sol       done
token/sync-native                  done, devnet (Token-2022)
token/unwrap-lamports              done, devnet (Token-2022)
token/unwrap-lamports/max          done, devnet (Token-2022)
token/withdraw-excess-lamports     built, not yet sent
token/account-data-size            open
token/amount-to-ui                 open
token/ui-to-amount                 open
token/batch                        open, last
```

`create-wrapped-sol` and `wrap-sol` were dropped rather than built; see the
composite section above. A wrapped-SOL account is made and funded from pieces
that already exist:

```text
create-kta or create-ata            -> account, 165 bytes, owned by program
initialize-wrapped-sol              -> initialized against program's native mint
system/transfer to the account      -> lamports rise, amount does not
sync-native                         -> amount := lamports - rent reserve
unwrap-lamports(/max)               -> lamports out, account kept
close-account                       -> lamports out, account gone
```

`sync-native` is the only instruction that reconciles a wrapped-SOL account's
`amount` with its lamports; nothing updates `amount` when SOL arrives by plain
transfer. It takes no authority, since recomputing a derived value needs nobody's
permission. On devnet an account holding 2,599,551 lamports against a 1,488,440
reserve synced to exactly 1,111,111.

`unwrap-lamports` is the partial counterpart to closing a wrapped-SOL account:
the account stays, rent-exempt and still wrapped, ready to be funded again. Its
amount is an `Option<u64>` on the wire, which this surface splits into
`unwrap-lamports` (amount required, sent present) and `unwrap-lamports/max` (sent
absent, the whole balance). The first attempts sent the amount as a bare `u64`
and then as nothing at all, both `InvalidInstructionData`, and then with a
4-byte `COption` tag, which failed a partial unwrap as `InsufficientFunds`
because the tag bytes had shifted into the amount — see the encoding rule
above. A full unwrap on devnet left the account at exactly its reserve; a
partial one moved exactly 5,000. Its authority is the account's owner or its
delegate, the spending rule, not close-account's.

`withdraw-excess-lamports` rescues SOL sent by plain transfer to any
Token-owned account — mint, token account, or multisig — and leaves the account
at its rent-exempt minimum, never closing it. The upstream doc lists the
authority as "owner/delegate"; which key that resolves to for each of the three
account kinds is not settled client-side, so the request takes an unqualified
`account` and `authority`, and a wrong one fails on chain rather than as a 400.
It has not been sent against a live cluster yet, so it is the next thing to
confirm here.

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

Amounts are decimal strings carrying raw base units, and every account field is
named by the role it plays:

```json
{
  "source_token_account": "source_token_account",
  "mint": "mint_account",
  "destination_token_account": "destination_token_account",
  "source_token_account_authority": "owner_or_delegate",
  "amount": "250000",
  "decimals": 6,
  "program": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  "fee_payer": "fee_payer",
  "multisig_signers": [],
  "recent_blockhash": "required",
  "durable_nonce_account": "optional"
}
```

`program` is required with no default, since a mint belongs to exactly one of
Token or Token-2022 forever and defaulting would make picking wrong silent. It
is the account rather than a `"classic" | "token2022"` enum, so a third
deployment needs no code change here to be reachable.

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
transaction, message, recent_blockhash, account_keys, signers,
nonce_authority (only when durable_nonce_account was used),
fee { payer, lamports, sol }
```

plus the selected `program` and the operation's own role-named fields. Where
the server resolved a value rather than echoing one — a mint read off the
account, a balance swept by `/max`, a `max_amount` granted — the response
reports it. Where the figure is only known on chain when the transaction lands,
the field is named `estimated_*` and says so.

## Safety Checks

- Every account read is checked against the request's `program` field before
  it is decoded — the mint's owner and, where applicable, the token account's
  owner must equal what was named, not merely decode successfully. A Token
  account decodes as a valid prefix of a Token-2022 layout, so without this an
  on-chain `IncorrectProgramId` would be the first sign of the mismatch instead
  of a 400 with a reason.
- Decode every involved account and verify its mint against the request's
  before building a transfer, burn, or close; for the unchecked variants,
  which name no mint, the destination is checked against the source's.
- `decimals`, on the checked variants that take it, is compared against the
  decoded mint rather than filled in from it, which is what lets a
  wrong-decimals amount come back as a 400. The `/max` variants take no
  `decimals` and read it from the mint, since there is no client-computed
  amount left to protect.
- A close of a non-native token account requires a zero balance; a native
  (wrapped SOL) account skips that check, since its balance is its lamports
  and closing it is how the SOL is unwrapped.
- An associated address is never trusted under that name. `transfer-from-ata`
  derives the source's through `PDA.Find` rather than accepting a
  caller-supplied one.
- A nonce authority is an additional signer, never a substitute for a token
  authority. Implemented, though duplicated per endpoint rather than shared —
  see step 1.
- Multisig authorities are checked against the account they name.
  `core.RequireMultisigAuthority` reads it, decodes it with
  `core.DecodeMultisig` (owner-checked like `DecodeMint`, but a fixed 355
  bytes since no extension mechanism attaches to a multisig account), and
  rejects an authority that is not initialized, that requires more signers
  than were given, or whose given signers include one not enrolled. It runs
  after the owner-or-delegate check in each endpoint and only when
  `multisig_signers` is non-empty. Confirmed live on devnet: `mint-to-checked`
  against a mint whose authority is a 2-of-3 multisig landed with two members
  signing. Naming a member wallet as the authority instead of the multisig
  account is rejected before building, correctly, as not being the mint
  authority.
- What is *not* caught client-side: anything a Token-2022 extension changes.
  `set-authority/owner/replace` on an account carrying `ImmutableOwner` builds
  normally and fails on chain, because telling that the extension is there
  means walking the extension TLV list, which nothing here parses yet. See the
  boundary below.

## Token-2022 Boundary

Token-2022 shares the base lifecycle but adds extension initialization and
extension-specific transfer, fee, metadata, confidential-transfer, and
authority rules. It cannot safely reuse fixed 82 / 165 byte assumptions.

Every endpoint here does take Token-2022 as its `program`, deliberately: on the
shared instruction surface the two programs are byte for byte the same, and
the endpoints have been exercised against Token-2022 on devnet throughout. What
they must not do is assume an extension is absent, and today they partly do.
Base layouts are read from the first 82 or 165 bytes, sizes are checked as "at
least", and an extended account whose type tag reads `Uninitialized` is
recognized as such — but nothing walks the extension list itself. So a
precondition an extension imposes (an `ImmutableOwner` blocking an owner
change, a `NonTransferable` mint, a transfer fee, a frozen default state)
passes the server's checks and fails on chain.

Closing that means a real TLV parser: walk the `u16` type / `u16` length
records past offset 165, match each against the extension type's actual
protocol ordinal, and expose the result to the existing checks. A parser that
guesses at an ordinal is worse than none — it would reject legitimate requests
— so it waits for its own document.

That document is `TOKEN_2022_API_PROPOSAL.md`, not yet written. It begins with
extension-aware sizing and parsing, then selects extensions to support. Two
things learned here carry over directly: the outer opcodes 25 through 46 are
already declared in `core/token.go` for reference, and any optional field in
their instruction data takes a one-byte tag (see the rules above).

## References

- Official Token Program instruction source (opcode list, account orders, and
  tag widths, stated in each variant's doc comment):
  https://github.com/solana-program/token/blob/main/interface/src/instruction.rs
- Associated Token Account program source:
  https://github.com/solana-program/associated-token-account
- Program derived address derivation:
  https://solana.com/docs/core/pda
- Solana SPL Token basics:
  https://solana.com/docs/tokens/basics
- Solana token account creation guide:
  https://solana.com/pt/docs/tokens/basics/create-token-account
- Unwrap lamports:
  https://solana.com/docs/tokens/advanced/unwrap-lamports
