# SVM API Roadmap

## Purpose

This is the high-level API roadmap for svmlab. It groups work by protocol
responsibility and records the implementation order.

~~~
account model -> deterministic addresses -> assets -> application state
-> transaction infrastructure -> ecosystem and validator operations
~~~

## Current Status

Core and endpoints had come apart around Token's freeze and thaw builders, the
same shape the first lifecycle was in before it shipped; that gap is closed.

System Program's field-fidelity pass is done. Every endpoint plays one role per
role name: a low-level API plays one role per endpoint, so
`transfer`/`transfer/max`/`transfer/spread`/`transfer/collect` all require both
sides to already exist, and `funding_payer`/`rent_payer`/`fee_payer` are the
three roles any endpoint draws from. `recent_blockhash` is always a required
field, never fetched server-side, and naming `durable_nonce_account` builds
against the stored value instead and prepends the advance. One finding from
that pass changes what is possible, not just what is named: the System
Program's `Transfer` (and `CreateAccount`'s internal lamport move) reject a
`from` account outright if it carries any data, regardless of who owns it.
Combined with `Allocate` being a one-time, non-shrinkable operation, a
System-owned account allocated to an arbitrary size other than the 80-byte
nonce layout has no recovery path within System Program at all — no
`system/close-account` exists or can exist, since System Program itself has no
generic close instruction. The only account shape System Program can un-stick
this way is a nonce account (`nonce/initialize` + `nonce/withdraw`/`withdraw/max`,
both already live); anything else needs a custom-deployed program to take
ownership via `assign` and drain it directly, which is exactly the case Vault's
`vault/close` is for below. A second finding from the same pass: the runtime
deducts the transaction fee from the fee payer in isolation, before any
instruction runs, and independently requires what that alone leaves to be zero
or rent-exempt — so a `max` sweep whose source is also the fee payer cannot
assume the whole balance is reachable; `transfer/max` and `transfer/collect`
both check this before building, not just when funding and paying overlap by
accident.

The same field-fidelity pass has now been run across every one of Token
classic's 20 endpoints too: `recent_blockhash` required and never
server-fetched, `nonce_account` renamed `durable_nonce_account`,
`GetMultipleAccounts` batching in place of per-account round trips everywhere
an endpoint reads more than one account, and every bare `authority` /
`account` / `new_authority` field renamed to say exactly which authority or
which role it is — `mint_authority`, `token_account_owner`,
`token_account_close_authority`, `freeze_authority`, and so on — so a caller
is never left guessing which of several possible meanings a generic name
carries. `token/create-account` is renamed `token/create-kta` (keypair token
account), paired against `create-ata`, since "create-account" was ambiguous
with System's own endpoint of the same name. `token/transfer-to-wallet` is
reworked into `token/transfer-from-ata`: it no longer derives or
auto-creates a destination associated account at all, only the *source* is
wallet-derived (owner + mint, must already exist); the destination is an
exact token account address the caller already knows, keypair or associated,
exactly as `transfer-checked` takes it. Three `max` endpoints were added,
mirroring System's: `transfer-checked/max` and `transfer-from-ata/max` sweep
the source token account's current balance (no rent-exemption floor applies
to a token balance the way it does to lamports, so the fee-payer-overlap
carve-out System needs does not apply here), and `approve-checked/max`
grants the maximum representable base-unit amount instead of reading a
balance at all — the standard effectively-unlimited approval pattern.

A new read-only endpoint, `/svm/account/authority`, reports every
authority-bearing field for whichever kind of account a public key names —
a nonce account's authority, a mint's `mint_authority`/`freeze_authority`, a
token account's `token_owner`/`delegate`/`close_authority`, or a multisig's
`m`/`n`/`signers`. Every field is always present in the response rather than
omitted when unset, and `close_authority` always reports the actual effective
closer (`close_authority.unwrap_or(owner)`) rather than requiring the caller
to apply that fallback themselves.

Token's multisig lifecycle is now live: `initialize-multisig`/
`initialize-multisig2` (the original and 2 opcodes, differing only in
whether the rent sysvar rides along) and `create-multisig`, the
`System.CreateAccount`-only composite that pairs with them. `burn-checked/max`
rounds out the max-sweep family (`transfer-checked/max`,
`transfer-from-ata/max`, `approve-checked/max`), sweeping a token account's
entire balance the same way the others do. A multisig, once initialized, can
never have its members or `m` changed and can never be closed — the classic
Token Program has no instruction for either, and unlike a mint there is no
Token-2022 extension that adds one; replacing a multisig means creating a new
one and repointing whatever named the old one as an authority through the
existing `set-authority` endpoints.

Building `create-multisig` forced a reconsideration of `create-mint` and
`create-kta`, which used to bundle `CreateAccount` with initialization in one
transaction specifically to close the race where somebody else initializes
the account first with their own authority. That race-closing is not this
API's job at the low level: a caller who wants it closed can build the two
instructions into one transaction themselves, the same as any other pairing
of a raw `create-*` and `initialize-*` endpoint. So `create-mint` and
`create-kta` were cut down to `CreateAccount` only — dropping
`mint_authority`/`freeze_authority`/`decimals` and `owner` respectively —
and now pair with `initialize-mint2`/`initialize-account3` exactly the way
`create-multisig` pairs with `initialize-multisig2`. This also surfaced a
real bug in `/svm/account/state`: its `initialized` field never recognized a
multisig account at all (355 bytes matches neither a mint's 82 nor a token
account's 165), so a freshly allocated, uninitialized multisig always
reported `initialized: true`; fixed by adding the missing `DecodeMultisig`
branch.

The unchecked classic opcodes are live too: `transfer`, `approve`, `mint-to`,
`burn` (+`max` on the first three; minting has no balance to sweep), and
`initialize-immutable-owner`. The unchecked variants take no mint or decimals
field at all — resolving mint server-side from the account instead — since
neither is named or verified against the accounts on chain, which is exactly
the failure mode the checked variants exist to catch.
`initialize-immutable-owner` is Token-2022-only: the classic Token Program's
deployed instruction processor has no arm for this opcode, so `program` is
restricted to Token-2022 here rather than accepting either, unlike every
other endpoint. It also has to run before `initialize-account*`, never after
— the program requires the base layout to still be `Uninitialized` when an
extension attaches — and this is checked client-side as a 400 by decoding
just the base 165 bytes, the same "is this already initialized" question
`initialize-mint*`/`initialize-account*` already answer for themselves.

Getting there also fixed a real bug shared by all five `initialize-mint*`/
`initialize-account*` endpoints: each required its target account to be
*exactly* 82 or 165 bytes, which silently rejected every Token-2022 account
with extension space appended past the base layout (a 170-byte
immutable-owner account, for instance). The check is now "at least" that
many bytes, and the two `DeserializeMint`/`DeserializeTokenAccount` calls
that used to receive the whole account buffer now receive only the base
slice (`raw[:core.MintSpace]`/`raw[:core.TokenAccountSpace]`), so extension
bytes past it are never mistaken for base-layout fields.

What is not caught client-side: `set-authority/owner/replace` (and any other
endpoint touching a property an extension can override) has no way to tell
that a token account carries the `ImmutableOwner` extension before sending
it, so an attempt to reassign one still only fails on chain, correctly, just
not as an early 400. Closing that gap for real needs a genuine Token-2022
extension TLV parser — walking the variable-length, multi-type extension
list past `core.TokenAccountTypeOffset` and matching against each
extension's real protocol ordinal — which is a meaningfully bigger,
separate undertaking than the single-field "is the base state Uninitialized"
check above, and is exactly the boundary this project has already drawn
around Token-2022 extensions generally (see the Token-2022 Program section
below and `TOKEN_2022_API_PROPOSAL.md`'s eventual scope). Guessing at an
unverified extension-type ordinal here would risk the worse failure mode of
wrongly rejecting a legitimate request, so this stays deferred rather than
half-built.

Getting `initialize-immutable-owner` working against a real Token-2022
account surfaced two more real bugs. First, all five
`initialize-mint`/`initialize-mint2`/`initialize-account`/
`initialize-account2`/`initialize-account3` endpoints required their target
to be *exactly* 82 or 165 bytes, silently rejecting every Token-2022 account
with extension space appended past the base layout (a 170-byte
immutable-owner account, for instance) — the check is now "at least" that
many bytes, and the `DeserializeMint`/`DeserializeTokenAccount` calls that
used to receive the whole account buffer now receive only the base slice, so
extension bytes past it are never mistaken for base-layout fields. Second,
`/svm/account/state`'s `initialized` field defaulted to `true` whenever an
account couldn't be decoded as a mint, token account, or multisig, which is
exactly what a Token-2022 account not yet past `initialize-account*` looks
like; it now checks whether the account is owned by a token program, large
enough to carry a type tag, and that tag itself reads `Uninitialized`, and
reports `initialized: false` in that case instead of falling through to the
default.

`system/nonce/create-account` is cut down to `CreateAccount` only, matching
create-mint/create-kta/create-multisig: it used to bundle `CreateAccount`
and `InitializeNonceAccount` in one transaction specifically to close the
same initialize-before-someone-else race those did, but closing that race
isn't this low-level API's job — `nonce/initialize` already existed as the
separate call to pair with it, so the `authority` field was dropped from
`nonce/create-account` entirely rather than newly built. `system/seed/create-account`
needed no equivalent change: it was already creation-only.

| Group                     | Core    | Endpoints | Notes                                                                       |
|---------------------------|---------|-----------|-----------------------------------------------------------------------------|
| RPC, signing, and tools   | done    | done      | account, fee, rent, simulation, send, status, key generation, signing, blockhash refresh, base58/base64 conversion, account/authority |
| System Program            | done    | done      | all 13 instructions, seed variants, durable nonce, multi/batch/collect transfer, field-fidelity pass done |
| PDA derivation            | done    | none      | Create and Find, checked against 2044 mainnet accounts; first used by ATA   |
| SPL Token classic         | done    | done      | lifecycle (create-only + initialize-* pairing), delegation, 7 set-authority, freeze/thaw, max variants, multisig lifecycle, unchecked opcodes (+max), and initialize-immutable-owner all live; native SOL and read-return-data next |
| Associated Token Account  | done    | done      | create, create-idempotent, transfer-from-ata (+max); recover-nested deferred |
| Vault custom program      | none    | none      | first deployed program and PDA signer exercise                              |

Token-2022 left the "later" list for its classic surface. `core.Token2022` is an
instance of the same type as `core.Token`, so every builder already reaches
either program; only the extension-specific part is still its own group.

## Recommended Core Path

~~~
System (done)
-> PDA derivation (done)
-> SPL Token classic first lifecycle (done)
-> Associated Token Account (done)
-> SPL Token classic delegation and administration (done)
-> SPL Token classic multisig lifecycle (done)
-> SPL Token classic compatibility opcodes (done)
-> SPL Token classic native SOL and read-return-data  <- here
-> Vault custom program
-> Compute Budget
-> Address Lookup Table
-> Token-2022 extensions
-> Metadata and NFT
-> Stake
-> Loader and deployment
~~~

ATA and Token swapped places against the original order, and both are done
now. Token's first lifecycle worked on keypair token accounts, so it needed
nothing from ATA, and running it first kept the endpoints verifiable without
a derivation in the loop. ATA followed once PDA existed: create-ata,
create-ata-idempotent, and transfer-from-ata (+max) are all live under
`/svm/v2/transaction/token/`. transfer-from-ata only derives the *source*
side — `owner` + `mint` — and never creates it if absent, since an account
nobody has funded has nothing to send; `destination_token_account` is an
exact address the caller already knows, the same contract transfer-checked
uses. An earlier draft derived and idempotently auto-created both sides from
two wallet addresses, which made the endpoint quietly composite in a way
nothing else in Token v2 was; that composed convenience is deferred to a
higher-level API generation (see the note near the end of this file) rather
than folded into what is otherwise a one-role-per-endpoint surface. Closing an
associated account needed nothing new:
close-account already took any 165-byte account regardless of how its
address came to exist, associated or keypair. What is still open is
recover-nested, for the rare case of an associated account mistakenly used as
a wallet with its own nested associated account beneath it; it is deferred
as a low-frequency cleanup tool rather than blocking anything.

## Group Catalogue

### 1. PDA Utilities

PDA has no private key. Only its defining program can sign through
invoke_signed, so generic transaction builders can derive, validate, and inspect
a PDA but cannot generically transfer from or create state at one.

The derivation itself is done. `core.PDA.Create` and `core.PDA.Find` are in
place on `core.Ed25519.IsOnCurve`, with the 16-seed and 32-byte limits, the
canonical bump search from 255 downwards, and `CreateWithSeed` kept separate
from it. No dependency was taken for the curve test; the field arithmetic is
local because only public addresses go through it.

What is not done is any endpoint. None of these exists yet:

~~~
pda/derive
pda/derive-with-bump
pda/validate
pda/classify
pda/derive/batch
pda/account
pda/account/validate
pda/seeds/encode
~~~

They are also not blocking anything. ATA derives internally rather than through
an HTTP call, so these are for inspection and learning and can follow whenever.
The one still-open requirement is typed seeds — string, raw bytes, pubkey, and
little-endian unsigned integers — which only an endpoint needs, since `core`
takes `[][]byte` and lets the caller encode.

### 2. Associated Token Account Program — done

ATA is the canonical PDA-backed token account for a wallet and mint. Kept as
a separate group even though Token APIs use it immediately, since it is a
different program with its own account list conventions, not an extra Token
opcode.

`core/ata.go` holds `Derive`, `Create`, and `CreateIdempotent`. The derivation
was already known to be right before any endpoint existed — it matched 1655
live associated accounts — and the create instructions confirmed cleanly
against it: no data at all in the plain form, one byte in the idempotent one.

Live under `/svm/v2/transaction/token/`:

~~~
create-ata               fails if the account already exists
create-ata-idempotent    succeeds either way; the one to prepend to a transfer
transfer-from-ata        derives only the source's associated account
transfer-from-ata/max    same, sweeping the source's current balance
~~~

transfer-from-ata takes `owner` + `mint` and derives only the *source's*
associated account from them; it is never created if absent, since an
unfunded account has nothing to send. `destination_token_account` is an
exact token account address the caller already knows, keypair or
associated, taken exactly the way transfer-checked takes it — no
destination is ever derived or auto-created here. This replaced an earlier
`transfer-to-wallet` design that derived and idempotently created *both*
sides from two wallet addresses; that shape made the endpoint quietly
composite (transfer bundled with a conditional create) in a way nothing
else in Token v2 was, so it was cut down to the one derivation that only
this endpoint can offer — the source lookup — and destination handling was
handed back to the same exact-address contract `transfer-checked` already
uses. A caller who wants the destination created first calls
create-ata-idempotent, then this endpoint, as two calls rather than one
endpoint doing both silently.

No dedicated close endpoint was needed: `token/close-account` already takes
any 165-byte Token or Token-2022 account, and an associated account is that
same layout at a derived address, indistinguishable to the instruction.

Not done: `recover-nested`, for an associated account that was mistakenly
funded as if it were a wallet and now has its own nested associated account
underneath it. Low-frequency cleanup, not on the path to anything else.

The token program is a seed of the address, so a wallet has a different
associated account for classic Token than for Token-2022 over the same mint.
Every endpoint above takes `program` for that reason, the same field the rest
of the Token lifecycle takes.

### 3. SPL Token Classic Program

The original Token Program has fixed 82-byte mint and 165-byte account layouts.
It covers minting, holder accounts, transfer, delegation, burning, authority
changes, freezing, multisig, wrapped SOL, and return-data utilities.

Core, the first lifecycle, delegation, and the multisig lifecycle are done:
the four layouts (mint, token account, nonce, multisig) parse, all 25 classic
opcodes are declared, and create-mint, create-kta, mint-to-checked,
transfer-checked (+max), burn-checked (+max), close-account,
approve-checked (+max), revoke, seven set-authority endpoints,
freeze-account, thaw-account, create-multisig, initialize-mint,
initialize-mint2, initialize-account, initialize-account2,
initialize-account3, initialize-multisig, initialize-multisig2, transfer
(+max), approve (+max), mint-to, burn (+max), and initialize-immutable-owner
are all live under `/svm/v2/transaction/token/`, alongside the reads at
`/svm/token/mint`, `/svm/token/account`, and `/svm/account/tokens`. Every one
of them checks what a live cluster would reject before building the
instruction — decimals against the mint, an account's mint against the
request's, frozen state, authority against owner or delegate (transfer, burn)
or against the mint's own authority (mint-to, freeze, thaw), close authority
as its own separate axis, and — for the raw `initialize-*` endpoints — that
the target account already exists, is owned by the right program, is at
least correctly sized (Token-2022 extensions may make it larger, never
smaller), and is not already initialized — so a mismatch comes back as a 400
with the reason instead of a signed transaction failing on chain.
freeze-account and thaw-account were the last builders sitting in `core` with
nothing serving them, and were verified by signing and sending both
directions on devnet rather than only building the transaction.

transfer/approve/mint-to/burn are the original, unchecked opcodes: none of
them names or verifies a mint or decimals against the accounts involved,
which is exactly the failure mode the checked variants exist to catch. mint
is still resolved server-side (from the account itself) and reported in the
response even though the request never supplies it, so a caller is not left
blind about what actually moved. transfer, approve, and burn round out with
`/max` sweep variants matching their checked counterparts; mint-to has no
`/max`, since supply has no balance to sweep.

initialize-immutable-owner is Token-2022-only: the classic Token Program's
deployed instruction processor has no arm for this opcode at all, so
`program` is restricted to Token-2022 specifically here, unlike every other
endpoint's either-program rule. It has to run before initialize-account*, not
after — the program requires the base layout to still be Uninitialized when
an extension attaches — which is checked client-side as a 400 the same way
initialize-mint*/initialize-account* check their own "already initialized"
question, by decoding just the base 165 bytes. What is not caught anywhere
client-side is the reverse direction: set-authority/owner/replace (and
anything else touching a property an extension can override) has no way to
tell a token account already carries this extension before sending, since
that requires walking the Token-2022 extension TLV list past
core.TokenAccountTypeOffset and matching real protocol ordinals — a
genuinely bigger, separate undertaking than a single base-state check, and
exactly the boundary already drawn around Token-2022 extensions generally
(group 7 below). An attempt to reassign an immutable-owner account still
fails, correctly, just on chain rather than as an early 400.

create-mint, create-kta, and create-multisig are deliberately creation-only:
each is a bare `System.CreateAccount` sized and owned for its target layout,
with no initialization bundled in and no authority/decimals/owner fields to
take, since it never builds the instruction that would use them. Pairing
create with initialize in one transaction — closing the race where somebody
else initializes the account first — is left to a caller who wants it, built
as two instructions themselves; this API surface plays one role per
endpoint. A multisig carries this further than a mint or token account can:
once initialized, its `m` and enrolled signers can never be changed, and it
can never be closed, since the classic Token Program has no instruction for
either and — unlike a mint's `MintCloseAuthority` — Token-2022 adds no
extension for it. Replacing a multisig means creating a new one and
repointing whatever named the old one as an authority through
`set-authority`.

Still open here: the return-data/native-SOL utilities (`account-data-size`,
`amount-to-ui`, `ui-to-amount`, wrapped SOL) and the two unverified opcodes
(`withdraw-excess-lamports`, `batch`). Detailed coverage:

~~~
TOKEN_API_PROPOSAL.md
~~~

Dependencies: PDA derivation, which is done. ATA is no longer a dependency —
the first lifecycle worked on keypair token accounts, so the two groups could
run in either order, and Token went first.

### 4. Vault Custom Program

Vault is the first project-deployed program. It turns PDA from an address tool
into real application state and a program signer.

Candidate APIs:

~~~
vault/derive
vault/create
vault/deposit-sol
vault/withdraw-sol
vault/create-token-vault
vault/deposit-token
vault/withdraw-token
vault/balance
vault/close
~~~

Suggested PDA seeds:

~~~
vault state:  ["vault", authority_pubkey]
SOL vault:    ["vault-sol", vault_state_pubkey]
token vault:  ["vault-token", vault_state_pubkey, mint_pubkey]
~~~

The program verifies authority, stored bump, mint, and destination. Token
withdrawal performs a Token Program CPI with the vault PDA as authority.

`vault/close` is also the first real example of a pattern System Program
cannot offer on its own: reclaiming lamports from an account that carries
data, by assigning it to a program that owns a drain/close instruction rather
than relying on System's `Transfer` (see Current Status).

Dependencies: PDA, Token, ATA.

### 5. Compute Budget Program

This is the transaction-resource and priority-fee group.

Candidate APIs:

~~~
transaction/compute-budget
transaction/compute-budget/limit
transaction/compute-budget/price
transaction/compute-budget/loaded-accounts-data-size-limit
~~~

Design it as an optional object accepted by every typed transaction builder:

~~~json
{
  "compute_budget": {
    "unit_limit": 200000,
    "micro_lamports_per_cu": "1000"
  }
}
~~~

Dependencies: none. Implement after Vault so priority fees have a real use case.

### 6. Address Lookup Table Program

ALT reduces transaction account-key size by storing addresses in an on-chain
lookup table.

Candidate APIs:

~~~
alt/create
alt/extend
alt/freeze
alt/deactivate
alt/close
alt/get
alt/list-addresses
transaction/versioned/build
~~~

This needs v0 versioned-message and address-table lookup serialization, not only
an ALT instruction builder.

Dependencies: transaction serializer evolution; useful with Vault and batches.

### 7. Token-2022 Program

Token-2022 is not a flag on classic Token, but the two do share a surface, and
this group is now only the part they do not share.

What is done: `core.Token2022` is an instance of the same type as `core.Token`,
carrying a different id. Every classic builder already reaches it, because the
opcodes, account orders, and base layouts are byte for byte identical. Live
Token-2022 accounts parse from their first 165 bytes, which was confirmed. So
these do not need their own endpoints at all — they are the classic ones with a
`token_program` field:

~~~
token-2022/create-mint
token-2022/create-account
token-2022/transfer-checked
~~~

What remains is what extensions change: sizes, initialization ordering, and the
instructions extensions add.

~~~
token-2022/mint-size
token-2022/account-size
token-2022/extensions/get
~~~

Sizes stop being constants here, which is the real break. A classic mint is 82
bytes and a classic token account is 165; a Token-2022 account is that plus a
type byte and a list of extension records, so rent, parsing, and `create` all
have to measure rather than assume.

Then choose extensions deliberately:

~~~
transfer-fee
metadata-pointer and token metadata
mint-close-authority
default-account-state
non-transferable
permanent-delegate
transfer-hook
confidential-transfer
~~~

Dependencies: complete classic Token model, ATA, extension-aware parsers.

### 8. Metaplex Metadata and NFT Programs

This is ecosystem-program work rather than Token Program work. It gives a mint
human-facing metadata and NFT-specific state.

Staying here rather than moving up next to ATA was reconsidered once and left
alone. The pull for moving it up is real: a mint has no name or symbol until
this exists, so it is the one gap in the lifecycle a wallet or explorer
actually shows. The case for leaving it where it is won: Metaplex Token
Metadata is a different program with its own account layout and its own
serialization, Borsh rather than this project's short-vec bincode, so it is a
second thing to learn rather than another instruction on a program already
understood. Groups 5 and 6 — delegation, freeze, and the compatibility
opcodes — are still the classic Token surface; finishing that before starting
a new program's serialization is the more valuable ordering, even though it
delays the part a screenshot would show off first.

Candidate APIs:

~~~
metadata/derive
metadata/get
metadata/create
metadata/update
metadata/master-edition/derive
metadata/master-edition/create
metadata/token-record/derive
~~~

Dependencies: PDA and Token.

### 9. Memo Program

A small transaction-annotation group.

Candidate APIs:

~~~
transaction/memo
transaction/memo/with-signers
~~~

Use it as a first cross-program composition test rather than sending memos by
themselves.

### 10. Ed25519, Secp256k1, and Secp256r1 Verification

Precompile instruction builders for verifying external signatures inside a
transaction.

Candidate APIs:

~~~
transaction/verify/ed25519
transaction/verify/secp256k1
transaction/verify/secp256r1
~~~

A consuming program must still inspect the verified instruction; signature
verification alone is not token approval or account ownership.

### 11. Stake Program

Stake teaches authorization, delegation, activation, deactivation, lockup,
split, merge, and withdrawal.

Candidate APIs:

~~~
stake/create-account
stake/initialize
stake/delegate
stake/deactivate
stake/withdraw
stake/authorize
stake/authorize-checked
stake/set-lockup
stake/set-lockup-checked
stake/split
stake/merge
stake/get
stake/accounts-by-authority
~~~

Dependencies: System. Keep this after application groups.

### 12. Vote Program

Vote accounts are mainly validator operations and have low value for normal
dApp users.

Candidate APIs:

~~~
vote/create-account
vote/initialize
vote/authorize
vote/authorize-checked
vote/update-vote-state
vote/withdraw
vote/get
~~~

Dependencies: System and validator knowledge. Keep after Stake.

### 13. BPF Loader and Program Deployment

This group creates, extends, deploys, upgrades, closes, and inspects executable
program accounts. It is powerful and should be devnet-only until thoroughly
tested.

Candidate APIs:

~~~
loader/program/get
loader/buffer/create
loader/buffer/write
loader/program/deploy
loader/program/upgrade
loader/program/set-authority
loader/program/close
~~~

Dependencies: deployment artifacts, chunked writes, and authority management.

### 14. Transaction Composer

A cross-cutting group that combines typed instructions into one atomic
transaction.

Candidate APIs:

~~~
transaction/compose
transaction/simulate-composed
transaction/size
transaction/required-signers
transaction/fee-preview
~~~

Example flows:

~~~
create ATA + transfer checked
create mint + initialize mint + create ATA + mint-to
advance durable nonce + vault withdraw + memo
compute budget + ALT lookup + multi-transfer
~~~

### 15. Account Discovery and Parsers

A cross-cutting group that turns raw account data into typed state and provides
indexed discovery where the chain supports it.

Candidate APIs:

~~~
account/classify
account/parse
account/multiple
token/accounts-by-owner
token/mints-by-authority
nonce/by-authority
program/accounts
pda/account
~~~

A wallet does not generically own every account it controls. Each program stores
authority differently, so discovery is program- and layout-specific.

The parsers behind `account/parse` partly exist: `NonceAccount`, `Mint`,
`TokenAccount`, and `Multisig` all decode today. `account/classify` mostly falls
out of the owner and the size, with one caveat worth writing down — a
Token-2022 account is not a fixed size, so size alone identifies a classic
account and not a modern one.

`token/accounts-by-owner` was the first of these to be needed rather than
merely listed, and it shipped as `/svm/account/tokens`: the question is what one
address controls, so it belongs with the account reads rather than the token
ones. It queries both token programs and reports the program per entry.

## Suggested Milestones

### Milestone A: App Foundations — done

~~~
PDA derivation (done) -> SPL Token classic (done) -> ATA (done)
~~~

Outcome: mint a token, create holder accounts, transfer safely, and inspect
resulting state.

All three pieces are live. PDA and the three token reads (`/svm/token/mint`,
`/svm/token/account`, `/svm/account/tokens`) were done first; the first
lifecycle — create-mint, create-kta, mint-to-checked, transfer-checked
(+max), burn-checked (+max), close-account — and ATA — create-ata,
create-ata-idempotent, transfer-from-ata (+max) — are all live under
`/svm/v2/transaction/token/`, delegation and administration (approve-checked
(+max), revoke, seven set-authority endpoints, freeze-account, thaw-account)
are live too, and so is the multisig lifecycle (create-multisig,
initialize-multisig, initialize-multisig2) alongside the raw
initialize-mint/initialize-mint2/initialize-account/initialize-account2/
initialize-account3 pairing that create-mint/create-kta/create-multisig now
close against. Every one of these endpoints has been through the System v2
field-fidelity pass. The milestone can be walked end to end: mint a token,
fund either a keypair or an associated account, move value between wallets
without either side deriving an address by hand, close what is left empty,
and hand authority to an m-of-n multisig instead of a single wallet. The
unchecked opcodes (transfer/approve/mint-to/burn, +max) and
initialize-immutable-owner are live too, alongside the checked variants they
exist to guard against. What is not in this milestone — the
return-data/native-SOL utilities — is TOKEN_API_PROPOSAL.md's next step, not
a gap in this one.

### Milestone B: Program-Controlled Assets

~~~
Vault -> Compute Budget -> Transaction Composer
~~~

Outcome: a deployed program controls SOL and token vault PDAs and users can
build realistic atomic transactions.

### Milestone C: Scaling and Modern Assets

~~~
ALT and versioned transactions -> Token-2022 -> Metadata and NFT
~~~

Outcome: large transactions and extension-aware asset workflows.

### Milestone D: Protocol Operations

~~~
Stake -> Vote -> Loader and deployment
~~~

Outcome: operational core-program coverage, with deployment tooling isolated
from normal application APIs.

## Out of Scope for a Generic API

- creating, signing for, transferring from, or closing an arbitrary PDA
- guessing an unknown program's PDA seed schema from an address
- parsing arbitrary program bytes without its layout or IDL
- treating Token-2022 accounts as classic fixed-size accounts
- funding an unknown off-curve address without a recovery policy

## Extended API Catalogue

The following is the broad candidate catalogue beyond the APIs implemented so
far. It intentionally includes both the recommended application path and
lower-priority compatibility, inspection, and protocol-completeness APIs.

### Token wrapped SOL

`token/freeze-account` and `token/thaw-account` are done — see group 3 above.
Still open:

~~~text
token/create-wrapped-sol
token/wrap-sol
token/sync-native
token/unwrap-lamports
~~~

`token/close-account` already unwraps a normal wrapped-SOL account by closing
it. `unwrap-lamports` should only be exposed after confirming the deployed
program accepts it on Devnet.

### Classic Token compatibility and low-level instructions

`token/initialize-mint`, `token/initialize-mint2`, `token/initialize-account`,
`token/initialize-account2`, `token/initialize-account3`,
`token/initialize-multisig`, `token/initialize-multisig2`, `token/transfer`
(+max), `token/approve` (+max), `token/mint-to`, `token/burn` (+max), and
`token/initialize-immutable-owner` are done — see group 3 above. Still open:

~~~text
token/account-data-size
token/amount-to-ui
token/ui-to-amount
token/withdraw-excess-lamports
token/batch
~~~

Checked variants remain the normal public path. This group is mainly for
learning, backwards compatibility, and custom composition. Confirm unverified
opcodes (`unwrap-lamports`, `withdraw-excess-lamports`, and `batch`) against a
live cluster before documenting them as usable.

### ATA helpers

~~~text
token/ata/derive
token/ata/validate
token/ata/recover-nested
token/ata/get-or-create
~~~

`derive` returns the ATA and bump for wallet + mint + token program;
`validate` checks a supplied address against that derivation. `recover-nested`
is a low-frequency repair tool. `get-or-create` is a read-plus-transaction
convenience endpoint, not a new ATA instruction.

### PDA HTTP utilities

~~~text
pda/derive
pda/find
pda/validate
pda/classify
pda/derive/batch
pda/seeds/encode
pda/account
~~~

Typed seed encoding should cover UTF-8 strings, raw bytes, public keys, and
little-endian u8/u16/u32/u64 values. These APIs make derivation inspectable;
they never give an external caller the ability to sign for a PDA.

### Transaction composition and Compute Budget

~~~text
transaction/build
transaction/append-instruction
transaction/compose
transaction/decode
transaction/inspect
transaction/required-signers
transaction/serialize
transaction/deserialize
transaction/refresh-blockhash
transaction/add-nonce
transaction/add-compute-budget
transaction/size
transaction/validate

transaction/compute-budget
transaction/compute-budget/limit
transaction/compute-budget/price
transaction/compute-budget/heap-frame
transaction/compute-budget/loaded-accounts-data-size-limit
transaction/estimate-compute
transaction/recommend-priority-fee
~~~

The preferred design is a shared optional `compute_budget` object on typed
builders, plus a composer for callers that need several typed instructions in
one atomic transaction. Estimate APIs can use simulation; fee recommendation
needs a cluster or provider data source.

### Vault custom program

~~~text
vault/derive
vault/create
vault/get
vault/deposit-sol
vault/withdraw-sol
vault/create-token-vault
vault/deposit-token
vault/withdraw-token
vault/balance
vault/authorize
vault/close
~~~

Vault is the first deployed-program milestone. Its PDA becomes a real program
signer through `invoke_signed`, and token withdrawal uses a Token Program CPI.
It connects PDA, ATA, Token, authority, and composed transactions in one flow.

### Address Lookup Tables and v0 transactions

~~~text
alt/create
alt/extend
alt/freeze
alt/deactivate
alt/close
alt/get
alt/list-addresses
alt/derive
transaction/v0/build
transaction/v0/compile
transaction/v0/resolve-lookups
~~~

This requires v0 message and lookup serialization as well as ALT instruction
builders. It is most useful with large vault and batch transactions.

### Token-2022 extensions

~~~text
token-2022/mint/extensions
token-2022/account/extensions
token-2022/account-data-size
token-2022/create-mint
token-2022/create-account
token-2022/initialize-extension/*
token-2022/transfer-fee/*
token-2022/transfer-hook/*
token-2022/default-account-state/*
token-2022/permanent-delegate/*
token-2022/non-transferable/*
token-2022/interest-bearing/*
token-2022/metadata-pointer/*
token-2022/group-pointer/*
token-2022/group-member-pointer/*
token-2022/confidential-transfer/*
token-2022/scaled-ui-amount/*
token-2022/immutable-owner
~~~

Classic builders already reach Token-2022's shared instruction surface. This
group begins where extensions change account size, initialization order,
parsing, and transfer rules.

### Metadata, NFT, and compressed NFT reads

~~~text
nft/mint
nft/create-metadata
nft/update-metadata
nft/verify-collection
nft/create-master-edition
nft/mint-edition
nft/transfer
nft/burn
nft/freeze
nft/thaw
nft/get
nft/get-metadata
nft/get-collection
nft/compressed/*
~~~

Compressed-NFT discovery normally needs a DAS or indexer-backed read API in
addition to standard Solana RPC.

### Stake, vote, validator, and loader APIs

~~~text
stake/create-account
stake/delegate
stake/deactivate
stake/withdraw
stake/split
stake/merge
stake/authorize
stake/lockup
stake/get
stake/list-by-authority
stake/rewards

vote/get
vote/list
vote/validators
vote/leader-schedule
vote/epoch-info
vote/epoch-schedule
vote/inflation-rewards
vote/stake-activation

program/get
program/account
program/buffer/create
program/buffer/write
program/deploy
program/upgrade
program/set-authority
program/close
program/programdata
program/verify
~~~

### Other built-in and account-discovery APIs

~~~text
memo/create
ed25519/verify
secp256k1/verify
secp256r1/verify
system/transfer-with-seed
account/nonces-by-authority
account/program-accounts
account/history
~~~

Rough idea, not v2, not scheduled: a seed-based durable nonce account
convenience endpoint — `seed/create-account` + `seed/allocate` (80 bytes) +
`nonce/initialize` bundled into one call. `nonce/create-account` itself is
no longer a one-shot bundle to be a counterpart to — it was cut down to
`CreateAccount` only, matching every other `create-*`/`initialize-*` pairing
in this API — so this would be the first genuinely composed convenience
endpoint of its kind rather than mirroring an existing one. Advancing a
nonce only ever checks the authority's signature, never the nonce account's
own, so a seed-derived (keyless) address works as a durable nonce account
today via that three-call chain — this would just be the one-shot
convenience wrapper. Belongs in a later, more composed API generation
(v4/v5-ish) rather than this low-level v2 pass.

## Recommended expanded sequence

~~~text
Token native SOL, wrapped SOL, and read-return-data
-> PDA HTTP utilities
-> transaction composer and Compute Budget
-> Vault program
-> ALT
-> Token-2022 extensions
-> NFT / Metaplex
-> Stake
-> Loader / deployment
~~~

Vault may move ahead of the remaining legacy compatibility instructions when
the goal is to exercise PDA signing in a real application. At the Token/Vault
boundary, add Devnet E2E tests for complete flows; the current `go test` run
compiles packages but does not yet execute repository test cases.
