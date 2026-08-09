# SVM API Roadmap

## Purpose

This is the high-level API roadmap for svmlab. It groups work by protocol
responsibility and records the implementation order.

~~~
account model -> deterministic addresses -> assets -> application state
-> transaction infrastructure -> ecosystem and validator operations
~~~

## Current Status

Core and endpoints are tracked apart, because they have come apart: the Token
builders exist and none of them is reachable over HTTP yet.

| Group                     | Core    | Endpoints | Notes                                                                       |
|---------------------------|---------|-----------|-----------------------------------------------------------------------------|
| RPC, signing, and tools   | done    | done      | account, fee, rent, simulation, send, status, key generation, signing       |
| System Program            | done    | done      | all 13 instructions, seed variants, durable nonce, multi and batch transfer |
| PDA derivation            | done    | none      | Create and Find, checked against 2044 mainnet accounts                      |
| SPL Token classic         | partial | none      | 3 layouts, 25 opcodes, 6 builders, 2 atomic creates; TOKEN_API_PROPOSAL.md  |
| Associated Token Account  | none    | none      | unblocked now that PDA is done                                              |
| Vault custom program      | none    | none      | first deployed program and PDA signer exercise                              |

Token-2022 left the "later" list for its classic surface. `core.Token2022` is an
instance of the same type as `core.Token`, so every builder already reaches
either program; only the extension-specific part is still its own group.

## Recommended Core Path

~~~
System (done)
-> PDA derivation (done)
-> SPL Token classic        <- here: core done, endpoints next
-> Associated Token Account
-> Vault custom program
-> Compute Budget
-> Address Lookup Table
-> Token-2022 extensions
-> Metadata and NFT
-> Stake
-> Loader and deployment
~~~

ATA and Token swapped places against the original order. Token's first
lifecycle works on keypair token accounts, so it needed nothing from ATA, and
running it first keeps the endpoints verifiable without a derivation in the
loop. The counter-argument is that `create-ata` plus `transfer-checked` is the
flow anyone actually uses; TOKEN_API_PROPOSAL.md step 4 carries the open
decision.

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

### 2. Associated Token Account Program

ATA is the canonical PDA-backed token account for a wallet and mint. Keep it as
a separate group even though Token APIs use it immediately.

Candidate APIs:

~~~
ata/derive
ata/validate
ata/account
transaction/ata/create
transaction/ata/create-idempotent
transaction/ata/recover-nested
~~~

Dependencies: PDA derivation (done), System (done), Token Program id (done). So
this group is unblocked and nothing in it is written yet. The derivation is
already known to be right — it matched 1655 live associated accounts — so what
remains here is the create instruction, which carries no data at all in its
plain form and one byte in its idempotent one.

Note that the token program is a seed of the address, so a wallet has different
associated accounts for classic Token and Token-2022 over otherwise identical
mints. `ata/derive` has to take it.

### 3. SPL Token Classic Program

The original Token Program has fixed 82-byte mint and 165-byte account layouts.
It covers minting, holder accounts, transfer, delegation, burning, authority
changes, freezing, multisig, wrapped SOL, and return-data utilities.

Core is partly done: the three layouts parse, all 25 classic opcodes are
declared, and six builders plus two atomic create pairs exist. No endpoint
exists. Detailed instruction coverage and implementation ordering:

~~~
TOKEN_API_PROPOSAL.md
~~~

Dependencies: PDA derivation, which is done. ATA is no longer a dependency —
the first lifecycle works on keypair token accounts, so the two groups can run
in either order.

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

`token/accounts-by-owner` is the first of these to be needed rather than merely
listed, since the Token read endpoints want it.

## Suggested Milestones

### Milestone A: App Foundations

~~~
PDA derivation (done) -> SPL Token classic -> ATA
~~~

Outcome: mint a token, create holder accounts, transfer safely, and inspect
resulting state.

Where it stands: PDA is done, and Token's builders are done with no endpoints
on them. The next concrete work is nine endpoints — six transaction builders
under `/svm/v2/transaction/token/` and three reads under `/svm/rpc/token/` —
of which only `accounts-by-owner` needs plumbing that does not exist, namely a
`getTokenAccountsByOwner` method on the RPC client.

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

