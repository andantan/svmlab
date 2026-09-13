# Third-party notice

`solana_zk_sdk_wasm.wasm` in this directory is copied verbatim, unmodified,
from the official Solana Foundation Go SDK:

- Source: https://github.com/solana-foundation/solana-go
- Path: `programs/zk-elgamal-proof/internal/bridge/solana_zk_sdk_wasm.wasm`
- License: Apache License 2.0 (https://github.com/solana-foundation/solana-go/blob/main/LICENSE)
- Retrieved: 2026-09-13, file size 2,492,755 bytes (verified against the
  size the GitHub contents API reports for that path)

This is a `wasm32` build of `solana-zk-sdk` (https://github.com/solana-program/zk-elgamal-proof),
the same Rust crate this codebase's own `core/extensions.go`,
`core/zk_proof.go`, and `core/ae_encryption.go` are checked against
throughout — used here, via `github.com/tetratelabs/wazero`, to generate
the zero-knowledge proofs this project has not (yet, or ever) reimplemented
natively in Go: range proofs (Bulletproofs), ciphertext-commitment
equality proofs, and batched grouped-ciphertext validity proofs, all
needed by Token-2022's ConfidentialTransfer `Transfer` instruction.

The bridge code in this package (`bridge.go`, `wasm.go`, and friends) is
this project's own, written against the same call ABI
(`zk_alloc`/`zk_free`, packed `(ptr<<32|len)` results, the `Arg` marshaling
scheme) documented and confirmed against solana-go's own
`internal/bridge/wasm.go` and `wasm_call.go` (same license, same repo) --
not copied verbatim, since this codebase's conventions (error handling,
naming, the absence of solana-go's own `zk` package types) differ enough
that a straight copy would not fit; ported by hand instead, function by
function, from the real source.
