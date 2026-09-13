// Package zkbridge calls into solana-zk-sdk's real Rust proof-generation
// code, compiled to wasm32 and run through wazero (pure Go, no cgo) --
// rather than a from-scratch Go port -- for the proof types this project
// has not reimplemented natively: range proofs (Bulletproofs),
// ciphertext-commitment equality proofs, and batched grouped-ciphertext
// validity proofs.
//
// See NOTICE.md for exactly what is copied from where, under what
// license, and what in this package is this project's own code written
// against the same call ABI rather than a verbatim copy.
//
// This exists because a from-scratch Go port carries real risk this
// project has already hit once: core/zk_proof.go's PubkeyValidityProof
// shipped with a transcript-construction bug that passed every local
// round-trip test (prover and verifier there made the same mistake, so
// they agreed with each other) and was only caught by an actual on-chain
// VerifyPubkeyValidity failure. Range proofs are a different, much
// larger protocol (Bulletproofs: generator derivation via an extendable
// hash, a recursive inner-product argument, batched multi-value proofs)
// with no equivalent of RFC 8452's published test vectors to pin a port
// against -- calling the real code sidesteps that risk entirely for the
// proofs built here, at the cost of a wasm binary and a wazero runtime
// this package owns.
package zkbridge

import (
	"context"
	cryptorand "crypto/rand"
	_ "embed"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed solana_zk_sdk_wasm.wasm
var bridgeWasm []byte

const (
	allocFunc = "zk_alloc"
	freeFunc  = "zk_free"

	// memoryPageLimit caps the guest's linear memory at 256 pages (16 MiB,
	// 64 KiB per page) -- generous for the fixed-size proof buffers this
	// package ever passes across the boundary, and a bound wazero needs
	// set explicitly rather than left unbounded.
	memoryPageLimit = 256

	// instancePoolSize is how many wasm module instances this package
	// keeps warm at once. Proof generation is not free (Bulletproofs in
	// particular does real curve arithmetic), and a fresh instance costs
	// a module instantiation on top of that; a small fixed pool amortizes
	// the second cost under concurrent calls without growing unbounded.
	instancePoolSize = 4
)

var (
	initOnce     sync.Once
	initErr      error
	wasmRuntime  wazero.Runtime
	wasmCompiled wazero.CompiledModule
	instancePool chan api.Module
)

func initWasmRuntime() {
	ctx := context.Background()

	rt := wazero.NewRuntimeWithConfig(ctx,
		wazero.NewRuntimeConfig().WithMemoryLimitPages(memoryPageLimit))
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		_ = rt.Close(ctx)
		initErr = fmt.Errorf("zkbridge: instantiating WASI host module: %w", err)
		return
	}

	compiled, err := rt.CompileModule(ctx, bridgeWasm)
	if err != nil {
		_ = rt.Close(ctx)
		initErr = fmt.Errorf("zkbridge: compiling bridge module: %w", err)
		return
	}

	wasmRuntime = rt
	wasmCompiled = compiled

	instancePool = make(chan api.Module, instancePoolSize)
	for range instancePoolSize {
		instancePool <- nil
	}
}

// getInstance takes a slot from the pool, instantiating it if the slot is
// still empty (nil).
func getInstance() (api.Module, error) {
	initOnce.Do(initWasmRuntime)
	if initErr != nil {
		return nil, initErr
	}

	if inst := <-instancePool; inst != nil {
		return inst, nil
	}

	inst, err := newInstance()
	if err != nil {
		instancePool <- nil
		return nil, err
	}

	return inst, nil
}

// returnInstance hands a slot back to the pool. inst may be nil -- a
// poisoned instance that was closed rather than reused -- in which case
// the next getInstance call instantiates a fresh one.
func returnInstance(inst api.Module) {
	instancePool <- inst
}

func newInstance() (mod api.Module, err error) {
	ctx := context.Background()

	cfg := wazero.NewModuleConfig().
		WithName("").
		WithStartFunctions(). // WASI reactor: suppress the implicit _start call
		WithRandSource(cryptorand.Reader)

	mod, err = wasmRuntime.InstantiateModule(ctx, wasmCompiled, cfg)
	if err != nil {
		return nil, fmt.Errorf("zkbridge: instantiating bridge module: %w", err)
	}
	defer func() {
		if err != nil {
			_ = mod.Close(ctx)
			mod = nil
		}
	}()

	for _, name := range []string{allocFunc, freeFunc} {
		if mod.ExportedFunction(name) == nil {
			return mod, fmt.Errorf("zkbridge: required export %q not found", name)
		}
	}

	return mod, nil
}
