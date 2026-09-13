package zkbridge

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/tetratelabs/wazero/api"
)

// Status codes the wasm prover returns in place of a result, confirmed
// against solana-go's own zk-elgamal-proof/errors.go rather than assumed
// from this package's own guesses at what a Rust panic boundary would
// report.
const (
	statusOK                     = 0
	statusBadInput               = -1
	statusProofGenerationError   = -2
	statusProofVerificationError = -3
	statusDecryptionError        = -4
	statusUnknownProofType       = -5
	statusOOM                    = -6
)

var (
	ErrBadInput          = errors.New("zkbridge: invalid input encoding")
	ErrProofGeneration   = errors.New("zkbridge: proof generation failed")
	ErrProofVerification = errors.New("zkbridge: proof verification failed")
	ErrDecryption        = errors.New("zkbridge: decryption failed")
	ErrUnknownProofType  = errors.New("zkbridge: unknown proof type")
	ErrOutOfMemory       = errors.New("zkbridge: out of memory")
)

// statusError maps a prover status code to its sentinel error.
func statusError(status int32) error {
	switch status {
	case statusBadInput:
		return ErrBadInput
	case statusProofGenerationError:
		return ErrProofGeneration
	case statusProofVerificationError:
		return ErrProofVerification
	case statusDecryptionError:
		return ErrDecryption
	case statusUnknownProofType:
		return ErrUnknownProofType
	case statusOOM:
		return ErrOutOfMemory
	default:
		return fmt.Errorf("zkbridge: unknown status %d", status)
	}
}

// Arg is a value that can cross into a wasm call: either a buffer written
// into the guest's linear memory (Bytes, U64s), or a plain integer passed
// directly as a wasm argument (Scalar).
type Arg interface {
	marshal() []byte
}

// Scalar is a u64 passed directly as a wasm call argument, not written
// into guest memory -- the "n" in a call like
// proof_batched_range_u128(n, commitments_ptr, ...).
type Scalar uint64

func (s Scalar) marshal() []byte { return nil } // never called; see buildArgs

// Bytes is an already-serialized buffer crossed as-is.
type Bytes []byte

func (b Bytes) marshal() []byte { return append([]byte(nil), b...) }

// U64s marshals as a little-endian u64 array -- the wire form
// solana-zk-sdk's wasm exports expect for an amounts list.
type U64s []uint64

func (s U64s) marshal() []byte {
	out := make([]byte, len(s)*8)
	for i, v := range s {
		binary.LittleEndian.PutUint64(out[i*8:], v)
	}
	return out
}

// Concat marshals as the concatenation of fixed-size POD byte slices
// (each already the exact wire layout a Rust #[repr(C)] Pod struct
// expects) -- a batched call's list of commitments or openings, each
// element already encoded by its own caller.
type Concat [][]byte

func (c Concat) marshal() []byte {
	var out []byte
	for _, b := range c {
		out = append(out, b...)
	}
	return out
}

// zeroize clears a transient buffer holding secret material (an opening,
// a proof, an intermediate wasm result) before it is dropped.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// span is one guest allocation a frame owns and is responsible for
// freeing.
type span struct {
	ptr, size uint32
}

// frame controls the guest memory allocations of a single wasm call, and
// the module instance it runs against.
type frame struct {
	inst     api.Module
	allocs   []span
	poisoned bool
}

func (f *frame) acquire() error {
	inst, err := getInstance()
	if err != nil {
		return err
	}
	f.inst = inst
	return nil
}

// release scrubs and frees every allocation the call made, then returns
// the instance to the pool -- or, if the call left the instance in a
// state this package cannot trust (a call trapped, or a free itself
// failed), closes it instead and returns a nil slot so the next
// getInstance call starts fresh.
func (f *frame) release() {
	f.scrubAndFree()
	if f.poisoned {
		_ = f.inst.Close(context.Background())
		f.inst = nil
	}
	returnInstance(f.inst)
}

func (f *frame) scrubAndFree() {
	mem := f.inst.Memory()
	if mem == nil {
		return
	}

	free := f.inst.ExportedFunction(freeFunc)
	ctx := context.Background()
	var zeros []byte
	for _, a := range f.allocs {
		if int(a.size) > len(zeros) {
			zeros = make([]byte, a.size)
		}
		mem.Write(a.ptr, zeros[:a.size])

		if f.poisoned {
			continue
		}
		if _, err := free.Call(ctx, uint64(a.ptr)); err != nil {
			f.poisoned = true
		}
	}
}

// write copies b into freshly allocated guest memory and returns the
// guest pointer.
func (f *frame) write(b []byte) (uint64, error) {
	if len(b) == 0 {
		return 0, errors.New("zkbridge: attempted to write an empty buffer")
	}

	res, err := f.inst.ExportedFunction(allocFunc).Call(context.Background(), uint64(len(b)))
	if err != nil {
		f.poisoned = true
		return 0, fmt.Errorf("zkbridge: guest alloc: %w", err)
	}
	if len(res) != 1 {
		return 0, fmt.Errorf("zkbridge: %s returned %d results, want 1", allocFunc, len(res))
	}

	ptr := uint32(res[0])
	if ptr == 0 {
		return 0, ErrOutOfMemory
	}

	f.allocs = append(f.allocs, span{ptr, uint32(len(b))})
	if !f.inst.Memory().Write(ptr, b) {
		return 0, errors.New("zkbridge: guest memory write out of range")
	}

	return uint64(ptr), nil
}

// decodeResult interprets an export's packed return value: a negative i64
// is a status code (statusError), zero is an empty-but-successful result,
// and a positive value packs a guest pointer (low 32 bits) and length
// (high 32 bits) -- confirmed against solana-go's own decodeResult rather
// than assumed from a generic "pointer and length" convention, since the
// specific packing (which half holds which) has to match the wasm side
// exactly or every read is garbage.
func (f *frame) decodeResult(raw uint64) ([]byte, error) {
	packed := int64(raw)
	if packed < 0 {
		return nil, statusError(int32(packed))
	}
	if packed == 0 {
		return nil, nil
	}

	ptr, length := uint32(packed), uint32(packed>>32)
	f.allocs = append(f.allocs, span{ptr, length})

	view, ok := f.inst.Memory().Read(ptr, length)
	if !ok {
		return nil, errors.New("zkbridge: guest memory read out of range")
	}

	out := make([]byte, length)
	copy(out, view)
	return out, nil
}

// buildArgs marshals each call argument, writing buffers into guest
// memory and passing Scalars through directly, in order.
func buildArgs(f *frame, parts ...Arg) ([]uint64, error) {
	args := make([]uint64, 0, len(parts))
	for _, part := range parts {
		if s, ok := part.(Scalar); ok {
			args = append(args, uint64(s))
			continue
		}

		b := part.marshal()
		ptr, err := f.write(b)
		zeroize(b)
		if err != nil {
			return nil, err
		}
		args = append(args, ptr)
	}
	return args, nil
}

// invoke borrows a pooled instance, marshals parts into export arguments,
// calls the named export, and copies out its result.
func invoke(name string, parts ...Arg) ([]byte, error) {
	f := &frame{}
	if err := f.acquire(); err != nil {
		return nil, err
	}
	defer f.release()

	args, err := buildArgs(f, parts...)
	if err != nil {
		return nil, err
	}

	fn := f.inst.ExportedFunction(name)
	if fn == nil {
		return nil, fmt.Errorf("zkbridge: export %q not found", name)
	}

	res, err := fn.Call(context.Background(), args...)
	if err != nil {
		f.poisoned = true
		return nil, fmt.Errorf("zkbridge: calling %s: %w", name, err)
	}
	if len(res) != 1 {
		return nil, fmt.Errorf("zkbridge: %s returned %d results, want 1", name, len(res))
	}

	return f.decodeResult(res[0])
}

// Invoke calls the named export and returns its raw result bytes.
func Invoke(name string, parts ...Arg) ([]byte, error) {
	return invoke(name, parts...)
}
