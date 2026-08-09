package core

import (
	"encoding/binary"
	"math/bits"

	"github.com/andantan/svmlab/core/types"
)

// ed25519Curve answers questions about the curve itself rather than about any
// key on it.
//
// It is a namespace like System and Sysvar: the curve is fixed by the
// algorithm, so there is no state to hold and nothing to initialize. What sets
// it apart from crypto.go in this package is the subject. There, an
// SVMEd25519Key is a key somebody holds; here, the question is whether 32 bytes
// could be such a key at all, which is what the PDA derivation turns on and
// what tells a wallet address apart from a program derived one.
type ed25519Curve struct{}

var Ed25519 = new(ed25519Curve)

// IsOnCurve reports whether b decompresses as an Edwards25519 point.
//
// That is what separates an address somebody can sign for from one nobody can.
// Every ordinary address is a public key, and a public key is a curve point by
// construction. A program derived address is a hash, and a hash is only a curve
// point by accident, so a derivation that rejects the accidents produces
// addresses with no private key anywhere in existence.
//
// Edwards-Y encoding stores little-endian y in the low 255 bits and the sign of
// x in the high bit. As in curve25519-dalek, the high bit is ignored while
// decoding y and non-canonical field encodings are reduced modulo p. The sign
// cannot change whether a square root for x exists, including the accepted
// negative-zero encoding.
func (_ *ed25519Curve) IsOnCurve(b []byte) bool {
	return isOnCurve(b)
}

// curveElement is an element of GF(2^255-19) represented by five little-endian
// radix-2^51 limbs. Limbs stay below 2^52 between operations.
//
// The arithmetic below performs no scalar operations and handles only public
// address bytes, so constant-time selection is unnecessary; the radix-51
// construction is here for speed, since finding one address runs the check
// twice on average and every miss costs a full field exponentiation. The carry
// and multiplication bounds follow the same construction used by
// curve25519-dalek and Go's edwards25519.
type curveElement struct {
	l0, l1, l2, l3, l4 uint64
}

type curveUint128 struct {
	lo, hi uint64
}

const curveMask51 uint64 = (1 << 51) - 1

var (
	curveZero = curveElement{}
	curveOne  = curveElement{l0: 1}

	// -121665 / 121666 mod (2^255 - 19), in radix 2^51.
	curveD = curveElement{
		l0: 929955233495203,
		l1: 466365720129213,
		l2: 1662059464998953,
		l3: 2033849074728123,
		l4: 1442794654840575,
	}
)

func isOnCurve(b []byte) bool {
	if len(b) != types.PublicKeyLength {
		return false
	}

	var y, y2, u, v, v2, v3, v6, v7 curveElement
	var uv3, uv7, pow, r, r2, check, negU curveElement

	y.setBytes(b)
	y2.square(&y)
	u.subtract(&y2, &curveOne) // u = y^2 - 1
	v.multiply(&curveD, &y2)
	v.add(&v, &curveOne) // v = d*y^2 + 1

	// r = u*v^3*(u*v^7)^((p-5)/8). Squaring r back and multiplying
	// by v distinguishes a square ratio (u/v) from a non-square one.
	v2.square(&v)
	v3.multiply(&v2, &v)
	v6.square(&v3)
	v7.multiply(&v6, &v)
	uv3.multiply(&u, &v3)
	uv7.multiply(&u, &v7)
	pow.pow22523(&uv7)
	r.multiply(&uv3, &pow)
	r2.square(&r)
	check.multiply(&v, &r2)

	if check.equal(&u) {
		return true
	}
	negU.negate(&u)
	return check.equal(&negU)
}

func (z *curveElement) setBytes(b []byte) {
	z.l0 = binary.LittleEndian.Uint64(b[0:8]) & curveMask51
	z.l1 = (binary.LittleEndian.Uint64(b[6:14]) >> 3) & curveMask51
	z.l2 = (binary.LittleEndian.Uint64(b[12:20]) >> 6) & curveMask51
	z.l3 = (binary.LittleEndian.Uint64(b[19:27]) >> 1) & curveMask51
	z.l4 = (binary.LittleEndian.Uint64(b[24:32]) >> 12) & curveMask51
}

func (z *curveElement) add(a, b *curveElement) {
	z.l0 = a.l0 + b.l0
	z.l1 = a.l1 + b.l1
	z.l2 = a.l2 + b.l2
	z.l3 = a.l3 + b.l3
	z.l4 = a.l4 + b.l4
	z.carryPropagate()
}

func (z *curveElement) subtract(a, b *curveElement) {
	// Add 2p before subtracting. Inputs are below 2^52 per limb, so this
	// prevents unsigned underflow without leaving the uint64 range.
	z.l0 = a.l0 + 0xFFFFFFFFFFFDA - b.l0
	z.l1 = a.l1 + 0xFFFFFFFFFFFFE - b.l1
	z.l2 = a.l2 + 0xFFFFFFFFFFFFE - b.l2
	z.l3 = a.l3 + 0xFFFFFFFFFFFFE - b.l3
	z.l4 = a.l4 + 0xFFFFFFFFFFFFE - b.l4
	z.carryPropagate()
}

func (z *curveElement) negate(a *curveElement) {
	z.subtract(&curveZero, a)
}

func (z *curveElement) multiply(a, b *curveElement) {
	a0, a1, a2, a3, a4 := a.l0, a.l1, a.l2, a.l3, a.l4
	b0, b1, b2, b3, b4 := b.l0, b.l1, b.l2, b.l3, b.l4

	r0 := curveMul(a0, b0)
	r0 = curveAddMul19(r0, a1, b4)
	r0 = curveAddMul19(r0, a2, b3)
	r0 = curveAddMul19(r0, a3, b2)
	r0 = curveAddMul19(r0, a4, b1)

	r1 := curveMul(a0, b1)
	r1 = curveAddMul(r1, a1, b0)
	r1 = curveAddMul19(r1, a2, b4)
	r1 = curveAddMul19(r1, a3, b3)
	r1 = curveAddMul19(r1, a4, b2)

	r2 := curveMul(a0, b2)
	r2 = curveAddMul(r2, a1, b1)
	r2 = curveAddMul(r2, a2, b0)
	r2 = curveAddMul19(r2, a3, b4)
	r2 = curveAddMul19(r2, a4, b3)

	r3 := curveMul(a0, b3)
	r3 = curveAddMul(r3, a1, b2)
	r3 = curveAddMul(r3, a2, b1)
	r3 = curveAddMul(r3, a3, b0)
	r3 = curveAddMul19(r3, a4, b4)

	r4 := curveMul(a0, b4)
	r4 = curveAddMul(r4, a1, b3)
	r4 = curveAddMul(r4, a2, b2)
	r4 = curveAddMul(r4, a3, b1)
	r4 = curveAddMul(r4, a4, b0)

	z.setReducedProduct(r0, r1, r2, r3, r4)
}

func (z *curveElement) square(a *curveElement) {
	a0, a1, a2, a3, a4 := a.l0, a.l1, a.l2, a.l3, a.l4

	r0 := curveMul(a0, a0)
	r0 = curveAddMul38(r0, a1, a4)
	r0 = curveAddMul38(r0, a2, a3)

	r1 := curveMul(a0*2, a1)
	r1 = curveAddMul38(r1, a2, a4)
	r1 = curveAddMul19(r1, a3, a3)

	r2 := curveMul(a0*2, a2)
	r2 = curveAddMul(r2, a1, a1)
	r2 = curveAddMul38(r2, a3, a4)

	r3 := curveMul(a0*2, a3)
	r3 = curveAddMul(r3, a1*2, a2)
	r3 = curveAddMul19(r3, a4, a4)

	r4 := curveMul(a0*2, a4)
	r4 = curveAddMul(r4, a1*2, a3)
	r4 = curveAddMul(r4, a2, a2)

	z.setReducedProduct(r0, r1, r2, r3, r4)
}

func (z *curveElement) setReducedProduct(r0, r1, r2, r3, r4 curveUint128) {
	c0 := curveShiftRight51(r0)
	c1 := curveShiftRight51(r1)
	c2 := curveShiftRight51(r2)
	c3 := curveShiftRight51(r3)
	c4 := curveShiftRight51(r4)

	rr0 := (r0.lo & curveMask51) + curveMul19(c4)
	rr1 := (r1.lo & curveMask51) + c0
	rr2 := (r2.lo & curveMask51) + c1
	rr3 := (r3.lo & curveMask51) + c2
	rr4 := (r4.lo & curveMask51) + c3

	z.l0 = (rr0 & curveMask51) + curveMul19(rr4>>51)
	z.l1 = (rr1 & curveMask51) + (rr0 >> 51)
	z.l2 = (rr2 & curveMask51) + (rr1 >> 51)
	z.l3 = (rr3 & curveMask51) + (rr2 >> 51)
	z.l4 = (rr4 & curveMask51) + (rr3 >> 51)
}

// pow22523 sets z = a^(2^252-3), which is (p-5)/8. The fixed addition
// chain uses 252 squarings but only 11 general multiplications.
func (z *curveElement) pow22523(a *curveElement) {
	var t0, t1, t2 curveElement

	t0.square(a)          // 2
	t1.square(&t0)        // 4
	t1.square(&t1)        // 8
	t1.multiply(a, &t1)   // 9
	t0.multiply(&t0, &t1) // 11
	t0.square(&t0)        // 22
	t0.multiply(&t1, &t0) // 2^5 - 1
	t1.squareN(&t0, 5)
	t0.multiply(&t1, &t0) // 2^10 - 1
	t1.squareN(&t0, 10)
	t1.multiply(&t1, &t0) // 2^20 - 1
	t2.squareN(&t1, 20)
	t1.multiply(&t2, &t1) // 2^40 - 1
	t1.squareN(&t1, 10)
	t0.multiply(&t1, &t0) // 2^50 - 1
	t1.squareN(&t0, 50)
	t1.multiply(&t1, &t0) // 2^100 - 1
	t2.squareN(&t1, 100)
	t1.multiply(&t2, &t1) // 2^200 - 1
	t1.squareN(&t1, 50)
	t0.multiply(&t1, &t0) // 2^250 - 1
	t0.squareN(&t0, 2)    // 2^252 - 4
	z.multiply(&t0, a)    // 2^252 - 3
}

func (z *curveElement) squareN(a *curveElement, n int) {
	z.square(a)
	for i := 1; i < n; i++ {
		z.square(z)
	}
}

func (z *curveElement) carryPropagate() {
	l0 := z.l0
	z.l0 = (z.l0 & curveMask51) + curveMul19(z.l4>>51)
	z.l4 = (z.l4 & curveMask51) + (z.l3 >> 51)
	z.l3 = (z.l3 & curveMask51) + (z.l2 >> 51)
	z.l2 = (z.l2 & curveMask51) + (z.l1 >> 51)
	z.l1 = (z.l1 & curveMask51) + (l0 >> 51)
}

func (z *curveElement) reduce() {
	z.carryPropagate()

	// z >= p exactly when adding 19 carries out of bit 255.
	c := (z.l0 + 19) >> 51
	c = (z.l1 + c) >> 51
	c = (z.l2 + c) >> 51
	c = (z.l3 + c) >> 51
	c = (z.l4 + c) >> 51
	z.l0 += 19 * c

	z.l1 += z.l0 >> 51
	z.l0 &= curveMask51
	z.l2 += z.l1 >> 51
	z.l1 &= curveMask51
	z.l3 += z.l2 >> 51
	z.l2 &= curveMask51
	z.l4 += z.l3 >> 51
	z.l3 &= curveMask51
	z.l4 &= curveMask51
}

func (z *curveElement) equal(a *curveElement) bool {
	x, y := *z, *a
	x.reduce()
	y.reduce()
	return x == y
}

func curveMul(a, b uint64) curveUint128 {
	hi, lo := bits.Mul64(a, b)
	return curveUint128{lo: lo, hi: hi}
}

func curveAddMul(v curveUint128, a, b uint64) curveUint128 {
	hi, lo := bits.Mul64(a, b)
	lo, carry := bits.Add64(lo, v.lo, 0)
	hi, _ = bits.Add64(hi, v.hi, carry)
	return curveUint128{lo: lo, hi: hi}
}

func curveMul19(v uint64) uint64 {
	return v + (v+v<<3)<<1
}

func curveAddMul19(v curveUint128, a, b uint64) curveUint128 {
	return curveAddMul(v, curveMul19(a), b)
}

func curveAddMul38(v curveUint128, a, b uint64) curveUint128 {
	return curveAddMul(v, curveMul19(a), b*2)
}

func curveShiftRight51(v curveUint128) uint64 {
	return v.hi<<13 | v.lo>>51
}
