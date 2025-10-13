package ds

import (
	"math/big"

	"github.com/sergelen02/HPPK_2/internal/core"
)

// Verify compares (Q'(F) == P'(H)) in F_p for linear polynomials:
//   left  = (q0*F) + (q1*F)*x   mod p
//   right = (p0*H) + (p1*H)*x   mod p
func Verify(pk *Public, msg []byte, sig *Signature) bool {
	P := pk.P
	Fp := core.NewField(P)

	x := core.HashToX(P, msg)
	F := new(big.Int).SetBytes(sig.F)
	H := new(big.Int).SetBytes(sig.H)

	// U(H) = p0*H + p1*H*x  (mod p)
	U0 := Fp.Mul(pk.Pprime0, H)          // p0*H
	U1 := Fp.Mul(pk.Pprime1, H)          // p1*H
	right := Fp.Add(U0, Fp.Mul(U1, x))   // p0*H + (p1*H)*x

	// V(F) = q0*F + q1*F*x  (mod p)
	V0 := Fp.Mul(pk.Qprime0, F)          // q0*F
	V1 := Fp.Mul(pk.Qprime1, F)          // q1*F
	left := Fp.Add(V0, Fp.Mul(V1, x))    // q0*F + (q1*F)*x

	return left.Cmp(right) == 0
}
