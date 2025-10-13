package ds

import (
	"math/big"

	"github.com/sergelen02/HPPK_2/internal/core"
)

func Verify(pk *Public, msg []byte, sig *Signature) bool {
	P := pk.P
	Fp := core.NewField(P)
	x := core.HashToX(P, msg)

	F := new(big.Int).SetBytes(sig.F) // f(x) mod p
	H := new(big.Int).SetBytes(sig.H) // h(x) mod p

	// U(H) = (p0*H) + (p1*H)*x  over F_p
	U0 := new(big.Int).Mod(new(big.Int).Mul(pk.Pprime0, H), P)
	U1 := new(big.Int).Mod(new(big.Int).Mul(pk.Pprime1, H), P)

	// V(F) = (q0*F) + (q1*F)*x  over F_p
	V0 := new(big.Int).Mod(new(big.Int).Mul(pk.Qprime0, F), P)
	V1 := new(big.Int).Mod(new(big.Int).Mul(pk.Qprime1, F), P)

	left  := Fp.Add(V0, Fp.Mul(V1, x))
	right := Fp.Add(U0, Fp.Mul(U1, x))

	return left.Cmp(right) == 0
}

