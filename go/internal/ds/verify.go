package ds


import (
"math/big"
"github.com/yourname/hppk/internal/core"
)


func Verify(pk *Public, msg []byte, sig *Signature) bool {
P := pk.P
Ffield := core.NewField(P)
x := core.HashToX(P, msg)
F := new(big.Int).SetBytes(sig.F)
H := new(big.Int).SetBytes(sig.H)


// U(H) for linear poly: U0(H), U1(H)
U0 := core.BarrettTerm(H, pk.Pprime0, pk.S1p, pk.Mu0, pk.K, P)
U1 := core.BarrettTerm(H, pk.Pprime1, pk.S1p, pk.Mu1, pk.K, P)
V0 := core.BarrettTerm(F, pk.Qprime0, pk.S2p, pk.Nu0, pk.K, P)
V1 := core.BarrettTerm(F, pk.Qprime1, pk.S2p, pk.Nu1, pk.K, P)


// compare V0 + V1*x ?= U0 + U1*x (mod p)
left := Ffield.Add(V0, Ffield.Mul(V1, x))
right := Ffield.Add(U0, Ffield.Mul(U1, x))
return left.Cmp(right)==0
}