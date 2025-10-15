package ds

import (
	"math/big"

	"github.com/sergelen02/HPPK_2/internal/core"
)

func Verify(pk *Public, msg []byte, sig *Signature) bool {
	P := pk.P
	Fp := core.NewField(P)
	x := core.HashToX(P, msg)

	// read F,H,U,V from signature
	F := new(big.Int).SetBytes(sig.F)
	H := new(big.Int).SetBytes(sig.H)
	U := new(big.Int).SetBytes(sig.U)
	V := new(big.Int).SetBytes(sig.V)

	// recompute alpha/beta
	alpha := new(big.Int).Add(pk.Pprime0, new(big.Int).Mul(pk.Pprime1, x))
	alpha.Mod(alpha, P)
	if alpha.Sign() < 0 { alpha.Add(alpha, P) }

	beta := new(big.Int).Add(pk.Qprime0, new(big.Int).Mul(pk.Qprime1, x))
	beta.Mod(beta, P)
	if beta.Sign() < 0 { beta.Add(beta, P) }

	// recompute expectedU and expectedV from F and H
	expectedU := new(big.Int).Mod(new(big.Int).Mul(alpha, H), P)
	expectedV := new(big.Int).Mod(new(big.Int).Mul(beta, F), P)

	// check that provided U and V match recomputed values
	if expectedU.Cmp(U) != 0 { return false }
	if expectedV.Cmp(V) != 0 { return false }

	// finally check relation U == V (redundant if above both match, but explicit)
	if U.Cmp(V) != 0 { return false }

	// All checks passed
	_ = Fp // (Fp available if more checks needed)
	return true
}
