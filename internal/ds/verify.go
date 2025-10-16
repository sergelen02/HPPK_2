package ds

import (
	"math/big"

	"github.com/sergelen02/HPPK_2/internal/core"
)

func Verify(pk *Public, msg []byte, sig *Signature) bool {
	if pk == nil || pk.P == nil || pk.P.Sign() == 0 || sig == nil {
		return false
	}
	if pk.Pprime0 == nil || pk.Pprime1 == nil || pk.Qprime0 == 
	nil || pk.Qprime1 == nil {
		return false
	}

	P := pk.P
	x := core.HashToX(P, msg)

	F := new(big.Int).SetBytes(sig.F) // F mod p
	H := new(big.Int).SetBytes(sig.H) // H mod p
	U := new(big.Int).SetBytes(sig.U) // claimed α·H
	V := new(big.Int).SetBytes(sig.V) // claimed β·F

	// α, β (mod p)
	alpha := new(big.Int).Add(pk.Pprime0, new(big.Int).Mul(pk.Pprime1, x))
	alpha.Mod(alpha, P)
	if alpha.Sign() < 0 { alpha.Add(alpha, P) }

	beta := new(big.Int).Add(pk.Qprime0, new(big.Int).Mul(pk.Qprime1, x))
	beta.Mod(beta, P)
	if beta.Sign() < 0 { beta.Add(beta, P) }

	// 기대값
	expU := new(big.Int).Mod(new(big.Int).Mul(alpha, H), P)
	expV := new(big.Int).Mod(new(big.Int).Mul(beta,  F), P)

	// 각각 일치하는지만 확인
	if expU.Cmp(U) != 0 { return false }
	if expV.Cmp(V) != 0 { return false }
	return true
}
