package ds

import "math/big"

// Verify (Alg.6):
// U_i(H) = H*p′_i - s1 * floor(H*μ_i / 2^K)
// V_i(F) = F*q′_i - s2 * floor(F*ν_i / 2^K)
// sum_i U_i x^i == sum_i V_i x^i  (mod p)
func Verify(pp *Params, pk *PublicKey, msg []byte, sig *Signature) bool {
	n := len(pk.Pprime)
	if n == 0 || n != len(pk.Qprime) || n != len(pk.Mu) || n != len(pk.Nu) {
		return false
	}
	x := hashToX(pp.P, msg)
	R := pp.R()

	// Horner-like 누산
	LHS := big.NewInt(0)
	RHS := big.NewInt(0)

	// 누적을 위해 뒤에서 앞으로 (x^n-1 ... x^0)
	for i := n - 1; i >= 0; i-- {
		// LHS = LHS*x + U_i(H)
		LHS = mulMod(LHS, x, pp.P)

		t1 := mulMod(sig.H, pk.Pprime[i], pp.P)
		floor := barrettFloor(sig.H, pk.Mu[i], R, pp.K)
		t2 := mulMod(pk.S1p, floor, pp.P)
		Ui := subMod(t1, t2, pp.P)

		LHS = addMod(LHS, Ui, pp.P)

		// RHS = RHS*x + V_i(F)
		RHS = mulMod(RHS, x, pp.P)

		s1 := mulMod(sig.F, pk.Qprime[i], pp.P)
		floorV := barrettFloor(sig.F, pk.Nu[i], R, pp.K)
		s2 := mulMod(pk.S2p, floorV, pp.P)
		Vi := subMod(s1, s2, pp.P)

		RHS = addMod(RHS, Vi, pp.P)
	}
	return LHS.Cmp(RHS) == 0
}
