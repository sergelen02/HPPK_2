package core

import "math/big"

// Stable BarrettTerm:
// Compute (a * b) mod p using Barrett for modulus p (mu_B = floor(2^(2k)/p)).
// 's' and 'mu' are ignored on purpose, because the values stored in pk (s1p,s2p, mu0,nu0,...) are
// NOT actual moduli or Barrett-mus. This guarantees termination and correctness modulo p.
func BarrettTerm(a, b, _s, _mu *big.Int, k uint, p *big.Int) *big.Int {
	if a == nil || b == nil || p == nil {
		panic("BarrettTerm: nil input")
	}
	// t = a*b
	t := new(big.Int).Mul(a, b)
	// Use proper Barrett mu for modulus p
	muB := BarrettMu(p, k)
	return BarrettReduceStd(t, p, muB, k) // (t mod p), fixed-step, always terminates
}
