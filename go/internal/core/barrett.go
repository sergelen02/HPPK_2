package core

import "math/big"


// Barrett style helper for DS verification path.
// floor((a*b)/R) with R=2^K (K bits).
func FloorMulDivR(a, b, K uint) *big.Int {
ab := new(big.Int).Mul(a, b)
return new(big.Int).Rsh(ab, K)
}


// U(H) = H*p' - s1*floor(H*mu / R) mod p
// V(F) = F*q' - s2*floor(F*nu / R) mod p
func BarrettTerm(A, prim, scale, mu *big.Int, K uint, p *big.Int) *big.Int {
// t = floor(A*mu / R)
t := FloorMulDivR(A, mu, K)
// r = A*prim - scale*t
r := new(big.Int).Mul(A, prim)
t2 := new(big.Int).Mul(scale, t)
r.Sub(r, t2)
r.Mod(r, p)
if r.Sign() < 0 { r.Add(r, p) }
return r
}