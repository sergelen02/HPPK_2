package kem


import (
"math/big"
"github.com/sergelen02/HPPK_2/internal/core"
)


// Decaps (demo): compute p̄=(P̄*R1 mod S1) mod p and q̄ analogously, then recover x from ratio
func Decaps(sk *KEMSecret, c *Cipher) *big.Int {
F := core.NewField(sk.P)
p1 := new(big.Int).Mod(new(big.Int).Mul(c.Pbar, sk.R1), sk.S1)
q1 := new(big.Int).Mod(new(big.Int).Mul(c.Qbar, sk.R2), sk.S2)
p1.Mod(p1, sk.P)
q1.Mod(q1, sk.P)
if q1.Sign() == 0 { return big.NewInt(0) }
// k = p1/q1 mod p
inv := F.Inv(q1)
if inv == nil { return big.NewInt(0) }
k := F.Mul(p1, inv)
// For λ=1: f0+f1*x = k*(h0+h1*x) => (f1 - k*h1)*x = (k*h0 - f0)
num := new(big.Int).Sub(new(big.Int).Mul(k, sk.H0), sk.F0)
den := new(big.Int).Sub(sk.F1, new(big.Int).Mul(k, sk.H1))
den = F.Norm(den)
invden := F.Inv(den)
if invden == nil { return big.NewInt(0) }
x := F.Mul(num, invden)
return x
}