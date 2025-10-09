package kem

import (
"encoding/json"
"math/big"
"github.com/yourname/hppk/internal/core"
)


type Cipher struct {
Pbar *big.Int `json:"pbar"`
Qbar *big.Int `json:"qbar"`
}


// Encaps: For λ=1, we simulate P̄, Q̄ as integer accumulations using random noise u1,u2
func Encaps(pk *KEMPublic, x *big.Int, noiseMin, noiseMax int64) *Cipher {
F := core.NewField(pk.P)
u1 := core.RandIntRange(noiseMin, noiseMax)
u2 := core.RandIntRange(noiseMin, noiseMax)
// Demo accumulation: treat as linear sums over monomials 1,x times noise
// Pbar = Σ P_ij * (x^i * u_j) -> simplified demo uses (x*u1 + u2)
pbar := new(big.Int).Add(new(big.Int).Mul(x, u1), u2)
qbar := new(big.Int).Add(new(big.Int).Mul(x, u2), u1)
pbar = F.Norm(pbar) // keep bounded notionally
qbar = F.Norm(qbar)
return &Cipher{Pbar:pbar, Qbar:qbar}
}


func (c *Cipher) Bytes() []byte { b,_ := json.Marshal(c); return b }