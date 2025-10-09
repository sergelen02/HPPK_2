package kem
package kem


import (
"encoding/json"
"math/big"


"github.com/yourname/hppk/internal/core"
)


type KEMSecret struct {
P *big.Int `json:"p"`
R1,S1 *big.Int `json:"r1","s1"`
R2,S2 *big.Int `json:"r2","s2"`
F,H core.Lin `json:"-"`
F0,F1 *big.Int `json:"f0","f1"`
H0,H1 *big.Int `json:"h0","h1"`
}


type KEMPublic struct {
P *big.Int `json:"p"`
// Encoded polynomial coefficients for P(x,·), Q(x,·) are implicit in λ=1 demo.
// For a minimal demo, we store f,h encrypted coefficients could be extended here.
}


type Params struct {
P *big.Int
L uint
K uint
NoiseMin int64
NoiseMax int64
}


func LoadParams(phex string, L, K uint, nmin, nmax int64) *Params {
p := new(big.Int)
p.SetString(phex, 16)
return &Params{P:p, L:L, K:K, NoiseMin:nmin, NoiseMax:nmax}
}


func KeyGenKEM(pp *Params) (*KEMSecret, *KEMPublic) {
F := core.NewField(pp.P)
// Choose f(x), h(x)
f0,f1 := core.RandZp(pp.P), core.RandZp(pp.P)
h0,h1 := core.RandZp(pp.P), core.RandZp(pp.P)
// Hidden rings (R,S) with gcd(R,S)=1; demo picks R=2^L, S ~ random big, ensure coprime.
R := new(big.Int).Lsh(big.NewInt(1), pp.L)
S1 := new(big.Int).Add(core.RandZp(pp.P), new(big.Int).Lsh(big.NewInt(1), pp.L-1))
S2 := new(big.Int).Add(core.RandZp(pp.P), new(big.Int).Lsh(big.NewInt(1), pp.L-1))
// Ensure coprime(R,S)
for new(big.Int).GCD(nil,nil,R,S1).Cmp(big.NewInt(1)) != 0 { S1.Add(S1,big.NewInt(1)) }
for new(big.Int).GCD(nil,nil,R,S2).Cmp(big.NewInt(1)) != 0 { S2.Add(S2,big.NewInt(1)) }


sk := &KEMSecret{P:pp.P, R1:R, S1:S1, R2:R, S2:S2, F:core.NewLin(f0,f1), H:core.NewLin(h0,h1), F0:f0,F1:f1,H0:h0,H1:h1}
pk := &KEMPublic{P:pp.P}
_ = F // placeholder for future checks
return sk, pk
}


func (sk *KEMSecret) MarshalJSON() ([]byte, error) {
type alias KEMSecret
aux := &struct{*alias}{alias:(*alias)(sk)}
return json.Marshal(aux)
}