package ds


import (
"encoding/json"
"math/big"
"github.com/yourname/hppk/internal/core"
)


type Secret struct {
P *big.Int `json:"p"`
R1,S1 *big.Int `json:"r1","s1"`
R2,S2 *big.Int `json:"r2","s2"`
F0,F1 *big.Int `json:"f0","f1"`
H0,H1 *big.Int `json:"h0","h1"`
K uint `json:"K"` // Barrett bits
}


type Public struct {
P *big.Int `json:"p"`
// Barrett-based public values for verification
Pprime0,Pprime1 *big.Int `json:"p0","p1"`
Qprime0,Qprime1 *big.Int `json:"q0","q1"`
Mu0,Mu1 *big.Int `json:"mu0","mu1"`
Nu0,Nu1 *big.Int `json:"nu0","nu1"`
S1p,S2p *big.Int `json:"s1p","s2p"`
K uint `json:"K"`
}


type Params struct { P *big.Int; L,K uint }


func KeyGenDS(p *big.Int, L, K uint) (*Secret, *Public) {
// f,h
f0,f1 := core.RandZp(p), core.RandZp(p)
h0,h1 := core.RandZp(p), core.RandZp(p)
// Rings
R := new(big.Int).Lsh(big.NewInt(1), L)
S1 := new(big.Int).Add(core.RandZp(p), new(big.Int).Lsh(big.NewInt(1), L-1))
S2 := new(big.Int).Add(core.RandZp(p), new(big.Int).Lsh(big.NewInt(1), L-1))
for new(big.Int).GCD(nil,nil,R,S1).Cmp(big.NewInt(1))!=0 { S1.Add(S1,big.NewInt(1)) }
for new(big.Int).GCD(nil,nil,R,S2).Cmp(big.NewInt(1))!=0 { S2.Add(S2,big.NewInt(1)) }


// Barrett scaling values (demo simplification: use linear coeffs)
beta := new(big.Int).Lsh(big.NewInt(1), 8) // small scale for demo
p0 := new(big.Int).Mod(new(big.Int).Mul(beta, f0), p)
p1 := new(big.Int).Mod(new(big.Int).Mul(beta, f1), p)
q0 := new(big.Int).Mod(new(big.Int).Mul(beta, h0), p)
q1 := new(big.Int).Mod(new(big.Int).Mul(beta, h1), p)
// floor((R*coeff)/S) approximators stored as integers μ,ν
mu0 := new(big.Int).Div(new(big.Int).Mul(R, f0), S1)
mu1 := new(big.Int).Div(new(big.Int).Mul(R, f1), S1)
nu0 := new(big.Int).Div(new(big.Int).Mul(R, h0), S2)
nu1 := new(big.Int).Div(new(big.Int).Mul(R, h1), S2)
s1p := new(big.Int).Mod(new(big.Int).Mul(beta, S1), p)
s2p := new(big.Int).Mod(new(big.Int).Mul(beta, S2), p)


sk := &Secret{P:p,R1:R,S1:S1,R2:R,S2:S2,F0:f0,F1:f1,H0:h0,H1:h1,K:K}
pk := &Public{P:p,Pprime0:p0,Pprime1:p1,Qprime0:q0,Qprime1:q1,Mu0:mu0,Mu1:mu1,Nu0:nu0,Nu1:nu1,S1p:s1p,S2p:s2p,K:K}
return sk, pk
}


func (sk *Secret) MarshalJSON() ([]byte, error) { type A Secret; return json.Marshal((*A)(sk)) }
func (pk *Public) MarshalJSON() ([]byte, error) { type A Public; return json.Marshal((*A)(pk)) }