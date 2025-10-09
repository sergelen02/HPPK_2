package core


import "math/big"


// Linear polynomial a0 + a1*x over F_p
type Lin struct { A0, A1 *big.Int }


func NewLin(a0, a1 *big.Int) Lin { return Lin{new(big.Int).Set(a0), new(big.Int).Set(a1)} }


func (L Lin) Eval(F *Field, x *big.Int) *big.Int {
t := new(big.Int).Mul(L.A1, x)
t.Add(t, L.A0)
return F.Norm(t)
}