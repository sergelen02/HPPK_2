package core

import "math/big"

type Field struct{ P *big.Int }

func NewField(p *big.Int) *Field {
	if p == nil || p.Sign() <= 0 {
		panic("Field: invalid modulus p")
	}
	return &Field{P: new(big.Int).Set(p)} // <-- 여기 P 로!
}

func (F *Field) Norm(a *big.Int) *big.Int {
	z := new(big.Int).Mod(a, F.P)
	if z.Sign() < 0 { z.Add(z, F.P) }
	return z
}

func (F *Field) Add(a, b *big.Int) *big.Int {
	z := new(big.Int).Add(a, b)
	return F.Norm(z)
}

func (F *Field) Sub(a, b *big.Int) *big.Int {
	z := new(big.Int).Sub(a, b)
	return F.Norm(z)
}

func (F *Field) Mul(a, b *big.Int) *big.Int {
	z := new(big.Int).Mul(a, b)
	return F.Norm(z)
}

func (F *Field) Inv(a *big.Int) *big.Int {
	z := new(big.Int).ModInverse(a, F.P)
	if z == nil { return nil }
	return z
}
