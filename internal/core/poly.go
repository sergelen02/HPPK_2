package core


import "math/big"


// Field arithmetic kept in field.go — here we focus on polynomials


// Poly1: univariate polynomial over F_p
// coeffs[k] is coefficient for x^k (0..deg)
type Poly1 struct { Coeffs []*big.Int }


func NewPoly1(coeffs []*big.Int) Poly1 {
out := make([]*big.Int, len(coeffs))
for i,c := range coeffs { out[i] = new(big.Int).Set(c) }
return Poly1{Coeffs: out}
}


func (P1 Poly1) Degree() int { return len(P1.Coeffs)-1 }


func (P1 Poly1) Eval(F *Field, x *big.Int) *big.Int {
acc := new(big.Int)
pow := big.NewInt(1)
for _, c := range P1.Coeffs {
term := new(big.Int).Mul(c, pow)
acc.Add(acc, term)
pow.Mul(pow, x)
}
return F.Norm(acc)
}


// MulPoly1: convolution (truncated to dA+dB)
func MulPoly1(F *Field, A, B Poly1) Poly1 {
deg := A.Degree() + B.Degree()
out := make([]*big.Int, deg+1)
for i := range out { out[i] = new(big.Int) }
for i, ai := range A.Coeffs {
for j, bj := range B.Coeffs {
out[i+j].Add(out[i+j], new(big.Int).Mul(ai, bj))
}
}
for i := range out { out[i] = F.Norm(out[i]) }
return Poly1{Coeffs: out}
}


// BPoly: B(x, u_vec) = sum_j ( B_j(x) * u_j )
// represented by array of univariate polys for each u_j
// B[j] is the polynomial for multiplier of u_j
type BPoly struct { B []Poly1 }


// BuildProductPolys: compute P = f(x)*B(x,u), Q = h(x)*B(x,u)
// Returns two coefficient matrices Pij, Qij where
// i indexes x^i (0..maxdeg), j indexes u_j (1..m)
func BuildProductPolys(F *Field, f, h Poly1, B BPoly) (Pij [][]*big.Int, Qij [][]*big.Int) {
m := len(B.B)
// For each j, compute convolution f*B_j and h*B_j
FP := make([]Poly1, m)
FQ := make([]Poly1, m)
maxdeg := 0
for j := 0; j < m; j++ {
FP[j] = MulPoly1(F, f, B.B[j])
FQ[j] = MulPoly1(F, h, B.B[j])
if FP[j].Degree() > maxdeg { maxdeg = FP[j].Degree() }
if FQ[j].Degree() > maxdeg { maxdeg = FQ[j].Degree() }
}
// Allocate matrices (maxdeg+1) x m
Pij = make([][]*big.Int, maxdeg+1)
Qij = make([][]*big.Int, maxdeg+1)
for i := 0; i <= maxdeg; i++ {
Pij[i] = make([]*big.Int, m)
Qij[i] = make([]*big.Int, m)
for j := 0; j < m; j++ {
var pc, qc *big.Int
if i < len(FP[j].Coeffs) { pc = new(big.Int).Set(FP[j].Coeffs[i]) } else { pc = new(big.Int) }
if i < len(FQ[j].Coeffs) { qc = new(big.Int).Set(FQ[j].Coeffs[i]) } else { qc = new(big.Int) }
Pij[i][j] = F.Norm(pc)
Qij[i][j] = F.Norm(qc)
}
}
return
}