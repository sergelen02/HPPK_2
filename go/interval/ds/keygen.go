package ds

import (
	"crypto/rand"
	"math/big"
)

// randMod: uniform [0, m)
func randMod(m *big.Int) *big.Int {
	x, _ := rand.Int(rand.Reader, m)
	if x.Sign() < 0 {
		x.Add(x, m)
	}
	return x
}

func coprime(a, b *big.Int) bool {
	g := new(big.Int).GCD(nil, nil, a, b)
	return g.Cmp(big.NewInt(1)) == 0
}

// demo P,Q coefficients (논문 재현 시 '결정적 생성' 또는 '부록값 로드'로 교체)
func makePQ(n int, p *big.Int) (P, Q []*big.Int) {
	P = make([]*big.Int, n)
	Q = make([]*big.Int, n)
	for i := 0; i < n; i++ {
		P[i] = randMod(p)
		Q[i] = randMod(p)
	}
	return
}

// μ_i = floor(R * P_i / S1),  ν_i = floor(R * Q_i / S2)
func computeMuNu(pp *Params, P, Q []*big.Int, S1, S2 *big.Int) (mu, nu []*big.Int) {
	if len(P) != len(Q) {
		panic("computeMuNu: P,Q length mismatch")
	}
	if S1.Sign() == 0 || S2.Sign() == 0 {
		panic("computeMuNu: S1 or S2 is zero")
	}
	R := pp.R()
	n := len(P)
	mu = make([]*big.Int, n)
	nu = make([]*big.Int, n)
	for i := 0; i < n; i++ {
		t := new(big.Int).Mul(R, P[i])
		t.Div(t, S1) // floor
		mu[i] = t

		u := new(big.Int).Mul(R, Q[i])
		u.Div(u, S2) // floor
		nu[i] = u
	}
	return
}

// Algorithm 4: DS KeyGen → (SK, PK)
func KeyGen(pp *Params, n int) (*SecretKey, *PublicKey) {
	if n <= 0 {
		n = pp.N
	}
	p := pp.P

	// 1) f,h 계수
	f0, f1 := randMod(p), randMod(p)
	h0, h1 := randMod(p), randMod(p)

	// 2) (R1,S1), (R2,S2) with gcd=1
	var R1, S1, R2, S2 *big.Int
	for {
		R1, S1 = randMod(p), randMod(p)
		if S1.Sign() == 0 {
			S1 = big.NewInt(1)
		}
		if coprime(R1, S1) {
			break
		}
	}
	for {
		R2, S2 = randMod(p), randMod(p)
		if S2.Sign() == 0 {
			S2 = big.NewInt(1)
		}
		if coprime(R2, S2) {
			break
		}
	}

	// 3) β
	beta := randMod(p)

	// 4) 공개 다항 P,Q
	Pc, Qc := makePQ(n, p)

	// 5) μ,ν
	mu, nu := computeMuNu(pp, Pc, Qc, S1, S2)

	// 6) p′, q′, s1, s2
	pprime := make([]*big.Int, n)
	qprime := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		pprime[i] = mulMod(beta, Pc[i], p)
		qprime[i] = mulMod(beta, Qc[i], p)
	}
	s1p := mulMod(beta, S1, p)
	s2p := mulMod(beta, S2, p)

	// 결과
	sk := &SecretKey{
		F0: f0, F1: f1,
		H0: h0, H1: h1,
		R1: R1, S1: S1,
		R2: R2, S2: S2,
		Beta: beta,
	}
	pk := &PublicKey{
		Pprime: pprime,
		Qprime: qprime,
		Mu:     mu,
		Nu:     nu,
		S1p:    s1p,
		S2p:    s2p,
	}
	return sk, pk
}
