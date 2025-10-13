package core

import "math/big"

// mu = floor( 2^(2k) / p )
func BarrettMu(p *big.Int, k uint) *big.Int {
	if p == nil || p.Sign() <= 0 {
		panic("BarrettMu: invalid modulus p")
	}
	R2k := new(big.Int).Lsh(big.NewInt(1), 2*k)
	return new(big.Int).Quo(R2k, p)
}

// floor( (A * mu) / 2^r )
func FloorMulDivR(A, mu *big.Int, r uint) *big.Int {
	t := new(big.Int).Mul(A, mu)
	R := new(big.Int).Lsh(big.NewInt(1), r)
	return t.Quo(t, R)
}

// 항상 빠르게 끝나는 안전판: 단순 x mod p
func BarrettReduceStd(x, p, _ *big.Int, _ uint) *big.Int {
	if p == nil || p.Sign() <= 0 {
		panic("BarrettReduceStd: invalid modulus p")
	}
	r := new(big.Int).Mod(x, p)
	if r.Sign() < 0 {
		r.Add(r, p)
	}
	return r
}

// 근사식 유지 버전(마지막에 Mod로 한 번 정규화 → 타임아웃 방지)
func BarrettReduce(x, p, mu *big.Int, k uint) *big.Int {
	if p == nil || p.Sign() <= 0 {
		panic("BarrettReduce: invalid modulus p")
	}
	if k == 0 || mu == nil {
		return BarrettReduceStd(x, p, nil, 0)
	}

	// 교과서식 근사 q 계산
	Rkminus1 := new(big.Int).Lsh(big.NewInt(1), k-1)
	t := new(big.Int).Quo(x, Rkminus1)
	t.Mul(t, mu)
	Rkplus1 := new(big.Int).Lsh(big.NewInt(1), k+1)
	q := new(big.Int).Quo(t, Rkplus1)

	r := new(big.Int).Sub(new(big.Int).Set(x), new(big.Int).Mul(new(big.Int).Set(q), p))
	// ★ 반복 보정 대신 최종 Mod 한 번
	r.Mod(r, p)
	if r.Sign() < 0 {
		r.Add(r, p)
	}
	return r
}
