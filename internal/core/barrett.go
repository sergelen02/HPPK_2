package core

import "math/big"

// BarrettMu returns μ = floor(2^(2k) / p).
// NOTE: μ는 "이 모듈러스 p"와 "같은 k"로 만들어야 합니다.
//      (다른 모듈러스/다른 k로 만든 μ를 쓰면 오검증/시간초과의 원인이 됩니다)
func BarrettMu(p *big.Int, k uint) *big.Int {
	if p == nil || p.Sign() <= 0 {
		panic("BarrettMu: invalid modulus p")
	}
	// R2k = 2^(2k)
	R2k := new(big.Int).Lsh(big.NewInt(1), 2*k)
	return new(big.Int).Quo(R2k, p)
}

// FloorMulDivR returns floor((A * mu) / 2^r).
// (호환용. 곳곳에서 같은 의미로 쓰이던 헬퍼)
func FloorMulDivR(A, mu *big.Int, r uint) *big.Int {
	t := new(big.Int).Mul(A, mu)
	R := new(big.Int).Lsh(big.NewInt(1), r)
	return t.Quo(t, R)
}

// BarrettReduceStd is a safe/fast fallback: r = x mod p with normalization.
func BarrettReduceStd(x, p, _ *big.Int, _ uint) *big.Int {
	if p == nil || p.Sign() <= 0 {
		panic("BarrettReduceStd: invalid modulus p")
	}
	// 빠른 경로: 0 <= x < p 인 경우 (참조 전달 위험이 있으므로 사본을 사용)
	if x.Sign() >= 0 && x.Cmp(p) < 0 {
		return new(big.Int).Set(x)
	}
	r := new(big.Int).Mod(x, p)
	if r.Sign() < 0 {
		r.Add(r, p)
	}
	return r
}

// BarrettReduce reduces x modulo p using Barrett reduction with (mu, k).
// 교과서식 근사 q = floor( floor(x/2^(k-1)) * μ / 2^(k+1) )을 쓰되,
// 마지막은 반복 보정 대신 한 번의 Mod로 정규화 → 타임아웃/루프 방지.
func BarrettReduce(x, p, mu *big.Int, k uint) *big.Int {
	if p == nil || p.Sign() <= 0 {
		panic("BarrettReduce: invalid modulus p")
	}
	// 파라미터가 맞지 않거나(k==0, mu==nil) 작은 입력이면 표준 mod로 폴백
	if k == 0 || mu == nil {
		return BarrettReduceStd(x, p, nil, 0)
	}
	if x.Sign() >= 0 && x.Cmp(p) < 0 {
		return new(big.Int).Set(x)
	}

	// q ≈ floor( floor(x / 2^(k-1)) * μ / 2^(k+1) )
	// NOTE: big.Int는 제자리 연산이 많아 반드시 새 객체로 보관합니다.
	RkMinus1 := new(big.Int).Lsh(big.NewInt(1), k-1) // 2^(k-1)
	t := new(big.Int).Quo(x, RkMinus1)               // floor(x / 2^(k-1))
	t.Mul(t, mu)
	RkPlus1 := new(big.Int).Lsh(big.NewInt(1), k+1) // 2^(k+1)
	q := new(big.Int).Quo(t, RkPlus1)

	// r = x - q*p
	qp := new(big.Int).Mul(q, p)
	r := new(big.Int).Sub(x, qp)

	// 반복 보정 대신 최종 Mod로 정규화 (음수 보정 포함)
	r.Mod(r, p)
	if r.Sign() < 0 {
		r.Add(r, p)
	}
	return r
}
