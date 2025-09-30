package ds

import "math/big"

// Params: 논문 파라미터.
//  - P: 모듈러 소수(데모 값; 논문 벡터로 교체 가능)
//  - K: Barrett 스케일. R = 2^K
//  - N: 다항 계수 길이(최소 스켈레톤은 2로 시작)
type Params struct {
	P *big.Int
	K int
	N int
}

// DefaultParams: 데모 파라미터.
// 논문 재현 시 P,K,N을 논문 표/부록 값으로 고정하세요.
func DefaultParams() *Params {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(59)) // p = 2^64 - 59 (prime)
	return &Params{P: p, K: 208, N: 2}
}

func (pp *Params) R() *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(pp.K))
}
