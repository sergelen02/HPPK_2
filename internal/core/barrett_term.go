package core

import "math/big"

// a*b를 s 로 Barrett 감소(필요 시 mu,k 사용), 그리고 (옵션) p로 최종 사상
func BarrettTerm(a, b, s, mu *big.Int, k uint, p *big.Int) *big.Int {
	t := new(big.Int).Mul(a, b)

	var r *big.Int
	if mu != nil && k != 0 {
		r = BarrettReduce(t, s, mu, k)
	} else {
		// mu가 없거나 k==0이면 안전판으로
		r = BarrettReduceStd(t, s, nil, 0)
	}

	// (옵션) F_p로 사상
	if p != nil {
		r.Mod(r, p)
		if r.Sign() < 0 {
			r.Add(r, p)
		}
	}
	return r
}
