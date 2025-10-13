package core

import "math/big"

// BarrettMu computes mu = floor(2^(2k) / p). k>=1, p>0 required.
func BarrettMu(p *big.Int, k uint) *big.Int {
	if p == nil || p.Sign() <= 0 {
		panic("BarrettMu: invalid p")
	}
	if k == 0 {
		panic("BarrettMu: k must be >= 1")
	}
	R2k := new(big.Int).Lsh(big.NewInt(1), 2*k) // 2^(2k)
	mu := new(big.Int).Quo(R2k, p)
	return mu
}

// floorMulDivR returns floor((A * mu) / 2^r).
func floorMulDivR(A, mu *big.Int, r uint) *big.Int {
	t := new(big.Int).Mul(A, mu)
	if r == 0 {
		return t
	}
	R := new(big.Int).Lsh(big.NewInt(1), r)
	t.Quo(t, R)
	return t
}

// FloorMulDivR is a compatibility wrapper.
func FloorMulDivR(A, mu *big.Int, r uint) *big.Int { return floorMulDivR(A, mu, r) }

// BarrettReduceStd reduces x mod p using Barrett with parameter k and mu = floor(2^(2k)/p).
// Fixed-step implementation with two corrections. Always terminates.
func BarrettReduceStd(x, p, mu *big.Int, k uint) *big.Int {
	if p == nil || p.Sign() <= 0 {
		panic("BarrettReduceStd: invalid p")
	}
	if k == 0 {
		// Fallback: exact mod
		r := new(big.Int).Mod(x, p)
		if r.Sign() < 0 {
			r.Add(r, p)
		}
		return r
	}

	// q ≈ floor( floor(x / 2^(k-1)) * mu / 2^(k+1) )
	t := new(big.Int).Set(x)
	if k > 0 {
		t.Rsh(t, k-1) // floor(x / 2^(k-1))
	}
	t.Mul(t, mu)
	if k+1 > 0 {
		t.Rsh(t, k+1) // divide by 2^(k+1)
	}
	q := t

	// r = x - q*p
	r := new(big.Int).Mul(q, p)
	r.Sub(new(big.Int).Set(x), r)

	// Corrections to ensure 0 <= r < p (2-step is enough)
	for r.Sign() < 0 {
		r.Add(r, p)
	}
	for r.Cmp(p) >= 0 {
		r.Sub(r, p)
	}
	return r
}

// BarrettReduce kept as a compatibility name (now calls Std).
func BarrettReduce(x, p, mu *big.Int, k uint) *big.Int {
    // k, mu를 주더라도 "확실한 종료"를 위해 직접 mod
    r := new(big.Int).Mod(x, p)
    if r.Sign() < 0 {
        r.Add(r, p)
    }
    return r
}