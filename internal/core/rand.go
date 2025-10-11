package core

import (
	"crypto/rand"
	"math/big"
)

func RandZp(F *Field) *big.Int {
	if F == nil || F.P == nil || F.P.Sign() <= 0 {
		panic("RandZp: field modulus p is missing or non-positive")
	}
	// 반환 범위: 1..p-1
	max := new(big.Int).Sub(F.P, big.NewInt(1)) // p-1
	if max.Sign() <= 0 {
		panic("RandZp: p must be > 1")
	}
	r, err := rand.Int(rand.Reader, max) // 0..p-2
	if err != nil { panic(err) }
	r.Add(r, big.NewInt(1)) // 1..p-1
	return r
}

// random in [min,max]
func RandIntRange(min, max int64) *big.Int {
	if max < min { max, min = min, max }
	rng := big.NewInt(max - min + 1)
	r, _ := rand.Int(rand.Reader, rng)
	r.Add(r, big.NewInt(min))
	return r
}
