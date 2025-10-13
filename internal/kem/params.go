package kem

import "math/big"

type Params struct {
    P        *big.Int
    N        int
    Lambda   int
    M        int
    L        uint
    K        uint
    NoiseMin int64
    NoiseMax int64
}

func LoadParams(pStr string, n, lambda, m int, L, K uint, nmin, nmax int64) *Params {
    P := new(big.Int)
    if _, ok := P.SetString(pStr, 0); !ok { // 0x/10진 모두
        return &Params{P: nil}
    }
    return &Params{
        P: P, N: n, Lambda: lambda, M: m, L: L, K: K,
        NoiseMin: nmin, NoiseMax: nmax,
    }
}
