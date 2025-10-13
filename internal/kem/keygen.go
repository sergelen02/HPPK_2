// internal/kem/keygen.go
package kem

import (
    "encoding/json"
    "math/big"

    "github.com/sergelen02/HPPK_2/internal/core"
)

type KEMSecret struct {
    P      *big.Int `json:"p"`
    R1     *big.Int `json:"r1"`
    S1     *big.Int `json:"s1"`
    R2     *big.Int `json:"r2"`
    S2     *big.Int `json:"s2"`
    F0     *big.Int `json:"f0"`
    F1     *big.Int `json:"f1"`
    H0     *big.Int `json:"h0"`
    H1     *big.Int `json:"h1"`
    N      int      `json:"n"`
    Lambda int      `json:"lambda"`
    M      int      `json:"m"`
}

type KEMPublic struct {
    P      *big.Int `json:"p"`
    N      int      `json:"n"`
    Lambda int      `json:"lambda"`
    M      int      `json:"m"`
    L      uint     `json:"L"`
    K      uint     `json:"K"`
    Pp [][]string   `json:"Pp"`
    Qp [][]string   `json:"Qp"`
}

// check L ≥ 2·log2 p + log2(m(λ+n+1))
func checkL(pp *Params) bool {
    log2p := pp.P.BitLen()
    boundTerm := pp.M * (pp.Lambda + pp.N + 1)
    log2term := 0
    for x := boundTerm; x > 0; x >>= 1 { log2term++ }
    need := 2*log2p + log2term
    return int(pp.L) >= need
}

func KeyGenKEM(pp *Params) (*KEMSecret, *KEMPublic) {
    if !checkL(pp) { return nil, nil }

    F := core.NewField(pp.P)

    // Choose linear f(x), h(x) for λ=1 baseline (extendible)
    f0, f1 := core.RandZp(F), core.RandZp(F)
    h0, h1 := core.RandZp(F), core.RandZp(F)
    f := core.NewPoly1([]*big.Int{f0, f1})
    h := core.NewPoly1([]*big.Int{h0, h1})

    // Build random B(x,u): m polynomials with degree n
    Bj := make([]core.Poly1, pp.M)
    for j := 0; j < pp.M; j++ {
        coeffs := make([]*big.Int, pp.N+1)
        for i := 0; i <= pp.N; i++ { coeffs[i] = core.RandZp(F) }
        Bj[j] = core.NewPoly1(coeffs)
    }
    B := core.BPoly{B: Bj}

    // P=f·B, Q=h·B coefficient matrices over F_p
    Pij, Qij := core.BuildProductPolys(F, f, h, B)

    // Hidden rings
    R := new(big.Int).Lsh(big.NewInt(1), pp.L)
    S1 := new(big.Int).Add(core.RandZp(F), new(big.Int).Lsh(big.NewInt(1), pp.L-1))
    S2 := new(big.Int).Add(core.RandZp(F), new(big.Int).Lsh(big.NewInt(1), pp.L-1))
    for new(big.Int).GCD(nil, nil, R, S1).Cmp(big.NewInt(1)) != 0 { S1.Add(S1, big.NewInt(1)) }
    for new(big.Int).GCD(nil, nil, R, S2).Cmp(big.NewInt(1)) != 0 { S2.Add(S2, big.NewInt(1)) }

    // Coefficient hiding: P' = (R*P) mod S1, Q' = (R*Q) mod S2
    rows := len(Pij)
    m := pp.M
    Pp := make([][]string, rows)
    Qp := make([][]string, rows)
    for i := 0; i < rows; i++ {
        Pp[i] = make([]string, m)
        Qp[i] = make([]string, m)
        for j := 0; j < m; j++ {
            penc := new(big.Int).Mod(new(big.Int).Mul(R, Pij[i][j]), S1)
            qenc := new(big.Int).Mod(new(big.Int).Mul(R, Qij[i][j]), S2)
            Pp[i][j] = penc.Text(16)
            Qp[i][j] = qenc.Text(16)
        }
    }

    sk := &KEMSecret{
        P: pp.P, R1: R, S1: S1, R2: R, S2: S2,
        F0: f0, F1: f1, H0: h0, H1: h1,
        N: pp.N, Lambda: pp.Lambda, M: pp.M,
    }
    pk := &KEMPublic{
        P: pp.P, N: pp.N, Lambda: pp.Lambda, M: pp.M, L: pp.L, K: pp.K,
        Pp: Pp, Qp: Qp,
    }
    return sk, pk
}

func (sk *KEMSecret) MarshalJSON() ([]byte, error) { type alias KEMSecret; return json.Marshal((*alias)(sk)) }
func (pk *KEMPublic) MarshalJSON() ([]byte, error) { type alias KEMPublic; return json.Marshal((*alias)(pk)) }

