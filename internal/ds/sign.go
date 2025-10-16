package ds

import (
	//"encoding/json"
	"fmt"
	"math/big"
	//"os"

	"github.com/sergelen02/HPPK_2/internal/core"
)

type Signature struct {
	F []byte // F value (reduced to field p for portability)
	H []byte // H value (reduced to field p for portability)
	U []byte // φ_A(H) mod p
	V []byte // φ_B(F) mod p
}

// internal/ds/sign.go 에 추가
// internal/ds/sign.go 에 추가
func SignWithPK(sk *Secret, pk *Public, msg []byte) (*Signature, error) {
    if sk == nil || sk.P == nil || sk.P.Sign() == 0 {
        return nil, fmt.Errorf("SignWithPK: invalid secret or modulus")
    }
    if pk == nil {
        return nil, fmt.Errorf("SignWithPK: pk is required (pass public key)")
    }

    // 1) x = H(msg) in F_p
    x := core.HashToX(sk.P, msg)

    // 2) f(x), h(x)  (정수연산)
    fx := new(big.Int).Add(new(big.Int).Mul(sk.F1, x), sk.F0)
    hx := new(big.Int).Add(new(big.Int).Mul(sk.H1, x), sk.H0)

    // 3) R^{-1} mod S
    r2inv := new(big.Int).ModInverse(new(big.Int).Mod(sk.R2, sk.S2), sk.S2)
    r1inv := new(big.Int).ModInverse(new(big.Int).Mod(sk.R1, sk.S1), sk.S1)
    if r2inv == nil || r1inv == nil {
        return nil, fmt.Errorf("SignWithPK: no inverse of R mod S")
    }

    // 4) F, H (mod S)
    Fv := new(big.Int).Mod(new(big.Int).Mul(fx, r2inv), sk.S2)
    Hv := new(big.Int).Mod(new(big.Int).Mul(hx, r1inv), sk.S1)

    // 5) α = p0 + p1*x, β = q0 + q1*x  (mod p)
    alpha := new(big.Int).Add(pk.Pprime0, new(big.Int).Mul(pk.Pprime1, x))
    alpha.Mod(alpha, sk.P)
    if alpha.Sign() < 0 { alpha.Add(alpha, sk.P) }

    beta := new(big.Int).Add(pk.Qprime0, new(big.Int).Mul(pk.Qprime1, x))
    beta.Mod(beta, sk.P)
    if beta.Sign() < 0 { beta.Add(beta, sk.P) }

    // 6) U = α·H (mod p), V = β·F (mod p)
    U := new(big.Int).Mod(new(big.Int).Mul(alpha, new(big.Int).Mod(Hv, sk.P)), sk.P)
    V := new(big.Int).Mod(new(big.Int).Mul(beta,  new(big.Int).Mod(Fv, sk.P)), sk.P)

    // 7) 고정 길이 직렬화(Null 방지)
    lenS1 := (sk.S1.BitLen()+7)/8
    lenS2 := (sk.S2.BitLen()+7)/8
    lenP  := (sk.P.BitLen()+7)/8
    if lenS1 == 0 || lenS2 == 0 || lenP == 0 {
        return nil, fmt.Errorf("SignWithPK: bad sizes")
    }

    Fbytes := make([]byte, lenS2); _ = Fv.FillBytes(Fbytes)
    Hbytes := make([]byte, lenS1); _ = Hv.FillBytes(Hbytes)
    Ubytes := make([]byte, lenP);  _ = U.FillBytes(Ubytes)
    Vbytes := make([]byte, lenP);  _ = V.FillBytes(Vbytes)

    return &Signature{F: Fbytes, H: Hbytes, U: Ubytes, V: Vbytes}, nil
}
