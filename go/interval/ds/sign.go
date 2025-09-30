package ds

import (
	"fmt"
	"math/big"
)

// Sign (Alg.5):
// F = (f(x) * R2^{-1}) mod S2
// H = (h(x) * R1^{-1}) mod S1
func Sign(pp *Params, sk *SecretKey, msg []byte) (*Signature, error) {
	if sk == nil {
		return nil, fmt.Errorf("sign: nil secret key")
	}
	x := hashToX(pp.P, msg)

	fx := evalLin(sk.F0, sk.F1, x, pp.P)
	hx := evalLin(sk.H0, sk.H1, x, pp.P)

	r2Inv := new(big.Int).ModInverse(sk.R2, sk.S2)
	if r2Inv == nil {
		return nil, fmt.Errorf("%w: R2 vs S2 not invertible", ErrNoInverse)
	}
	r1Inv := new(big.Int).ModInverse(sk.R1, sk.S1)
	if r1Inv == nil {
		return nil, fmt.Errorf("%w: R1 vs S1 not invertible", ErrNoInverse)
	}

	F := new(big.Int).Mul(fx, r2Inv)
	F.Mod(F, sk.S2)
	if F.Sign() < 0 {
		F.Add(F, sk.S2)
	}

	H := new(big.Int).Mul(hx, r1Inv)
	H.Mod(H, sk.S1)
	if H.Sign() < 0 {
		H.Add(H, sk.S1)
	}

	return &Signature{F: F, H: H}, nil
}
