package ds

import "math/big"

// Secret Key (HPPK DS)
type SecretKey struct {
	// f(x)=f0+f1 x, h(x)=h0+h1 x (mod p)
	F0, F1 *big.Int
	H0, H1 *big.Int
	// hidden ring params (gcd=1)
	R1, S1 *big.Int
	R2, S2 *big.Int
	// blinding
	Beta *big.Int
}

// Public Key (derived)
type PublicKey struct {
	// scaled polys
	Pprime []*big.Int // p′_i = beta * P_i (mod p)
	Qprime []*big.Int // q′_i = beta * Q_i (mod p)
	// Barrett constants
	Mu []*big.Int // μ_i = floor(R * P_i / S1)
	Nu []*big.Int // ν_i = floor(R * Q_i / S2)
	// scaled moduli
	S1p *big.Int // s1 = beta * S1 (mod p)
	S2p *big.Int // s2 = beta * S2 (mod p)
}

// Signature
type Signature struct {
	F *big.Int
	H *big.Int
}
