// Package dsref implements the HPPK-DS verification equations from
// Kuang et al., arXiv:2311.08967v3, Section 5.
//
// This package is deliberately separate from the legacy internal/ds package.
// The legacy package uses a simplified linear relation and is retained only
// for the recorded public-key-only forgery regression.
package dsref

import (
	"crypto/sha512"
	"math/big"
)

// PublicKey contains only values available to an HPPK-DS verifier.
//
// PPrime, QPrime, Mu, and Nu are indexed as [noise variable j][power i].
// S1ModP and S2ModP are s1 and s2 in Equation (29), not the hidden ring
// moduli S1 and S2.
type PublicKey struct {
	P          *big.Int
	R          *big.Int
	N          int
	Lambda     int
	M          int
	RingBits   int
	S1ModP     *big.Int
	S2ModP     *big.Int
	PPrime     [][]*big.Int
	QPrime     [][]*big.Int
	Mu         [][]*big.Int
	Nu         [][]*big.Int
}

// Signature is the HPPK-DS signature defined in Section 5.2: sig = {F, H}.
type Signature struct {
	F *big.Int
	H *big.Int
}

// HashToField maps a message digest into F_p. Callers that already have a
// protocol digest may pass those digest bytes directly as msg.
func HashToField(p *big.Int, msg []byte) *big.Int {
	sum := sha512.Sum512(msg)
	x := new(big.Int).SetBytes(sum[:])
	return x.Mod(x, p)
}

// Verify evaluates Equations (28) and (25) at x = Hash(M).
func Verify(pk *PublicKey, msg []byte, sig *Signature) bool {
	if !validPublicKey(pk) || !validSignature(sig, pk.RingBits) {
		return false
	}
	return VerifyAt(pk, HashToField(pk.P, msg), sig)
}

// VerifyAt is exposed for the paper's toy-example golden test, where x=9 is
// supplied directly. Production callers should use Verify.
func VerifyAt(pk *PublicKey, x *big.Int, sig *Signature) bool {
	if !validPublicKey(pk) || !validSignature(sig, pk.RingBits) || x == nil {
		return false
	}
	x = mod(x, pk.P)
	degree := pk.N + pk.Lambda

	// Equation (25) requires equality for every noise-variable polynomial.
	for j := 0; j < pk.M; j++ {
		uValue := big.NewInt(0)
		vValue := big.NewInt(0)
		xPower := big.NewInt(1)

		for i := 0; i <= degree; i++ {
			uij := embeddedCoefficient(sig.H, pk.PPrime[j][i], pk.S1ModP, pk.Mu[j][i], pk.R, pk.P)
			vij := embeddedCoefficient(sig.F, pk.QPrime[j][i], pk.S2ModP, pk.Nu[j][i], pk.R, pk.P)

			uValue.Add(uValue, new(big.Int).Mul(uij, xPower))
			uValue.Mod(uValue, pk.P)
			vValue.Add(vValue, new(big.Int).Mul(vij, xPower))
			vValue.Mod(vValue, pk.P)
			xPower.Mul(xPower, x)
			xPower.Mod(xPower, pk.P)
		}
		if uValue.Cmp(vValue) != 0 {
			return false
		}
	}
	return true
}

// embeddedCoefficient implements Equation (28):
// [a*b' - s*floor(a*mu/R)] mod p.
func embeddedCoefficient(a, scaled, s, mu, r, p *big.Int) *big.Int {
	q := new(big.Int).Mul(a, mu)
	q.Quo(q, r)
	value := new(big.Int).Mul(a, scaled)
	value.Sub(value, new(big.Int).Mul(s, q))
	return mod(value, p)
}

func validPublicKey(pk *PublicKey) bool {
	if pk == nil || pk.P == nil || pk.R == nil || pk.S1ModP == nil || pk.S2ModP == nil {
		return false
	}
	if pk.P.Sign() <= 0 || pk.R.Sign() <= 0 || pk.M < 2 || pk.N < 1 || pk.Lambda < 1 || pk.RingBits <= 0 {
		return false
	}
	if !pk.P.ProbablyPrime(32) {
		return false
	}
	degree := pk.N + pk.Lambda + 1
	return validMatrix(pk.PPrime, pk.M, degree) &&
		validMatrix(pk.QPrime, pk.M, degree) &&
		validMatrix(pk.Mu, pk.M, degree) &&
		validMatrix(pk.Nu, pk.M, degree)
}

func validMatrix(matrix [][]*big.Int, rows, columns int) bool {
	if len(matrix) != rows {
		return false
	}
	for _, row := range matrix {
		if len(row) != columns {
			return false
		}
		for _, value := range row {
			if value == nil || value.Sign() < 0 {
				return false
			}
		}
	}
	return true
}

func validSignature(sig *Signature, ringBits int) bool {
	if sig == nil || sig.F == nil || sig.H == nil || sig.F.Sign() < 0 || sig.H.Sign() < 0 {
		return false
	}
	// The hidden ring moduli remain private. The public ring-size bound rejects
	// non-canonical oversized encodings without disclosing S1 or S2.
	return sig.F.BitLen() <= ringBits && sig.H.BitLen() <= ringBits
}

func mod(value, p *big.Int) *big.Int {
	result := new(big.Int).Mod(value, p)
	if result.Sign() < 0 {
		result.Add(result, p)
	}
	return result
}
