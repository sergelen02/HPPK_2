package dsref

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

const maxSigningAttempts = 64

// Params specifies the HPPK-DS parameters used by KeyGen.
//
// RingBits is the hidden-ring bit length L. BarrettBits is K and must leave
// at least a 32-bit margin over L, following the paper's Barrett discussion.
type Params struct {
	P           *big.Int
	N           int
	Lambda      int
	M           int
	RingBits    int
	BarrettBits int
}

// SecretKey contains the private polynomial coefficients and hidden-ring
// values. It must never be transmitted to a verifier.
type SecretKey struct {
	P  *big.Int
	R1 *big.Int
	S1 *big.Int
	R2 *big.Int
	S2 *big.Int
	F  []*big.Int
	H  []*big.Int
	B  [][]*big.Int
	Params Params
}

// KeyGen constructs the dual-hidden-ring HPPK-DS key pair described by
// Equations (21)-(24) and (29).
func KeyGen(params Params) (*SecretKey, *PublicKey, error) {
	if err := validateParams(params); err != nil {
		return nil, nil, err
	}

	s1, err := randomOdd(params.RingBits)
	if err != nil {
		return nil, nil, err
	}
	s2, err := randomOdd(params.RingBits)
	if err != nil {
		return nil, nil, err
	}
	r1, err := randomUnit(s1)
	if err != nil {
		return nil, nil, err
	}
	r2, err := randomUnit(s2)
	if err != nil {
		return nil, nil, err
	}
	beta, err := randomNonzero(params.P)
	if err != nil {
		return nil, nil, err
	}

	f, err := randomPolynomial(params.Lambda+1, params.P)
	if err != nil {
		return nil, nil, err
	}
	h, err := randomPolynomial(params.Lambda+1, params.P)
	if err != nil {
		return nil, nil, err
	}
	b, err := randomPolynomialMatrix(params.M, params.N+1, params.P)
	if err != nil {
		return nil, nil, err
	}

	r := new(big.Int).Lsh(big.NewInt(1), uint(params.BarrettBits))
	degree := params.N + params.Lambda + 1
	pPrime := makeMatrix(params.M, degree)
	qPrime := makeMatrix(params.M, degree)
	mu := makeMatrix(params.M, degree)
	nu := makeMatrix(params.M, degree)

	for j := 0; j < params.M; j++ {
		pCoefficients := multiplyPolynomials(f, b[j], params.P)
		qCoefficients := multiplyPolynomials(h, b[j], params.P)

		for i := 0; i < degree; i++ {
			pEncrypted := new(big.Int).Mul(r1, pCoefficients[i])
			pEncrypted.Mod(pEncrypted, s1)
			qEncrypted := new(big.Int).Mul(r2, qCoefficients[i])
			qEncrypted.Mod(qEncrypted, s2)

			pPrime[j][i] = mod(new(big.Int).Mul(beta, pEncrypted), params.P)
			qPrime[j][i] = mod(new(big.Int).Mul(beta, qEncrypted), params.P)
			mu[j][i] = new(big.Int).Quo(new(big.Int).Mul(r, pEncrypted), s1)
			nu[j][i] = new(big.Int).Quo(new(big.Int).Mul(r, qEncrypted), s2)
		}
	}

	sk := &SecretKey{
		P:  cloneInt(params.P),
		R1: r1,
		S1: s1,
		R2: r2,
		S2: s2,
		F:  f,
		H:  h,
		B:  b,
		Params: Params{
			P: cloneInt(params.P), N: params.N, Lambda: params.Lambda, M: params.M,
			RingBits: params.RingBits, BarrettBits: params.BarrettBits,
		},
	}
	pk := &PublicKey{
		P:        cloneInt(params.P),
		R:        r,
		N:        params.N,
		Lambda:   params.Lambda,
		M:        params.M,
		RingBits: params.RingBits,
		S1ModP:   mod(new(big.Int).Mul(beta, s1), params.P),
		S2ModP:   mod(new(big.Int).Mul(beta, s2), params.P),
		PPrime:   pPrime,
		QPrime:   qPrime,
		Mu:       mu,
		Nu:       nu,
	}
	return sk, pk, nil
}

// Sign implements Section 5.2. It samples a fresh alpha for every signature.
// The paper permits retrying with a new alpha if verification would fail due
// to Barrett approximation; this implementation retries at most 64 times.
func Sign(sk *SecretKey, pk *PublicKey, msg []byte) (*Signature, error) {
	if !validSecretKey(sk) || !validPublicKey(pk) || sk.P.Cmp(pk.P) != 0 {
		return nil, errors.New("invalid HPPK-DS key pair")
	}
	for attempt := 0; attempt < maxSigningAttempts; attempt++ {
		alpha, err := randomNonzero(sk.P)
		if err != nil {
			return nil, err
		}
		sig, err := signWithAlpha(sk, msg, alpha)
		if err != nil {
			return nil, err
		}
		if Verify(pk, msg, sig) {
			return sig, nil
		}
	}
	return nil, fmt.Errorf("HPPK-DS signing exhausted %d Barrett verification retries", maxSigningAttempts)
}

func signWithAlpha(sk *SecretKey, msg []byte, alpha *big.Int) (*Signature, error) {
	if !validSecretKey(sk) || alpha == nil || alpha.Sign() <= 0 || alpha.Cmp(sk.P) >= 0 {
		return nil, errors.New("invalid signing input")
	}
	x := HashToField(sk.P, msg)
	fx := evaluatePolynomial(sk.F, x, sk.P)
	hx := evaluatePolynomial(sk.H, x, sk.P)

	r2Inverse := new(big.Int).ModInverse(sk.R2, sk.S2)
	r1Inverse := new(big.Int).ModInverse(sk.R1, sk.S1)
	if r1Inverse == nil || r2Inverse == nil {
		return nil, errors.New("hidden-ring multiplier is not invertible")
	}
	f := new(big.Int).Mul(alpha, fx)
	f.Mod(f, sk.P)
	f.Mul(f, r2Inverse)
	f.Mod(f, sk.S2)
	h := new(big.Int).Mul(alpha, hx)
	h.Mod(h, sk.P)
	h.Mul(h, r1Inverse)
	h.Mod(h, sk.S1)
	return &Signature{F: f, H: h}, nil
}

func validateParams(params Params) error {
	if params.P == nil || !params.P.ProbablyPrime(32) {
		return errors.New("P must be a positive prime")
	}
	if params.N < 1 || params.Lambda < 1 || params.M < 2 {
		return errors.New("N and Lambda must be >= 1 and M must be >= 2")
	}
	if params.RingBits < 2*params.P.BitLen() {
		return errors.New("RingBits must be at least twice the field-prime bit length")
	}
	if params.BarrettBits < params.RingBits+32 {
		return errors.New("BarrettBits must be at least RingBits + 32")
	}
	return nil
}

func validSecretKey(sk *SecretKey) bool {
	if sk == nil || sk.P == nil || sk.R1 == nil || sk.S1 == nil || sk.R2 == nil || sk.S2 == nil {
		return false
	}
	if validateParams(sk.Params) != nil || sk.P.Cmp(sk.Params.P) != 0 {
		return false
	}
	if len(sk.F) != sk.Params.Lambda+1 || len(sk.H) != sk.Params.Lambda+1 ||
		!validMatrix(sk.B, sk.Params.M, sk.Params.N+1) {
		return false
	}
	return new(big.Int).GCD(nil, nil, sk.R1, sk.S1).Cmp(big.NewInt(1)) == 0 &&
		new(big.Int).GCD(nil, nil, sk.R2, sk.S2).Cmp(big.NewInt(1)) == 0
}

func randomPolynomial(length int, p *big.Int) ([]*big.Int, error) {
	out := make([]*big.Int, length)
	for i := range out {
		value, err := randomFieldElement(p)
		if err != nil {
			return nil, err
		}
		out[i] = value
	}
	return out, nil
}

func randomPolynomialMatrix(rows, columns int, p *big.Int) ([][]*big.Int, error) {
	out := make([][]*big.Int, rows)
	for i := range out {
		row, err := randomPolynomial(columns, p)
		if err != nil {
			return nil, err
		}
		out[i] = row
	}
	return out, nil
}

func multiplyPolynomials(a, b []*big.Int, p *big.Int) []*big.Int {
	out := make([]*big.Int, len(a)+len(b)-1)
	for i := range out {
		out[i] = big.NewInt(0)
	}
	for i, av := range a {
		for j, bv := range b {
			product := new(big.Int).Mul(av, bv)
			out[i+j].Add(out[i+j], product)
			out[i+j].Mod(out[i+j], p)
		}
	}
	return out
}

func evaluatePolynomial(coefficients []*big.Int, x, p *big.Int) *big.Int {
	value := big.NewInt(0)
	for i := len(coefficients) - 1; i >= 0; i-- {
		value.Mul(value, x)
		value.Add(value, coefficients[i])
		value.Mod(value, p)
	}
	return value
}

func makeMatrix(rows, columns int) [][]*big.Int {
	out := make([][]*big.Int, rows)
	for i := range out {
		out[i] = make([]*big.Int, columns)
	}
	return out
}

func randomFieldElement(p *big.Int) (*big.Int, error) {
	return rand.Int(rand.Reader, p)
}

func randomNonzero(p *big.Int) (*big.Int, error) {
	upper := new(big.Int).Sub(p, big.NewInt(1))
	value, err := rand.Int(rand.Reader, upper)
	if err != nil {
		return nil, err
	}
	return value.Add(value, big.NewInt(1)), nil
}

func randomOdd(bits int) (*big.Int, error) {
	if bits < 3 {
		return nil, errors.New("hidden ring requires at least three bits")
	}
	span := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	value, err := rand.Int(rand.Reader, span)
	if err != nil {
		return nil, err
	}
	value.Add(value, span)
	value.SetBit(value, 0, 1)
	return value, nil
}

func randomUnit(modulus *big.Int) (*big.Int, error) {
	upper := new(big.Int).Sub(modulus, big.NewInt(2))
	for {
		value, err := rand.Int(rand.Reader, upper)
		if err != nil {
			return nil, err
		}
		value.Add(value, big.NewInt(2))
		if new(big.Int).GCD(nil, nil, value, modulus).Cmp(big.NewInt(1)) == 0 {
			return value, nil
		}
	}
}

func cloneInt(value *big.Int) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set(value)
}
