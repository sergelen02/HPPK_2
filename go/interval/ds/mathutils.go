package ds

import (
	"crypto/sha256"
	"math/big"
)

// ---- modular helpers ----

func mod(a, m *big.Int) *big.Int {
	x := new(big.Int).Mod(a, m)
	if x.Sign() < 0 {
		x.Add(x, m)
	}
	return x
}
func addMod(a, b, m *big.Int) *big.Int { return mod(new(big.Int).Add(a, b), m) }
func subMod(a, b, m *big.Int) *big.Int { return mod(new(big.Int).Sub(a, b), m) }
func mulMod(a, b, m *big.Int) *big.Int { return mod(new(big.Int).Mul(a, b), m) }

func expMod(x *big.Int, e int, m *big.Int) *big.Int {
	res := big.NewInt(1)
	base := new(big.Int).Set(x)
	for i := 0; i < e; i++ {
		res = mulMod(res, base, m)
	}
	return res
}

// Barrett floor: floor(z * c / 2^K) where R=2^K
func barrettFloor(z, c, R *big.Int, K int) *big.Int {
	t := new(big.Int).Mul(z, c)
	t.Rsh(t, uint(K)) // divide by 2^K
	return t
}

// x = H(msg) mod p  (도메인 분리는 필요 시 추가)
func hashToX(p *big.Int, msg []byte) *big.Int {
	h := sha256.Sum256(msg)
	x := new(big.Int).SetBytes(h[:])
	return mod(x, p)
}

// linear polynomial eval: a0 + a1*x  (mod p)
func evalLin(a0, a1, x, p *big.Int) *big.Int {
	t := new(big.Int).Mul(a1, x)
	t.Add(t, a0)
	return mod(t, p)
}
