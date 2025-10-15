package core
// core/barrett_test.go

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func randBig(bits int) *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
	// 랜덤하게 부호도 바꿔보기
	if b, _ := rand.Int(rand.Reader, big.NewInt(2)); b.Bit(0) == 1 {
		n.Neg(n)
	}
	return n
}

func TestBarrettReduce_EqualsMod(t *testing.T) {
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61", 16)
	K := uint(256)
	mu := BarrettMu(p, K)

	for i := 0; i < 200; i++ {
		x := randBig(2048)
		got := BarrettReduce(x, p, mu, K)
		want := new(big.Int).Mod(x, p)
		if want.Sign() < 0 { want.Add(want, p) }
		if got.Cmp(want) != 0 {
			t.Fatalf("mismatch on iter %d\n got=%x\nwant=%x", i, got, want)
		}
	}
}
