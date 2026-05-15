package ds

import (
	"crypto/sha256"
	"testing"
)

func genFixture(t *testing.T) (*Params, *DSSecretKey, *DSPublicKey, []byte) {
	pp := DefaultParams()
	// 데모용 P,Q 계수 (실제는 KeyGen 파이프라인에서 생성)
	P := []*big.Int{big.NewInt(123), big.NewInt(456)}
	Q := []*big.Int{big.NewInt(789), big.NewInt(987)}
	sk, pk := KeyGenDS(pp, P, Q)
	msg := []byte("hello world")
	return pp, sk, pk, msg
}

func Benchmark_Sign(b *testing.B) {
	pp, sk, _, msg := genFixture(nil)
	domain := []byte("HPPK-DS|bench")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Sign(pp, sk, domain, msg)
	}
}

func Benchmark_Verify(b *testing.B) {
	pp, sk, pk, msg := genFixture(nil)
	domain := []byte("HPPK-DS|bench")
	sig, _ := Sign(pp, sk, domain, msg)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Verify(pp, pk, domain, msg, sig)
	}
}
