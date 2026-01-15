package main

import (
	"math/big"
	"testing"

	"github.com/sergelen02/HPPK_2/internal/core"
	"github.com/sergelen02/HPPK_2/internal/ds"
)

func benchFixture(b *testing.B) (*ds.Secret, *ds.Public, []byte) {
	b.Helper()

	// ds는 Field가 필요함: core.NewField(p *big.Int)
	F := core.NewField(big.NewInt(65537))

	// L, K는 필요에 맞게 조정
	sk, pk := ds.KeyGenDS(F, 2, 1)

	msg := []byte("hello world")
	return sk, pk, msg
}

func Benchmark_SignWithPK(b *testing.B) {
	sk, pk, msg := benchFixture(b)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = ds.SignWithPK(sk, pk, msg)
	}
}

func Benchmark_Verify(b *testing.B) {
	sk, pk, msg := benchFixture(b)

	sig, err := ds.SignWithPK(sk, pk, msg)
	if err != nil {
		b.Fatalf("SignWithPK error: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = ds.Verify(pk, msg, sig)
	}
}
