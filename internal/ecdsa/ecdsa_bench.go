// /workspaces/hppk-ds/internal/ecdsa_bench/ecdsa_bench_test.go
package ecdsa_bench

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

var sinkSigR, sinkSigS, sinkOK bool

func Benchmark_ECDSA_Sign(b *testing.B) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	msg := []byte("The quick brown fox jumps over the lazy dog")
	d := sha256.Sum256(msg)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r, s, _ := ecdsa.Sign(rand.Reader, priv, d[:])
		_ = r
		_ = s
	}
}

func Benchmark_ECDSA_Verify(b *testing.B) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := &priv.PublicKey
	msg := []byte("The quick brown fox jumps over the lazy dog")
	d := sha256.Sum256(msg)
	r, s, _ := ecdsa.Sign(rand.Reader, priv, d[:])
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ok := ecdsa.Verify(pub, d[:], r, s)
		if !ok {
			b.Fatal("verify failed")
		}
	}
}
