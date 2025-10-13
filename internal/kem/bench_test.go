// internal/kem/bench_test.go
package kem_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/sergelen02/HPPK_2/internal/kem"
)

type kemParams struct {
	P        string `json:"p"`
	N        int    `json:"n"`
	Lambda   int    `json:"lambda"`
	M        int    `json:"m"`
	L        uint   `json:"L"`
	K        uint   `json:"K"`
	NoiseMin int64  `json:"noise_min"`
	NoiseMax int64  `json:"noise_max"`
}

func loadKEMParams(tb testing.TB) *kem.Params {
	tb.Helper()
	path := os.Getenv("BENCH_PARAMS")
	if path == "" {
		path = filepath.Join("configs", "params", "level1.json")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("read %s: %v", path, err)
	}
	var cfg kemParams
	if err := json.Unmarshal(b, &cfg); err != nil {
		tb.Fatalf("unmarshal %s: %v", path, err)
	}
	pp := kem.LoadParams(cfg.P, cfg.N, cfg.Lambda, cfg.M, cfg.L, cfg.K, cfg.NoiseMin, cfg.NoiseMax)
	if pp == nil || pp.P == nil || pp.P.Sign() <= 0 {
		tb.Fatalf("invalid p in params: %q", cfg.P)
	}
	return pp
}

var (
	onceKEMKeys sync.Once
	skKEM       *kem.KEMSecret
	pkKEM       *kem.KEMPublic
	ppGlobal    *kem.Params
)

func initKEMKeys(tb testing.TB) {
	pp := loadKEMParams(tb)
	sk, pk := kem.KeyGenKEM(pp)
	if sk == nil || pk == nil {
		tb.Fatalf("KeyGenKEM failed (check L bound in params)")
	}
	ppGlobal, skKEM, pkKEM = pp, sk, pk
}

func BenchmarkKEM_KeyGen(b *testing.B) {
	pp := loadKEMParams(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if sk, pk := kem.KeyGenKEM(pp); sk == nil || pk == nil {
			b.Fatal("KeyGenKEM failed")
		}
	}
}

func BenchmarkKEM_Encaps(b *testing.B) {
	onceKEMKeys.Do(func() { initKEMKeys(b) })
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Encaps가 (ct, shared) 반환하도록 구현되어 있어야 합니다.
		_, _ = kem.Encaps(pkKEM, nil, ppGlobal.NoiseMin, ppGlobal.NoiseMax)
	}
}

func BenchmarkKEM_Decaps(b *testing.B) {
	onceKEMKeys.Do(func() { initKEMKeys(b) })
	// 미리 한 번 캡슐화해서 ct 준비
	ct, _ := kem.Encaps(pkKEM, nil, ppGlobal.NoiseMin, ppGlobal.NoiseMax)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = kem.Decaps(skKEM, ct)
	}
}

