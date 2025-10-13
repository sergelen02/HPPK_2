// internal/kem/bench_test.go
package kem_test

import (
	"embed"
	"encoding/json"
	"os"
	//ath/filepath"
	"testing"

	"github.com/sergelen02/HPPK_2/internal/kem"
)

// 테스트용 파라미터를 바이너리에 포함
//go:embed testdata/level1.json
var testFS embed.FS

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

	// 1) 환경변수 우선
	if path := os.Getenv("BENCH_PARAMS"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			tb.Fatalf("read %s: %v", path, err)
		}
		var cfg kemParams
		if err := json.Unmarshal(b, &cfg); err != nil {
			tb.Fatalf("unmarshal %s: %v", path, err)
		}
		return kem.LoadParams(cfg.P, cfg.N, cfg.Lambda, cfg.M, cfg.L, cfg.K, cfg.NoiseMin, cfg.NoiseMax)
	}

	// 2) 내장 testdata 사용
	b, err := testFS.ReadFile("testdata/level1.json")
	if err != nil {
		tb.Fatalf("embed read testdata/level1.json: %v", err)
	}
	var cfg kemParams
	if err := json.Unmarshal(b, &cfg); err != nil {
		tb.Fatalf("unmarshal embedded params: %v", err)
	}
	return kem.LoadParams(cfg.P, cfg.N, cfg.Lambda, cfg.M, cfg.L, cfg.K, cfg.NoiseMin, cfg.NoiseMax)
}

var (
	onceKEMKeys syncOnce
	skKEM       *kem.KEMSecret
	pkKEM       *kem.KEMPublic
	ppGlobal    *kem.Params
)

func initKEMKeys(tb testing.TB) bool {
	tb.Helper()
	pp := loadKEMParams(tb)
	if pp == nil || pp.P == nil || pp.P.Sign() <= 0 {
		tb.Log("invalid params; skipping KEM init")
		return false
	}
	sk, pk := kem.KeyGenKEM(pp)
	if sk == nil || pk == nil {
		tb.Log("KeyGenKEM failed (L bound?); skipping")
		return false
	}
	ppGlobal, skKEM, pkKEM = pp, sk, pk
	return true
}

func BenchmarkKEM_KeyGen(b *testing.B) {
	pp := loadKEMParams(b)
	if pp == nil || pp.P == nil || pp.P.Sign() <= 0 {
		b.Skip("no params")
	}
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
	if pkKEM == nil || ppGlobal == nil {
		b.Skip("keys not initialized")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = kem.Encaps(pkKEM, nil, ppGlobal.NoiseMin, ppGlobal.NoiseMax)
	}
}

func BenchmarkKEM_Decaps(b *testing.B) {
	onceKEMKeys.Do(func() { initKEMKeys(b) })
	if skKEM == nil || pkKEM == nil || ppGlobal == nil {
		b.Skip("keys not initialized")
	}
	// 캡슐문 준비
	ct, _ := kem.Encaps(pkKEM, nil, ppGlobal.NoiseMin, ppGlobal.NoiseMax)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = kem.Decaps(skKEM, ct)
	}
}

// 재사용용 얕은 once
type syncOnce struct{ done uint32 }
func (o *syncOnce) Do(f func()) {
	if o.done == 0 {
		f()
		o.done = 1
	}
}
