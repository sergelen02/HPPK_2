package ds_test
// internal/ds/bench_test.go

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sergelen02/HPPK_2/internal/core"
	"github.com/sergelen02/HPPK_2/internal/ds"
)

type paramsFile struct {
	P string `json:"p"`       // "0x..." 또는 10진 문자열
	L uint   `json:"L"`
	K uint   `json:"K"`
}

func loadFieldAndDSParams(tb testing.TB) (*core.Field, uint, uint) {
	tb.Helper()

	// 환경변수로 경로 오버라이드 가능 (없으면 repo 루트 기준 기본값)
	path := os.Getenv("BENCH_PARAMS")
	if path == "" {
		// 워크스페이스 루트에서 실행하는 것을 권장합니다.
		path = filepath.Join("configs", "params", "level1.json")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("read %s: %v", path, err)
	}
	var cfg paramsFile
	if err := json.Unmarshal(b, &cfg); err != nil {
		tb.Fatalf("unmarshal %s: %v", path, err)
	}
	if cfg.P == "" {
		tb.Fatalf("params: missing p (hex or decimal as string)")
	}
	P := core.ParseBigIntAuto(cfg.P) // 0x/10진 자동 파싱(없으면 직접 구현: SetString(s,0))

	return core.NewField(P), cfg.L, cfg.K
}

var (
	onceDSKeys syncOnce // 경량 sync.Once 대체 (아래 구현)
	benchSK    *ds.Secret
	benchPK    *ds.Public
)

func initDSKeys(tb testing.TB) {
	F, L, K := loadFieldAndDSParams(tb)
	sk, pk := ds.KeyGenDS(F, L, K)
	if sk == nil || pk == nil {
		tb.Fatalf("KeyGenDS returned nil (check params L,K)")
	}
	benchSK, benchPK = sk, pk
}

// ---- Benchmarks ----

func BenchmarkDS_KeyGen(b *testing.B) {
	F, L, K := loadFieldAndDSParams(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if sk, pk := ds.KeyGenDS(F, L, K); sk == nil || pk == nil {
			b.Fatal("KeyGenDS failed")
		}
	}
}

func BenchmarkDS_Sign_Short(b *testing.B)   { benchmarkDSSign(b, 32) }
func BenchmarkDS_Sign_Medium(b *testing.B)  { benchmarkDSSign(b, 256) }
func BenchmarkDS_Sign_Large(b *testing.B)   { benchmarkDSSign(b, 4096) }

func benchmarkDSSign(b *testing.B, msgLen int) {
	onceDSKeys.Do(func() { initDSKeys(b) })
	msg := make([]byte, msgLen)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ds.Sign(benchSK, msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDS_Verify_Short(b *testing.B)  { benchmarkDSVerify(b, 32) }
func BenchmarkDS_Verify_Medium(b *testing.B) { benchmarkDSVerify(b, 256) }
func BenchmarkDS_Verify_Large(b *testing.B)  { benchmarkDSVerify(b, 4096) }

func benchmarkDSVerify(b *testing.B, msgLen int) {
	onceDSKeys.Do(func() { initDSKeys(b) })
	msg := make([]byte, msgLen)
	sig, err := ds.Sign(benchSK, msg)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !ds.Verify(benchPK, msg, sig) {
			b.Fatal("verify failed")
		}
	}
}

// ---- tiny sync.Once to avoid importing sync ----
type syncOnce struct{ done uint32 }
func (o *syncOnce) Do(f func()) {
	if o.done == 0 {
		f()
		o.done = 1
	}
}
