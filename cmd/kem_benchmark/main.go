package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	kem "github.com/sergelen02/HPPK_2/internal/kem"
)

type KEMConfig struct {
	P        string
	N        int
	Lambda   int
	M        int
	L        uint
	K        uint
	NoiseMin int64
	NoiseMax int64
}

type BenchRow struct {
	Scheme         string
	Operation      string
	Iteration      int
	InputType      string
	InputSizeBytes int
	TimeNS         int64
}

func loadConfig(path string) KEMConfig {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var cfg KEMConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		panic(err)
	}
	return cfg
}

func paramTag(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	return strings.ToLower(strings.TrimSuffix(base, ext))
}

func writeCSV(path string, rows []BenchRow) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{
		"scheme", "operation", "iteration", "input_type", "input_size_bytes", "time_ns",
	}); err != nil {
		panic(err)
	}

	for _, r := range rows {
		if err := w.Write([]string{
			r.Scheme,
			r.Operation,
			strconv.Itoa(r.Iteration),
			r.InputType,
			strconv.Itoa(r.InputSizeBytes),
			strconv.FormatInt(r.TimeNS, 10),
		}); err != nil {
			panic(err)
		}
	}
}

func main() {
	paramPath := flag.String("param", "configs/params/kem/p1.json", "path to KEM parameter json")
	flag.Parse()

	cfg := loadConfig(*paramPath)
	tag := paramTag(*paramPath)

	pp := kem.LoadParams(cfg.P, cfg.N, cfg.Lambda, cfg.M, cfg.L, cfg.K, cfg.NoiseMin, cfg.NoiseMax)
	x := big.NewInt(123456789)

	var rows []BenchRow

	// KeyGen: 100회
	var sampleSK *kem.KEMSecret
	var samplePK *kem.KEMPublic
	for i := 1; i <= 100; i++ {
		start := time.Now()
		sk, pk := kem.KeyGenKEM(pp)
		elapsed := time.Since(start).Nanoseconds()

		if i == 1 {
			sampleSK = sk
			samplePK = pk
		}

		rows = append(rows, BenchRow{
			Scheme:         "HPPK-KEM",
			Operation:      "KeyGen",
			Iteration:      i,
			InputType:      "params",
			InputSizeBytes: 0,
			TimeNS:         elapsed,
		})
	}

	if sampleSK == nil || samplePK == nil {
		panic("sample KEM keypair not generated")
	}

	// Encaps: 1000회
	var sampleCT *kem.Ciphertext
	for i := 1; i <= 1000; i++ {
		start := time.Now()
		ct, _ := kem.Encaps(samplePK, x, cfg.NoiseMin, cfg.NoiseMax)
		elapsed := time.Since(start).Nanoseconds()

		if i == 1 {
			sampleCT = ct
		}

		rows = append(rows, BenchRow{
			Scheme:         "HPPK-KEM",
			Operation:      "Encaps",
			Iteration:      i,
			InputType:      "fixed_x",
			InputSizeBytes: len(x.Bytes()),
			TimeNS:         elapsed,
		})
	}

	if sampleCT == nil {
		panic("sample ciphertext not generated")
	}

	// Decaps: 1000회
	for i := 1; i <= 1000; i++ {
		start := time.Now()
		_ = kem.Decaps(sampleSK, sampleCT)
		elapsed := time.Since(start).Nanoseconds()

		rows = append(rows, BenchRow{
			Scheme:         "HPPK-KEM",
			Operation:      "Decaps",
			Iteration:      i,
			InputType:      "ciphertext",
			InputSizeBytes: 0,
			TimeNS:         elapsed,
		})
	}

	out := fmt.Sprintf("/home/sergelen.8711/exp-hppk/results/offchain/kem/hppk_kem_%s_benchmark.csv", tag)
	writeCSV(out, rows)

	fmt.Println("KEM benchmark completed.")
	fmt.Println("Output:", out)
}
