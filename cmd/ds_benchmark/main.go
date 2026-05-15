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

	core "github.com/sergelen02/HPPK_2/internal/core"
	ds "github.com/sergelen02/HPPK_2/internal/ds"
)

type DSConfig struct {
	L uint
	K uint
	P string
}

type BenchRow struct {
	Scheme         string
	Operation      string
	Iteration      int
	InputType      string
	InputSizeBytes int
	TimeNS         int64
}

func loadConfig(path string) DSConfig {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var cfg DSConfig
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

	w.Write([]string{"scheme", "operation", "iteration", "input_type", "input_size_bytes", "time_ns"})
	for _, r := range rows {
		w.Write([]string{
			r.Scheme,
			r.Operation,
			strconv.Itoa(r.Iteration),
			r.InputType,
			strconv.Itoa(r.InputSizeBytes),
			strconv.FormatInt(r.TimeNS, 10),
		})
	}
}

func main() {
	paramPath := flag.String("param", "configs/params/ds/p1.json", "path to DS parameter json")
	flag.Parse()

	cfg := loadConfig(*paramPath)
	tag := paramTag(*paramPath)

	p, ok := new(big.Int).SetString(cfg.P, 10)
	if !ok {
		panic("invalid field prime P")
	}
	F := core.NewField(p)

	msg := []byte("benchmark-message-0001")

	var rows []BenchRow

	var sampleSK *ds.Secret
	var samplePK *ds.Public
	for i := 1; i <= 100; i++ {
		start := time.Now()
		sk, pk := ds.KeyGenDS(F, cfg.L, cfg.K)
		elapsed := time.Since(start).Nanoseconds()

		if i == 1 {
			sampleSK = sk
			samplePK = pk
		}

		rows = append(rows, BenchRow{
			Scheme:         "HPPK-DS",
			Operation:      "KeyGen",
			Iteration:      i,
			InputType:      "params",
			InputSizeBytes: 0,
			TimeNS:         elapsed,
		})
	}

	if sampleSK == nil || samplePK == nil {
		panic("sample DS keypair not generated")
	}

	var sampleSig *ds.Signature
	for i := 1; i <= 1000; i++ {
		start := time.Now()
		sig, err := ds.SignWithPK(sampleSK, samplePK, msg)
		if err != nil {
			panic(err)
		}
		elapsed := time.Since(start).Nanoseconds()

		if i == 1 {
			sampleSig = sig
		}

		rows = append(rows, BenchRow{
			Scheme:         "HPPK-DS",
			Operation:      "Sign",
			Iteration:      i,
			InputType:      "message",
			InputSizeBytes: len(msg),
			TimeNS:         elapsed,
		})
	}

	if sampleSig == nil {
		panic("sample signature not generated")
	}

	for i := 1; i <= 1000; i++ {
		start := time.Now()
		ok := ds.Verify(samplePK, msg, sampleSig)
		elapsed := time.Since(start).Nanoseconds()

		if !ok {
			panic("verify failed for valid signature")
		}

		rows = append(rows, BenchRow{
			Scheme:         "HPPK-DS",
			Operation:      "Verify",
			Iteration:      i,
			InputType:      "message",
			InputSizeBytes: len(msg),
			TimeNS:         elapsed,
		})
	}

	out := fmt.Sprintf("/home/sergelen.8711/exp-hppk/results/offchain/ds/hppk_ds_%s_benchmark.csv", tag)
	writeCSV(out, rows)

	fmt.Println("DS benchmark completed.")
	fmt.Println("Output:", out)
}
