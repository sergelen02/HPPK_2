package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/sergelen02/HPPK_2/internal/core"
	ds "github.com/sergelen02/HPPK_2/internal/ds"
)

type BenchRow struct {
	Scheme         string
	Operation      string
	Iteration      int
	InputType      string
	InputSizeBytes int
	TimeNS         int64
}

type SizeRow struct {
	Scheme         string
	PublicKeyBytes int
	SecretKeyBytes int
	SignatureBytes int
}

func mustRead(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return b
}

func mustMkdirParent(path string) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}
}

func writeBenchCSV(path string, rows []BenchRow) {
	mustMkdirParent(path)

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

	if err := w.Error(); err != nil {
		panic(err)
	}
}

func writeSizeCSV(path string, row SizeRow) {
	mustMkdirParent(path)

	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{
		"scheme", "public_key_bytes", "secret_key_bytes", "signature_bytes",
	}); err != nil {
		panic(err)
	}

	if err := w.Write([]string{
		row.Scheme,
		strconv.Itoa(row.PublicKeyBytes),
		strconv.Itoa(row.SecretKeyBytes),
		strconv.Itoa(row.SignatureBytes),
	}); err != nil {
		panic(err)
	}

	if err := w.Error(); err != nil {
		panic(err)
	}
}

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func main() {
	msg := mustRead("/home/sergelen.8711/exp-hppk/dataset/msg_32.txt")
	if len(msg) != 32 {
		panic("msg_32.txt must be 32 bytes")
	}

	var P big.Int
	if _, ok := P.SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61", 0); !ok {
		panic("invalid modulus p")
	}
	F := core.NewField(&P)

	const L uint = 272
	const K uint = 256

	var rows []BenchRow

	var samplePK *ds.Public
	var sampleSK *ds.Secret

	for i := 1; i <= 100; i++ {
		start := time.Now()

		sk, pk := ds.KeyGenDS(F, L, K)

		elapsed := time.Since(start).Nanoseconds()

		if i == 1 {
			samplePK = pk
			sampleSK = sk
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

	if samplePK == nil || sampleSK == nil {
		panic("samplePK/sampleSK is nil: KeyGenDS failed")
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
		panic("sampleSig is nil")
	}

	for i := 1; i <= 1000; i++ {
		start := time.Now()

		ok := ds.Verify(samplePK, msg, sampleSig)

		elapsed := time.Since(start).Nanoseconds()

		if !ok {
			panic("HPPK-DS verify failed for valid signature")
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

	pkBytes := mustMarshal(samplePK)
	skBytes := mustMarshal(sampleSK)
	sigBytes := mustMarshal(sampleSig)

	benchPath := "/home/sergelen.8711/exp-hppk/results/offchain/hppk_benchmark.csv"
	sizePath := "/home/sergelen.8711/exp-hppk/results/offchain/hppk_sizes.csv"

	writeBenchCSV(benchPath, rows)
	writeSizeCSV(sizePath, SizeRow{
		Scheme:         "HPPK-DS",
		PublicKeyBytes: len(pkBytes),
		SecretKeyBytes: len(skBytes),
		SignatureBytes: len(sigBytes),
	})

	fmt.Println("HPPK-DS benchmark completed.")
	fmt.Println("Output files:")
	fmt.Println("-", benchPath)
	fmt.Println("-", sizePath)
}
