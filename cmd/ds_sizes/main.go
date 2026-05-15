package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	core "github.com/sergelen02/HPPK_2/internal/core"
	ds "github.com/sergelen02/HPPK_2/internal/ds"
)

type DSConfig struct {
	L uint
	K uint
	P string
}

type SizeRow struct {
	Scheme         string
	PublicKeyBytes int
	SecretKeyBytes int
	SignatureBytes int
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

func mustSize(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return len(b)
}

func writeCSV(path string, row SizeRow) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	w.Write([]string{"scheme", "public_key_bytes", "secret_key_bytes", "signature_bytes"})
	w.Write([]string{
		row.Scheme,
		fmt.Sprintf("%d", row.PublicKeyBytes),
		fmt.Sprintf("%d", row.SecretKeyBytes),
		fmt.Sprintf("%d", row.SignatureBytes),
	})
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

	sk, pk := ds.KeyGenDS(F, cfg.L, cfg.K)
	sig, err := ds.SignWithPK(sk, pk, msg)
	if err != nil {
		panic(err)
	}

	row := SizeRow{
		Scheme:         "HPPK-DS",
		PublicKeyBytes: mustSize(pk),
		SecretKeyBytes: mustSize(sk),
		SignatureBytes: mustSize(sig),
	}

	out := fmt.Sprintf("/home/sergelen.8711/exp-hppk/results/offchain/ds/hppk_ds_%s_sizes.csv", tag)
	writeCSV(out, row)

	fmt.Println("DS size measurement completed.")
	fmt.Println("Output:", out)
}
