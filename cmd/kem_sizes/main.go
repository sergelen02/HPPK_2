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

	kem "github.com/sergelen02/HPPK_2/internal/kem"
)

type SizeRow struct {
	Scheme            string
	PublicKeyBytes    int
	SecretKeyBytes    int
	CiphertextBytes   int
	SharedSecretBytes int
}

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

func writeCSV(path string, row SizeRow) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{
		"scheme",
		"public_key_bytes",
		"secret_key_bytes",
		"ciphertext_bytes",
		"shared_secret_bytes",
	}); err != nil {
		panic(err)
	}

	if err := w.Write([]string{
		row.Scheme,
		fmt.Sprintf("%d", row.PublicKeyBytes),
		fmt.Sprintf("%d", row.SecretKeyBytes),
		fmt.Sprintf("%d", row.CiphertextBytes),
		fmt.Sprintf("%d", row.SharedSecretBytes),
	}); err != nil {
		panic(err)
	}
}

func mustSize(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return len(b)
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

func main() {
	paramPath := flag.String("param", "configs/params/kem/p1.json", "path to KEM parameter json")
	flag.Parse()

	cfg := loadConfig(*paramPath)
	tag := paramTag(*paramPath)

	pp := kem.LoadParams(cfg.P, cfg.N, cfg.Lambda, cfg.M, cfg.L, cfg.K, cfg.NoiseMin, cfg.NoiseMax)
	x := big.NewInt(123456789)

	sk, pk := kem.KeyGenKEM(pp)
	ct, ss := kem.Encaps(pk, x, cfg.NoiseMin, cfg.NoiseMax)

	row := SizeRow{
		Scheme:            "HPPK-KEM",
		PublicKeyBytes:    mustSize(pk),
		SecretKeyBytes:    mustSize(sk),
		CiphertextBytes:   mustSize(ct),
		SharedSecretBytes: len(ss),
	}

	out := fmt.Sprintf("/home/sergelen.8711/exp-hppk/results/offchain/kem/hppk_kem_%s_sizes.csv", tag)
	writeCSV(out, row)

	fmt.Println("KEM size measurement completed.")
	fmt.Println("Output:", out)
	fmt.Printf("PK=%d bytes | SK=%d bytes | CT=%d bytes | SS=%d bytes\n",
		row.PublicKeyBytes, row.SecretKeyBytes, row.CiphertextBytes, row.SharedSecretBytes)
}
