// cmd/kem/keygen/main.go
package main

import (
	"encoding/json"
	"flag"
	"log"
	//"math/big"
	"os"
	"strings"

	"github.com/sergelen02/HPPK_2/internal/kem"
)

type paramFile struct {
	P        string `json:"p"`       // "0x..." 또는 10진 문자열
	PHex     string `json:"p_hex"`   // (옵션) 순수 16진
	N        int    `json:"n"`
	Lambda   int    `json:"lambda"`
	M        int    `json:"m"`
	L        uint   `json:"L"`
	K        uint   `json:"K"`
	NoiseMin int64  `json:"noise_min"`
	NoiseMax int64  `json:"noise_max"`
}

func main() {
	paramsPath := flag.String("params", "./configs/params/level1.json", "param json")
	outSk := flag.String("out", "sk_kem.json", "secret out")
	outPk := flag.String("pub", "pk_kem.json", "public out")
	flag.Parse()

	b, err := os.ReadFile(*paramsPath)
	if err != nil {
		log.Fatalf("read %s: %v", *paramsPath, err)
	}

	var cfg paramFile
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("unmarshal %s: %v", *paramsPath, err)
	}

	// p 문자열 추출 (p 우선, 없으면 p_hex)
	pStr := strings.TrimSpace(cfg.P)
	if pStr == "" && cfg.PHex != "" {
		pStr = cfg.PHex
	}
	if pStr == "" {
		log.Fatalf("params missing p/p_hex")
	}

	// kem.LoadParams는 base 0 파싱을 지원하도록 구현되었다고 가정
	pp := kem.LoadParams(pStr, cfg.N, cfg.Lambda, cfg.M, cfg.L, cfg.K, cfg.NoiseMin, cfg.NoiseMax)
	if pp == nil || pp.P == nil || pp.P.Sign() <= 0 {
		log.Fatalf("invalid modulus p (parsed from %q)", pStr)
	}

	sk, pk := kem.KeyGenKEM(pp)
	if sk == nil || pk == nil {
		log.Fatalf("KeyGenKEM failed (check L bound)")
	}

	mustWriteJSON(*outSk, sk)
	mustWriteJSON(*outPk, pk)
}

func mustWriteJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
}

