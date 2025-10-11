// cmd/kem/encaps/main.go
package main

import (
	"encoding/json"
	"flag"
	"log"
	"math/big"
	"os"

	"github.com/sergelen02/HPPK_2/internal/kem"
)

// 외부 params 파일(노이즈 범위용)
type Params struct {
	NoiseMin int64 `json:"noise_min"`
	NoiseMax int64 `json:"noise_max"`
}

func main() {
	// ---- flags ----
	pkPath := flag.String("pk", "pk_kem.json", "public key JSON path")
	outCT := flag.String("out", "ct.json", "ciphertext JSON output path")
	xStr := flag.String("x", "", "optional u ∈ Z_p (0x.. hex or decimal)")
	noiseMin := flag.Int64("noise-min", 0, "noise min (overrides params if set)")
	noiseMax := flag.Int64("noise-max", 0, "noise max (overrides params if set)")
	paramsPath := flag.String("params", "", "optional params JSON (for noise_min/max if pk lacks)")
	flag.Parse()

	// ---- load pk ----
	var pk kem.KEMPublic
	mustReadJSON(*pkPath, &pk)

	// ---- optional x (u) parsing ----
	var x *big.Int
	if *xStr != "" {
		x = new(big.Int)
		if _, ok := x.SetString(*xStr, 0); !ok {
			log.Fatalf("invalid -x: %q (use 0x.. or decimal)", *xStr)
		}
	} else {
		x = nil // Encaps 내부에서 난수 선택한다고 가정
	}

	// ---- noise range decide (flags > params) ----
	var nmin, nmax int64
	if *noiseMin != 0 || *noiseMax != 0 {
		nmin, nmax = *noiseMin, *noiseMax
	} else if *paramsPath != "" {
		var par Params
		mustReadJSON(*paramsPath, &par)
		nmin, nmax = par.NoiseMin, par.NoiseMax
	} else {
		log.Fatal("noise range not provided: set -noise-min/-noise-max or provide -params with noise_min/noise_max")
	}

	// ---- encapsulate ----
	// Encaps는 (ct) 1개만 반환
	ct := kem.Encaps(&pk, x, nmin, nmax)

	// ---- write outputs ----
	mustWriteJSON(*outCT, ct)
}

// ---------- helpers ----------
func mustReadJSON(path string, v any) {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		log.Fatalf("unmarshal %s: %v", path, err)
	}
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
