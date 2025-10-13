// cmd/kem/encaps/main.go
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
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
	keyOut := flag.String("key", "", "optional shared key output file (raw bytes)")
	xStr := flag.String("x", "", "optional u ∈ Z_p (0x.. hex or decimal)")
	noiseMin := flag.Int64("noise-min", 0, "noise min (overrides params if set)")
	noiseMax := flag.Int64("noise-max", 0, "noise max (overrides params if set)")
	paramsPath := flag.String("params", "", "optional params JSON (provides noise_min/max if flags unset)")
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
		x = nil // Encaps 내부에서 난수 선택
	}

	// ---- noise range (flags > params > fallback) ----
	var nmin, nmax int64
	switch {
	case *noiseMin != 0 || *noiseMax != 0:
		nmin, nmax = *noiseMin, *noiseMax
	case *paramsPath != "":
		var par Params
		mustReadJSON(*paramsPath, &par)
		nmin, nmax = par.NoiseMin, par.NoiseMax
	default:
		// 필요시 기본값(데모)
		nmin, nmax = 1, 5
	}

	// ---- encapsulate ----
	ct, shared := kem.Encaps(&pk, x, nmin, nmax)

	// ---- write outputs ----
	mustWriteJSON(*outCT, ct)
	if *keyOut != "" {
		if err := os.WriteFile(*keyOut, shared, 0o600); err != nil {
			log.Fatalf("write %s: %v", *keyOut, err)
		}
		fmt.Printf("shared key written to %s (%d bytes)\n", *keyOut, len(shared))
	} else {
		fmt.Printf("shared key (%d bytes): %s\n", len(shared), hex.EncodeToString(shared))
	}
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
