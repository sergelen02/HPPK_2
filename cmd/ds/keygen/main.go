// cmd/ds/keygen/main.go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/sergelen02/HPPK_2/internal/core"
	"github.com/sergelen02/HPPK_2/internal/ds"
)

type paramFile struct {
	P    string `json:"p"`
	PHex string `json:"p_hex"`
	L    uint   `json:"L"`
	K    uint   `json:"K"`
}

func main() {
	paramsPath := flag.String("params", "./configs/params/level1.json", "param json path")
	outSk := flag.String("out", "sk.json", "secret key output")
	outPk := flag.String("pub", "pk.json", "public key output")
	printMode := flag.String("print", "", `print to stdout: "json" or "kv" (optional)`)
	flag.Parse()

	// load params
	b, err := os.ReadFile(*paramsPath)
	if err != nil { log.Fatalf("read %s: %v", *paramsPath, err) }
	var cfg paramFile
	if err := json.Unmarshal(b, &cfg); err != nil { log.Fatalf("unmarshal %s: %v", *paramsPath, err) }

	// parse p
	var P big.Int
	switch {
	case cfg.P != "":
		if _, ok := P.SetString(cfg.P, 0); !ok { log.Fatalf("invalid p: %q", cfg.P) }
	case cfg.PHex != "":
		if _, ok := P.SetString(cfg.PHex, 16); !ok { log.Fatalf("invalid p_hex: %q", cfg.PHex) }
	default:
		log.Fatalf("params missing p/p_hex")
	}
	if cfg.L < 2 { log.Fatalf("params: L must be >= 2 (got %d)", cfg.L) }

	F := core.NewField(&P)
	sk, pk := ds.KeyGenDS(F, cfg.L, cfg.K)

	// 1) 파일 저장 (기존 행동 유지)
	writeJSON(*outSk, sk)
	writeJSON(*outPk, pk)

	// 2) 추가로 콘솔 출력(옵션)
	switch *printMode {
	case "json":
		type out struct {
			Secret any `json:"sk"`
			Public any `json:"pk"`
		}
		o := out{Secret: sk, Public: pk}
		pretty, _ := json.MarshalIndent(o, "", "  ")
		fmt.Println(string(pretty))
	case "kv":
		// 사람이 보기 쉬운 decimal+hex 출력
		fmt.Println("== Public (kv) ==")
		fmt.Printf("p   = %s (0x%s)\n", pk.P.String(), pk.P.Text(16))
		fmt.Printf("p0  = %s (0x%s)\n", pk.Pprime0.String(), pk.Pprime0.Text(16))
		fmt.Printf("p1  = %s (0x%s)\n", pk.Pprime1.String(), pk.Pprime1.Text(16))
		fmt.Printf("q0  = %s (0x%s)\n", pk.Qprime0.String(), pk.Qprime0.Text(16))
		fmt.Printf("q1  = %s (0x%s)\n", pk.Qprime1.String(), pk.Qprime1.Text(16))
		fmt.Printf("mu0 = %s\n", pk.Mu0.String())
		fmt.Printf("mu1 = %s\n", pk.Mu1.String())
		fmt.Printf("nu0 = %s\n", pk.Nu0.String())
		fmt.Printf("nu1 = %s\n", pk.Nu1.String())
		fmt.Printf("s1 = %s (0x%s)\n", pk.S1.String(), pk.S1.Text(16))
		fmt.Printf("s2 = %s (0x%s)\n", pk.S2.String(), pk.S2.Text(16))
		fmt.Printf("K   = %d\n", pk.K)
		fmt.Println("== Secret present: yes (not displayed)")
	default:
		// no stdout printing
	}
}

func writeJSON(path string, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil { log.Fatalf("marshal %s: %v", path, err) }
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
}
