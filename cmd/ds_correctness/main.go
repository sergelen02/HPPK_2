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

type Result struct {
	Scheme   string
	TestCase string
	Result   string
	Detail   string
}

func passFail(ok bool) string {
	if ok {
		return "pass"
	}
	return "fail"
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

func writeCSV(path string, rows []Result) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{"scheme", "test_case", "result", "detail"}); err != nil {
		panic(err)
	}
	for _, r := range rows {
		if err := w.Write([]string{r.Scheme, r.TestCase, r.Result, r.Detail}); err != nil {
			panic(err)
		}
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

	sk, pk := ds.KeyGenDS(F, cfg.L, cfg.K)
	sig, err := ds.SignWithPK(sk, pk, msg)
	if err != nil {
		panic(err)
	}

	var rows []Result

	okValid := ds.Verify(pk, msg, sig)
	rows = append(rows, Result{
		Scheme:   "HPPK-DS",
		TestCase: "sign_verify_valid",
		Result:   passFail(okValid),
		Detail:   "valid message + valid signature",
	})

	tamperedMsg := make([]byte, len(msg))
	copy(tamperedMsg, msg)
	tamperedMsg[0] ^= 0x01

	okTamperedMsg := ds.Verify(pk, tamperedMsg, sig)
	rows = append(rows, Result{
		Scheme:   "HPPK-DS",
		TestCase: "verify_tampered_message",
		Result:   passFail(!okTamperedMsg),
		Detail:   "tampered message must fail verification",
	})

	// signature 변조: JSON round-trip 없이 구조 복제 어려우면,
	// 새 서명을 만들고 메시지와 mismatch 테스트로 대체
	otherMsg := []byte("different-message")
	sig2, err := ds.SignWithPK(sk, pk, otherMsg)
	if err != nil {
		panic(err)
	}
	okTamperedSig := ds.Verify(pk, msg, sig2)
	rows = append(rows, Result{
		Scheme:   "HPPK-DS",
		TestCase: "verify_mismatched_signature",
		Result:   passFail(!okTamperedSig),
		Detail:   "signature for another message must fail verification",
	})

	out := fmt.Sprintf("/home/sergelen.8711/exp-hppk/results/offchain/ds/hppk_ds_%s_correctness.csv", tag)
	writeCSV(out, rows)

	fmt.Println("DS correctness completed.")
	fmt.Println("Output:", out)
}
