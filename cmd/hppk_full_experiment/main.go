package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/sergelen02/HPPK_2/internal/core"
	"github.com/sergelen02/HPPK_2/internal/ds"
	"github.com/sergelen02/HPPK_2/internal/kem"
)

// ---------- util ----------
func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func writeCSV(path string, header []string, rows [][]string) {
	os.MkdirAll("/home/sergelen.8711/exp-hppk/results/offchain", 0755)

	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	w.Write(header)
	for _, r := range rows {
		w.Write(r)
	}
}

func size(v any) int {
	b, _ := json.Marshal(v)
	return len(b)
}

// ---------- main ----------
func main() {

	out := "/home/sergelen.8711/exp-hppk/results/offchain"

	// ======================================================
	// 0. PARAM LOAD (Level I 기준)
	// ======================================================

	// DS Field
	P := big.NewInt(65537)
	F := core.NewField(P)

	dsL := uint(2)
	dsK := uint(1)

	// KEM은 checkL 조건 때문에 L이 충분히 커야 함.
	// p=65537, n=64, lambda=128, m=1이면 필요 L은 약 42 이상.
	kemL := uint(42)
	kemK := uint(1)

	// KEM Params
	pp := kem.LoadParams(
		"65537",
		64,
		128,
		1,
		kemL,
		kemK,
		-5,
		5,
	)

	msg := []byte("Hello HPPK")

	// ======================================================
	// 1. KEM
	// ======================================================

	start := time.Now()
	kemSK, kemPK := kem.KeyGenKEM(pp)
	tKEMKeyGen := time.Since(start).Nanoseconds()

	if kemSK == nil || kemPK == nil {
		panic(fmt.Sprintf("KeyGenKEM failed: check params, especially L. current L=%d", pp.L))
	}

	start = time.Now()
	ct, ss1 := kem.Encaps(kemPK, nil, pp.NoiseMin, pp.NoiseMax)
	tEncaps := time.Since(start).Nanoseconds()

	start = time.Now()
	ss2 := kem.Decaps(kemSK, ct)
	tDecaps := time.Since(start).Nanoseconds()

	if !bytes.Equal(ss1, ss2) {
		panic("KEM failed: shared key mismatch")
	}

	// ======================================================
	// 2. DS
	// ======================================================

	start = time.Now()
	dsSK, dsPK := ds.KeyGenDS(F, dsL, dsK)
	tDSKeyGen := time.Since(start).Nanoseconds()

	start = time.Now()
	sig, err := ds.SignWithPK(dsSK, dsPK, msg)
	if err != nil {
		panic(err)
	}
	tSign := time.Since(start).Nanoseconds()

	start = time.Now()
	ok := ds.Verify(dsPK, msg, sig)
	tVerify := time.Since(start).Nanoseconds()

	if !ok {
		panic("DS verify failed")
	}

	// ======================================================
	// 3. Correctness Tests
	// ======================================================

	rowsCorrect := [][]string{
		{"HPPK", "KEM_shared_key_match", pass(bytes.Equal(ss1, ss2))},
		{"HPPK", "DS_valid_signature", pass(ok)},
	}

	// tamper msg
	msg2 := []byte("Hacked")
	rowsCorrect = append(rowsCorrect,
		[]string{"HPPK", "DS_tampered_msg", pass(!ds.Verify(dsPK, msg2, sig))})

	// wrong pk
	_, wrongPK := ds.KeyGenDS(F, dsL, dsK)
	rowsCorrect = append(rowsCorrect,
		[]string{"HPPK", "DS_wrong_pk", pass(!ds.Verify(wrongPK, msg, sig))})

	writeCSV(out+"/hppk_full_correctness.csv",
		[]string{"scheme", "test", "result"},
		rowsCorrect)

	// ======================================================
	// 4. Benchmark (single-run demo)
	// ======================================================

	rowsBench := [][]string{
		{"HPPK", "KEM_KeyGen", fmt.Sprint(tKEMKeyGen)},
		{"HPPK", "KEM_Encaps", fmt.Sprint(tEncaps)},
		{"HPPK", "KEM_Decaps", fmt.Sprint(tDecaps)},
		{"HPPK", "DS_KeyGen", fmt.Sprint(tDSKeyGen)},
		{"HPPK", "DS_Sign", fmt.Sprint(tSign)},
		{"HPPK", "DS_Verify", fmt.Sprint(tVerify)},
	}

	writeCSV(out+"/hppk_full_benchmark.csv",
		[]string{"scheme", "operation", "time_ns"},
		rowsBench)

	// ======================================================
	// 5. Size
	// ======================================================

	rowsSize := [][]string{
		{"HPPK",
			fmt.Sprint(size(kemPK)),
			fmt.Sprint(size(kemSK)),
			fmt.Sprint(size(ct)),
			fmt.Sprint(size(dsPK)),
			fmt.Sprint(size(dsSK)),
			fmt.Sprint(size(sig)),
			fmt.Sprint(len(ss1)),
		},
	}

	writeCSV(out+"/hppk_full_sizes.csv",
		[]string{"scheme", "kem_pk", "kem_sk", "ciphertext", "ds_pk", "ds_sk", "signature", "shared_key"},
		rowsSize)

	fmt.Println("HPPK FULL EXPERIMENT DONE")
}

func pass(b bool) string {
	if b {
		return "pass"
	}
	return "fail"
}
