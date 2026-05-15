package main

import (
	"encoding/csv"
	"fmt"
	"os"

)

type Result struct {
	Scheme   string
	TestCase string
	Result   string
	Detail   string
}

func mustRead(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return b
}

func passFail(ok bool) string {
	if ok {
		return "pass"
	}
	return "fail"
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
	// HPPK는 우선 raw message 기준으로 테스트
	msg := mustRead("dataset/msg_32.txt")
	if len(msg) != 32 {
		panic("msg_32.txt must be 32 bytes")
	}

	// TODO: 여기만 실제 keygen 함수명에 맞게 수정
	// 예시:
	// pk, sk := ds.KeyGen()
	// 또는
	// pk, sk, err := ds.KeyGen()
	// 또는
	// pp := ds.DefaultParams()
	// pk, sk := ds.KeyGen(pp)

	var (
		pk interface{}
		sk interface{}
	)

	_ = pk
	_ = sk

	// ===== 실제 코드에 맞춰 수정할 부분 시작 =====
	// sig := ds.Sign(sk, msg)
	// okValid := ds.Verify(pk, msg, sig)

	// tampered msg
	// tamperedMsg := make([]byte, len(msg))
	// copy(tamperedMsg, msg)
	// tamperedMsg[0] ^= 0x01
	// okTamperedMsg := ds.Verify(pk, tamperedMsg, sig)

	// tampered sig
	// tamperedSig := *sig
	// tamperedSig.Alpha.Add(tamperedSig.Alpha, big.NewInt(1)) // 예시, 실제 필드에 맞게 수정
	// okTamperedSig := ds.Verify(pk, msg, &tamperedSig)
	// ===== 실제 코드에 맞춰 수정할 부분 끝 =====

	var rows []Result

	rows = append(rows, Result{
		Scheme:   "HPPK",
		TestCase: "sign_verify_valid",
		Result:   "TODO",
		Detail:   "valid message + valid signature",
	})

	rows = append(rows, Result{
		Scheme:   "HPPK",
		TestCase: "verify_tampered_message",
		Result:   "TODO",
		Detail:   "tampered message must fail verification",
	})

	rows = append(rows, Result{
		Scheme:   "HPPK",
		TestCase: "verify_tampered_signature",
		Result:   "TODO",
		Detail:   "tampered signature must fail verification",
	})

	writeCSV("results/offchain/hppk_correctness.csv", rows)

	fmt.Println("HPPK correctness skeleton generated.")
}
