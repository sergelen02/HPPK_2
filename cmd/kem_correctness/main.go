package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"math/big"
	"os"
	"reflect"

	kem "github.com/sergelen02/HPPK_2/internal/kem"
)

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

func tamperCiphertext(ct *kem.Ciphertext) *kem.Ciphertext {
	if ct == nil {
		panic("ciphertext is nil")
	}

	clone := *ct
	rv := reflect.ValueOf(&clone).Elem()

	bigIntPtrType := reflect.TypeOf(&big.Int{})
	byteSliceType := reflect.TypeOf([]byte{})

	for i := 0; i < rv.NumField(); i++ {
		f := rv.Field(i)

		// *big.Int 필드 변조
		if f.Type() == bigIntPtrType && !f.IsNil() && f.CanSet() {
			orig := f.Interface().(*big.Int)
			mod := new(big.Int).Set(orig)
			mod.Add(mod, big.NewInt(1))
			f.Set(reflect.ValueOf(mod))
			return &clone
		}

		// []byte 필드 변조
		if f.Type() == byteSliceType && f.Len() > 0 && f.CanSet() {
			orig := f.Bytes()
			mod := make([]byte, len(orig))
			copy(mod, orig)
			mod[0] ^= 0x01
			f.Set(reflect.ValueOf(mod))
			return &clone
		}
	}

	panic("no mutable ciphertext field found to tamper")
}

func main() {
	// TODO: 실제 bench_test.go / params.go와 맞지 않으면 여기 파라미터를 조정하세요.
	pp := kem.LoadParams("257", 256, 128, 2, 64, 32, -3, 3)

	x := big.NewInt(123456789)
	noiseMin := int64(-3)
	noiseMax := int64(3)

	var rows []Result

	// 1) 정상 KeyGen
	sk, pk := kem.KeyGenKEM(pp)
	okKeyGen := sk != nil && pk != nil
	rows = append(rows, Result{
		Scheme:   "HPPK-KEM",
		TestCase: "keygen_success",
		Result:   passFail(okKeyGen),
		Detail:   "secret/public key generated",
	})

	// 2) 정상 Encaps/Decaps
	ct, ssEnc := kem.Encaps(pk, x, noiseMin, noiseMax)
	ssDec := kem.Decaps(sk, ct)
	okMatch := bytes.Equal(ssEnc, ssDec)

	rows = append(rows, Result{
		Scheme:   "HPPK-KEM",
		TestCase: "encaps_decaps_match",
		Result:   passFail(okMatch),
		Detail:   "shared secret from encaps/decaps must match",
	})

	// 3) 변조 ciphertext
	tamperedCT := tamperCiphertext(ct)
	ssTampered := kem.Decaps(sk, tamperedCT)
	okTampered := !bytes.Equal(ssEnc, ssTampered)

	rows = append(rows, Result{
		Scheme:   "HPPK-KEM",
		TestCase: "tampered_ciphertext",
		Result:   passFail(okTampered),
		Detail:   "tampered ciphertext must fail or produce different shared secret",
	})

	// 4) 잘못된 secret key
	sk2, _ := kem.KeyGenKEM(pp)
	ssWrong := kem.Decaps(sk2, ct)
	okWrong := !bytes.Equal(ssEnc, ssWrong)

	rows = append(rows, Result{
		Scheme:   "HPPK-KEM",
		TestCase: "wrong_secret_key",
		Result:   passFail(okWrong),
		Detail:   "wrong secret key must fail or produce different shared secret",
	})

	out := "/home/sergelen.8711/exp-hppk/results/offchain/hppk_kem_correctness.csv"
	writeCSV(out, rows)

	fmt.Println("KEM correctness test completed.")
	fmt.Println("Output:", out)
	for _, r := range rows {
		fmt.Printf("%s | %s | %s | %s\n", r.Scheme, r.TestCase, r.Result, r.Detail)
	}
}
