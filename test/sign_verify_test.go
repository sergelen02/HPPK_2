// internal/ds/sign_verify_test.go
package ds_test

import (
	"math/big"
	"testing"

	"github.com/sergelen02/HPPK_2/internal/core"
	"github.com/sergelen02/HPPK_2/internal/ds"
)

func TestSignVerify(t *testing.T) {
	// p: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61 (128-bit)
	var P big.Int
	if _, ok := P.SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61", 0); !ok {
		t.Fatal("invalid p")
	}
	F := core.NewField(&P)

	const L uint = 272 // (≈260) 이상
	const K uint = 256

	sk, pk := ds.KeyGenDS(F, L, K)

	msg := []byte("hello quantum")

	// 공개키를 넘기는 새 API 사용
	sig, err := ds.SignWithPK(sk, pk, msg)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	if !ds.Verify(pk, msg, sig) {
		t.Fatal("verify failed")
	}
}
