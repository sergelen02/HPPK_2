package ds

import (
	"math/big"
	"testing"

	"github.com/sergelen02/HPPK_2/internal/core"
)

func testField(t *testing.T) *core.Field {
	// TODO: 아래 한 줄만 "레포에 실제 존재하는 Field 생성 함수"로 교체
	// 예: core.NewField(big.NewInt(65537)), core.NewField(...), core.NewFieldFromParams(...)

	F := core.NewField(big.NewInt(65537)) // <- 예시. 너 레포에 맞게 바꿔야 함.
	if F == nil {
		t.Fatal("core.Field is nil")
	}
	return F
}

func Test_Golden_SmallP(t *testing.T) {
	F := testField(t)

	sk, pk := KeyGenDS(F, 2, 1)

	msg := []byte("abc")

	sig, err := SignWithPK(sk, pk, msg)
	if err != nil {
		t.Fatalf("SignWithPK error: %v", err)
	}

	if ok := Verify(pk, msg, sig); !ok {
		t.Fatal("verify=false")
	}
}
