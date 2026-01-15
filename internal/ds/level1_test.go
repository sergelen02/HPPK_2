package ds

import (
	"math/big"
	"testing"

	"github.com/sergelen02/HPPK_2/internal/core"
)

func Test_LevelI_Deterministic(t *testing.T) {
	// Field: Z_p
	// 테스트용 소수 p (필요하면 레포에서 사용하는 p로 맞추세요)
	F := core.NewField(big.NewInt(65537))

	// KeyGenDS(F, L, K)
	sk, pk := KeyGenDS(F, 2, 1)
	if sk == nil || pk == nil {
		t.Fatal("KeyGenDS returned nil")
	}

	msg := []byte("hello-phaseA")

	// SignWithPK(sk, pk, msg)
	sig, err := SignWithPK(sk, pk, msg)
	if err != nil {
		t.Fatalf("SignWithPK error: %v", err)
	}

	// Verify(pk, msg, sig)
	if ok := Verify(pk, msg, sig); !ok {
		t.Fatal("verify=false")
	}
}
