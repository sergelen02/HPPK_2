package ds

import (
	"math/big"
	"testing"

	"github.com/sergelen02/HPPK_2/internal/core"
)

func Test_LevelI_SignVerify(t *testing.T) {
	F := core.NewField(big.NewInt(65537))

	sk, pk := KeyGenDS(F, uint(2), uint(1))
	if sk == nil || pk == nil {
		t.Fatal("KeyGenDS returned nil")
	}

	msg := []byte("level1")

	sig, err := SignWithPK(sk, pk, msg)
	if err != nil {
		t.Fatalf("SignWithPK error: %v", err)
	}
	if sig == nil {
		t.Fatal("SignWithPK returned nil signature")
	}

	if ok := Verify(pk, msg, sig); !ok {
		t.Fatal("verify=false")
	}
}
