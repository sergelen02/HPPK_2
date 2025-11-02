package ds

import "testing"

func Test_LevelI_Deterministic(t *testing.T) {
	pp := testParams()

	sk, pk, err := KeyGen(pp, 1, 1, 1)
	if err != nil {
		t.Fatalf("KeyGen error: %v", err)
	}

	msg := []byte("hello-phaseA")

	sig, _, err := Sign(pp, sk, msg)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	ok := Verify(pp, pk, sig, msg)
	if !ok {
		t.Fatal("verify=false")
	}
}
