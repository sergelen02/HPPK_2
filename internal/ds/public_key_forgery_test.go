package ds

import (
	"math/big"
	"testing"

	"github.com/sergelen02/HPPK_2/internal/core"
)

// TestVerifyRejectsPublicKeyOnlyForgery checks that an attacker cannot create
// a valid signature using only public-key values. It intentionally fails on
// the vulnerable implementation until Verify is redesigned.
func TestVerifyRejectsPublicKeyOnlyForgery(t *testing.T) {
	field := core.NewField(big.NewInt(65537))
	_, pk := KeyGenDS(field, 2, 1)
	msg := []byte("public-key-only-forgery")

	// The attacker chooses F and H, then derives U and V from public data.
	f := big.NewInt(1)
	h := big.NewInt(1)
	x := core.HashToX(pk.P, msg)

	alpha := new(big.Int).Add(pk.Pprime0, new(big.Int).Mul(pk.Pprime1, x))
	alpha.Mod(alpha, pk.P)
	beta := new(big.Int).Add(pk.Qprime0, new(big.Int).Mul(pk.Qprime1, x))
	beta.Mod(beta, pk.P)

	forged := &Signature{
		F: f.Bytes(),
		H: h.Bytes(),
		U: new(big.Int).Mod(new(big.Int).Mul(alpha, h), pk.P).Bytes(),
		V: new(big.Int).Mod(new(big.Int).Mul(beta, f), pk.P).Bytes(),
	}

	if Verify(pk, msg, forged) {
		t.Fatal("public-key-only forgery was accepted")
	}
}
