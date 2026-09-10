package dsref

import (
	"math/big"
	"testing"
)

func TestKeyGenSignVerify(t *testing.T) {
	params := testParams()
	sk, pk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	msg := []byte("reference-hppk-ds-sign-verify")
	sig, err := Sign(sk, pk, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(pk, msg, sig) {
		t.Fatal("valid reference HPPK-DS signature was rejected")
	}

	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 1
	if Verify(pk, tampered, sig) {
		t.Fatal("signature was accepted for a tampered message")
	}
}

func TestIndependentKeysRejectCrossVerification(t *testing.T) {
	params := testParams()
	skA, pkA, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen A: %v", err)
	}
	skB, pkB, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen B: %v", err)
	}
	msg := []byte("independent-agent-keys")

	sigA, err := Sign(skA, pkA, msg)
	if err != nil {
		t.Fatalf("Sign A: %v", err)
	}
	if !Verify(pkA, msg, sigA) {
		t.Fatal("Agent A signature was rejected by Agent A public key")
	}
	if Verify(pkB, msg, sigA) {
		t.Fatal("Agent A signature was accepted by Agent B public key")
	}

	sigB, err := Sign(skB, pkB, msg)
	if err != nil {
		t.Fatalf("Sign B: %v", err)
	}
	if !Verify(pkB, msg, sigB) {
		t.Fatal("Agent B signature was rejected by Agent B public key")
	}
	if Verify(pkA, msg, sigB) {
		t.Fatal("Agent B signature was accepted by Agent A public key")
	}
}

func TestRejectsSignatureAndPublicKeyTampering(t *testing.T) {
	sk, pk, err := KeyGen(testParams())
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	msg := []byte("tamper-reference-hppk-ds")
	sig, err := Sign(sk, pk, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tamperedSignature := &Signature{
		F: new(big.Int).Add(sig.F, big.NewInt(1)),
		H: new(big.Int).Set(sig.H),
	}
	if Verify(pk, msg, tamperedSignature) {
		t.Fatal("tampered F was accepted")
	}
	tamperedSignature = &Signature{
		F: new(big.Int).Set(sig.F),
		H: new(big.Int).Add(sig.H, big.NewInt(1)),
	}
	if Verify(pk, msg, tamperedSignature) {
		t.Fatal("tampered H was accepted")
	}

	tamperedPublicKey := copyPublicKey(pk)
	tamperedPublicKey.Mu[0][0].Add(tamperedPublicKey.Mu[0][0], big.NewInt(1))
	if Verify(tamperedPublicKey, msg, sig) {
		t.Fatal("tampered Barrett public-key coefficient was accepted")
	}
}

func testParams() Params {
	return Params{
		P:           big.NewInt(65537),
		N:           1,
		Lambda:      1,
		M:           2,
		RingBits:    64,
		BarrettBits: 96,
	}
}

func copyPublicKey(pk *PublicKey) *PublicKey {
	copyMatrix := func(source [][]*big.Int) [][]*big.Int {
		out := make([][]*big.Int, len(source))
		for i := range source {
			out[i] = make([]*big.Int, len(source[i]))
			for j := range source[i] {
				out[i][j] = new(big.Int).Set(source[i][j])
			}
		}
		return out
	}
	return &PublicKey{
		P:        new(big.Int).Set(pk.P),
		R:        new(big.Int).Set(pk.R),
		N:        pk.N,
		Lambda:   pk.Lambda,
		M:        pk.M,
		RingBits: pk.RingBits,
		S1ModP:   new(big.Int).Set(pk.S1ModP),
		S2ModP:   new(big.Int).Set(pk.S2ModP),
		PPrime:   copyMatrix(pk.PPrime),
		QPrime:   copyMatrix(pk.QPrime),
		Mu:       copyMatrix(pk.Mu),
		Nu:       copyMatrix(pk.Nu),
	}
}
