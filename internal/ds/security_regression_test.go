//go:build securityregression

package ds

import (
	"math/big"
	"testing"

	"github.com/sergelen02/HPPK_2/internal/core"
)

var securityRegressionMessage = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

func newSecurityRegressionKeyPair(t *testing.T) (*Secret, *Public) {
	t.Helper()

	// The small field keeps this logic-level regression suite fast.
	// The Phase-A runner separately validates a real Level-V key pair.
	field := core.NewField(big.NewInt(65537))
	sk, pk := KeyGenDS(field, 32, 64)
	if sk == nil || pk == nil {
		t.Fatal("KeyGenDS returned nil key")
	}
	return sk, pk
}

func signSecurityRegressionMessage(t *testing.T, sk *Secret, pk *Public, msg []byte) *Signature {
	t.Helper()

	sig, err := SignWithPK(sk, pk, msg)
	if err != nil {
		t.Fatalf("SignWithPK: %v", err)
	}
	if sig == nil {
		t.Fatal("SignWithPK returned nil signature")
	}
	return sig
}

func TestSecurityRegressionValidSignatureAccepted(t *testing.T) {
	sk, pk := newSecurityRegressionKeyPair(t)
	sig := signSecurityRegressionMessage(t, sk, pk, securityRegressionMessage)

	if !Verify(pk, securityRegressionMessage, sig) {
		t.Fatal("valid HPPK signature was rejected")
	}
}

func TestSecurityRegressionRejectsTamperedMessage(t *testing.T) {
	sk, pk := newSecurityRegressionKeyPair(t)
	sig := signSecurityRegressionMessage(t, sk, pk, securityRegressionMessage)

	tampered := append([]byte(nil), securityRegressionMessage...)
	tampered[0] ^= 0x01

	if Verify(pk, tampered, sig) {
		t.Fatal("signature for the original message was accepted for a one-byte modified message")
	}
}

func TestSecurityRegressionRejectsSignatureForDifferentMessage(t *testing.T) {
	sk, pk := newSecurityRegressionKeyPair(t)
	sig := signSecurityRegressionMessage(t, sk, pk, securityRegressionMessage)

	otherMessage := append([]byte(nil), securityRegressionMessage...)
	otherMessage[len(otherMessage)-1] ^= 0x80

	if Verify(pk, otherMessage, sig) {
		t.Fatal("signature was accepted for a different well-formed message")
	}
}

func TestSecurityRegressionRejectsTamperedSignatureFields(t *testing.T) {
	sk, pk := newSecurityRegressionKeyPair(t)
	original := signSecurityRegressionMessage(t, sk, pk, securityRegressionMessage)

	cases := []struct {
		name string
		edit func(*Signature)
	}{
		{
			name: "F",
			edit: func(sig *Signature) { sig.F[len(sig.F)-1] ^= 0x01 },
		},
		{
			name: "H",
			edit: func(sig *Signature) { sig.H[len(sig.H)-1] ^= 0x01 },
		},
		{
			name: "U",
			edit: func(sig *Signature) { sig.U[len(sig.U)-1] ^= 0x01 },
		},
		{
			name: "V",
			edit: func(sig *Signature) { sig.V[len(sig.V)-1] ^= 0x01 },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := cloneSignature(original)
			tc.edit(tampered)

			if Verify(pk, securityRegressionMessage, tampered) {
				t.Fatalf("one-byte modification of signature field %s was accepted", tc.name)
			}
		})
	}
}

func TestSecurityRegressionIndependentAgentKeys(t *testing.T) {
	skA, pkA := newSecurityRegressionKeyPair(t)
	skB, pkB := newSecurityRegressionKeyPair(t)

	sigA := signSecurityRegressionMessage(t, skA, pkA, securityRegressionMessage)
	if !Verify(pkA, securityRegressionMessage, sigA) {
		t.Fatal("Agent A signature was rejected by Agent A public key")
	}
	if Verify(pkB, securityRegressionMessage, sigA) {
		t.Fatal("Agent A signature was accepted by independent Agent B public key")
	}

	sigB := signSecurityRegressionMessage(t, skB, pkB, securityRegressionMessage)
	if !Verify(pkB, securityRegressionMessage, sigB) {
		t.Fatal("Agent B signature was rejected by Agent B public key")
	}
}

// This is the decisive unforgeability regression test.
//
// An attacker knows pk and msg, chooses F and H, then calculates U and V using
// only public values. A secure signature verifier MUST reject this value because
// no private key was used. The current implementation is expected to fail this
// test until the verification equation is corrected to enforce the intended
// HPPK-DS secret-key relation.
func TestSecurityRegressionRejectsPublicOnlyForgery(t *testing.T) {
	_, pk := newSecurityRegressionKeyPair(t)
	forged := publicOnlyForgery(pk, securityRegressionMessage)

	if Verify(pk, securityRegressionMessage, forged) {
		t.Fatal("SECURITY FAILURE: public-key-only forged signature was accepted")
	}
}

func publicOnlyForgery(pk *Public, msg []byte) *Signature {
	p := pk.P
	x := core.HashToX(p, msg)

	alpha := new(big.Int).Add(pk.Pprime0, new(big.Int).Mul(pk.Pprime1, x))
	alpha.Mod(alpha, p)
	beta := new(big.Int).Add(pk.Qprime0, new(big.Int).Mul(pk.Qprime1, x))
	beta.Mod(beta, p)

	f := big.NewInt(1)
	h := big.NewInt(1)
	u := new(big.Int).Set(alpha)
	v := new(big.Int).Set(beta)

	return &Signature{
		F: fixedWidthBytes(f, pk.S2),
		H: fixedWidthBytes(h, pk.S1),
		U: fixedWidthBytes(u, p),
		V: fixedWidthBytes(v, p),
	}
}

func fixedWidthBytes(v, modulus *big.Int) []byte {
	width := (modulus.BitLen() + 7) / 8
	out := make([]byte, width)
	return v.FillBytes(out)
}

func cloneSignature(sig *Signature) *Signature {
	return &Signature{
		F: append([]byte(nil), sig.F...),
		H: append([]byte(nil), sig.H...),
		U: append([]byte(nil), sig.U...),
		V: append([]byte(nil), sig.V...),
	}
}
