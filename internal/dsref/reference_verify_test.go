package dsref

import (
	"math/big"
	"testing"
)

// TestPaperToyExampleVerify fixes the public key and signature published in
// Section 5.5 of arXiv:2311.08967v3. The paper uses p=13, m=2, R=2^24,
// x=9, F=5683, and H=5357.
func TestPaperToyExampleVerify(t *testing.T) {
	pk := paperToyPublicKey()
	sig := &Signature{F: big.NewInt(5683), H: big.NewInt(5357)}

	if !VerifyAt(pk, big.NewInt(9), sig) {
		t.Fatal("paper toy-example signature was rejected")
	}
}

func TestPaperToyExampleRejectsSignatureTampering(t *testing.T) {
	pk := paperToyPublicKey()
	original := &Signature{F: big.NewInt(5683), H: big.NewInt(5357)}

	cases := []struct {
		name string
		sig  *Signature
	}{
		{"F", &Signature{F: big.NewInt(5684), H: new(big.Int).Set(original.H)}},
		{"H", &Signature{F: new(big.Int).Set(original.F), H: big.NewInt(5358)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if VerifyAt(pk, big.NewInt(9), tc.sig) {
				t.Fatalf("tampered %s was accepted", tc.name)
			}
		})
	}
}

func TestPaperToyExampleRejectsPublicKeyTampering(t *testing.T) {
	pk := paperToyPublicKey()
	pk.PPrime[0][0].Add(pk.PPrime[0][0], big.NewInt(1))
	sig := &Signature{F: big.NewInt(5683), H: big.NewInt(5357)}

	if VerifyAt(pk, big.NewInt(9), sig) {
		t.Fatal("tampered public-key coefficient was accepted")
	}
}

func paperToyPublicKey() *PublicKey {
	return &PublicKey{
		P:        big.NewInt(13),
		R:        new(big.Int).Lsh(big.NewInt(1), 24),
		N:        1,
		Lambda:   1,
		M:        2,
		RingBits: 24,
		S1ModP:   big.NewInt(11),
		S2ModP:   big.NewInt(12),
		PPrime: matrix(
			[]int64{11, 11, 6},
			[]int64{3, 6, 8},
		),
		QPrime: matrix(
			[]int64{3, 4, 6},
			[]int64{7, 3, 9},
		),
		Mu: matrix(
			[]int64{12862449, 10905066, 15192550},
			[]int64{6617583, 15192550, 372717},
		),
		Nu: matrix(
			[]int64{13724671, 3040767, 1514495},
			[]int64{16765439, 13724671, 15239167},
		),
	}
}

func matrix(rows ...[]int64) [][]*big.Int {
	out := make([][]*big.Int, len(rows))
	for i, row := range rows {
		out[i] = make([]*big.Int, len(row))
		for j, value := range row {
			out[i][j] = big.NewInt(value)
		}
	}
	return out
}
