package ds

import (
	"encoding/binary"
	"testing"
)

// DCE 방지용 sink
var (
	sinkSK  *SecretKey
	sinkPK  *PublicKey
	sinkSig *Signature
	sinkOK  bool
)

func mustKeyPair(b *testing.B, pp *Params, n int) (*SecretKey, *PublicKey) {
	sk, pk := KeyGen(pp, n)
	if sk == nil || pk == nil {
		b.Fatalf("KeyGen returned nil")
	}
	return sk, pk
}

func mustSign(b *testing.B, pp *Params, sk *SecretKey, m []byte) *Signature {
	sig, err := Sign(pp, sk, m)
	if err != nil || sig == nil {
		b.Fatalf("Sign failed: %v", err)
	}
	return sig
}

func makeMsg(i int) []byte {
	m := make([]byte, 32)
	binary.LittleEndian.PutUint32(m, uint32(i))
	return m
}

func BenchmarkKeyGen(b *testing.B) {
	pp := DefaultParams()
	n := pp.N
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkSK, sinkPK = KeyGen(pp, n)
	}
}

func BenchmarkSign(b *testing.B) {
	pp := DefaultParams()
	n := pp.N
	sk, _ := mustKeyPair(b, pp, n)

	for _, L := range []int{32, 64, 256, 1024} {
		b.Run(byteSize(L), func(b *testing.B) {
			msg := make([]byte, L)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				binary.LittleEndian.PutUint32(msg, uint32(i))
				sinkSig, _ = Sign(pp, sk, msg)
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	pp := DefaultParams()
	n := pp.N
	sk, pk := mustKeyPair(b, pp, n)
	msg := makeMsg(0xC0DEC0DE)
	sig := mustSign(b, pp, sk, msg)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkOK = Verify(pp, pk, msg, sig)
	}
}

// ---- small utils ----
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
func byteSize(n int) string { return itoa(n) + "B" }
