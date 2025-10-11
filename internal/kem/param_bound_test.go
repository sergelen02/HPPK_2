// internal/kem/param_bound_test.go
package kem_test

import (
	"testing"

	"github.com/sergelen02/HPPK_2/internal/kem"
)

// NOTE:
// - LoadParams가 SetString(..., 0)이라면 p는 "0x..." 형태로 주세요.
// - 만약 LoadParams가 SetString(..., 16)이라면 p를 "FFFFFFFF..." (0x 없이)로 넘기면 됩니다.

const (
	pHexOK = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61" // 128-bit 예시
	n      = 3
	lambda = 1
	m      = 2
	Kbits  = 256
	nmin   = 1
	nmax   = 5
)

func TestKEMParamBound_FailsWithSmallL(t *testing.T) {
	Lsmall := uint(192) // 하한(~260) 미만 → 실패 의도
	pp := kem.LoadParams(pHexOK, n, lambda, m, Lsmall, Kbits, nmin, nmax)

	sk, pk := kem.KeyGenKEM(pp)
	if sk != nil || pk != nil {
		t.Fatalf("expected failure for small L=%d, but got non-nil keys", Lsmall)
	}
}

func TestKEMParamBound_SucceedsWithLargeL(t *testing.T) {
	Lok := uint(272) // 하한(≈260) 이상
	pp := kem.LoadParams(pHexOK, n, lambda, m, Lok, Kbits, nmin, nmax)

	sk, pk := kem.KeyGenKEM(pp)
	if sk == nil || pk == nil {
		t.Fatalf("expected success for L=%d (>= bound), but got nil keys", Lok)
	}
}
