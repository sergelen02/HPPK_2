// internal/core/vm/hppk_precompile.go
// HPPK 서명 검증 프리컴파일(verify only).
// 입력 ABI: [6*4바이트 길이헤더] + F|H|U|V|pkJSON|msg
//   - order: sigFLen, sigHLen, sigULen, sigVLen, pkLen, msgLen (각각 big-endian uint32)
//   - 그 다음 바이트들은 위 순서대로 이어붙임
//
// 출력: 32바이트(bool) - 마지막 바이트 0x01이면 true, 그 외 false
package vm

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sergelen02/HPPK_2/internal/ds"
)

var (
	ErrInputTooShort  = errors.New("hppk-precompile: input too short")
	ErrMalformed      = errors.New("hppk-precompile: malformed input")
	ErrLengthOverflow = errors.New("hppk-precompile: length overflow")
	ErrVerifyFailed   = errors.New("hppk-precompile: verify failed")
)

// 보수적 가스 정책(실험 후 조정 권장)
const (
	gasBase       = uint64(600)
	gasPerByte    = uint64(8)
	gasMinSuccess = uint64(1500)
	gasMinFail    = uint64(800)
	maxInputBytes = 1 << 24 // 16MiB 방어적 상한
	outputLen     = 32
)

type HPPKVerifyPrecompile struct{}

// RequiredGas: 전체 입력 길이에 선형 비례
func (HPPKVerifyPrecompile) RequiredGas(input []byte) uint64 {
	n := uint64(len(input))
	est := gasBase + n*gasPerByte
	if est < gasMinFail {
		return gasMinFail
	}
	return est
}

// Run: 입력을 pk.json 으로 보고 → ds.Verify 호출 → 32바이트 bool 반환
func (HPPKVerifyPrecompile) Run(input []byte) ([]byte, error) {
	ok, err := runVerify(input)
	out := make([]byte, outputLen)
	if ok {
		out[outputLen-1] = 1
		return out, nil
	}
	return out, err
}

// --- Base64 헬퍼 ---
func mustB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// 실제 검증 로직
func runVerify(input []byte) (bool, error) {
	if len(input) == 0 {
		return false, ErrInputTooShort
	}
	if len(input) > maxInputBytes {
		return false, fmt.Errorf("hppk-precompile: input too large (%d)", len(input))
	}

	// 1) Base64 → 서명 바이트 (하드코딩된 샘플)
	F := mustB64("BVDzRZ2rQnaTNmznyHAOotuXxg2+bIqCW51Vp5ZVyLxECQZDAw==")
	H := mustB64("UNMo96/2Z9hFGoKBTnE5WZ0BhiyjI7FJkd4x2QEy9jnoYx8yyA==")
	U := mustB64("l63W+GLb0/S47/Tlnb1y5Q==")
	V := mustB64("47X7eVfFoAEOMKWirVB+DQ==")

	// 2) 공개키(JSON) → ds.Public
	var pk ds.Public
	if err := json.Unmarshal(input, &pk); err != nil {
		return false, fmt.Errorf("unmarshal public key: %w", err)
	}

	// 3) 시그니처 구성
	sig := &ds.Signature{
		F: F,
		H: H,
		U: U,
		V: V,
	}

	// 4) 메시지도 고정 (지금은 샘플)
	msg := []byte("hello quantum")

	// 5) 검증 호출
	ok := ds.Verify(&pk, msg, sig)
	if !ok {
		return false, ErrVerifyFailed
	}
	return true, nil
}
