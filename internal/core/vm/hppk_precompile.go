// internal/core/vm/hppk_precompile.go
// HPPK 서명 검증 프리컴파일(verify only).
// 입력 ABI: [6*4바이트 길이헤더] + F|H|U|V|pkJSON|msg
//   - order: sigFLen, sigHLen, sigULen, sigVLen, pkLen, msgLen (각각 big-endian uint32)
//   - 그 다음 바이트들은 위 순서대로 이어붙임
//
// 출력: 32바이트(bool) - 마지막 바이트 0x01이면 true, 그 외 false
package vm

import (
	"encoding/binary"
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

// Run: 파싱 → ds.Verify 호출 → 32바이트 bool 반환
func (HPPKVerifyPrecompile) Run(input []byte) ([]byte, error) {
	ok, err := runVerify(input)
	out := make([]byte, outputLen)
	if ok {
		out[outputLen-1] = 1
		return out, nil
	}
	return out, err
}

func runVerify(input []byte) (bool, error) {
	if len(input) < 24 { // 6개 길이헤더 * 4바이트
		return false, ErrInputTooShort
	}
	if len(input) > maxInputBytes {
		return false, fmt.Errorf("hppk-precompile: input too large (%d)", len(input))
	}

	// 길이 헤더
	fLen := int(binary.BigEndian.Uint32(input[0:4]))
	hLen := int(binary.BigEndian.Uint32(input[4:8]))
	uLen := int(binary.BigEndian.Uint32(input[8:12]))
	vLen := int(binary.BigEndian.Uint32(input[12:16]))
	pkLen := int(binary.BigEndian.Uint32(input[16:20]))
	msgLen := int(binary.BigEndian.Uint32(input[20:24]))

	for _, x := range []int{fLen, hLen, uLen, vLen, pkLen, msgLen} {
		if x < 0 {
			return false, ErrLengthOverflow
		}
	}

	total := 24 + fLen + hLen + uLen + vLen + pkLen + msgLen
	if total != len(input) {
		return false, ErrMalformed
	}

	pos := 24
	F := input[pos : pos+fLen]
	pos += fLen
	H := input[pos : pos+hLen]
	pos += hLen
	U := input[pos : pos+uLen]
	pos += uLen
	V := input[pos : pos+vLen]
	pos += vLen
	pkJSON := input[pos : pos+pkLen]
	pos += pkLen
	msg := input[pos : pos+msgLen]

	// 공개키(JSON) → ds.Public
	var pk ds.Public
	if err := json.Unmarshal(pkJSON, &pk); err != nil {
		return false, fmt.Errorf("unmarshal public key: %w", err)
	}

	// 시그니처: 고정 길이 직렬화 규약을 그대로 사용
	sig := &ds.Signature{
		F: append([]byte(nil), F...),
		H: append([]byte(nil), H...),
		U: append([]byte(nil), U...),
		V: append([]byte(nil), V...),
	}

	// 실제 검증
	ok := ds.Verify(&pk, msg, sig)
	if !ok {
		return false, ErrVerifyFailed
	}
	return true, nil
}
