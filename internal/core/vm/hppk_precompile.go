package vm

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	ds "github.com/sergelen02/HPPK_DS/internal/ds"
)

var (
	// 프리컴파일 고정 주소
	HPPKAddress = common.HexToAddress("0x000000000000000000000000000000000000000b")

	// 가스 모델: base + perByte * (sig+pk)
	hppkGasBase    = uint64(3000) // 초기치: ecrecover 참고
	hppkGasPerByte = uint64(12)   // 초기치: 실측 후 보정 예정
)

type HPPKVerify struct{}

func (c *HPPKVerify) RequiredGas(input []byte) uint64 {
	// 입력: ABI-encoded (bytes32 msgHash, bytes sig, bytes pubkey)
	// 안전: 최소 길이 체크 후 선형비례
	if len(input) < 32 { // 너무 짧으면 최소 가스
		return hppkGasBase
	}
	// 길이를 대략 사용 (정확한 ABI 파싱은 Run에서)
	return hppkGasBase + hppkGasPerByte*uint64(len(input))
}

func (c *HPPKVerify) Run(evm *EVM, input []byte, _ bool) ([]byte, error) {
	// 1) ABI decoding
	msgHash, sig, pub, err := decodeHPPKArgs(input)
	if err != nil {
		return abiBool(false), nil // 포맷오류도 false 반환
	}

	// 2) DS Verify 호출 (Params는 내부에서 안전 디폴트 사용 또는 체인 파라미터로 전달)
	pp := levelIDefaultParams()
	ok := verifyHPPK(pp, msgHash, sig, pub)
	return abiBool(ok), nil
}

// ---- 내부 유틸 (스텁/스켈레톤; 실제 구현에서 바꿔 넣기) ----

func decodeHPPKArgs(b []byte) (msg32 [32]byte, sig []byte, pub []byte, err error) {
	// 간단 파서(스켈레톤): 실제론 go-ethereum/accounts/abi 로 Unpack 권장
	if len(b) < 32 {
		return msg32, nil, nil, errors.New("short input")
	}
	copy(msg32[:], b[:32])
	// 이후 슬라이스는 프로젝트 상황에 맞게 포맷 정의
	// 예: b[32:32+sigLen] -> sig, 나머지 -> pub
	// 여기서는 데모로 반반 분할
	half := (len(b) - 32) / 2
	sig = append([]byte(nil), b[32:32+half]...)
	pub = append([]byte(nil), b[32+half:]...)
	return
}

func levelIDefaultParams() *ds.Params {
	// 당신 레포의 Params 필드에 맞게 세팅
	// 최소: p, L, K, R 등
	// 없으면 ds 쪽에 LevelI() 같은 헬퍼를 만들어 import
	return &ds.Params{} // TODO: 실제 필드 채우기
}

func verifyHPPK(pp *ds.Params, msg32 [32]byte, sig, pub []byte) bool {
	// 해시→메시지 변환 규칙은 DS 구현과 동일하게
	s := &ds.Signature{}
	pk := &ds.PublicKey{} // pub로부터 복원 규약을 합의 (고정길이 직렬화 권장)
	return ds.Verify(pp, pk, s, msg32[:])
}

// ABI bool (32바이트)
func abiBool(b bool) []byte {
	out := make([]byte, 32)
	if b {
		out[31] = 1
	}
	return out
}

var _ PrecompiledContract = &HPPKVerify{}
