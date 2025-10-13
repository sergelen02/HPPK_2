// internal/kem/encaps.go
package kem

import (
	"crypto/sha256"
	"encoding/json"
	"math/big"

	"github.com/sergelen02/HPPK_2/internal/core"
)

// 캡슐문 구조(필요 시 확장)
type Ciphertext struct {
	U string `json:"u"` // 예: u = x mod p (hex)
	// TODO: 필요하면 더 추가 (e.g., V, W, noise terms, tags)
}

// Encaps는 (ciphertext, sharedSecret) 두 값을 반환합니다.
// x==nil이면 Z_p에서 난수 선택. noiseMin/Max는 후속 구현에서 사용 가능(현재는 미사용; 시그니처만 유지)
func Encaps(pk *KEMPublic, x *big.Int, noiseMin, noiseMax int64) (*Ciphertext, []byte) {
	F := core.NewField(pk.P)
	if x == nil {
		x = core.RandZp(F)
	}
	uHex := new(big.Int).Mod(x, pk.P).Text(16)

	ct := &Ciphertext{U: uHex}

	// 데모용 공유키: 캡슐문 직렬화 후 해시 (실제 설계로 교체 가능)
	raw, _ := json.Marshal(ct)
	h := sha256.Sum256(raw)
	return ct, h[:] // (ct, shared)
}

// Decaps는 같은 방식으로 공유키를 복원(데모)
// 실제 설계로 교체 시 sk와 ct를 이용한 복원 로직을 채우세요.
func Decaps(sk *KEMSecret, ct *Ciphertext) []byte {
	raw, _ := json.Marshal(ct)
	h := sha256.Sum256(raw)
	return h[:]
}
