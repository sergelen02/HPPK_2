// internal/kem/encaps.go
// internal/kem/encaps.go
package kem

import (
	"crypto/sha256"
	"encoding/json"
	"math/big"

	"github.com/sergelen02/HPPK_2/internal/core"
)

// 캡슐문 구조
type Ciphertext struct {
	U string `json:"u"` // 예: u = x mod p (hex)
}

// Encaps: (ciphertext, sharedSecret) 반환
func Encaps(pk *KEMPublic, x *big.Int, noiseMin, noiseMax int64) (*Ciphertext, []byte) {
	F := core.NewField(pk.P)
	if x == nil {
		x = core.RandZp(F)
	}
	ct := &Ciphertext{U: new(big.Int).Mod(x, pk.P).Text(16)}

	raw, _ := json.Marshal(ct)
	h := sha256.Sum256(raw)
	return ct, h[:]
}

// Decaps: 데모용(실제 설계로 교체 가능)
func Decaps(sk *KEMSecret, ct *Ciphertext) []byte {
	raw, _ := json.Marshal(ct)
	h := sha256.Sum256(raw)
	return h[:]
}
