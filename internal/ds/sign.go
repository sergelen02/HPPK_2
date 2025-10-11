package ds

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/sergelen02/HPPK_2/internal/core"
)

type Signature struct {
	F, H []byte
}

func Sign(sk *Secret, msg []byte) (*Signature, error) {
	// 유한체(F_p) 컨텍스트
	Fq := core.NewField(sk.P)

	// 메시지를 x ∈ F_p로 해시
	x := core.HashToX(sk.P, msg)

	// f(x), h(x) = (f1*x + f0), (h1*x + h0)
	fx := new(big.Int).Add(new(big.Int).Mul(sk.F1, x), sk.F0)
	hx := new(big.Int).Add(new(big.Int).Mul(sk.H1, x), sk.H0)

	// R⁻¹ mod S (정수환에서 역원: (R mod S)의 모듈러 역원)
	r2inv := new(big.Int).ModInverse(new(big.Int).Mod(sk.R2, sk.S2), sk.S2)
	r1inv := new(big.Int).ModInverse(new(big.Int).Mod(sk.R1, sk.S1), sk.S1)
	if r2inv == nil || r1inv == nil {
		return nil, fmt.Errorf("no modular inverse for R mod S")
	}

	// F = f(x) * R2^{-1} mod S2, H = h(x) * R1^{-1} mod S1
	Fv := new(big.Int).Mod(new(big.Int).Mul(fx, r2inv), sk.S2)
	Hv := new(big.Int).Mod(new(big.Int).Mul(hx, r1inv), sk.S1)

	// 최종적으로 F_p로 정규화 (서명 직렬화 전에 mod p)
	Fv = Fq.Norm(Fv)
	Hv = Fq.Norm(Hv)

	return &Signature{F: Fv.Bytes(), H: Hv.Bytes()}, nil
}

func WriteJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
