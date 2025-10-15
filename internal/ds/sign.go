package ds

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/sergelen02/HPPK_2/internal/core"
)

type Signature struct {
	F []byte // F value (reduced to field p for portability)
	H []byte // H value (reduced to field p for portability)
	U []byte // φ_A(H) mod p
	V []byte // φ_B(F) mod p
}

func Sign(sk *Secret, msg []byte) (*Signature, error) {
	// 유한체(F_p) 컨텍스트
	Fq := core.NewField(sk.P)

	// 메시지를 x ∈ F_p로 해시
	x := core.HashToX(sk.P, msg)

	// f(x), h(x) = (f1*x + f0), (h1*x + h0)  (정수 영역)
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

	// 공개키에 저장된 p0,p1,q0,q1을 사용해서 U,V 계산 (서명자가 직접 계산하여 함께 보냄)
	// U = φ_A(H) = (p0 + p1 * x) * H  mod p
	// V = φ_B(F) = (q0 + q1 * x) * F  mod p
	// (여기서는 Public 구조의 필드명을 그대로 사용한다고 가정)
	// NOTE: Sign은 sk만 받으므로 보통 p0/p1/q0/q1은 sk에서 유추하거나 sk이 아닌 별도 pk가 필요.
	// 데모에서는 sk에 같은 값들이 들어있다고 가정하거나, 키 생성 시 sk에 pk 필드를 포함하세요.
	// 여기서는 실용성을 위해 sk에 같은 스케일 계수를 임시로 포함한다고 가정하여 구현.
	// 만약 sk에 없다면 Sign 함수에 pk 인자를 추가하도록 수정하세요.

	// --- 데모 목적: sk가 갖고 있다 가정(실환경에선 Sign에 pk 인자를 전달) ---
	// 아래는 pk-like values을 sk에서 찾는다고 가정한 구현 (필요시 변경)
	// For safety, ensure sk has corresponding fields or pass pk into Sign.

	// we attempt to fetch p0,p1,q0,q1 via reflection-like expectation:
	// to keep code simple for demo, assume sk has Pprime0/Pprime1/Qprime0/Qprime1 fields.
	// If not present in sk, the caller should call Sign with the pk available.

	type pkish struct {
		Pprime0 *big.Int `json:"p0"`
		Pprime1 *big.Int `json:"p1"`
		Qprime0 *big.Int `json:"q0"`
		Qprime1 *big.Int `json:"q1"`
	}
	var probe pkish
	// try marshal/unmarshal sk -> probe (cheap and robust)
	b, _ := json.Marshal(sk)
	_ = json.Unmarshal(b, &probe)

	if probe.Pprime0 == nil || probe.Pprime1 == nil || probe.Qprime0 == nil || probe.Qprime1 == nil {
		// unable to compute U/V from sk alone — caller should provide pk
		// For minimal change: return signature with F/H only (but then Verify must accept)
		// Here we fail explicitly to avoid silent inconsistent behavior.
		return nil, fmt.Errorf("Sign: missing pk scaling values in secret; call Sign with pk or embed p0/q0 in sk for demo")
	}

	// compute alpha = p0 + p1*x  (mod p)
	alpha := new(big.Int).Add(probe.Pprime0, new(big.Int).Mul(probe.Pprime1, x))
	alpha.Mod(alpha, sk.P)
	if alpha.Sign() < 0 { alpha.Add(alpha, sk.P) }

	// compute beta = q0 + q1*x  (mod p)
	beta := new(big.Int).Add(probe.Qprime0, new(big.Int).Mul(probe.Qprime1, x))
	beta.Mod(beta, sk.P)
	if beta.Sign() < 0 { beta.Add(beta, sk.P) }

	U := new(big.Int).Mod(new(big.Int).Mul(alpha, Hv), sk.P)
	V := new(big.Int).Mod(new(big.Int).Mul(beta, Fv), sk.P)

	// assemble signature
	sig := &Signature{
		F: Fv.Bytes(),
		H: Hv.Bytes(),
		U: U.Bytes(),
		V: V.Bytes(),
	}
	return sig, nil
}

func WriteJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
