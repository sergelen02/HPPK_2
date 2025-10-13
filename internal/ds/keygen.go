package ds

import (
	"encoding/json"
	"math/big"

	"github.com/sergelen02/HPPK_2/internal/core"
)

type Secret struct {
	P  *big.Int `json:"p"`
	R1 *big.Int `json:"r1"`
	S1 *big.Int `json:"s1"`
	R2 *big.Int `json:"r2"`
	S2 *big.Int `json:"s2"`
	F0 *big.Int `json:"f0"`
	F1 *big.Int `json:"f1"`
	H0 *big.Int `json:"h0"`
	H1 *big.Int `json:"h1"`
	K  uint     `json:"K"` // Barrett bits (데모용)
}

type Public struct {
	P *big.Int `json:"p"`

	// 검증식에 쓰이는 선형 계수(스케일된 공개값)
	Pprime0 *big.Int `json:"p0"`
	Pprime1 *big.Int `json:"p1"`
	Qprime0 *big.Int `json:"q0"`
	Qprime1 *big.Int `json:"q1"`

	// Barrett 근사 파라미터(현재 검증 경량화 경로에서는 미사용이지만 보존)
	Mu0 *big.Int `json:"mu0"`
	Mu1 *big.Int `json:"mu1"`
	Nu0 *big.Int `json:"nu0"`
	Nu1 *big.Int `json:"nu1"`

	// ★ 실제 모듈러스(검증에서 s로 사용하려면 공개되어 있어야 함)
	S1 *big.Int `json:"S1"`
	S2 *big.Int `json:"S2"`

	K uint `json:"K"`
}

// 선택적: 남겨두려면 그대로 두세요.
type Params struct {
	P *big.Int
	L uint
	K uint
}

// Field(모듈러스) 기반 KeyGen — RandZp/Norm 일관성 확보
func KeyGenDS(F *core.Field, L, K uint) (*Secret, *Public) {
	if F == nil || F.P == nil || F.P.Sign() <= 0 {
		panic("KeyGenDS: invalid field modulus p")
	}
	if L < 2 {
		panic("KeyGenDS: L must be >= 2")
	}

	p := F.P

	// f, h ← Z_p
	f0, f1 := core.RandZp(F), core.RandZp(F)
	h0, h1 := core.RandZp(F), core.RandZp(F)

	// 링 파라미터
	R := new(big.Int).Lsh(big.NewInt(1), L)
	S1 := new(big.Int).Add(core.RandZp(F), new(big.Int).Lsh(big.NewInt(1), L-1))
	S2 := new(big.Int).Add(core.RandZp(F), new(big.Int).Lsh(big.NewInt(1), L-1))
	for new(big.Int).GCD(nil, nil, R, S1).Cmp(big.NewInt(1)) != 0 {
		S1.Add(S1, big.NewInt(1))
	}
	for new(big.Int).GCD(nil, nil, R, S2).Cmp(big.NewInt(1)) != 0 {
		S2.Add(S2, big.NewInt(1))
	}

	// 데모 스케일(필요시 조정 가능)
	beta := new(big.Int).Lsh(big.NewInt(1), 8)
	p0 := new(big.Int).Mod(new(big.Int).Mul(beta, f0), p)
	p1 := new(big.Int).Mod(new(big.Int).Mul(beta, f1), p)
	q0 := new(big.Int).Mod(new(big.Int).Mul(beta, h0), p)
	q1 := new(big.Int).Mod(new(big.Int).Mul(beta, h1), p)

	// 근사 계수(참고용/보존)
	mu0 := new(big.Int).Quo(new(big.Int).Mul(R, f0), S1)
	mu1 := new(big.Int).Quo(new(big.Int).Mul(R, f1), S1)
	nu0 := new(big.Int).Quo(new(big.Int).Mul(R, h0), S2)
	nu1 := new(big.Int).Quo(new(big.Int).Mul(R, h1), S2)

	sk := &Secret{
		P: p, R1: R, S1: S1, R2: R, S2: S2,
		F0: f0, F1: f1, H0: h0, H1: h1, K: K,
	}
	pk := &Public{
		P: p,
		Pprime0: p0, Pprime1: p1,
		Qprime0: q0, Qprime1: q1,
		Mu0: mu0, Mu1: mu1, Nu0: nu0, Nu1: nu1,
		S1: S1, S2: S2, // ← 핵심: 검증에서 바로 사용할 실제 모듈러스
		K:  K,
	}
	return sk, pk
}

func (sk *Secret) MarshalJSON() ([]byte, error) { type A Secret; return json.Marshal((*A)(sk)) }
func (pk *Public) MarshalJSON() ([]byte, error) { type A Public; return json.Marshal((*A)(pk)) }
