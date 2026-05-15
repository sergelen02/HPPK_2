package hppkapi

import (
	"encoding/json"
	"fmt"

	"github.com/sergelen02/HPPK_2/internal/ds"
)

// precompile 입력 파트 그대로 받아 검증
func VerifyFromParts(sigF, sigH, sigU, sigV, pkJSON, msg []byte) (bool, error) {
	if len(sigF)==0 || len(sigH)==0 || len(sigU)==0 || len(sigV)==0 || len(pkJSON)==0 || len(msg)==0 {
		return false, fmt.Errorf("empty parts")
	}

	var pk ds.Public
	if err := json.Unmarshal(pkJSON, &pk); err != nil {
		return false, fmt.Errorf("pk json unmarshal: %w", err)
	}

	var sig ds.Signature
	// ⚠️ 여기 4줄은 ds.Signature 실제 필드명에 맞게 바뀔 수 있습니다(에러가 알려줌)
	sig.F = sigF
	sig.H = sigH
	sig.U = sigU
	sig.V = sigV

	ok := ds.Verify(&pk, msg, &sig)
	return ok, nil
}
