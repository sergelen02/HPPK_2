package hppkapi

import (
	"encoding/json"
	"fmt"

	ds "github.com/sergelen02/HPPK_2/internal/ds"
)

type Secret = ds.Secret
type Public = ds.Public
type Signature = ds.Signature

func DecodeSecretJSON(b []byte) (*Secret, error) {
	var sk Secret
	if err := json.Unmarshal(b, &sk); err != nil {
		return nil, fmt.Errorf("decode secret json: %w", err)
	}
	if sk.P == nil || sk.P.Sign() == 0 {
		return nil, fmt.Errorf("decode secret json: invalid modulus p")
	}
	return &sk, nil
}

func DecodePublicJSON(b []byte) (*Public, error) {
	var pk Public
	if err := json.Unmarshal(b, &pk); err != nil {
		return nil, fmt.Errorf("decode public json: %w", err)
	}
	if pk.P == nil || pk.P.Sign() == 0 {
		return nil, fmt.Errorf("decode public json: invalid modulus p")
	}
	return &pk, nil
}

func DecodeSignatureJSON(b []byte) (*Signature, error) {
	var sig Signature
	if err := json.Unmarshal(b, &sig); err != nil {
		return nil, fmt.Errorf("decode signature json: %w", err)
	}
	return &sig, nil
}

func EncodeSignatureJSON(sig *Signature) ([]byte, error) {
	if sig == nil {
		return nil, fmt.Errorf("signature is nil")
	}
	out, err := json.Marshal(sig)
	if err != nil {
		return nil, fmt.Errorf("encode signature json: %w", err)
	}
	return out, nil
}

func SignWithPK(sk *Secret, pk *Public, msg []byte) (*Signature, error) {
	return ds.SignWithPK(sk, pk, msg)
}

func Verify(pk *Public, msg []byte, sig *Signature) bool {
	return ds.Verify(pk, msg, sig)
}
