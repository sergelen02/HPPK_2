package hppkapi

import (
	"encoding/json"

	ds "github.com/sergelen02/HPPK_2/internal/ds"
)

type Public = ds.Public
type Secret = ds.Secret
type Signature = ds.Signature

func DecodePublicJSON(b []byte) (*Public, error) {
	var pk Public
	if err := json.Unmarshal(b, &pk); err != nil {
		return nil, err
	}
	return &pk, nil
}

func DecodeSecretJSON(b []byte) (*Secret, error) {
	var sk Secret
	if err := json.Unmarshal(b, &sk); err != nil {
		return nil, err
	}
	return &sk, nil
}

func DecodeSignatureJSON(b []byte) (*Signature, error) {
	var sig Signature
	if err := json.Unmarshal(b, &sig); err != nil {
		return nil, err
	}
	return &sig, nil
}

func EncodeSignatureJSON(sig *Signature) ([]byte, error) {
	return json.Marshal(sig)
}

func SignWithPK(sk *Secret, pk *Public, msg []byte) (*Signature, error) {
	return ds.SignWithPK(sk, pk, msg)
}

func Verify(pk *Public, msg []byte, sig *Signature) bool {
	return ds.Verify(pk, msg, sig)
}
