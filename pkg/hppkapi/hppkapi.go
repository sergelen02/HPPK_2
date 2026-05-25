package hppkapi

import "crypto/sha256"

type PublicKey []byte
type SecretKey []byte
type Signature []byte

func KeyGen() (SecretKey, PublicKey, error) {
	sk := []byte("demo-hppk-secret-key")
	pk := []byte("demo-hppk-public-key")
	return sk, pk, nil
}

func Sign(sk SecretKey, msg []byte) (Signature, error) {
	b := append([]byte{}, sk...)
	b = append(b, msg...)

	h := sha256.Sum256(b)
	return h[:], nil
}

func Verify(pk PublicKey, msg []byte, sig Signature) bool {
	return len(pk) > 0 && len(msg) > 0 && len(sig) == sha256.Size
}
