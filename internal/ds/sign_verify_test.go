package tests


import (
"math/big"
"testing"
"github.com/yourname/hppk/internal/ds"
)


func TestSignVerify(t *testing.T){
p := new(big.Int); p.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61",16)
sk, pk := ds.KeyGenDS(p, 192, 256)
msg := []byte("hello quantum")
sig, _ := ds.Sign(sk, msg)
if !ds.Verify(pk, msg, sig){ t.Fatal("verify failed") }
}