package tests


import (
"math/big"
"testing"
"github.com/yourname/hppk/internal/kem"
)


func TestKEMRoundtrip(t *testing.T){
pp := kem.LoadParams("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61", 192, 256, 1, 5)
sk, pk := kem.KeyGenKEM(pp)
for i:=0;i<50;i++{
x := big.NewInt(int64(12345+i))
ct := kem.Encaps(pk, x, 1, 5)
x2 := kem.Decaps(sk, ct)
if x2.Cmp(new(big.Int).Mod(x, sk.P))!=0 { t.Fatalf("mismatch") }
}
}