package core


import (
"crypto/sha256"
"encoding/hex"
"math/big"
)


// HashToX: x = H(M) mod p
func HashToX(p *big.Int, msg []byte) *big.Int {
h := sha256.Sum256(msg)
x := new(big.Int).SetBytes(h[:])
x.Mod(x, p)
if x.Sign() == 0 { x.SetInt64(1) }
return x
}


func Hex(b []byte) string { return hex.EncodeToString(b) }