package ds


import (
"encoding/json"
"github.com/yourname/hppk/internal/core"
"io/ioutil"
)


type Signature struct { F, H []byte }


func Sign(sk *Secret, msg []byte) (*Signature, error) {
Fq := core.NewField(sk.P)
x := core.HashToX(sk.P, msg)
// F = f(x) * R2^{-1} mod S2 (we compute in integers, then reduce)
fx := new(big.Int).Add(new(big.Int).Mul(sk.F1, x), sk.F0)
hx := new(big.Int).Add(new(big.Int).Mul(sk.H1, x), sk.H0)
// Inverse of R modulo S: we approximate using big.Int.ModInverse on (R mod S)
r2inv := new(big.Int).ModInverse(new(big.Int).Mod(sk.R2, sk.S2), sk.S2)
r1inv := new(big.Int).ModInverse(new(big.Int).Mod(sk.R1, sk.S1), sk.S1)
if r2inv == nil || r1inv == nil { return nil, ioErr("no inv") }
Fv := new(big.Int).Mod(new(big.Int).Mul(fx, r2inv), sk.S2)
Hv := new(big.Int).Mod(new(big.Int).Mul(hx, r1inv), sk.S1)
Fv = Fq.Norm(Fv)
Hv = Fq.Norm(Hv)
return &Signature{F:Fv.Bytes(), H:Hv.Bytes()}, nil
}


func ioErr(s string) error { return fmt.Errorf(s) }


func WriteJSON(path string, v any) error {
b, _ := json.MarshalIndent(v, "", " ")
return ioutil.WriteFile(path, b, 0o644)
}