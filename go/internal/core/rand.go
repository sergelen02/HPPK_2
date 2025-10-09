package core


import (
"crypto/rand"
"math/big"
)


func RandZp(p *big.Int) *big.Int {
r, _ := rand.Int(rand.Reader, p)
if r.Sign() == 0 { r.SetInt64(1) }
return r
}


// random in [min,max]
func RandIntRange(min, max int64) *big.Int {
if max < min { max, min = min, max }
rng := big.NewInt(max - min + 1)
r, _ := rand.Int(rand.Reader, rng)
r.Add(r, big.NewInt(min))
return r
}