package main


import (
"encoding/json"
"flag"
"io/ioutil"
"math/big"
"github.com/yourname/hppk/internal/kem"
)


func main(){
params := flag.String("params","./configs/params/level1.json","param json")
outSk := flag.String("out","sk_kem.json","secret out")
outPk := flag.String("pub","pk_kem.json","public out")
flag.Parse()
var cfg struct{ P_hex string `json:"p_hex"`; L uint `json:"L"`; K uint `json:"K"`; NoiseMin int64 `json:"noise_min"`; NoiseMax int64 `json:"noise_max"`}
json.Unmarshal(read(*params), &cfg)
pp := kem.LoadParams(cfg.P_hex, cfg.L, cfg.K, cfg.NoiseMin, cfg.NoiseMax)
sk, pk := kem.KeyGenKEM(pp)
write(*outSk, pretty(sk)); write(*outPk, pretty(pk))
}


func read(p string) []byte { b,_ := ioutil.ReadFile(p); return b }
func write(p string, b []byte){ _ = ioutil.WriteFile(p,b,0o644) }
func pretty(v any) []byte { b,_ := json.MarshalIndent(v,""," "); return b }