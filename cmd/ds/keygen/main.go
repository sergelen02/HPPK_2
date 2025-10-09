package main


import (
"encoding/json"
"flag"
"io/ioutil"
"math/big"
"github.com/yourname/hppk/internal/ds"
)


func main(){
params := flag.String("params", "./configs/params/level1.json", "param json")
outSk := flag.String("out", "sk.json", "secret out")
outPk := flag.String("pub", "pk.json", "public out")
flag.Parse()
b, _ := ioutil.ReadFile(*params)
var cfg struct{ P_hex string `json:"p_hex"`; L uint `json:"L"`; K uint `json:"K"`}
json.Unmarshal(b, &cfg)
p := new(big.Int); p.SetString(cfg.P_hex,16)
sk, pk := ds.KeyGenDS(p, cfg.L, cfg.K)


ioutil.WriteFile(*outSk, must(json.MarshalIndent(sk,""," ")), 0o644)
ioutil.WriteFile(*outPk, must(json.MarshalIndent(pk,""," ")), 0o644)
}


func must(b []byte, _ error) []byte { return b }