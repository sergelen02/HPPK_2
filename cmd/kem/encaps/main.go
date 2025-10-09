package main


import (
"encoding/json"
"flag"
"io/ioutil"
"math/big"
"github.com/yourname/hppk/internal/kem"
)


func main(){
pkPath := flag.String("pk","pk_kem.json","public json")
out := flag.String("out","ct.json","cipher out")
xHex := flag.String("x","","optional x hex")
flag.Parse()
var pk kem.KEMPublic; json.Unmarshal(read(*pkPath), &pk)
var x *big.Int
if *xHex == "" { x = big.NewInt(12345) } else { x=new(big.Int); x.SetString(*xHex,0) }
ct := kem.Encaps(&pk, x, 1, 5)
write(*out, pretty(ct))
}


func read(p string) []byte { b,_ := ioutil.ReadFile(p); return b }
func write(p string, b []byte){ _ = ioutil.WriteFile(p,b,0o644) }
func pretty(v any) []byte { b,_ := json.MarshalIndent(v,""," "); return b }