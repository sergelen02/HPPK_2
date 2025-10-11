package main


import (
"encoding/json"
"flag"
"io/ioutil"
"github.com/sergelen02/HPPK_2/internal/ds"
)


func main(){
skPath := flag.String("sk","sk.json","secret key json")
in := flag.String("in","msg.txt","message file")
out := flag.String("out","sig.json","signature out")
flag.Parse()
var sk ds.Secret
json.Unmarshal(read(*skPath), &sk)
msg := read(*in)
sig, _ := ds.Sign(&sk, msg)
write(*out, pretty(sig))
}


func read(p string) []byte { b,_ := ioutil.ReadFile(p); return b }
func write(p string, b []byte) { _ = ioutil.WriteFile(p,b,0o644) }
func pretty(v any) []byte { b,_ := json.MarshalIndent(v,""," "); return b }