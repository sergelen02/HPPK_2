package main


import (
"encoding/json"
"flag"
"fmt"
"io/ioutil"
"github.com/yourname/hppk/internal/ds"
)


func main(){
pkPath := flag.String("pk","pk.json","public key json")
in := flag.String("in","msg.txt","message file")
sigPath := flag.String("sig","sig.json","signature json")
flag.Parse()
var pk ds.Public; json.Unmarshal(read(*pkPath), &pk)
var sig ds.Signature; json.Unmarshal(read(*sigPath), &sig)
ok := ds.Verify(&pk, read(*in), &sig)
fmt.Println(ok)
}


func read(p string) []byte { b,_ := ioutil.ReadFile(p); return b }