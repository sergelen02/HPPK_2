package main


import (
"encoding/json"
"flag"
"fmt"
"io/ioutil"
"github.com/yourname/hppk/internal/kem"
)


func main(){
skPath := flag.String("sk","sk_kem.json","secret json")
ctPath := flag.String("ct","ct.json","cipher json")
flag.Parse()
var sk kem.KEMSecret; json.Unmarshal(read(*skPath), &sk)
var ct kem.Cipher; json.Unmarshal(read(*ctPath), &ct)
x := kem.Decaps(&sk, &ct)
fmt.Printf("x=%s\n", x.Text(16))
}


func read(p string) []byte { b,_ := ioutil.ReadFile(p); return b }