package main

import (
	"encoding/hex"
	"fmt"

	"github.com/sergelen02/HPPK_2/internal/ds"
)

func main() {
	pp := ds.DefaultParams()
	sk, _ := ds.KeyGen(pp, pp.N)
	msg := []byte("hello-phaseA")
	sig, err := ds.Sign(pp, sk, msg)
	if err != nil {
		panic(err)
	}
	fmt.Println("F:", hex.EncodeToString(sig.F.Bytes()))
	fmt.Println("H:", hex.EncodeToString(sig.H.Bytes()))
}
