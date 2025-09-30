package main

import (
	"fmt"

	"github.com/sergelen02/HPPK_2/internal/ds"
)

func main() {
	pp := ds.DefaultParams()
	sk, pk := ds.KeyGen(pp, pp.N)
	msg := []byte("hello-phaseA")
	sig, _ := ds.Sign(pp, sk, msg)
	ok := ds.Verify(pp, pk, msg, sig)
	fmt.Println("verify:", ok)
}
