package main

import (
	"encoding/hex"
	"fmt"

	"github.com/sergelen02/HPPK_2/internal/ds"
)

func main() {
	pp := ds.DefaultParams()
	sk, pk := ds.KeyGen(pp, pp.N)
	fmt.Println("F0:", hex.EncodeToString(sk.F0.Bytes()))
	fmt.Println("S1p:", hex.EncodeToString(pk.S1p.Bytes()))
}
