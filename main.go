package main

import (
    "fmt"
    "github.com/sergelen02/HPPK_2/internal/ds"
)

func main() {
    msg := []byte("hello hppk")

    pk, sk := ds.KeyGen()

    sig := ds.Sign(sk, msg)

    ok := ds.Verify(pk, msg, sig)

    fmt.Println("verify:", ok)

    fmt.Printf("pk: %x\n", pk)
    fmt.Printf("sig: %x\n", sig)
}
