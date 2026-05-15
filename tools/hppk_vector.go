package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/sergelen02/HPPK_2/internal/core"
	"github.com/sergelen02/HPPK_2/internal/ds"
)

func main() {
	// golden_test.go 와 동일
	F := core.NewField(big.NewInt(65537))
	sk, pk := ds.KeyGenDS(F, uint(2), uint(1))
	if sk == nil || pk == nil {
		fmt.Fprintln(os.Stderr, "KeyGenDS returned nil")
		os.Exit(1)
	}

	msg := []byte("abc")

	sig, err := ds.SignWithPK(sk, pk, msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SignWithPK error: %v\n", err)
		os.Exit(1)
	}

	if !ds.Verify(pk, msg, sig) {
		fmt.Fprintln(os.Stderr, "Verify failed (unexpected)")
		os.Exit(1)
	}

	pkJSON, err := json.Marshal(pk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "json.Marshal(pk) error: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile("/tmp/pk.json", pkJSON, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write pk.json error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("PK_JSON_PATH=/tmp/pk.json")
	fmt.Println("MSG=abc")
	fmt.Println("F_B64=" + base64.StdEncoding.EncodeToString(sig.F))
	fmt.Println("H_B64=" + base64.StdEncoding.EncodeToString(sig.H))
	fmt.Println("U_B64=" + base64.StdEncoding.EncodeToString(sig.U))
	fmt.Println("V_B64=" + base64.StdEncoding.EncodeToString(sig.V))
}
