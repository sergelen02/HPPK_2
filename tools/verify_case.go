package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sergelen02/HPPK_2/internal/ds"
)

func mustRead(p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", p, err)
		os.Exit(1)
	}
	return b
}

func main() {
	dir := "/tmp/hppkcase"
	F := mustRead(filepath.Join(dir, "F.bin"))
	H := mustRead(filepath.Join(dir, "H.bin"))
	U := mustRead(filepath.Join(dir, "U.bin"))
	V := mustRead(filepath.Join(dir, "V.bin"))
	pkJSON := mustRead(filepath.Join(dir, "pk.json"))
	msg := mustRead(filepath.Join(dir, "msg.bin"))

	var pk ds.Public
	if err := json.Unmarshal(pkJSON, &pk); err != nil {
		fmt.Fprintf(os.Stderr, "pk json unmarshal: %v\n", err)
		os.Exit(1)
	}

	sig := &ds.Signature{F: F, H: H, U: U, V: V}
	ok := ds.Verify(&pk, msg, sig)
	fmt.Printf("OFFCHAIN_VERIFY=%v\n", ok)
	fmt.Printf("lens F=%d H=%d U=%d V=%d pk=%d msg=%d\n", len(F), len(H), len(U), len(V), len(pkJSON), len(msg))
}
