package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"

	"github.com/sergelen02/HPPK_2/internal/core"
	"github.com/sergelen02/HPPK_2/internal/ds"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func makeMsg(msgLen int) []byte {
	if msgLen <= 0 {
		msgLen = 1
	}
	msg := make([]byte, msgLen)
	for i := 0; i < msgLen; i++ {
		msg[i] = byte('a' + (i % 26))
	}
	return msg
}

func main() {
	// usage: go run ./tools/make_case.go [msgLen]
	msgLen := 3
	if len(os.Args) >= 2 {
		n, err := strconv.Atoi(os.Args[1])
		if err != nil || n <= 0 {
			fmt.Fprintf(os.Stderr, "invalid msgLen: %q\n", os.Args[1])
			os.Exit(1)
		}
		msgLen = n
	}

	dir := "/tmp/hppkcase"
	must(os.MkdirAll(dir, 0755))

	Fld := core.NewField(big.NewInt(65537))
	sk, pk := ds.KeyGenDS(Fld, uint(2), uint(1))
	if sk == nil || pk == nil {
		fmt.Fprintln(os.Stderr, "KeyGenDS returned nil")
		os.Exit(1)
	}

	msg := makeMsg(msgLen)

	sig, err := ds.SignWithPK(sk, pk, msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SignWithPK error: %v\n", err)
		os.Exit(1)
	}
	if sig == nil {
		fmt.Fprintln(os.Stderr, "SignWithPK returned nil sig")
		os.Exit(1)
	}

	if !ds.Verify(pk, msg, sig) {
		fmt.Fprintln(os.Stderr, "Verify failed (unexpected)")
		os.Exit(1)
	}

	pkJSON, err := json.Marshal(pk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "json.Marshal(pk): %v\n", err)
		os.Exit(1)
	}

	must(os.WriteFile(filepath.Join(dir, "pk.json"), pkJSON, 0644))
	must(os.WriteFile(filepath.Join(dir, "msg.bin"), msg, 0644))
	must(os.WriteFile(filepath.Join(dir, "F.bin"), sig.F, 0644))
	must(os.WriteFile(filepath.Join(dir, "H.bin"), sig.H, 0644))
	must(os.WriteFile(filepath.Join(dir, "U.bin"), sig.U, 0644))
	must(os.WriteFile(filepath.Join(dir, "V.bin"), sig.V, 0644))

	fmt.Println("WROTE /tmp/hppkcase/{F,H,U,V}.bin, pk.json, msg.bin (consistent set)")
	// 한 줄로 출력 (newline-in-string 방지)
	fmt.Printf("lens F=%d H=%d U=%d V=%d pk=%d msg=%d\n", len(sig.F), len(sig.H), len(sig.U), len(sig.V), len(pkJSON), len(msg))
}
