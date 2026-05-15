package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/sergelen02/HPPK_2/internal/core"
	"github.com/sergelen02/HPPK_2/internal/ds"
)

func mustWrite(path string, b []byte) {
	if err := os.WriteFile(path, b, 0o644); err != nil {
		panic(err)
	}
}

func main() {
	outDir := flag.String("out", "/tmp/hppkcase", "output directory")
	msgStr := flag.String("msg", "hello-phaseA", "message")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		panic(err)
	}

	F := core.NewField(big.NewInt(65537))

	sk, pk := ds.KeyGenDS(F, 2, 1)

	msg := []byte(*msgStr)
	sig, err := ds.SignWithPK(sk, pk, msg)
	if err != nil {
		panic(err)
	}

	pkJSON, err := json.Marshal(pk)
	if err != nil {
		panic(err)
	}
	mustWrite(filepath.Join(*outDir, "pk.json"), pkJSON)
	mustWrite(filepath.Join(*outDir, "msg.bin"), msg)

	mustWrite(filepath.Join(*outDir, "F.bin"), sig.F)
	mustWrite(filepath.Join(*outDir, "H.bin"), sig.H)
	mustWrite(filepath.Join(*outDir, "U.bin"), sig.U)
	mustWrite(filepath.Join(*outDir, "V.bin"), sig.V)

	fmt.Println("wrote:", *outDir)
}
