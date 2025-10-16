// cmd/ds/sign/main.go
package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/sergelen02/HPPK_2/internal/ds"
)

func main() {
	// flags
	skPath := flag.String("sk",  "sk.json",  "secret key JSON path")
	pkPath := flag.String("pk",  "pk.json",  "public key JSON path")
	inPath := flag.String("in",  "msg.txt",  "message file to sign")
	outSig := flag.String("out", "sig.json", "signature JSON output path")
	flag.Parse()

	// load keys
	var sk ds.Secret
	var pk ds.Public
	mustReadJSON(*skPath, &sk)
	mustReadJSON(*pkPath, &pk)

	// read message
	msg, err := os.ReadFile(*inPath)
	if err != nil {
		log.Fatalf("read %s: %v", *inPath, err)
	}

	// sign (Sign must be Sign(sk, pk, msg [bit]))
	sig, err := ds.SignWithPK(&sk, &pk, msg)
	if err != nil {
		log.Fatal(err)
	}

	// write signature JSON
	mustWriteJSON(*outSig, sig)
}

// --- helpers ---
func mustReadJSON(path string, v any) {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		log.Fatalf("unmarshal %s: %v", path, err)
	}
}

func mustWriteJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
}
