// cmd/kem/decaps/main.go
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/sergelen02/HPPK_2/internal/kem"
)

func main() {
	skPath := flag.String("sk", "sk_kem.json", "secret key JSON")
	ctPath := flag.String("ct", "ct.json", "ciphertext JSON")
	keyOut := flag.String("key", "", "optional shared key output file (raw bytes)")
	flag.Parse()

	var sk kem.KEMSecret
	mustReadJSON(*skPath, &sk)

	var ct kem.Ciphertext
	mustReadJSON(*ctPath, &ct)

	shared := kem.Decaps(&sk, &ct)

	if *keyOut != "" {
		if err := os.WriteFile(*keyOut, shared, 0o600); err != nil {
			log.Fatalf("write %s: %v", *keyOut, err)
		}
		fmt.Printf("shared key written to %s (%d bytes)\n", *keyOut, len(shared))
	} else {
		fmt.Printf("shared key (%d bytes): %s\n", len(shared), hex.EncodeToString(shared))
	}
}

func mustReadJSON(path string, v any) {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		log.Fatalf("unmarshal %s: %v", path, err)
	}
}
