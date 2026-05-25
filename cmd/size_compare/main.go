package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/sergelen02/HPPK_2/internal/core"
	"github.com/sergelen02/HPPK_2/internal/ds"
)

type Params struct {
	P string `json:"p"`
	L uint   `json:"L"`
	K uint   `json:"K"`
}

func parseP(s string) *big.Int {
	return core.ParseBigIntAuto(s)
}

func rawBigLen(x *big.Int) int {
	if x == nil {
		return 0
	}
	return len(x.Bytes())
}

func fixedBigLen(x *big.Int, bits uint) int {
	if x == nil {
		return 0
	}
	n := int((bits + 7) / 8)
	if n == 0 {
		return len(x.Bytes())
	}
	return n
}

func hppkPublicSize(pk *ds.Public) int {
	return rawBigLen(pk.P) +
		rawBigLen(pk.Pprime0) + rawBigLen(pk.Pprime1) +
		rawBigLen(pk.Qprime0) + rawBigLen(pk.Qprime1) +
		rawBigLen(pk.Mu0) + rawBigLen(pk.Mu1) +
		rawBigLen(pk.Nu0) + rawBigLen(pk.Nu1) +
		rawBigLen(pk.S1) + rawBigLen(pk.S2) +
		8 // K uint64 기준
}

func hppkSecretSize(sk *ds.Secret) int {
	return rawBigLen(sk.P) +
		rawBigLen(sk.R1) + rawBigLen(sk.S1) +
		rawBigLen(sk.R2) + rawBigLen(sk.S2) +
		rawBigLen(sk.F0) + rawBigLen(sk.F1) +
		rawBigLen(sk.H0) + rawBigLen(sk.H1) +
		8 // K uint64 기준
}

func hppkSignatureSize(sig *ds.Signature) int {
	return len(sig.F) + len(sig.H) + len(sig.U) + len(sig.V)
}

func main() {
	paramPath := "configs/params/level1.json"
	if len(os.Args) >= 2 {
		paramPath = os.Args[1]
	}

	b, err := os.ReadFile(paramPath)
	if err != nil {
		panic(err)
	}

	var cfg Params
	if err := json.Unmarshal(b, &cfg); err != nil {
		panic(err)
	}

	F := core.NewField(parseP(cfg.P))
	sk, pk := ds.KeyGenDS(F, cfg.L, cfg.K)

	msg := []byte("12345678901234567890123456789012") // 32 bytes
	sig, err := ds.SignWithPK(sk, pk, msg)
	if err != nil {
		panic(err)
	}

	ecdsaSK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaSK, digest[:])
	if err != nil {
		panic(err)
	}

	ecdsaPubUncompressed := elliptic.Marshal(elliptic.P256(), ecdsaSK.X, ecdsaSK.Y)
	ecdsaPubCompressed := elliptic.MarshalCompressed(elliptic.P256(), ecdsaSK.X, ecdsaSK.Y)

	ecdsaSigRaw64 := 32 + 32
	ecdsaSigMinimal := rawBigLen(r) + rawBigLen(s)

	rows := [][]string{
		{"scheme", "component", "bytes", "detail"},
		{"ECDSA-P256", "public_key_uncompressed", fmt.Sprint(len(ecdsaPubUncompressed)), "04||X||Y"},
		{"ECDSA-P256", "public_key_compressed", fmt.Sprint(len(ecdsaPubCompressed)), "02/03||X"},
		{"ECDSA-P256", "private_key", "32", "scalar d"},
		{"ECDSA-P256", "signature_raw_fixed", fmt.Sprint(ecdsaSigRaw64), "r(32)+s(32)"},
		{"ECDSA-P256", "signature_minimal_bigint", fmt.Sprint(ecdsaSigMinimal), "len(r.Bytes())+len(s.Bytes())"},

		{"HPPK-DS", "public_key_full", fmt.Sprint(hppkPublicSize(pk)), "P+p0+p1+q0+q1+mu0+mu1+nu0+nu1+S1+S2+K"},
		{"HPPK-DS", "private_key_full", fmt.Sprint(hppkSecretSize(sk)), "P+R1+S1+R2+S2+f0+f1+h0+h1+K"},
		{"HPPK-DS", "signature_full", fmt.Sprint(hppkSignatureSize(sig)), "F+H+U+V"},
		{"HPPK-DS", "signature_FH_only_wrong_metric", fmt.Sprint(len(sig.F) + len(sig.H)), "비교용: 실제 Verify 입력 전체가 아님"},
		{"HPPK-DS", "signature_UV_extra", fmt.Sprint(len(sig.U) + len(sig.V)), "U+V"},
	}

	out := "results/offchain/size_compare.csv"
	_ = os.MkdirAll("results/offchain", 0755)

	f, err := os.Create(out)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	for _, row := range rows {
		if err := w.Write(row); err != nil {
			panic(err)
		}
	}

	fmt.Println("written:", out)
}
