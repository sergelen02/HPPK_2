package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"runtime"
	"sort"
	"strconv"
	"time"

	"github.com/sergelen02/HPPK_2/internal/core"
	"github.com/sergelen02/HPPK_2/internal/ds"
)

const ITER = 1000

type RawRow struct {
	Scheme    string
	Operation string
	InputType string
	InputSize int
	Iteration int
	TimeNS    int64
	Success   bool
}

type SummaryRow struct {
	Scheme    string
	Operation string
	InputType string
	InputSize int
	Count     int
	MeanNS    float64
	MedianNS  float64
	StddevNS  float64
	MinNS     int64
	MaxNS     int64
	MeanUS    float64
	MeanMS    float64
}

func writeCSV(path string, header []string, rows [][]string) {
	os.MkdirAll("/home/sergelen.8711/exp-hppk/results/offchain", 0755)

	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write(header); err != nil {
		panic(err)
	}
	for _, r := range rows {
		if err := w.Write(r); err != nil {
			panic(err)
		}
	}
}

func jsonSize(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return len(fmt.Sprintf("%#v", v))
	}
	return len(b)
}

func summarize(rows []RawRow) []SummaryRow {
	group := map[string][]RawRow{}

	for _, r := range rows {
		key := r.Scheme + "|" + r.Operation + "|" + r.InputType + "|" + strconv.Itoa(r.InputSize)
		group[key] = append(group[key], r)
	}

	var out []SummaryRow

	for _, rs := range group {
		if len(rs) == 0 {
			continue
		}

		times := make([]int64, 0, len(rs))
		for _, r := range rs {
			times = append(times, r.TimeNS)
		}

		sort.Slice(times, func(i, j int) bool {
			return times[i] < times[j]
		})

		var sum float64
		for _, t := range times {
			sum += float64(t)
		}
		mean := sum / float64(len(times))

		var median float64
		n := len(times)
		if n%2 == 1 {
			median = float64(times[n/2])
		} else {
			median = float64(times[n/2-1]+times[n/2]) / 2.0
		}

		var variance float64
		for _, t := range times {
			diff := float64(t) - mean
			variance += diff * diff
		}
		variance = variance / float64(len(times))
		stddev := math.Sqrt(variance)

		r0 := rs[0]
		out = append(out, SummaryRow{
			Scheme:    r0.Scheme,
			Operation: r0.Operation,
			InputType: r0.InputType,
			InputSize: r0.InputSize,
			Count:     len(times),
			MeanNS:    mean,
			MedianNS:  median,
			StddevNS:  stddev,
			MinNS:     times[0],
			MaxNS:     times[len(times)-1],
			MeanUS:    mean / 1000.0,
			MeanMS:    mean / 1000000.0,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Scheme != out[j].Scheme {
			return out[i].Scheme < out[j].Scheme
		}
		if out[i].Operation != out[j].Operation {
			return out[i].Operation < out[j].Operation
		}
		return out[i].InputSize < out[j].InputSize
	})

	return out
}

func main() {
	outDir := "/home/sergelen.8711/exp-hppk/results/offchain"

	messages := []struct {
		Name string
		Msg  []byte
	}{
		{"32B", make([]byte, 32)},
		{"256B", make([]byte, 256)},
		{"4KB", make([]byte, 4096)},
	}

	for i := range messages {
		for j := range messages[i].Msg {
			messages[i].Msg[j] = byte(j % 251)
		}
	}

	var raw []RawRow
	var correctness [][]string

	// =====================================================
	// HPPK-DS setup
	// =====================================================

	F := core.NewField(big.NewInt(65537))
	dsL := uint(2)
	dsK := uint(1)

	var hppkSK *ds.Secret
	var hppkPK *ds.Public

	for i := 1; i <= ITER; i++ {
		start := time.Now()
		sk, pk := ds.KeyGenDS(F, dsL, dsK)
		elapsed := time.Since(start).Nanoseconds()

		if i == 1 {
			hppkSK = sk
			hppkPK = pk
		}

		raw = append(raw, RawRow{
			Scheme:    "HPPK-DS",
			Operation: "KeyGen",
			InputType: "none",
			InputSize: 0,
			Iteration: i,
			TimeNS:    elapsed,
			Success:   sk != nil && pk != nil,
		})
	}

	if hppkSK == nil || hppkPK == nil {
		panic("HPPK KeyGenDS failed")
	}

	// =====================================================
	// ECDSA setup
	// =====================================================

	var ecdsaSK *ecdsa.PrivateKey

	for i := 1; i <= ITER; i++ {
		start := time.Now()
		sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		elapsed := time.Since(start).Nanoseconds()

		if err != nil {
			panic(err)
		}
		if i == 1 {
			ecdsaSK = sk
		}

		raw = append(raw, RawRow{
			Scheme:    "ECDSA-P256",
			Operation: "KeyGen",
			InputType: "none",
			InputSize: 0,
			Iteration: i,
			TimeNS:    elapsed,
			Success:   sk != nil,
		})
	}

	// =====================================================
	// Sign / Verify benchmark by message size
	// =====================================================

	var sampleHPPKSig *ds.Signature
	var sampleECDSASig []byte

	for _, m := range messages {
		// HPPK Sign
		for i := 1; i <= ITER; i++ {
			start := time.Now()
			sig, err := ds.SignWithPK(hppkSK, hppkPK, m.Msg)
			elapsed := time.Since(start).Nanoseconds()

			if err != nil {
				panic(err)
			}
			if m.Name == "32B" && i == 1 {
				sampleHPPKSig = sig
			}

			raw = append(raw, RawRow{
				Scheme:    "HPPK-DS",
				Operation: "Sign",
				InputType: m.Name,
				InputSize: len(m.Msg),
				Iteration: i,
				TimeNS:    elapsed,
				Success:   sig != nil,
			})
		}

		// HPPK Verify
		hSig, err := ds.SignWithPK(hppkSK, hppkPK, m.Msg)
		if err != nil {
			panic(err)
		}

		for i := 1; i <= ITER; i++ {
			start := time.Now()
			ok := ds.Verify(hppkPK, m.Msg, hSig)
			elapsed := time.Since(start).Nanoseconds()

			if !ok {
				panic("HPPK verify failed")
			}

			raw = append(raw, RawRow{
				Scheme:    "HPPK-DS",
				Operation: "Verify",
				InputType: m.Name,
				InputSize: len(m.Msg),
				Iteration: i,
				TimeNS:    elapsed,
				Success:   ok,
			})
		}

		// ECDSA Sign
		for i := 1; i <= ITER; i++ {
			digest := sha256.Sum256(m.Msg)

			start := time.Now()
			sig, err := ecdsa.SignASN1(rand.Reader, ecdsaSK, digest[:])
			elapsed := time.Since(start).Nanoseconds()

			if err != nil {
				panic(err)
			}
			if m.Name == "32B" && i == 1 {
				sampleECDSASig = sig
			}

			raw = append(raw, RawRow{
				Scheme:    "ECDSA-P256",
				Operation: "Sign",
				InputType: m.Name,
				InputSize: len(m.Msg),
				Iteration: i,
				TimeNS:    elapsed,
				Success:   sig != nil,
			})
		}

		// ECDSA Verify
		digest := sha256.Sum256(m.Msg)
		eSig, err := ecdsa.SignASN1(rand.Reader, ecdsaSK, digest[:])
		if err != nil {
			panic(err)
		}

		for i := 1; i <= ITER; i++ {
			start := time.Now()
			ok := ecdsa.VerifyASN1(&ecdsaSK.PublicKey, digest[:], eSig)
			elapsed := time.Since(start).Nanoseconds()

			if !ok {
				panic("ECDSA verify failed")
			}

			raw = append(raw, RawRow{
				Scheme:    "ECDSA-P256",
				Operation: "Verify",
				InputType: m.Name,
				InputSize: len(m.Msg),
				Iteration: i,
				TimeNS:    elapsed,
				Success:   ok,
			})
		}
	}

	// =====================================================
	// Correctness tests
	// =====================================================

	msg := messages[0].Msg

	hSig, err := ds.SignWithPK(hppkSK, hppkPK, msg)
	if err != nil {
		panic(err)
	}

	hValid := ds.Verify(hppkPK, msg, hSig)

	tampered := append([]byte{}, msg...)
	tampered[0] ^= 0xff

	hTampered := ds.Verify(hppkPK, tampered, hSig)

	_, wrongPK := ds.KeyGenDS(F, dsL, dsK)
	hWrongPK := ds.Verify(wrongPK, msg, hSig)

	eDigest := sha256.Sum256(msg)
	eSig, err := ecdsa.SignASN1(rand.Reader, ecdsaSK, eDigest[:])
	if err != nil {
		panic(err)
	}
	eValid := ecdsa.VerifyASN1(&ecdsaSK.PublicKey, eDigest[:], eSig)

	eTamperedDigest := sha256.Sum256(tampered)
	eTampered := ecdsa.VerifyASN1(&ecdsaSK.PublicKey, eTamperedDigest[:], eSig)

	otherECDSA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eWrongPK := ecdsa.VerifyASN1(&otherECDSA.PublicKey, eDigest[:], eSig)

	correctness = append(correctness,
		[]string{"HPPK-DS", "valid_signature", pass(hValid)},
		[]string{"HPPK-DS", "tampered_message_should_fail", pass(!hTampered)},
		[]string{"HPPK-DS", "wrong_public_key_should_fail", pass(!hWrongPK)},
		[]string{"ECDSA-P256", "valid_signature", pass(eValid)},
		[]string{"ECDSA-P256", "tampered_message_should_fail", pass(!eTampered)},
		[]string{"ECDSA-P256", "wrong_public_key_should_fail", pass(!eWrongPK)},
	)

	// =====================================================
	// Raw CSV
	// =====================================================

	var rawCSV [][]string
	for _, r := range raw {
		rawCSV = append(rawCSV, []string{
			r.Scheme,
			r.Operation,
			r.InputType,
			strconv.Itoa(r.InputSize),
			strconv.Itoa(r.Iteration),
			strconv.FormatInt(r.TimeNS, 10),
			strconv.FormatBool(r.Success),
		})
	}

	writeCSV(
		outDir+"/hppk_vs_ecdsa_raw.csv",
		[]string{"scheme", "operation", "input_type", "input_size_bytes", "iteration", "time_ns", "success"},
		rawCSV,
	)

	// =====================================================
	// Summary CSV
	// =====================================================

	summary := summarize(raw)

	var summaryCSV [][]string
	for _, r := range summary {
		summaryCSV = append(summaryCSV, []string{
			r.Scheme,
			r.Operation,
			r.InputType,
			strconv.Itoa(r.InputSize),
			strconv.Itoa(r.Count),
			fmt.Sprintf("%.2f", r.MeanNS),
			fmt.Sprintf("%.2f", r.MedianNS),
			fmt.Sprintf("%.2f", r.StddevNS),
			strconv.FormatInt(r.MinNS, 10),
			strconv.FormatInt(r.MaxNS, 10),
			fmt.Sprintf("%.4f", r.MeanUS),
			fmt.Sprintf("%.6f", r.MeanMS),
		})
	}

	writeCSV(
		outDir+"/hppk_vs_ecdsa_summary.csv",
		[]string{
			"scheme", "operation", "input_type", "input_size_bytes", "count",
			"mean_ns", "median_ns", "stddev_ns", "min_ns", "max_ns", "mean_us", "mean_ms",
		},
		summaryCSV,
	)

	// =====================================================
	// Correctness CSV
	// =====================================================

	writeCSV(
		outDir+"/hppk_vs_ecdsa_correctness.csv",
		[]string{"scheme", "test_case", "result"},
		correctness,
	)

	// =====================================================
	// Size CSV
	// =====================================================

	ecdsaPubBytes := len(ecdsaSK.PublicKey.X.Bytes()) + len(ecdsaSK.PublicKey.Y.Bytes())
	ecdsaPrivBytes := len(ecdsaSK.D.Bytes())

	sizeRows := [][]string{
		{
			"HPPK-DS",
			strconv.Itoa(jsonSize(hppkPK)),
			strconv.Itoa(jsonSize(hppkSK)),
			strconv.Itoa(jsonSize(sampleHPPKSig)),
		},
		{
			"ECDSA-P256",
			strconv.Itoa(ecdsaPubBytes),
			strconv.Itoa(ecdsaPrivBytes),
			strconv.Itoa(len(sampleECDSASig)),
		},
	}

	writeCSV(
		outDir+"/hppk_vs_ecdsa_sizes.csv",
		[]string{"scheme", "public_key_bytes", "secret_key_bytes", "signature_bytes"},
		sizeRows,
	)

	// =====================================================
	// Environment CSV
	// =====================================================

	writeCSV(
		outDir+"/hppk_vs_ecdsa_env.csv",
		[]string{"goos", "goarch", "go_version", "num_cpu", "iterations"},
		[][]string{{
			runtime.GOOS,
			runtime.GOARCH,
			runtime.Version(),
			strconv.Itoa(runtime.NumCPU()),
			strconv.Itoa(ITER),
		}},
	)

	fmt.Println("HPPK vs ECDSA experiment completed.")
	fmt.Println("Output:")
	fmt.Println(outDir + "/hppk_vs_ecdsa_raw.csv")
	fmt.Println(outDir + "/hppk_vs_ecdsa_summary.csv")
	fmt.Println(outDir + "/hppk_vs_ecdsa_correctness.csv")
	fmt.Println(outDir + "/hppk_vs_ecdsa_sizes.csv")
	fmt.Println(outDir + "/hppk_vs_ecdsa_env.csv")
}

func pass(ok bool) string {
	if ok {
		return "pass"
	}
	return "fail"
}
