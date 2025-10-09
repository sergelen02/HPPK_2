# HPPK_2

hppk/
go.mod
go.sum
README.md
configs/params/level1.json
internal/core/{field.go,barrett.go,hash.go,poly.go,rand.go}
internal/kem/{keygen.go,encaps.go,decaps.go}
internal/ds/{keygen.go,sign.go,verify.go}
cmd/kem/{keygen,encaps,decaps}/main.go
cmd/ds/{keygen,sign,verify}/main.go
tests/{kem_roundtrip_test.go,ds_signverify_test.go}

module github.com/yourname/hppk


go 1.23


require (
golang.org/x/crypto v0.26.0 // indirect (for future use)
)

# HPPK — Minimal Reference (Go)


Implements 6 algorithms (Alg1–6) of HPPK (λ=1). Suitable for local tests and containerization.


## Build
```bash
go mod tidy
go build ./..
