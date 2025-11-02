package test

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/sergelen02/HPPK_2/internal/core/vm"
)

// 간단 단위 테스트(예시)
func TestPrecompileVerify(t *testing.T) {
	p := vm.HPPKVerifyPrecompile{}

	// pk.json 로드 (여러분 저장소 루트에 존재)
	pkBytes, err := os.ReadFile("pk.json")
	if err != nil {
		t.Fatal(err)
	}

	// 임시로 ds.KeyGenDS → Sign → 입력 패킹해서 Run 호출
	// 실제 테스트에선 여러분의 기존 sign 코드/샘플을 사용
	F := bytes.Repeat([]byte{0xAA}, 64)
	H := bytes.Repeat([]byte{0xBB}, 32)
	U := bytes.Repeat([]byte{0xCC}, 32)
	V := bytes.Repeat([]byte{0xDD}, 32)
	msg := []byte("hello quantum")

	// 헤더 + 바디
	hdr := make([]byte, 24)
	binary.BigEndian.PutUint32(hdr[0:4], uint32(len(F)))
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(H)))
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(U)))
	binary.BigEndian.PutUint32(hdr[12:16], uint32(len(V)))
	binary.BigEndian.PutUint32(hdr[16:20], uint32(len(pkBytes)))
	binary.BigEndian.PutUint32(hdr[20:24], uint32(len(msg)))

	in := bytes.Join([][]byte{hdr, F, H, U, V, pkBytes, msg}, nil)
	out, err := p.Run(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 32 {
		t.Fatalf("bad out len")
	}
	// out[31] == 1 이면 true
}
