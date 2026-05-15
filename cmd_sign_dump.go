package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sergelen02/HPPK_2/internal/ds"
)

func main() {
	msg := []byte("hello quantum")

	// TODO: 아래 2줄은 ds 패키지 실제 API에 맞춰야 합니다.
	// 우선 컴파일 에러가 나면, 그 에러 메시지에 맞춰 함수명을 고치면 됩니다.
	pk, sk, err := ds.KeyGen()
	_ = sk
	if err != nil {
		panic(err)
	}

	// sig, err := ds.Sign(sk, msg)  // ds.Sign이 없으면 컴파일 에러로 확인
	// if err != nil { panic(err) }

	// 일단 pk만 저장(여기까지는 KeyGen만 맞추면 성공)
	pkb, _ := json.Marshal(pk)
	_ = os.WriteFile("pk_gen.json", pkb, 0644)

	// fmt.Println(base64.StdEncoding.EncodeToString(sig.F)) // 나중에 sig가 생기면
	_ = os.WriteFile("msg.txt", []byte(base64.StdEncoding.EncodeToString(msg)), 0644)

	fmt.Println("wrote pk_gen.json (and msg.txt)")
}
