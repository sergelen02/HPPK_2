package ds

import "testing"

// 필요시 실제 Params 생성기로 바꾸세요. (예: LevelI(), NewParams(...))
// KeyGen이 내부에서 pp 필드를 세팅한다면 nil도 허용될 수 있습니다.
func testParams() *Params { return nil }

func Test_Golden_SmallP(t *testing.T) {
	pp := testParams()

	// 레포 실제 시그니처: KeyGen(pp, n, m, lambda) -> (sk, pk, err)
	sk, pk, err := KeyGen(pp, 1, 1, 1)
	if err != nil {
		t.Fatalf("KeyGen error: %v", err)
	}

	msg := []byte("abc")

	// 레포 실제 시그니처: Sign(pp, sk, msg) -> (sig, extra, err)  (extra는 테스트에서 무시)
	sig, _, err := Sign(pp, sk, msg)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	// 레포 실제 시그니처: Verify(pp, pk, sig, msg) -> bool
	ok := Verify(pp, pk, sig, msg)
	if !ok {
		t.Fatal("verify=false")
	}
}
