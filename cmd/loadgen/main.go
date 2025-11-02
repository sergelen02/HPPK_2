package loadgen
// cmd/loadgen/main.go
package main

import (
  "context"
  "crypto/sha256"
  "fmt"
  "log"
  "math/rand"
  "time"
  "github.com/ethereum/go-ethereum/ethclient"
)

func main() {
  rpc := "http://<EXTERNAL-IP>:8545"
  c, err := ethclient.Dial(rpc)
  if err != nil { log.Fatal(err) }
  defer c.Close()

  // 데모: 1000회 해시 생성 후 프리컴파일 호출 대신 더미 RPC로 대체
  // 실제로는 지갑 컨트랙트의 verify 함수를 call/estimateGas로 호출
  n := 1000
  var lat []time.Duration
  for i:=0; i<n; i++ {
    msg := fmt.Sprintf("m-%d-%d", i, rand.Int())
    h := sha256.Sum256([]byte(msg))

    t0 := time.Now()
    // TODO: call HPPK.verify(msgHash=h[:], sig, pub) via eth_call
    _ = h
    // _, err := c.CallContract(context.Background(), msg, nil) // pseudo
    // if err != nil { ... }
    lat = append(lat, time.Since(t0))
  }
  // p95 구하는 코드 추가해도 좋습니다.
  fmt.Println("done", len(lat))
}
