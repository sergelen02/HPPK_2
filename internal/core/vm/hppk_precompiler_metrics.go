// internal/core/vm/hppk_precomiler_metrics.go
// (파일명은 저장소의 기존 이름을 그대로 따름: 'precomiler' 오타 포함)
package vm

import (
	"time"

	"github.com/ethereum/go-ethereum/metrics"
)

var (
	mCallsTotal   = metrics.NewRegisteredCounter("hppkpc/calls/total", nil)
	mSuccessTotal = metrics.NewRegisteredCounter("hppkpc/calls/success", nil)
	mFailureTotal = metrics.NewRegisteredCounter("hppkpc/calls/failure", nil)

	mBytesIn      = metrics.NewRegisteredMeter("hppkpc/bytes/in", nil)
	mInputLenHist = metrics.NewRegisteredHistogram("hppkpc/input/len", nil, metrics.NewExpDecaySample(1028, 0.015))
	mLatencyTimer = metrics.NewRegisteredTimer("hppkpc/latency/run", nil)
	mGasUsedHist  = metrics.NewRegisteredHistogram("hppkpc/gas/used", nil, metrics.NewExpDecaySample(1028, 0.015))
)

// 메트릭 수집을 위해 Run을 감싸는 래퍼(선택적으로 사용)
func hookedRun(p HPPKVerifyPrecompile, in []byte) (out []byte, err error) {
	start := time.Now()
	mCallsTotal.Inc(1)
	mBytesIn.Mark(int64(len(in)))
	mInputLenHist.Update(int64(len(in)))

	out, err = p.Run(in)

	mLatencyTimer.UpdateSince(start)
	if err != nil {
		mFailureTotal.Inc(1)
	} else {
		mSuccessTotal.Inc(1)
	}
	return
}

// 필요 시 VM 가스 계측 시점에서 호출
func observeGasUsed(gas uint64) {
	mGasUsedHist.Update(int64(gas))
}
