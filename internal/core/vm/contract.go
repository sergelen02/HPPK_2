// internal/core/vm/contracts.go
package vm

import "github.com/ethereum/go-ethereum/common"

var PrecompiledContractsHomestead = map[common.Address]PrecompiledContract{
	// ... 기존 항목들
	common.HexToAddress("0x00000000000000000000000000000000000000F5"): HPPKVerifyPrecompile{},
}

// 필요한 다른 하드포크 맵(Berlin, London 등)에도 동일 등록
