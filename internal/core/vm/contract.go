// Homestead 또는 London 이후 테이블에 매핑
// import 라인에 hppk_precompile.go의 패키지 이미 vm 이므로 불필요
var PrecompiledContractsHomestead = map[common.Address]PrecompiledContract{
	// ...
	HPPKAddress: &HPPKVerify{},
}
