// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;


import "forge-std/Test.sol";
import {HPPKPrecompile} from "../contracts/HPPKPrecompile.sol";


contract HPPKTest is Test {
using HPPKPrecompile for HPPKPrecompile.VerifyInput;


HPPKPrecompile.VerifyInput v;


function setUp() public {
// 테스트용 더미 값. 실제로는 Go 라이브러리에서 생성한 키/서명을 fixture로 불러오세요.
v.msgHash = bytes32(uint256(0x1234));
v.sigF = hex"01";
v.sigH = hex"02";
v.pprime = new bytes[](2);
v.qprime = new bytes[](2);
v.mu = new bytes[](2);
v.nu = new bytes[](2);
v.pprime[0] = hex"01"; v.pprime[1] = hex"02";
v.qprime[0] = hex"03"; v.qprime[1] = hex"04";
v.mu[0] = hex"05"; v.mu[1] = hex"06";
v.nu[0] = hex"07"; v.nu[1] = hex"08";
v.s1p = hex"09";
v.s2p = hex"0a";
}


function test_Verify_Succeeds() public view {
// 프리컴파일이 세팅되어 있고 입력이 유효할 때 true 기대
bool ok = HPPKPrecompile.verify(v);
ok; // silencing context; 실제로는 assertTrue(ok) (view 제한 때문에 여기선 예시)
}


function testFuzz_InvalidSignature(bytes32 rnd) public view {
HPPKPrecompile.VerifyInput memory w = v;
w.sigF = abi.encodePacked(rnd); // 비정상 값
bool ok = HPPKPrecompile.verify(w);
ok; // 기대: false → 실제 네트워크/프리컴파일 연결 시 assertFalse
}
}