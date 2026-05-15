// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract BenchECDSA is Test {
    function _splitSig(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "bad sig len");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    function testGas_ECDSAVerify() public {
        bytes32 digest = keccak256("hello-gas");

        // 실제 실험에서는 off-chain에서 만든 진짜 sig 넣는 것이 가장 좋음
        bytes memory sig = new bytes(65);
        address signer = address(0x1234);

        uint256 g0 = gasleft();

        // 더미 입력에서는 실패할 수 있으니 require는 일단 생략
        (bytes32 r, bytes32 s, uint8 v) = _splitSig(sig);
        ecrecover(digest, v, r, s);

        uint256 used = g0 - gasleft();
        emit log_named_uint("ecdsa_gas", used);
    }
}
