// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BenchECDSA {
    function _splitSig(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "bad sig len");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    function benchECDSA(bytes32 digest, bytes memory sig, address signer) external {
        (bytes32 r, bytes32 s, uint8 v) = _splitSig(sig);
        address recovered = ecrecover(digest, v, r, s);
        require(recovered == signer, "ecdsa verify failed");
    }
}
