// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
library HPPK {
    address constant PRECOMPILE = address(0x0b);
    function verify(bytes32 messageHash, bytes memory sig, bytes memory pub) internal view returns (bool ok) {
        (bool success, bytes memory ret) = PRECOMPILE.staticcall(abi.encode(messageHash, sig, pub));
        if (!success || ret.length < 32) return false;
        ok = (ret[31] == 0x01);
    }
}
