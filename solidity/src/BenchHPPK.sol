// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../contracts/HPPK_Precompile.sol";

contract BenchHPPK {
    function benchHPPK(bytes32 digest, bytes memory sig, bytes memory pub) external {
        HPPK.verify(digest, sig, pub);
    }
}
