// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../contracts/HPPK_Precompile.sol";

contract BenchHPPKPrecompile {
    function benchHPPKPrecompile(
        bytes memory F,
        bytes memory H,
        bytes memory U,
        bytes memory V,
        bytes memory pk,
        bytes memory msg_
    ) external view {
        bool ok = HPPK.verifyPacked(F, H, U, V, pk, msg_);
        require(ok, "hppk precompile verify failed");
    }
}
