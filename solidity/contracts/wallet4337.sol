// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./HPPK_Precompile.sol";

contract Wallet4337 {

    function validateUserOpPacked(
        bytes calldata F,
        bytes calldata H,
        bytes calldata U,
        bytes calldata V,
        bytes calldata pub,
        bytes calldata msg_
    ) external view returns (bool) {
        return HPPK.verifyPacked(F, H, U, V, pub, msg_);
    }
}
