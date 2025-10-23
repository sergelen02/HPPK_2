// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "./HPPKPrecompile.sol";

contract Wallet4337 {
    using HPPK for bytes;

    // 실제 ERC-4337 구현에서는 EntryPoint의 validateUserOp 시그니처에 맞춰 작성
    function validateUserOp(bytes32 userOpHash, bytes calldata sig, bytes calldata pub) external view returns (bool) {
        return HPPK.verify(userOpHash, sig, pub);
    }
}
