
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./HPPKPrecompile.sol";

interface IEntryPoint {
    function getUserOpHash(bytes calldata userOp) external view returns (bytes32);
    // 실제 EntryPoint 인터페이스와 맞추세요.
}

contract SimpleAccount {
    using HPPKPrecompile for bytes32;

    address public owner;
    IEntryPoint public entryPoint;

    constructor(address _owner, address _entryPoint) {
        owner = _owner;
        entryPoint = IEntryPoint(_entryPoint);
    }

    // ERC-4337 validateUserOp(signature bytes encoded) -> return uint256 validationData
    // This is simplified: we assume the bundler/entrypoint will call validateUserOp with the userOp bytes as context.
    // In practice EntryPoint calls account.validateUserOp(userOp) with the struct; adjust as per your EntryPoint ABI.
    function validateUserOp(bytes calldata userOp, bytes calldata signature) external view returns (bool) {
        // 1) Recover message hash to be verified. For many wallets it's the "userOpHash" computed externally.
        // We will assume the caller (EntryPoint) passes the userOpHash as the first 32 bytes of userOp or provides an API.
        bytes32 userOpHash = keccak256(userOp); // or call entryPoint.getUserOpHash(userOp)

        // 2) Parse signature layout. We choose signature = abi.encode(sigBytes, pubKeyBytes)
        // For simplicity, expect signature = abi.encodePacked(uint16(sigLen), sig, pub) or ABI-encoded tuple.
        // Here we assume ABI-encoded tuple (bytes sig, bytes pub)
        (bytes memory sigBytes, bytes memory pubBytes) = abi.decode(signature, (bytes, bytes));

        // 3) Call precompile
        bool ok = userOpHash.verify(sigBytes, pubBytes);
        return ok;
    }

    // Simple execute to let EntryPoint call this account (not central to verification)
    function execute(address to, uint256 value, bytes calldata data) external {
        require(msg.sender == address(entryPoint), "only entrypoint");
        (bool success,) = to.call{value: value}(data);
        require(success);
    }
}
