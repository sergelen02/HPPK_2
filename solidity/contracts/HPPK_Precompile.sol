
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library HPPK {
    // Geth 프리컴파일 주소 (ByzantiumPrecompiledContracts 테이블에서 0x0b로 등록한 주소)
    address constant PRECOMPILE = address(0x0b);

    /// @notice HPPK 서명을 프리컴파일을 통해 검증
    /// @param messageHash 서명 대상 메시지의 keccak256 해시 (32 bytes)
    /// @param sig         HPPK 서명 (raw bytes)
    /// @param pub         HPPK 공개키 (raw bytes)
    /// @return ok         검증 성공 여부
    function verify(
        bytes32 messageHash,
        bytes memory sig,
        bytes memory pub
    ) internal view returns (bool ok) {
        (bool success, bytes memory ret) =
            PRECOMPILE.staticcall(abi.encode(messageHash, sig, pub));

        if (!success || ret.length == 0) {
            return false;
        }

        // 프리컴파일이 ABI-encoded bool 하나를 반환한다고 가정
        ok = abi.decode(ret, (bool));
    }
}
