// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library HPPK {
    // Geth 프리컴파일 주소
    address constant PRECOMPILE = address(0x0b);

    error PrecompileCallFailed();
    error PrecompileBadReturn();

    function verifyPacked(
        bytes memory F,
        bytes memory H,
        bytes memory U,
        bytes memory V,
        bytes memory pk,
        bytes memory msg_
    ) internal view returns (bool ok) {
        bytes memory input = _packInput(F, H, U, V, pk, msg_);

        (bool success, bytes memory out) = PRECOMPILE.staticcall(input);
        if (!success) revert PrecompileCallFailed();

        // 현재 Go 테스트 기준: 길이 32 바이트, 마지막 바이트가 1이면 true
        if (out.length != 32) revert PrecompileBadReturn();

        return uint8(out[31]) == 1;
    }

    function _packInput(
        bytes memory F,
        bytes memory H,
        bytes memory U,
        bytes memory V,
        bytes memory pk,
        bytes memory msg_
    ) internal pure returns (bytes memory out) {
        bytes memory hdr = new bytes(24);

        _writeU32BE(hdr, 0,  F.length);
        _writeU32BE(hdr, 4,  H.length);
        _writeU32BE(hdr, 8,  U.length);
        _writeU32BE(hdr, 12, V.length);
        _writeU32BE(hdr, 16, pk.length);
        _writeU32BE(hdr, 20, msg_.length);

        out = bytes.concat(hdr, F, H, U, V, pk, msg_);
    }

    function _writeU32BE(bytes memory buf, uint256 off, uint256 x) private pure {
        require(buf.length >= off + 4, "header overflow");
        require(x <= type(uint32).max, "len too large");

        buf[off + 0] = bytes1(uint8(x >> 24));
        buf[off + 1] = bytes1(uint8(x >> 16));
        buf[off + 2] = bytes1(uint8(x >> 8));
        buf[off + 3] = bytes1(uint8(x));
    }
}
