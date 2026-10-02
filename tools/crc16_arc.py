#!/usr/bin/env python3
"""
CRC-16/ARC implementation for Humax SDL files.

Parameters:
    polynomial = 0x8005 (reflected = 0xA001)
    init       = 0
    refin      = True
    refout     = True
    xorout     = 0

Reference test vector: crc16_arc(b"123456789") == 0xBB3D
"""


def crc16_arc(payload: bytes) -> int:
    """Compute CRC-16/ARC of input bytes."""
    crc = 0
    for byte in payload:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc = crc >> 1
    return crc


def verify_sdl_crc(sdl_data: bytes) -> tuple[bool, int, int]:
    """
    Verify CRC in an SDL file.
    
    Returns: (is_valid, computed_crc, stored_crc)
    """
    if len(sdl_data) < 141:
        raise ValueError("SDL file too small (need at least 141 bytes)")
    
    computed = crc16_arc(sdl_data[2:139])
    stored = (sdl_data[0x8B] << 8) | sdl_data[0x8C]
    return (computed == stored, computed, stored)


def fix_sdl_crc(sdl_data: bytes) -> bytes:
    """Recompute and insert correct CRC."""
    data = bytearray(sdl_data)
    crc = crc16_arc(data[2:139])
    data[0x8B] = (crc >> 8) & 0xFF
    data[0x8C] = crc & 0xFF
    return bytes(data)


if __name__ == "__main__":
    import sys
    
    # Test vector
    assert crc16_arc(b"123456789") == 0xBB3D, "Test vector failed!"
    print("[OK] Test vector passes: crc16_arc('123456789') == 0xBB3D")
    
    if len(sys.argv) == 2:
        with open(sys.argv[1], 'rb') as f:
            data = f.read()
        valid, computed, stored = verify_sdl_crc(data)
        status = "VALID" if valid else "INVALID"
        print(f"\n[{status}] {sys.argv[1]}")
        print(f"  Computed CRC: 0x{computed:04X}")
        print(f"  Stored CRC:   0x{stored:04X}")
