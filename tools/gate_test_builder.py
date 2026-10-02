#!/usr/bin/env python3
"""Build test SDL files that trigger specific validation gates."""

import sys
import argparse
from crc16_arc import crc16_arc, fix_sdl_crc


# Gate → (byte_offset, modification_strategy)
GATES = {
    'D01': {'offset': 0x00, 'new': 0x49, 'desc': 'Magic byte (0x11 → 0x49)'},
    'D02': {'offset': 0x8B, 'new': 0xFF, 'desc': 'CRC corrupted (don\'t recompute)'},
    'D06': {'offset': 0x02, 'new': 0x10, 'desc': 'manufacturer_code (0x0F → 0x10)'},
    'D07': {'offset': 0x03, 'new': 0x46, 'desc': 'hardware_code (0x45 → 0x46)'},
    'D0B': {'offset': 0x04, 'new': 0x01, 'desc': 'load_sequence (low value)'},
    'E00': {'offset_pair': (0x24, 0x25), 'new': (0x00, 0x06), 'desc': 'variant (0x0005 → 0x0006)'},
    'E02': {'offset_pair': (0x20, 0x21), 'new': (0xFF, 0xFF), 'desc': 'both partition_count and upd_variant non-zero'},
    'C05': {'offset_pair': (0x35, 0x36), 'new': (0x00, 0x2C), 'desc': 'sig_sysid (0x002B → 0x002C)'},
    'C06': {'offset_pair': (0x37, 0x38), 'new': (0x00, 0x01), 'desc': 'sig_sysver (0x0000 → 0x0001)'},
    'C0F': {'offset': 0x39, 'new': 0xFF, 'desc': 'sig_subver (0x00 → 0xFF)'},
    'C09': {'offset': 0x3B, 'new': 0x00, 'desc': 'signature byte flipped (zero first byte)'},
}


def build_gate_test(sdl_data: bytes, gate: str) -> bytes:
    """Modify SDL to trigger the specified gate."""
    if gate not in GATES:
        raise ValueError(f"Unknown gate {gate}. Options: {list(GATES.keys())}")
    
    data = bytearray(sdl_data)
    spec = GATES[gate]
    
    if 'offset' in spec:
        data[spec['offset']] = spec['new']
    elif 'offset_pair' in spec:
        o1, o2 = spec['offset_pair']
        data[o1], data[o2] = spec['new']
    
    # Fix CRC (except for D02 which deliberately leaves it wrong)
    if gate != 'D02':
        data = bytearray(fix_sdl_crc(bytes(data)))
    
    return bytes(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True, help='Original SDL file')
    parser.add_argument('--gate', required=True, choices=list(GATES.keys()),
                        help='Which gate to trigger')
    parser.add_argument('--output', required=True, help='Output modified SDL file')
    args = parser.parse_args()
    
    with open(args.input, 'rb') as f:
        original = f.read()
    
    modified = build_gate_test(original, args.gate)
    
    with open(args.output, 'wb') as f:
        f.write(modified)
    
    print(f"Gate {args.gate}: {GATES[args.gate]['desc']}")
    print(f"Modified SDL written to: {args.output}")
    print(f"Place on USB with upgrade.dsc pointing to this file")
    print(f"Expected device error: 0x80000{args.gate}")


if __name__ == '__main__':
    main()
