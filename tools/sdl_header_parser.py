#!/usr/bin/env python3
"""Parse Humax SDL file header fields."""

import sys
import struct


def parse_sdl_header(sdl_data: bytes) -> dict:
    """Extract all known header fields from SDL data."""
    if len(sdl_data) < 141:
        raise ValueError("SDL file too small")
    
    return {
        'magic': sdl_data[0x00],
        'manufacturer_code': sdl_data[0x02],
        'hardware_code': sdl_data[0x03],
        'load_sequence_number': sdl_data[0x04],
        'date_string': sdl_data[0x08:0x15].decode('latin-1', errors='replace').rstrip('\x00'),
        'partition_count': sdl_data[0x20],
        'upd_variant': sdl_data[0x21],
        'variant': struct.unpack('>H', sdl_data[0x24:0x26])[0],
        'label': sdl_data[0x26:0x35].decode('latin-1', errors='replace').rstrip('\x00'),
        'sig_sysid': struct.unpack('>H', sdl_data[0x35:0x37])[0],
        'sig_sysver': struct.unpack('>H', sdl_data[0x37:0x39])[0],
        'sig_subver': sdl_data[0x39],
        'sig_version': sdl_data[0x3A],
        'signature': sdl_data[0x3B:0x8B].hex(),
        'crc': struct.unpack('>H', sdl_data[0x8B:0x8D])[0],
        'payload_size': len(sdl_data) - 0x8D,
    }


def print_header(fields: dict):
    """Human-readable header dump."""
    print(f"Magic:                 0x{fields['magic']:02X}")
    print(f"Manufacturer code:     0x{fields['manufacturer_code']:02X} ({fields['manufacturer_code']})")
    print(f"Hardware code:         0x{fields['hardware_code']:02X} ({fields['hardware_code']})")
    print(f"Load sequence:         0x{fields['load_sequence_number']:02X} ({fields['load_sequence_number']})")
    print(f"Date string:           {fields['date_string']!r}")
    print(f"Partition count:       0x{fields['partition_count']:02X}")
    print(f"Update variant:        0x{fields['upd_variant']:02X}")
    print(f"Variant:               0x{fields['variant']:04X} ({fields['variant']})")
    print(f"Label:                 {fields['label']!r}")
    print(f"Signature sysid:       0x{fields['sig_sysid']:04X} ({fields['sig_sysid']})")
    print(f"Signature sysver:      0x{fields['sig_sysver']:04X} ({fields['sig_sysver']})")
    print(f"Signature subver:      0x{fields['sig_subver']:02X} ({fields['sig_subver']})")
    print(f"Signature version:     0x{fields['sig_version']:02X}")
    print(f"CRC-16/ARC:            0x{fields['crc']:04X}")
    print(f"Signature (first 16B): {fields['signature'][:32]}...")
    print(f"Payload size:          {fields['payload_size']:,} bytes")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <sdl_file>")
        sys.exit(1)
    
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    
    print(f"File: {sys.argv[1]}  ({len(data):,} bytes)\n")
    fields = parse_sdl_header(data)
    print_header(fields)
