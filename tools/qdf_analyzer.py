#!/usr/bin/env python3
"""Analyze Humax QDF channel export files."""

import sys
import math
import hashlib


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    e = 0.0
    for f in freq:
        if f:
            p = f / len(data)
            e -= p * math.log2(p)
    return e


def analyze_qdf(path: str):
    with open(path, 'rb') as f:
        data = f.read()
    
    print(f"=== QDF Analysis: {path} ===\n")
    print(f"Size:        {len(data):,} bytes (0x{len(data):04X})")
    print(f"MD5:         {hashlib.md5(data).hexdigest()}")
    print(f"Total entropy: {entropy(data):.3f} bits/byte\n")
    
    # Structural analysis
    print(f"=== Structure ===")
    print(f"Fixed header (0x00-0x0F):  {data[:16].hex()}")
    print(f"  Expected (test device):  7edf41f9fb54caf2ff27bd10dcd76391")
    print(f"  Match: {'YES' if data[:16].hex() == '7edf41f9fb54caf2ff27bd10dcd76391' else 'NO (different device)'}")
    
    print(f"\nIV candidate (0x10-0x1F):  {data[0x10:0x20].hex()}")
    print(f"Last 80 bytes (sig/MAC):   {data[-80:-48].hex()}...\n")
    
    print(f"=== Entropy by region ===")
    print(f"  Fixed header (16B):       {entropy(data[:16]):.3f}")
    print(f"  IV region (16B):          {entropy(data[0x10:0x20]):.3f}")
    print(f"  Body (0x20 to -80):       {entropy(data[0x20:-80]):.3f}")
    print(f"  Last 80B:                 {entropy(data[-80:]):.3f}")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <qdf_file>")
        sys.exit(1)
    analyze_qdf(sys.argv[1])
