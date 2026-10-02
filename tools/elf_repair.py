#!/usr/bin/env python3
"""
Repair a truncated MIPS ELF executable for Ghidra import.

Some embedded firmware ELF binaries extracted from flash dumps have
truncated section header tables (e_shoff pointing past EOF) and/or
truncated LOAD segments. Ghidra's ELF loader crashes with a
NullPointerException during GOT/PLT fixup when this happens
(ElfDefaultGotPltMarkup.isValidPointer).

This script:
1. Parses the ELF32 program header table (which usually survives intact,
   since it's needed near the start of the file for execution)
2. Zero-pads the file to cover any truncated LOAD segment
3. Disables the section header table (e_shoff/e_shnum/e_shstrndx = 0)
   so Ghidra doesn't try to parse the (possibly also truncated) table

Usage: python3 elf_repair.py <input.elf> <output.elf>
"""

import struct
import sys


def repair_elf(in_path: str, out_path: str):
    with open(in_path, 'rb') as f:
        data = bytearray(f.read())

    if data[:4] != b'\x7fELF':
        raise ValueError("Not an ELF file")
    if data[4] != 1:
        raise ValueError("Only ELF32 supported")

    is_le = data[5] == 1
    endian = '<' if is_le else '>'

    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
     e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = \
        struct.unpack(endian + 'HHIIIIIHHHHHH', data[16:52])

    print(f"e_entry=0x{e_entry:08x} e_phoff=0x{e_phoff:08x} e_phnum={e_phnum}")
    print(f"e_shoff=0x{e_shoff:08x} file_size=0x{len(data):08x} "
          f"{'(TRUNCATED)' if e_shoff > len(data) else '(OK)'}")

    # Find max required file extent from LOAD segments (p_type == 1)
    max_needed = len(data)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            continue
        (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz,
         p_flags, p_align) = struct.unpack(endian + 'IIIIIIII', data[off:off+32])
        if p_type == 1:  # PT_LOAD
            needed_end = p_offset + p_filesz
            if needed_end > max_needed:
                max_needed = needed_end
            print(f"  LOAD: file[0x{p_offset:08x}:0x{needed_end:08x}] "
                  f"-> vaddr 0x{p_vaddr:08x}  "
                  f"{'(needs padding)' if needed_end > len(data) else '(OK)'}")

    if max_needed > len(data):
        pad = max_needed - len(data)
        data.extend(b'\x00' * pad)
        print(f"Zero-padded {pad} bytes to cover truncated LOAD segment(s)")

    # Disable section header table parsing
    struct.pack_into(endian + 'I', data, 32, 0)   # e_shoff
    struct.pack_into(endian + 'H', data, 48, 0)   # e_shnum
    struct.pack_into(endian + 'H', data, 50, 0)   # e_shstrndx
    print("Disabled section header table (e_shoff/e_shnum/e_shstrndx = 0)")

    with open(out_path, 'wb') as f:
        f.write(data)
    print(f"\nWritten: {out_path} ({len(data):,} bytes)")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.elf> <output.elf>")
        sys.exit(1)
    repair_elf(sys.argv[1], sys.argv[2])
