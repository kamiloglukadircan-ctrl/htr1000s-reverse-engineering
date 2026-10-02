# SDL File Format Specification

Humax Software Download Loader (SDL) file format for HTR-1000S / HDR-1000S family (Humax Model 5 generation).

## File Structure

```
┌─────────────────────────────────────────┐
│ HEADER (141 bytes)                      │
│ ├─ 0x00     magic                       │
│ ├─ 0x02     manufacturer_code           │
│ ├─ 0x03     hardware_code               │
│ ├─ 0x04     load_sequence_number        │
│ ├─ 0x08-14  ASCII date                  │
│ ├─ 0x20     partition_count             │
│ ├─ 0x21     upd_variant                 │
│ ├─ 0x24-25  variant (BE)                │
│ ├─ 0x26-34  label (ASCII)               │
│ ├─ 0x35-36  sig_sysid (BE)              │
│ ├─ 0x37-38  sig_sysver (BE)             │
│ ├─ 0x39     sig_subver                  │
│ ├─ 0x3A     sig_version                 │
│ ├─ 0x3B-8A  SIGNATURE BLOCK (80 bytes)  │
│ └─ 0x8B-8C  CRC-16/ARC (BE)             │
├─────────────────────────────────────────┤
│ PAYLOAD (N bytes)                       │
│ ├─ Firmware binary blocks               │
│ ├─ Loader partition update              │
│ └─ Metadata config section (INI, end)   │
└─────────────────────────────────────────┘
```

## Field details

### Magic byte (0x00)
- `0x11` = Model 5 format (HTR-1000S, HDR-1000S)
- `0x49` = Different Humax family (HD-3600S2, HD-3601S2) — rejected by Model 5 loader at D01

### manufacturer_code (0x02)
- `0x0F` = Humax (ID 15)
- Checked at D06

### hardware_code (0x03)
- Device-specific
- HTR-1000S accepts `0x45`
- Checked at D07

### load_sequence_number (0x04)
- Monotonic counter per firmware release
- Window-checked at D0B (not exact match)
- Likely enforces `new >= current` anti-downgrade

### Mutual exclusion fields (0x20-0x21)
- `partition_count` and `upd_variant` cannot both be non-zero
- Enforces: SDL is either multi-partition update OR variant switch, not both
- Checked at E02

### variant (0x24-25, big-endian)
- Must match device variant
- HTR-1000S accepts `0x0005`
- Checked at E00

### Signature identifier triplet (0x35-0x39)
- `sig_sysid` (0x35-36 BE): Points to which resident key to use → C05
- `sig_sysver` (0x37-38 BE): Key version within that sysid → C06
- `sig_subver` (0x39): Signature format/content version → C0F

HTR-1000S user device:
```
sig_sysid    = 0x002B
sig_sysver   = 0x0000
sig_subver   = 0x23 (varies per firmware)
```

### CRC (0x8B-0x8C, big-endian)
- Algorithm: **CRC-16/ARC** (polynomial 0x8005 reflected = 0xA001)
- Range: bytes `[2:139]` (137 bytes)
- Position: `0x8B` (high) `0x8C` (low), big-endian
- Checked at D02

### Signature (0x3B-0x8A, 80 bytes)
- Algorithm: **Irdeto FlexiFlash v1 — RSA-PSS SHA-256**
- Covers: entire file (header + payload)
- Verified using device's resident key matched via sig_sysid + sig_sysver
- Checked at C09 (final gate)

## Payload structure

After header (byte 0x8D onwards):
- Firmware binary blocks (compressed/encrypted)
- Optional LOADER partition update data
- **Config section** (INI format, in cleartext) at end of file

### Config section (information disclosure)

Humax internal build system writes metadata here:

```ini
[Manufacturer_Data]
MANUFACTURER_ID=0x0F
HARDWARE_VERSION=73       ; Internal "X49" project code
LOADER_VERSION=3.1
FLASH_BLOCKS=82
TARGET_ADDRESS=0x80000000

[Flash_Configuration]
BLK1_STRT=0x80000000, BLK1_LEN=0x00080000
... (82 blocks of 512KB each)

[Input_Files]
FLASH_FILE=O:\source\HUMAX\HW_X49\<Operator>\<binary>.bin

[Output_Control]
OUTFILE=HMX<model>_<date>-<seq>.S<version>

; Build operator identifiers
I00=<operator_id_1>
I98=<operator_id_2>
```

This leaks Humax's internal server drive mappings (O: for source, R: for manufacturing config).

## CRC-16/ARC reference implementation

See `tools/crc16_arc.py` for Python implementation. Test vectors:

```
crc16_arc(b"123456789")                       = 0xBB3D
crc16_arc(ir1000s_sdl[2:139])                 = 0x2E49  ; matches stored CRC
```
