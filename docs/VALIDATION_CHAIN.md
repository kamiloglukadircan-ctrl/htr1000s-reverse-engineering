# HTR-1000S SDL Validation Chain

Loader checks SDL files sequentially through 12 "gates". If any gate fails, device shows an error code (`0x8000XXXX`) and does not flash.

## Discovered Gates (11 of 12)

| Gate | Error Code | Field | Byte Offset | Device Error Message |
|------|-----------|-------|-------------|---------------------|
| **D01** | `0x80000D01` | Magic byte | `0x00` | *Invalid file format* |
| **D02** | `0x80000D02` | CRC-16/ARC | `0x8B-0x8C` | *CRC check failed* |
| **D06** | `0x80000D06` | manufacturer_code | `0x02` | *The manufacturer_code field of the download header does not match that of the STB* |
| **D07** | `0x80000D07` | hardware_code | `0x03` | *Hardware code mismatch* |
| **D0B** | `0x80000D0B` | load_sequence_number | `0x04` | *The load_sequence_number field of the download header is not within the valid window for this STB* |
| **D0C** | `0x80000D0C` | *UNKNOWN* | `?` | *(not reached in testing — rare condition)* |
| **E00** | `0x80000E00` | variant | `0x24-0x25` | *The variant field of the download header does not match that of the STB* |
| **E02** | `0x80000E02` | partition_count / upd_variant | `0x20-0x21` | *The partition_count and upd_variant fields of the download header are both non-zero* |
| **C05** | `0x80000C05` | sig_sysid | `0x35-0x36` | *The system ID of the download signature does not match the resident key* |
| **C06** | `0x80000C06` | sig_sysver (key version) | `0x37-0x38` | *The key version of the download signature does not match the STB resident key* |
| **C0F** | `0x80000C0F` | sig_subver (signature version) | `0x39` | *The signature version of the download is out of step with the signature version resident in the STB* |
| **C09** | `0x80000C09` | RSA-PSS SHA-256 | `0x3B-0x8A` (over whole file) | *The download signature has failed a self-check* |

## Gate Ordering (observed)

```
File loaded
    ↓
D01 (magic)
    ↓
D02 (CRC)
    ↓
D06 (manufacturer)
    ↓
D07 (hardware)
    ↓
D0B (load sequence window)
    ↓
E00 (variant)
    ↓
E02 (partition_count/upd_variant exclusivity)
    ↓
[D0C — unknown]
    ↓
C05 (resident key sysid lookup)
    ↓
C06 (resident key version check)
    ↓
C0F (signature version check)
    ↓
C09 (RSA-PSS SHA-256 math verify) ← FINAL GATE
    ↓
FLASH BEGINS
```

## Semantic Insights

### D0B — "valid window"
load_sequence_number uses a **window check**, not exact match. Likely enforces anti-downgrade (`new_seq ≥ current_seq`) with possible upper bound.

### E02 — mutual exclusion
`partition_count` and `upd_variant` are mutually exclusive. SDL can be either:
- Multi-partition update (partition_count set, upd_variant zero)
- Variant switch (upd_variant set, partition_count zero)

Not both.

### C05/C06 — Resident Key Architecture
Device NAND stores keys indexed by `(sysid, key_version)`. Signature references which key to use. Different Humax operators (Al Jazeera, Filbox Turkey, etc.) share the same sysid namespace but have different physical keys — tested by flashing original Al Jazeera firmware (passes C05/C06 but fails C09 because Al Jazeera's private key doesn't match Filbox's resident public key).

### C09 — Final gate
RSA-PSS SHA-256 verification. Signature at offset `0x3B-0x8A` (80 bytes), computed over entire file content. All tested modifications (zero signature, pattern signatures, QDF-derived signatures, structured guesses) failed here.

## Reproducing Gate Tests

Tool: `tools/gate_test_builder.py`

```bash
python3 tools/gate_test_builder.py --input original.sdl --gate D06 --output test.sdl
```

Each gate test modifies the corresponding byte to a known-wrong value and recomputes CRC. User submits to device via USB upgrade, device returns specific error code.

## Error code source

All error codes and messages were captured directly from the HTR-1000S device screen during active testing. Messages match strings found in the `humaxtv` Linux userspace binary (specifically ERROR dialog table).
