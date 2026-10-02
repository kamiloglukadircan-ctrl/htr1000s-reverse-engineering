# QDF Channel Export Format

QDF (Quick Data File?) is used by HTR-1000S for USB channel list export/import.

## File Structure

```
┌────────────────────────────────────────┐
│ 0x0000-0x000F  16B  FIXED HEADER       │ Same across all exports from same device
│ 0x0010-0x001F  16B  RANDOM IV          │ Different per export
│ 0x0020-xxxxxx  N*16B  Encrypted body   │ AES-CBC presumably
│ Last 80B       80B  Signature/MAC      │ Different per export (varies with content)
└────────────────────────────────────────┘
```

## Fixed Header (device-specific)

For the test device (sysid 0x002B, HW 0x45):

```
7edf41f9fb54caf2ff27bd10dcd76391
```

This header:
- Identical across 6 different exports (confirmed deterministic)
- Not found in humaxtv binary or NAND dump
- Likely runtime-derived: `AES-Encrypt(magic, device_key, IV=0)` or `hash(device_key)`
- Probably device-specific fingerprint

## Known behavior

### Export operation
Device "Export channels to USB" produces `export.qdf` file:
- Minimum size: 4192 bytes (first export after cold boot)
- Steady-state size: 4208 bytes (subsequent exports)
- Each export produces unique IV + unique body + unique signature

### Import operation
Device "Load channels from USB" accepts and processes `export.qdf`.

## ⚠️ Validation is WEAK

Comprehensive testing shows **no cryptographic validation** on QDF import:

| Modification | Device response |
|-------------|-----------------|
| Last 80 bytes zeroed | ✅ "Process completed" |
| Middle 2KB zeroed | ✅ "Process completed" |
| First header byte flipped | ✅ "Process completed" |
| Byte 0x500 flipped | ✅ "Process completed" |

Device appears to:
1. Open file
2. Attempt decryption
3. If garbage → silently load zero channels
4. Report "success"

No cryptographic signature check, no HMAC validation, no structural integrity check beyond basic parsing.

## 💎 CRITICAL BUG: Parser Crash

### Reproduction

1. Create 10-byte file of all zeros, name `export.qdf`
2. Place on USB stick (FAT32)
3. Insert USB into HTR-1000S
4. Device menu: "Load channels from USB"
5. **Device immediately crashes and reboots**

### Classification

- **Type**: Denial of Service (DoS)
- **Impact**: Device crash + automatic recovery via reboot
- **CWE candidates**: 
  - CWE-125 (Out-of-bounds Read) — most likely
  - CWE-824 (Access of Uninitialized Pointer)
  - CWE-787 (Out-of-bounds Write) — less likely

### Attack surface

- **Prerequisite**: Physical USB access
- **Requires**: User action (navigates to import menu)
- **Impact scope**: Local only, no persistence, no data loss, reboot recovers
- **Severity**: Low (DoS only, no code execution demonstrated)

### Open questions

- Can the crash be triggered with other sizes/patterns?
- Does the crash reach memory corruption primitives?
- Can it be chained to code execution?

Full fuzzing + Ghidra analysis of QDF import function in `humaxtv` required to answer.

### Responsible disclosure

Reporting to Humax Security Team planned.

## QDF samples

NOT included in this repo (device-specific data, privacy caution).

If you have your own HTR-1000S, you can produce exports via:
```
Settings → Channels → USB → Export to USB
```

## Reverse engineering status

- Fixed header: identified
- IV placement: identified (bytes 0x10-0x1F)
- Encryption: AES-CBC (inferred from structure)
- Encryption key: NOT recovered (likely device-specific, stored in NAND "settings" partition)
- Content format: not reverse engineered (would require decryption first)
