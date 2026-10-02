# Contributing

## 🎯 Current blocker (as of this session)

The SDL signature verification logic (gates D01-C09, RSA-PSS SHA-256) is **NOT** in the
`humaxtv` Linux userspace binary — we confirmed this today by importing it into Ghidra
(headless, after fixing a truncated-ELF crash) and finding zero code/data cross-references
to the crypto strings it contains (`pkcs1psssha256`, `RSAPublicKey`, `rootKeyHash`, etc.).
Those strings belong to Irdeto's Conditional Access (CA) content-key system — a different
subsystem from USB firmware update validation.

The actual validation logic runs in a **separate loader binary** (device shows "LOADER 3.2.1"
on screen during USB update). We found a reference to it in NAND at two locations
(`0x02aa3388` and `0x02ac3388`, 128KB apart — primary/backup copies) under the label
`IRDETO_LOADER_PARTITION`, sitting right next to a `IRDETO_CPCB_ENCRYPTED` tag. The
surrounding bytes have high entropy — **this partition appears to be encrypted at rest.**

**This is the actual blocker: we need the decrypted loader binary, or the key/method to
decrypt it, to find where the RSA public key is loaded from and extract it.**

## What's needed

### 🔴 Highest value — would directly unblock the project
- **The decrypted `IRDETO_LOADER_PARTITION` binary** from any Model 5 device (HTR-1000S,
  HDR-1000S), or knowledge of how Humax encrypts this partition (algorithm, key derivation)
- **SPI-NOR flash dump** via CH341A or similar — the loader may exist unencrypted there,
  separate from the NAND copy (worth testing if you have the hardware)
- **JTAG access** to dump the BSP (Broadcom Secure Processor) state or runtime memory
  during a USB update — would let us see the loader decrypted in RAM

### 🟠 High value
- Additional **TRSIAC-branded SDL files** (any version — even one lets us diff against
  the Al Jazeera file we have and see what's genuinely operator-specific vs shared)
- **Humax GPL compliance disclosures** covering HTR-1000S / HDR-1000S / HDR-2000T
  (Humax is legally obligated to publish GPL component source — kernel, possibly u-boot/CFE)
- Anyone with existing Ghidra/IDA experience on Broadcom BCM7xxx STB loaders who recognizes
  this architecture

### 🟡 Medium value
- Reproduction of our 11 gate tests on another HTR-1000S / HDR-1000S device (confirms
  findings aren't device-specific)
- Confirmation (or refutation) of the QDF crash bug on another device — see
  `docs/QDF_FORMAT.md` for exact repro steps (10-byte all-zero `export.qdf` via USB)
- Discovery of the unknown **D0C gate** (see `docs/VALIDATION_CHAIN.md`)
- Systematic fuzzing of the QDF import function (crash size/pattern boundary) — could
  reveal whether the DoS bug is a controllable buffer overflow vs. simple null-deref

### 🟢 Welcome
- Translations (Russian, German, Czech satellite scene — this device family was sold
  across multiple markets under different brand names)
- Code improvements for `tools/`
- Writeup corrections — see the note in `docs/VALIDATION_CHAIN.md` about which gate
  error messages are screen-verified (photographed) vs. unverified

## Code of conduct

- Research only on hardware you own
- No distribution of unlicensed firmware files
- Follow responsible disclosure for new vulnerabilities (QDF crash bug disclosure to
  Humax Security is planned/in progress)
- No piracy / CAS bypass contributions — this project is about firmware format RE and
  responsible vulnerability research, not reviving Filbox subscriptions

## Submission

- Open an issue describing what you'd like to add
- Or send a PR with the change
- Include references/evidence (device model, firmware version, screenshots of error
  codes, hash of any binary you're referencing)
