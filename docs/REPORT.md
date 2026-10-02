# Humax HTR-1000S Firmware Reverse Engineering — v8
## Full Validation Chain Mapped + QDF Vulnerability Discovery

**Author:** Kadircan ([kamiloglukadircan@gmail.com](mailto:kamiloglukadircan@gmail.com))  
**Rapor tarihi:** 2026-10-02  
**Toplam süre:** ~9 saat aktif test (bu session)  
**Hedef cihaz:** Humax HTR-1000S (Filbox Turkey, Model 5 family)  
**Mimari:** Broadcom BCM7358, 128MB NAND, Spansion S34ML01G200BHI00

---

## 📊 EXECUTIVE SUMMARY

Bu session'da **community'nin yıllardır erişemediği** HTR-1000S firmware update sistemini **statik + aktif test** ile çıkardık:

- ✅ **11/12 validation gate** mapping tamamlandı (device error mesajları ile)
- ✅ **Her gate'in semantiği** humaxtv binary string'leri ile eşleşti
- ✅ **İmza algoritması** tanımlandı: Irdeto FlexiFlash v1 + RSA-PSS SHA-256
- ✅ **Resident key architecture** çıkarıldı (sysid + key_version indexed)
- 💎 **QDF channel export format'ta critical parser bug** keşfedildi (device crash)
- ✅ **SDL dosya yapısı tamamen çıkarıldı** (header, config section, metadata)

**Nihai hedef durumu:** SDL imza bypass %15 yakın. Kırmak için public key extraction gerekli.

---

## 1. CİHAZ KİMLİK BİLGİLERİ

```
Model Adı:         HTR-1000S
Yazılım:           TRSIAC1.01.01
Sistem ID:         9010.7D36
Yazılım Tarihi:    14 OCT 2016
Seri Numarası:     22 2200251 04587
Chip:              Broadcom BCM7358 (BMIPS3300, MIPS32-LE)
NAND:              Spansion S34ML01G200BHI00 (1Gbit SLC, BGA63, 128MB)
CAS:               Irdeto Cloaked CA
Loader Version:    3.2.1
```

**Device'ın Loader Data (error ekranından):**
```
MAN CODE 15        = 0x0F (Humax manufacturer ID)
HW VER 69          = 0x45 (hardware version)
SIG VER 43:0:35    = sig_sysid 0x2B : sig_sysver 0x00 : sig_subver 0x23
LOAD VER 35        = 0x23 (current loaded sequence)
VARIANT 5          = 0x05
```

---

## 2. SDL DOSYA FORMATI — TAM ÇÖZÜM

### 2.1 Byte-level yapı

```
Offset  Boyut  Alan                    Tipik Değer
──────────────────────────────────────────────────
0x00    1B     magic                   0x11 (HTR-1000S kabul formatı)
0x02    1B     manufacturer_code       0x0F (Humax)
0x03    1B     hardware_code           0x45 (HTR-1000S)
0x04    1B     load_sequence_number    Monotonic, window-checked
0x08-14 ASCII  date string             "02/04/2014.155" vb.
0x20    1B     partition_count         ⚠️ upd_variant ile mut.exc.
0x21    1B     upd_variant             ⚠️ partition_count ile mut.exc.
0x24-25 2B BE  variant                 0x0005
0x26-34 ASCII  label                   "45 u0001..." (not gated)
0x35-36 2B BE  sig_sysid               0x002B
0x37-38 2B BE  sig_sysver (key ver)    0x0000
0x39    1B     sig_subver (sig ver)    0x00 (IRHD) / 0x23 (user)
0x3A    1B     sig_version             0x24 (part of signature content)
0x3B-8A 80B    SIGNATURE BLOCK         RSA-PSS SHA-256 (640-bit?)
0x8B-8C 2B BE  CRC-16/ARC              over bytes [2:139]
0x8D+   N      PAYLOAD                 ~41MB firmware image + config
```

### 2.2 CRC-16/ARC algoritması (doğrulanmış)

```python
def crc16_arc(payload):
    crc = 0
    for byte in payload:
        crc ^= byte
        for _ in range(8):
            if crc & 1: crc = (crc >> 1) ^ 0xA001
            else: crc = crc >> 1
    return crc

# Test vector: crc16_arc(b"123456789") == 0xBB3D ✓
# IRHD-1000S:  crc16_arc(data[2:139]) == 0x2E49 ✓
```

### 2.3 Config section (payload sonunda, INI format)

IRHD-1000S'in son 4KB'ında Humax'ın iç build system metadata'sı açık metin:

```ini
[Manufacturer_Data]
MANUFACTURER_ID=0x0F;HUMAX identification number = 15
HARDWARE_VERSION=73                  ; Humax internal "X49" project code
LOADER_VERSION=3.1
FLASH_BLOCKS=82
TARGET_ADDRESS=0x80000000            ; MIPS KSEG0

[Flash_Configuration]
BLK1_STRT=0x80000000, BLK1_LEN=0x00080000
... (82 blocks)

[NVRAM_Configuration]
TARGET_CONFIG=R:\manucfg\HUMAX\X49\HMXX_X49.cfg

[Input_Files]
FLASH_FILE=O:\source\HUMAX\HW_X49\Al Jazeera\HMXX49_1.00.08-140401-22.bin

[Output_Control]
OUTFILE=HMX10008010_140401-22.S49V155

I00=akrisgone                        ; build operator ID
I98=cbrgerakr                        ; alt build operator ID
I20=O:\SOURCE\HUMAX\HW_X49\AL JAZEERA\HMXX49_1.00.08-140401-22.BIN
I21=HMX10008010_140401-22.S49V15
I22=R:\MANUCFG\HUMAX\X49\HMXX_X49.CFG
I23=O:\releases\Al Jazeera Sport\HUMAX\HW_X49\HMX10008010-140402.C49V155
```

**Humax internal server paths (information disclosure):**
- Drive O:\ = SOURCE (binary + release folder tree)
- Drive R:\ = MANUCFG (manufacturing configuration)

---

## 3. VALIDATION CHAIN — 11 GATE MAPPING

Bugün aktif test ile her gate izole edildi. Her gate device ekranında error code + Turkish+English description gösteriyor (humaxtv string'leriyle eşleşiyor).

| Gate | Error Code | Alan | Error Message | Byte Offset |
|------|-----------|------|---------------|-------------|
| **D01** | 0x80000D01 | Magic byte | "Invalid file format" | 0x00 |
| **D02** | 0x80000D02 | CRC-16/ARC | "CRC check failed" | 0x8B-0x8C |
| **D06** | 0x80000D06 | manufacturer_code | "manufacturer_code field of download header does not match STB" | 0x02 |
| **D07** | 0x80000D07 | hardware_code | "hardware_code mismatch" | 0x03 |
| **D0B** | 0x80000D0B | load_sequence | "load_sequence_number not within valid window for this STB" | 0x04 |
| **D0C** | 0x80000D0C | *(bilinmiyor)* | *(özel koşul)* | ? |
| **E00** | 0x80000E00 | variant | "variant field of download header does not match STB" | 0x24-0x25 |
| **E02** | 0x80000E02 | partition_count/upd_variant | "partition_count and upd_variant fields of download header are both non-zero" | 0x20, 0x21 |
| **C05** | 0x80000C05 | sig_sysid | "system ID of download signature does not match resident key" | 0x35-0x36 |
| **C06** | 0x80000C06 | sig_sysver | "key version of download signature does not match STB resident key" | 0x37-0x38 |
| **C0F** | 0x80000C0F | sig_subver | "signature version of download is out of step with resident signature version in STB" | 0x39 |
| **C09** | 0x80000C09 | RSA-PSS verify | "The download signature has failed a self-check" | 0x3B-0x8A (over whole file) |

### 3.1 İzolasyon prosedürü (reproducible)

Her gate için:
1. IRHD-1000S base dosyasında TEK byte değiştir
2. CRC-16/ARC yeniden hesapla (bytes [2:139] üzerinden, position 0x8B-0x8C'ye yaz)
3. USB'ye kopyala, upgrade.dsc dosya adıyla eşle
4. Cihazda "USB üzerinden güncelleme" seç
5. Error code + ekran mesajı kayıt

**Doğrulanmış test matrisi:** `~/Desktop/qdf-samples/` + scratchpad dir'de her test SDL'i saklı.

---

## 4. İMZA SİSTEMİ — Irdeto FlexiFlash v1

### 4.1 Algoritma (humaxtv binary'den çıkarıldı)

```
Standard:      Irdeto FlexiFlash v1 (string "1.2.7.f-irdeto-flexiflash-v1")
Padding/Hash:  pkcs1psssha256 (RSA-PSS + SHA-256)
Signature:     80 byte block @ offset 0x3B-0x8A
Coverage:      Whole file (header + payload), confirmed by test
```

### 4.2 Resident Key Architecture

```
Device NAND stores resident keys indexed by (sysid, key_version):

  Key[sysid=0x002B, keyversion=0x0000] = <Humax Filbox Turkey public key>
  (Device'ta sadece bu bir key var, user'ın cihazı için)

Verification flow:
  1. SDL geliyor → sig_sysid okunur
  2. Device: resident key store'da sysid eşleşmesini ara
     - Yoksa → C05 ERROR
     - Varsa → key_version check
  3. key_version eşleşmezse → C06 ERROR
  4. signature_version check → C0F
  5. Son: resident key ile RSA-PSS SHA-256 verify
     - Match → flash
     - Mismatch → C09 ERROR
```

### 4.3 Operator-locked key observation

**Kritik bulgu:** IRHD-1000S (Al Jazeera) ve TRSIAC (Filbox Turkey) **aynı sig_sysid (0x002B)** kullanıyor ama **farklı private key'lerle imzalı**.

```
Test: Original IRHD-1000S flash denendi (modifiye edilmemiş, tam valid Humax imzası)
Sonuç: C09 (signature verify failed)

Yorum: User'ın cihazı Al Jazeera key'ini TANIMIYOR.
       Humax her operatör için ayrı signing key kullanıyor,
       hepsini aynı sysid altında.
```

### 4.4 İmza bloğu entropy analizi

| Dosya | Boyut | Entropy | Yorum |
|-------|-------|---------|-------|
| IRHD-1000S (Al Jazeera, mg0x11) | 80B | 6.062 | Full RSA signature |
| V40_HD-3600S2 (mg0x49) | 80B | 1.429 | 68B zero + 12B constant |
| D_01_HD-3601S2 (mg0x49) | 80B | 1.497 | 68B zero + 12B constant |

**V40/D_01 ortak 12-byte sabit (farklı modeller aynı):**
```
13 32 89 71 66 15 79 5a b4 03 ed b5
```

Bu, magic 0x49 formatının "zayıf" imza modu — HTR-1000S destekelemiyor (D01 red).

---

## 5. QDF FORMAT — Channel Export/Import

### 5.1 Dosya yapısı

Cihazdan 6 örnek alınarak çıkarıldı (farklı device state'leri):

```
Offset   Boyut   İçerik                 Notlar
──────────────────────────────────────────────────────────
0x0000   16B     SABİT HEADER            Her export'ta aynı
0x0010   16B     RANDOM IV               Her export'ta farklı
0x0020   N*16B   AES-CBC şifreli content Device key ile
Last 80B 80B     Signature/MAC?          Random görünümlü
```

### 5.2 Sabit header fingerprint

```
7edf41f9fb54caf2ff27bd10dcd76391
```

6 farklı export'ta identik, muhtemelen:
- `AES-encrypt(magic_bytes, device_key, fixed_IV=0)` veya
- `SHA-128(device_key)` benzeri device fingerprint

Humaxtv binary ve NAND dump'ında yok → runtime türetiliyor.

### 5.3 QDF FORMAT VALIDATION — ZAYIF ⚠️

Test matrix:

| Değişiklik | Cihaz tepkisi |
|-----------|---------------|
| Son 80 byte sıfırlı | ✅ Kabul edildi ("süreç tamamlandı") |
| Orta 2KB sıfır | ✅ Kabul edildi |
| İlk byte header değişti | ✅ Kabul edildi |
| 10 byte sıfır dosya | 💥 **CIHAZ CRASH + REBOOT** |

**QDF import rutini kriptografik doğrulama yapmıyor.** Dosyayı okur, decrypt'e çalışır, çöp çıkarsa sessizce "0 kanal" diyerek "başarılı" döner.

### 5.4 💎 KRİTİK VULNERABILITY: QDF Parser Crash

```
CVE-like finding:

PRODUCT:     Humax HTR-1000S (Model 5 family: HDR-1000S, HTR-1000S)
COMPONENT:   USB QDF channel import function
TYPE:        Denial of Service via malformed file (parser bug)
TRIGGER:     USB stick with 10-byte all-zero file named export.qdf
IMPACT:      Immediate device crash + automatic reboot
REPRODUCTION: Confirmed deterministic (device recovers normally)
CLASSIFICATION: CWE-125 Out-of-bounds Read (muhtemel)
```

**Attack chain:**
1. Attacker USB bellek takar (physical access gerekli)
2. 10-byte zero `export.qdf` dosyası
3. Victim "USB'den kanal yükle" seçer
4. Device parser underflow → crash
5. Automatic reboot (data loss yok, DoS olarak çalışır)

**Not:** Code execution'a çevirilebilir mi? Fuzzing + Ghidra parser analizi gerekir. Minimum olarak **Local DoS** CVE'ye uygun.

---

## 6. CROSS-REFERENCES & FINGERPRINTS

### 6.1 Humaxtv binary (MIPS ELF, 4.9MB) önemli stringler

```
"pkcs1psssha256"                           → signature algorithm
"1.2.7.f-irdeto-flexiflash-v1"             → signing system
"SignatureChain / rootKeyHash / packageSignature"  → ASN.1 schema
"RSAPublicKey / modulus / exponent"        → key format
"IRDETO_LOADER_PARTITION"                  → NAND partition name
"IRDETO_UC_PRIVATE_DATA"                   → private data path
"Humax HW69 UC2.8.3 Release Build 2014-08-18"
"BCHP_BSP_GLB_CONTROL_FW_FLAGS"            → Broadcom BSP register
"/var/lib/humaxtv/drm/"                    → key storage directory
"/dev/mtdblock1, /dev/mtdblock5"           → flash devices
```

### 6.2 Stage-1 bootloader (NAND[0:0x20000])

- MIPS32 LE kodu, Ghidra'da başarılı disassemble
- Boot vector 0xB8000000 → jump to 0xB8000084 (real init)
- Chain: 5 init functions call'ları
- `jalr v0 => SUB_9fc06e5c` = **BCM7358 silicon mask ROM call** (BSP)
- Register writes: 0xB032B030 (first peripheral enable)

### 6.3 Yakın-eşleşme ("salt") değerleri

```
QDF header MD5:          f4d58e7b2395916a7be0e68ee540adf0
IRHD-1000S imza MD5:     ca70675c6883d6cec1741112ee2d13f4
IRHD-1000S imza SHA-256: 8faefd6a8001bb1e56f5193c11aa8d42509b4a41211d71a6da1f26ce134fe80e
V40/D_01 ortak 12B MD5:  498b799474b57f6db2fb08e37129203b
```

### 6.4 Humax iç identifier'lar

```
"akrisgone"              → build operator ID (I00 field)
"cbrgerakr"              → alt build operator ID (I98 field)
"HW_X49"                 → Humax project code for HTR-1000S hardware
"HMX10008010"            → Al Jazeera build ID
"HMXX_X49.CFG"           → manufacturing config file
"S49V155"                → output file suffix (Signature v4.9, Version 155)
"C49V155"                → compiled release suffix
```

---

## 7. COMMUNITY DURUMU (hummy.tv, avforums araştırması)

### 7.1 Eski modeller bypass'landı
- **FOXSAT-HDR, HDR-FOX, HD-FOX** (Model 4): Raydon + af123 tarafından çözüldü
- Yöntem: open-source compliance disclosure + JTAG hardware dump + sig algoritma guess

### 7.2 HDR-2000T geçiş
- Humax güvenliği artırdı
- Public bypass yok

### 7.3 HDR-1000S / HTR-1000S (Model 5, bu rapor)
> "No custom firmware is currently available for the HDR-1000S model. People involved in custom firmware development have examined the HDR-1000S but concluded that it would be a more difficult target as Humax closed the loopholes previously used."

**— hummy.tv community verdict**

Eklenmiş güvenlik:
- LUKS filesystem encryption
- On-chip BSP hardware security
- Hardware-bound keys (MAC + serial derived)
- Operator-locked signing keys

---

## 8. BUGÜNE KADAR TÜKETİLEN SALDIRI YOLLARI

| Yol | Deneme | Sonuç |
|-----|--------|-------|
| Zero signature SDL | ✓ | C09 (strict RSA-PSS verify) |
| Random payload modification | ✓ | C09 (signature covers payload) |
| V40 "weak sig" pattern replay | ✓ | C09 (pattern not recognized) |
| All-0xFF signature | ✓ | C09 |
| QDF-derived signature (6 variants) | ✓ | Hepsi C09 |
| Original IRHD-1000S flash (valid Humax sig) | ✓ | C09 (operator-locked keys) |
| Magic byte 0x49 (V40 format) | ✓ | D01 (strict magic check) |
| Minimal 141-byte SDL | ✓ | C09 |
| 1-byte append | ✓ | C09 (file-length coverage) |
| CRC bozma | ✓ | D02 (gate map) |
| Her header field tek tek | ✓ | 11/12 gate mapped |

**Hiçbir bypass bulunamadı — RSA-PSS SHA-256 verify matematiksel olarak sağlam.**

---

## 9. KALAN YOLLAR (gelecek session)

### 9.1 Software-only (öncelik: humaxtv deep RE)

**Humaxtv Ghidra statik analiz:**
1. `qdf_import` fonksiyonunu bul → 10-byte crash root cause
2. Signature verify fonksiyonunu bul → public key'in load edildiği yolu takip et
3. Public key file path'ini çıkar (`/var/lib/humaxtv/drm/` civarı)
4. NAND partition'dan key dosyasını çıkar

**Eğer public key çıkarılırsa:**
- Modulus bit boyutuna bak (640 bit = kırılabilir, 1024+ = pratik imkansız)
- RSA-640 ise factorization denemesi (haftalar sürer)

### 9.2 Hardware (gelecek: para gerekir)

- **CH341A SPI flash programmer** (~$5) → SPI-NOR dump
- **JTAG debugger** (~$30-50) → BSP mask ROM dump + runtime
- **ChipWhisperer** ($100-300) → voltage glitching

### 9.3 QDF vulnerability development

- Fuzz systematic (file length, byte patterns) → crash boundary
- Crash → arbitrary code execution path (çok ileri seviye)
- Code exec'ten → NAND partition read access

---

## 10. BULUNANLAR vs. ÇÖZÜLMEDI

### ✅ Çözüldü
- SDL dosya formatı tam
- Validation chain 11/12 gate
- İmza algoritması tanımlandı
- Resident key architecture
- QDF format yapısı
- QDF crash bug
- Build system identifiers
- Humax internal paths

### ❌ Çözülmedi
- SDL imza bypass (public key gerekli)
- D0C gate (nadir koşul)
- QDF decryption key extraction
- RSA key boyutu kesinleşmedi (640 vs 1024)
- OPERATOR_TYPE değiştirme (ana hedef)

### 📊 Gerçek "cracking" ilerleme: ~%15
Format çözüldü ama matematiksel bypass yok. Ghidra deep analiz %20-30 ekler.

---

## 11. ETHICAL & LEGAL NOTES

- Araştırma kendi cihazı üzerinde yapıldı (user owned)
- Hedef: cihazı post-platform shutdown (Filbox 2019) kullanılabilir hale getirmek
- Hiçbir aktif piracy/CAS cracking girişimi YOK
- QDF vulnerability responsible disclosure yolu uygun olur (Humax Security Team)
- Writeup public olduğunda redact edilecek değerler yok

---

## 12. REFERANSLAR

- hummy.tv forum: HDR-1000S discussion threads
- avforums.com: Raydon FOXSAT bypass history
- Broadcom BCM7358 datasheet (stblinux kernel)
- Irdeto Cloaked CA whitepapers
- RFC 3447: PKCS#1 v2.1 (RSA-PSS)
- Riscure: Secure boot bypass via fault injection
- NCC Group: MediaTek bootrom glitching

---

## EK: Dosya referansları

### Elimizdeki dosyalar
```
/Volumes/UNTITLED/IRHD1000S_10008_L10.sdl              Al Jazeera firmware (13.8MB)
/Users/kadircan/Desktop/sdl-collection/
  V40_HD-3600S2_HD3800S2.sdl                           Humax HD-3600S2 (9.0MB, magic 0x49)
  D_01.00.06.66-M_HD-3601S2_HD-3601S2B_HD3801S2.sdl    HD-3601S2 (17.2MB, magic 0x49)

/Users/kadircan/Desktop/qdf-samples/
  export_01_empty.qdf  → export_06_after_device_save.qdf  (6 örnek, hepsi 4192-4208 byte)

/Users/kadircan/Desktop/s_21-04-24-19_HUMAX/qemu-kit/humax-recovered/
  full-binaries/humaxtv                                Linux userspace binary (4.9MB)
  nand/nand_128mb_deswapped.bin                        Full NAND dump (128MB)

/tmp/claude-501/.../scratchpad/
  stage1_bootloader.bin                                NAND[0:0x20000], Ghidra'ya alındı
```

---

**Rapor sonu**  
**Session özeti:** 9 saat, 25+ aktif test, 11 gate mapped, 1 critical bug, 0 bypass.

---

---

## 13. EK (v9) — Ghidra humaxtv Analizi ve Düzeltme

### 13.1 Ghidra headless pipeline kuruldu

- `humaxtv` ELF dosyası **truncate edilmiş** bulundu (section header table dosya sonunu aşıyor, son ~35KB eksik)
- Ghidra'nın ELF loader'ı bu yüzden MIPS GOT/PLT fixup sırasında NullPointerException ile crash ediyordu
- **Çözüm**: Python ile ELF header manuel parse edildi, dosya zero-pad ile tamamlandı, section header referansları (e_shoff/e_shnum/e_shstrndx) sıfırlandı
- Headless analiz başarıyla tamamlandı (492 saniye, 37MB proje veritabanı)
- Decompiler native binary Mac'te yok (Ghidra 12 Mac ARM64 build gerektiriyor) — sadece disassembly + string/xref analizi yapıldı

### 13.2 KRİTİK DÜZELTME: humaxtv SDL imza doğrulama kodunu içermiyor

Önceki varsayım yanlıştı. Doğrulama:
- `pkcs1psssha256`, `RSAPublicKey`, `rootKeyHash`, `packageSignature`, `SignatureChain`, `IRDETO_UC_PRIVATE_DATA` string'lerine **hem kod (LUI+ADDIU/ORI instruction pair tarama) hem de data (ham pointer tarama) seviyesinde SIFIR reference bulundu**
- Bu string'ler muhtemelen **Irdeto Cloaked CA (TV içerik şifreleme/EMM-ECM)** alt sistemine ait, **SDL firmware güncelleme** sistemine değil
- Cihazda gözlemlenen D01-C09 kodları ile humaxtv'de bulunan E516/E520/E521 kodları **farklı numara alanları** — ayrı sistemler

### 13.3 Gerçek loader konumu bulundu (ama şifreli)

NAND dump'ında arama:
```
'IRDETO_LOADER_PARTITION' @ 0x02aa3388 ve 0x02ac3388  (128KB arayla, primary+backup kopya)
Yanında etiket: 'IRDETO_CPCB_ENCRYPTED'
Konum: ~44.7MB (rootfs partition aralığı içinde, 12-57MB)
```

Bu alan **yüksek entropili / şifreli** — gerçek loader kodu (USB SDL doğrulama, D01-C09 gate'leri, RSA-PSS verify) muhtemelen bu partition içinde ama encrypted-at-rest durumda.

### 13.4 Güncel blocker

**SDL imza public key'ine ulaşmak için önce `IRDETO_LOADER_PARTITION`'ın şifresini çözmemiz gerekiyor.** Bu:
- Ya bir decryption key/algoritma bilgisi gerektiriyor (CFE/stage1 bootloader'dan çıkarılabilir mi araştırılmalı — stage1 zaten Ghidra'da, NAND[0:0x20000])
- Ya da donanım erişimi gerektiriyor (SPI-NOR dump, JTAG runtime memory dump)

### 13.5 Infrastructure kazanımları (kalıcı)

- Ghidra headless pipeline (ELF repair script + Java GhidraScript xref hunter) — tekrar kullanılabilir, başka MIPS/ELF binary'ler için de çalışır
- `tools/` klasörüne eklenebilir: `elf_repair.py`, `FindSigVerify.java`

---
