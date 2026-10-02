# HTR-1000S Reverse Engineering - Arama/Doğrulama Parmak İzleri
## Internet'te aranacak değerler

---

## 1. QDF Dosya Formatı Sabit Header (16 byte)
**Her export'ta aynı çıktı:**
```
7edf41f9fb54caf2ff27bd10dcd76391
```
Olası arama varyasyonları:
- `7edf41f9` (ilk 4 byte, muhtemel magic)
- `7edf41f9fb54caf2` (ilk 8 byte)
- `91 63 d7 dc 10 bd 27 ff f2 ca 54 fb f9 41 df 7e` (reverse endianness)

Arama yerleri:
- Google (direkt hex)
- GitHub code search: `7edf41f9fb54caf2`
- Humax leaked firmware repolari
- Irdeto reference docs

---

## 2. SDL İmza Blokları (80 byte her biri)

### IRHD-1000S (Al Jazeera, 2014) imzası:
```
da93ca20 ad29fcf0 b0245bce 74f85785
68226f94 e02b5555 9da4ca56 41568146
beb94c9f 78550752 75589609 f1fe0442
74f375f2 3db4ece6 9b0568ae b1b7df0b
c70ce9a4 c2f9337d b1ed62d0 d08eee03
```
MD5 of this signature: `(hesapla aşağıda)`

### V40_HD-3600S2 imzası (son 12 byte dolu):
```
13 32 89 71 66 15 79 5a b4 03 ed b5
```

### D_01_HD-3601S2 imzası (son 12 byte dolu, V40 ile AYNI):
```
13 32 89 71 66 15 79 5a b4 03 ed b5
```

**Bu 12-byte sabit özellikle önemli — iki farklı Humax modelinde aynı.**

---

## 3. Humax İç Build System Identifiers (IRHD-1000S config section'dan)

```
I00=akrisgone
I98=cbrgerakr
```
Bu string'lerde Google / GitHub araması:
- `"akrisgone"`
- `"cbrgerakr"`
- `"akrisgone" humax`
- `"cbrgerakr" humax`

---

## 4. Build System File Paths (Humax internal server)

```
O:\SOURCE\HUMAX\HW_X49\AL JAZEERA\HMXX49_1.00.08-140401-22.BIN
R:\MANUCFG\HUMAX\X49\HMXX_X49.CFG
O:\releases\Al Jazeera Sport\HUMAX\HW_X49\HMX10008010-140402.C49V155
```

Aranacak:
- `"HW_X49" humax`
- `"HMXX49"` 
- `"MANUCFG humax"`
- `"HMX10008010"`
- `"S49V155"` (output file suffix)
- `"C49V155"`
- `"HMXX_X49"` (manuf config file)

---

## 5. Cihaz Sistem Değerleri (user cihazından)

```
Model Adı:         HTR-1000S
Yazılım:           TRSIAC1.01.01
Sistem ID:         9010.7D36
Tarih:             14 OCT 2016
Seri Numarası:     22 2200251 04587

Error Code Context:
  MAN CODE 15 (0x0F)
  HW VER 69 (0x45)
  SIG VER 43:0:35 (0x2B:0x00:0x23)
  LOAD VER 35 (0x23)
  VARIANT 5
  LOADER 3.2.1
```

Aranacak kombinasyonlar:
- `"9010.7D36"`
- `"TRSIAC1" humax`
- `"TRSIAC" humax filbox`
- `"HTR-1000S" filbox leaked firmware`
- `"HMXX_X49" OR "HMXX_X9x" humax config`

---

## 6. Humaxtv Binary'den çıkan Önemli Stringler

```
pkcs1psssha256
1.2.7.f-irdeto-flexiflash-v1
SignatureChain / rootKeyHash / packageSignature
RSAPublicKey / modulus / exponent
IRDETO_LOADER_PARTITION
IRDETO_UC_PRIVATE_DATA
Humax HW69 UC2.8.3 Release Build 2014-08-18
BCHP_BSP_GLB_CONTROL_FW_FLAGS
E516-0 Invalid package signature  <- bizim C09'un ismi
E520-0 FlexiFlash download
```

Aranacak kombinasyonlar:
- `"flexiflash v1" "pkcs1psssha256"`
- `"IRDETO_UC_PRIVATE_DATA" leak`
- `"Humax HW69 UC2.8.3"` (specific build id)
- `"irdeto-flexiflash-v1" source code`

---

## 7. BCM7358 Donanım Bilgileri

```
Chip: Broadcom BCM7358 (BMIPS3300, MIPS32-LE)
NAND: Spansion S34ML01G200BHI00 (1Gbit SLC, BGA63)
Reset vector base: 0xBFC00000 (standard MIPS)
Boot ROM region: 0x9FC00000 (silikon içi mask ROM)
Register space: 0xB0000000-0xB0FFFFFF (chip control)
Specifically found: 0xB032B030 (first peripheral enable)
BSP: BCHP_BSP_GLB_CONTROL_FW_FLAGS register
```

Aranacak:
- `"BCM7358" datasheet`
- `"BCM7358" GPL source leak`
- `"BCHP_BSP" register leaked`

---

## 8. CRC-16/ARC Teyit Edilmiş

```
Algoritma: CRC-16/ARC (poly 0x8005, reflected 0xA001, init 0, xorout 0)
Range:     SDL byte [2:139] (header excluding first 2 bytes)
Position:  bytes 0x8B-0x8C (big-endian)
```
Standart — sorun değil, bulgu olarak kaydet.

---

## 9. Validation Chain (bulunan hata kodları)

```
D01  Format/magic validation
D02  Hardware version check  
D07  Loader version check
E00  (unknown yet)
D0B  (unknown yet)
D0C  (unknown yet)
C05  Content pre-check
C0F  Pre-signature check
C09  Signature verify  ← bizim takıldığımız
```

---

## 10. SDL Dosyaları MD5 Fingerprintleri

```
IRHD1000S_10008_L10.sdl       : 26d55f07f0b7783173522473ce3a73d9
V40_HD-3600S2_HD3800S2.sdl    : 3ea6bf8d8930b5500ad14a67f16893bc
D_01.00.06.66-M_HD-3601S2...  : 6890f91ff068b423fd3dc330d2d5e96f
```

Internet'te hash araması: VirusTotal, filename search

---

## ÖNERİLEN ARAMA SIRASI

1. **Yüksek değerli:** `"7edf41f9"` GitHub code search (QDF magic)
2. **Yüksek değerli:** `"akrisgone" OR "cbrgerakr"` Google
3. **Yüksek değerli:** `TRSIAC1 filbox firmware`
4. **Değerli:** `"HTR-1000S" OR "HDR-1000S" leaked sdl site:*.ru OR site:*.cn`
5. **Değerli:** `"pkcs1psssha256" "flexiflash" irdeto`
6. **Değerli:** `"IRDETO_UC_PRIVATE_DATA" dump leak`
7. **Değerli:** `"HMX10008010" humax filbox download`
8. **Low priority:** `"BCM7358" GPL kernel source` (zaten GitHub'da var)
