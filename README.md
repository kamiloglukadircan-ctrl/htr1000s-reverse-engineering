# HTR-1000S Firmware Reverse Engineering

**Humax HTR-1000S (Filbox Turkey) satellite receiver firmware reverse engineering project**

[🇹🇷 Türkçe](#türkçe) | [🇬🇧 English](#english)

---

## English

### What is this?

Independent reverse engineering of the Humax HTR-1000S (Filbox Turkey variant) firmware update system. The device belongs to Humax's "Model 5" generation (same family as HDR-1000S) which hummy.tv community described as:

> "Significantly hardened security model. No custom firmware is currently available for the HDR-1000S model. People involved in custom firmware development have examined the HDR-1000S but concluded that it would be a more difficult target."

This repo documents an attempt to go deeper than the community's prior work.

### 🆘 We need help — here's exactly where we're stuck

The SDL signature check (RSA-PSS SHA-256) runs in a loader binary that is **encrypted at
rest in NAND** under the label `IRDETO_LOADER_PARTITION` (found next to an
`IRDETO_CPCB_ENCRYPTED` tag). We confirmed the Linux-side `humaxtv` binary does NOT
contain this logic — its crypto strings belong to an unrelated Conditional Access
subsystem. See [CONTRIBUTING.md](CONTRIBUTING.md) for the precise ask: **we need the
decrypted loader partition, a SPI-NOR dump, or the decryption method**, from anyone with
the hardware (CH341A / JTAG) or existing knowledge of this encryption scheme.

### Key findings

- ✅ **Full validation chain mapped**: 11 of 12 gates identified (D01, D02, D06, D07, D0B, E00, E02, C05, C06, C0F, C09) with exact byte offsets and error code semantics
- ✅ **Signature system identified**: Irdeto FlexiFlash v1 using RSA-PSS SHA-256
- ✅ **Resident key architecture**: Device stores keys indexed by (sysid, key_version); keys are operator-locked per Humax market
- ✅ **SDL file format fully documented**: byte-level layout including hidden INI config section
- 💎 **CVE-worthy bug discovered**: QDF channel import function crashes on 10-byte malformed file (DoS)
- 📊 **CRC algorithm confirmed**: CRC-16/ARC over bytes [2:139]

### Status

- **Format reversal**: ~95% complete
- **Signature bypass**: not achieved (RSA-PSS SHA-256 is mathematically sound; public key extraction would be the next step)

### Why

The Filbox satellite platform shut down in 2019 making many HTR-1000S devices functionally bricked. Research aims to understand what unlocking would require — fully software-only (currently answer: not possible without public key extraction via humaxtv Ghidra analysis or hardware probing).

### Repo contents

```
docs/
  REPORT.md                Full technical writeup (480 lines)
  VALIDATION_CHAIN.md      Gate-by-gate breakdown with error messages
  SDL_FORMAT.md            Byte-level SDL file layout
  QDF_FORMAT.md            Channel export format + crash bug
  SIGNATURE_FINGERPRINTS.md  Searchable hashes for cross-reference

tools/
  crc16_arc.py             CRC-16/ARC implementation with test vectors
  sdl_header_parser.py     Parse any SDL file's header fields
  qdf_analyzer.py          Analyze QDF export files
  gate_test_builder.py     Build test SDL files for gate isolation

samples/
  (SDL/QDF files NOT included for copyright reasons)
```

### Contributing

If you have:
- Access to a Humax HTR-1000S device
- SDL files from the Filbox TRSIAC distribution (any version)
- Humax GPL compliance disclosures for Model 5 generation
- Ideas for the remaining D0C gate

Please open an issue or PR.

### Legal

- Research performed on researcher-owned hardware
- No conditional access (CAS) bypass attempted
- No pirated firmware distributed
- QDF crash bug: responsible disclosure to Humax Security planned

### License

CC BY-SA 4.0 for documentation. MIT for tools/code.

---

## Türkçe

### Bu nedir?

Humax HTR-1000S (Filbox Türkiye versiyonu) uydu alıcısının firmware güncelleme sisteminin bağımsız tersine mühendislik çalışması. Cihaz Humax'ın "Model 5" neslinin bir parçası (HDR-1000S ile aynı aile). hummy.tv community'si bu modeli şöyle tanımlıyor:

> "Önemli ölçüde sertleştirilmiş güvenlik modeli. HDR-1000S için custom firmware şu an yok. Custom firmware geliştirmeye dahil olanlar HDR-1000S'i inceledi ancak daha zor bir hedef olduğu sonucuna vardı."

Bu repo community'nin daha önce yapamadığı derinlikte çalışmayı belgeliyor.

### 🆘 Yardım gerekiyor — tam olarak nerede takıldığımız

SDL imza kontrolü (RSA-PSS SHA-256), NAND'da **şifreli halde duran** bir loader binary'sinde
çalışıyor (`IRDETO_LOADER_PARTITION` etiketi, yanında `IRDETO_CPCB_ENCRYPTED` tag'i ile).
Linux tarafındaki `humaxtv` binary'sinin bu mantığı İÇERMEDİĞİNİ doğruladık — oradaki crypto
string'leri alakasız bir Conditional Access alt sistemine ait. Tam detay için
[CONTRIBUTING.md](CONTRIBUTING.md)'ye bak: **ihtiyacımız olan şey şifresi çözülmüş loader
partition'ı, bir SPI-NOR dump'ı, veya şifre çözme yöntemi** — CH341A/JTAG donanımı olan
veya bu şifreleme şemasını bilen herkesten.

### Önemli bulgular

- ✅ **Validation chain haritası**: 12 gate'in 11'i tam byte offset ve error semantiği ile tespit edildi (D01, D02, D06, D07, D0B, E00, E02, C05, C06, C0F, C09)
- ✅ **İmza sistemi**: Irdeto FlexiFlash v1 (RSA-PSS SHA-256)
- ✅ **Resident key mimarisi**: Cihaz anahtarları (sysid, key_version) kombinasyonu ile indexli; her Humax pazarına özel key
- ✅ **SDL dosya formatı**: Gizli INI config section dahil tam byte-level çıkartıldı
- 💎 **CVE'ye değer bug**: QDF kanal import fonksiyonu 10 byte'lık geçersiz dosyada crash ediyor (DoS)
- 📊 **CRC algoritması**: CRC-16/ARC, bytes [2:139] üzerinden

### Durum

- **Format çözümü**: ~%95 tamam
- **İmza bypass**: başarısız (RSA-PSS SHA-256 matematik olarak güvenli; sonraki adım public key extraction)

### Neden

Filbox platformu 2019'da kapandı, binlerce HTR-1000S cihazı fonksiyonel olarak çöp durumunda. Araştırma, bu cihazların yazılım-only unlock'u için neyin gerekli olduğunu anlamayı amaçlıyor (şu anki cevap: humaxtv Ghidra analizi veya donanım probing olmadan mümkün değil).

### Katkıda bulunma

Eğer sende varsa:
- Humax HTR-1000S cihazı
- Filbox TRSIAC dağıtımından SDL dosyaları (herhangi sürüm)
- Humax Model 5 nesli için GPL compliance belgeleri
- Kalan D0C gate için fikir

Issue aç veya PR gönder.

### Yasal

- Araştırma araştırmacının kendi donanımında yapıldı
- CAS bypass denemesi yok
- Pirated firmware dağıtımı yok
- QDF crash bug için Humax Security'ye responsible disclosure planlanıyor
