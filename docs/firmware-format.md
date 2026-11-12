# Supported firmware container

These observations apply to the evaluated LZ5014 R/P containers. Other Brother
families may use different framing, compression, signing or update transports.

- Official input begins with PJL `EXECUTE BRDOWNLOAD` and a `DATA=` body.
- The original body carries an RSA-2048 PKCS#1 v1.5 / SHA-256 signature.
  `verify_update_signature.py` verifies it offline. An embedded public key alone
  establishes internal consistency, not independently trusted manufacturer identity.
- ROM0 starts with 256 direct bytes, followed by tagged frames. Each frame has
  a prior-frame 16-bit byte sum, tag/length and logical offset. Normal data frames
  hold at most 4095 bytes. A final 27-byte footer contains model/date/checksum data.
- ROM0's final two bytes contain the sum of all preceding logical ROM0 bytes
  modulo 65536. The displayed firmware suffix follows that value.
- RO and RW are zlib streams with declared compressed/expanded sizes and load
  addresses. RO is recompressed with window bits 13. The new payload is appended
  as uncompressed flash-resident data before the ROM0 footer, with unchanged
  original RO/RW load addresses.
- Repacking updates ROM0 size, frame checksums, outer lengths, complementary
  flash-header offset/size fields and the observed legacy CRC.
- The legacy CRC is reflected polynomial `0x8408`, initial value zero. The
  selected prefix is stored in the profile metadata. The model body starts with
  `8CA-U29-001`; related static tables also contain `8CA-U29-002`.
- The evaluated legacy path accepts the modified package without preserving
  its original RSA signature. This is not evidence that another model accepts
  unsigned updates, and CRC integrity is not cryptographic authenticity.

The builder independently re-extracts the package and compares complete ROM0
bytes, patched RO, original RW and original ROM1. It rejects overlapping flash
regions, unexpected hook instructions, writable/BSS payload segments, BE8 code,
wrong architecture and unrecognized exact source hashes.

Useful offline tools:

```sh
python tools/verify_update_signature.py ORIGINAL.djf
python tools/extract_djf.py ORIGINAL.djf build/extracted
python tools/inspect_legacy_update.py ORIGINAL.djf
python tools/make_analysis_elf.py build/extracted/ro.bin build/analysis.elf \
  --base 0x40037000 --entry-offset YOUR_VERIFIED_OFFSET
```

An analysis ELF is not a firmware update. For mixed ARM/Thumb code, establish
instruction state for each entry; this wrapper seeds one mode per invocation.
Do not interpret a misdecoded ARM helper or a missing function as runtime evidence.
