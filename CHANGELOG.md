# Changelog

[English](CHANGELOG.md) | [简体中文](CHANGELOG.zh.md)

All notable changes to `tongsuo-go` are documented in this file.
The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning 2.0.0](https://semver.org/).

> The project's major version is `0`, so the API is **not** considered stable;
> downstream consumers should read this file before upgrading. Section headers
> (`Added` / `Changed` / `Fixed` / `Documentation` / `BREAKING`, etc.) follow
> the Keep a Changelog convention. Technical terms (SM2 / SM3 / SM4 / PEM /
> DER / PKCS#7 / PKCS#8 / PKCS#12 / openssl / CRL / CSR / OCSP / NTLS / JWK
> / RFC xxxx, etc.) are kept verbatim and **not** translated.
>
> The Chinese version of this file lives at [CHANGELOG.zh.md](CHANGELOG.zh.md).

---

## [0.1.1] - 2026-09-09

### Added

- Added EdDSA algorithm packages `crypto/ed25519` and `crypto/ed448`
  (RFC 8032): 32B / 57B seeds and public-key bytes interoperate with the Go
  standard library and WireGuard.
- Added the X25519 ECDH package `crypto/x25519` (RFC 7748): 32-byte shared
  secret interoperable with Go `crypto/ecdh` and WireGuard.
- Added the ECDH package `crypto/ecdh` for curve-based key agreement.
- Added the KDF package `crypto/kdf` for HKDF / PBKDF2 derivation and
  availability probing.
- Added the unified `key/` package: cross-algorithm key interfaces
  (symmetric / asymmetric), PEM auto-sniffing parsing, key lifecycle
  management (`Handle` / `Store`), and KDF derivation — **delivered in
  v0.1.1**, not a roadmap item.
- Added a sign API to `crypto/rsa` that selects the digest by hash.
- `x509` gained `CRL.Verify`; `Extension` gained an OID field that returns
  the extension's dotted OID; EdDSA keys support digest-less sign / verify
  for certificates, CSRs, and CRLs.
- `tls` client gained peer certificate validation and timeout semantics.
- Added internal helper packages `internal/digest` and `internal/testutil`.

### Changed

- `internal/core` introduced `core.RandomBytes`, removing `crypto/rand`'s
  dependency on `internal/native`.
- Tightened `internal/core` coding conventions and slimmed down the core
  layer.
- AES / SM4 block-cipher `Block` switched to a template-plus-copy pattern
  to support safe concurrent reuse.

### Fixed

- `internal/core`: added nil / closed defensive checks to accessors; fixed
  a stack-container leak in `ChainVerify`.
- `internal/native`: fixed the use-after-free in
  `X509_CRL_get0_authority_key_id`.
- AES / SM4-GCM now enforces a 12-byte nonce length.
- Corrected asymmetric encrypt / decrypt semantics and PEM-load type safety
  in the RSA, SM2, and `key` packages.
- `asn1` DER parsing gained a nesting-depth limit.
- `ocsp.Check` now adaptively matches certificate status hashes.

### Documentation

- Added architecture notes for the `key` package (merged in v0.1.1).
- Cleaned up Phase-stage markers from the roadmap and code comments.
- Removed `ci-cd.md` and `roadmap.md`; updated cross-references in other
  docs.
- `docs/architecture.md` synced with the current directory structure and
  version numbers.
- Added pragmatic guidance on zeroing sensitive buffers.
- Synced documentation for Ed25519, Ed448, and X25519 support.
- Reworked `README.md` into a Chinese-English bilingual version.

---

## [0.1.0] - 2026-09-03

### Added

#### Algorithm engines (`crypto/`)

- SM3 hash algorithm.
- SM4 symmetric encryption (ECB / CBC / CTR / OFB / CFB / GCM), with a
  Zero-padding convenience helper.
- SM2 asymmetric (GenerateKey / Encrypt / Decrypt / Sign / Verify); added
  SM2 ciphertext format conversion DER ↔ C1C3C2 ↔ C1C2C3 along with
  `EncryptWithOrder` / `DecryptWithOrder`.
- AES (ECB / CBC / CTR / GCM, with the `cipher.AEAD` interface).
- HMAC (SM3 / SHA256 / SHA384, with `SumSM3` / `SumSHA256` / `SumSHA384`
  convenience helpers).
- Hashes: MD5 / SHA1 / SHA256 / SHA512.
- Secure random-number generation (`Read` / `Bytes`).

#### Key infrastructure

- RSA: GenerateKey / Load / Marshal (PKCS#8 / PKCS#1 / encrypted PEM) /
  Sign (PKCS1v15 / PSS) / Verify / Encrypt+Decrypt (PKCS1v15 / OAEP) /
  Params / ChangePassword / Match.
- ECDSA: GenerateKey / Load / Marshal / Sign / Verify / Params.
- `CreateCertificate` / CSR generalized to `PublicKey` / `PrivateKey`
  interfaces; SM2 / RSA / ECDSA can all sign, with the digest chosen
  automatically per key type.
- Encrypted private-key PEM / change password / extract public key / key
  matching.

#### Certificates and protocols

- X.509 certificate parsing / creation / self-signing / CA issuance
  (SM2 + SM3 + RSA + ECDSA).
- Structured certificate parsing: full RDN / SAN / KeyUsage / EKU / SKID /
  AKID.
- Certificate fingerprints: sha1 / sha256 / sm3 / md5 / sha384 / sha512.
- PEM ↔ DER conversion (certificate / CSR).
- CSR construction (`NewEmptyCertificateRequest`: SetSubject / SetPublicKey
  / SetChallengePassword / AddExtensions / Sign).
- Certificate chain validation (Store / `ChainVerify`; failures map to
  `*VerifyError`).
- CRL parsing (revocation entries include reasons) and `RevocationCheck`.
- TLS / NTLS transport layer (`Dial` / Server / Conn / Config; NTLS dual
  certificates via `Config.SignCert` / `EncCert`).

#### Containers and formats

- PKCS#12 (Pack / Parse / `ChangePassword`).
- PKCS#7 (Build / Extract / `MarshalPEM`).
- OCSP (`CreateRequest` / `ParseResponse` / `Verify`).
- ASN.1 DER parse tree and hex dump.
- JWK ↔ PEM (RSA / EC).
- RSA XML ↔ PEM (.NET `RSAKeyValue`).

#### Engineering

- Top-level package restructuring (BC namespace layering):
  - `crypto/*` hosts algorithm engines only (`aes` / `ecdsa` / `hmac` /
    `md5` / `rand` / `rsa` / `sha1` / `sha256` / `sha512` / `sm2` / `sm3` /
    `sm4`).
  - 6 non-algorithm packages promoted to top-level: `asn1` / `jwk` /
    `ocsp` / `tls` / `x509`; `pkcs` (`pkcs7`, `pkcs12`) and `xml` (`rsa`)
    remain sub-namespaces.
  - `crypto/x509` split by responsibility into 6 files (`x509` / `name` /
    `csr` / `store` / `crl` / `helpers`) and promoted to top-level as
    `x509/`.
- 3 runnable minimal examples: `examples/{sm2, self-signed-cert,
  ntls-loopback}`.
- 56 public-API `Example*` test functions (godoc-friendly).
- Segmented bilingual GoDoc comments covering the public API.
- Design docs: architecture / development guide / testing guide /
  bilingual-GoDoc spec / roadmap.

### Fixed

- Stability improvements accumulated before the first public release; not
  enumerated here, see git history for details.

### BREAKING / Known limitations

- **BREAKING**: While MAJOR=0, the API is unstable; downstream consumers
  must read the CHANGELOG before upgrading.
- `crypto/rand` shares its name with the standard library's `crypto/rand`
  (path retained; documented as a caveat).
- Tongsuo 8.4 ABI is assumed.
- Integration tests under `-tags tongsuocli` depend on `/opt/tongsuo`.

---

[Unreleased]: https://github.com/blue-cloud-net/tongsuo-go/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/blue-cloud-net/tongsuo-go/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/blue-cloud-net/tongsuo-go/releases/tag/v0.1.0
