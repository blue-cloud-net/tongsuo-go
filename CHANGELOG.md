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

## [0.1.2] - 2026-09-10

### Added

- `crypto/ecdh` now supports the OKP curves `X25519()` and `X448()`
  (RFC 7748) alongside P-256 / P-384 / P-521.
- Added `Secp256k1()` to `crypto/ecdh`; availability depends on the runtime
  Tongsuo provider.
- Added the `crypto/x448` package (X448 ECDH, RFC 7748): key generation, PEM
  (PKCS#8 / SPKI) round-trip, 56-byte raw key interop and `SharedSecret`.
- `key` gained `AlgX448` and `GenerateX448Key`.
- `internal/core`: added `MarshalEncryptedPEMWithCipher` for exporting
  encrypted PEM with a caller-supplied cipher (e.g. AES-256-CBC), to
  support custom encryption pipelines beyond the built-in default.

### Changed

- `internal/core`: `Derive` rejects the all-zero shared secret produced by
  OKP low-order points (RFC 7748 §6.1), matching Go's `crypto/ecdh`.
- `crypto/ecdh`: OKP curves are dispatched through a typed curve kind
  instead of comparing display names, and `ECDH` rejects non-EC algorithm
  pairs explicitly.

### Fixed

- `crypto/ecdh`: the `*_tongsuocli_test.go` interop test now actually
  invokes the Tongsuo `openssl` CLI; it previously only exercised
  `internal/core`.
- `internal/testutil`: added `OpenSSLAvailable` and `SkipIfNoOpenSSL`, so CLI
  interop tests skip instead of failing when the Tongsuo binary is missing.

### Documentation

- Documented X25519 / X448 / secp256k1 support in `crypto/ecdh`, and synced
  `docs/architecture.md` and `docs/testing-guide.md`.

---

## [0.2.0] - TBD

### Added

- `tls`: new `DialContext(ctx, network, addr, cfg)` drives both the TCP
  dial and the TLS/NTLS handshake under the same context. `Dial` is now a
  `context.Background()` wrapper around `DialContext` and remains source
  compatible.
- `tls.Conn`: new `HandshakeContext(ctx)` runs the handshake on a goroutine
  and unwinds in-progress `SSL_read` / `SSL_write` waits via the underlying
  `SetDeadline` + raw-socket close when `ctx` is cancelled; the exported
  `Handshake()` is a `context.Background()` wrapper.
- `tls.Conn`: new `PeerCertificates() ([]*x509.Certificate, error)` returns
  the leaf and any intermediates received from the peer; for NTLS a second
  accessor `PeerEncCertificates() ([]*x509.Certificate, error)` returns
  the encryption certificate chain.
- `tls`: new `CipherSuites(version uint16) []CipherSuiteInfo` enumerates the
  ciphers supported by an `SSL_CTX` for a given protocol version
  (`0x0301`–`0x0304` and `NTLSVersion = 0x0101`); each entry exposes
  `{Name, ID, MinVersion, MaxVersion}`.
- `tls`: new `NTLSVersion uint16 = 0x0101` constant for NTLS protocol
  probing.
- `tls.Config.CipherSuites`: names starting with `TLS_` are forwarded to
  Tongsuo's TLS 1.3 `SSL_CTX_set_ciphersuites`; legacy names (no `TLS_`
  prefix) are routed to the classic `SSL_CTX_set_cipher_list`. Names that
  fail to match in either path are skipped (no fatal error); a final
  empty match set surfaces as `ErrNoSharedCipher`.
- `tls`: new sentinel errors `ErrVersionNotSupported`, `ErrNoSharedCipher`,
  `ErrPeerVerification`, `ErrNetwork` and a typed `*HandshakeError`
  (`Op` / `Kind` / `Err`) that classifies OpenSSL errors by library +
  reason (`SSL_R_NO_SHARED_CIPHER`, `SSL_R_UNSUPPORTED_PROTOCOL`,
  `X509_R_CERT_VERIFY_FAILED`, etc.) without losing `ctx.Err()`
  passthrough.
- `x509.Certificate`: new `Close() error` releases any cgo-managed
  resources held by the certificate; safe to call multiple times.

### Changed

- `tls.Server.Accept`: now returns immediately after constructing the
  `*Conn`; the TLS/NTLS handshake is deferred until `Handshake()` /
  `HandshakeContext()` is called on the returned connection. Existing
  callers that did not invoke `Handshake` now need to do so explicitly;
  callers that already call `Handshake` are unaffected.

### Fixed

- `internal/core`: `SSLConn.retry` now detects a user-set deadline that
  has already expired and returns a `net.Error` (`Timeout() == true`,
  also `errors.Is(err, os.ErrDeadlineExceeded)`) instead of busy-looping
  on 1 ms `syscall.Select` waits. This makes `SetReadDeadline` /
  `SetWriteDeadline` take effect promptly on every platform and fixes the
  `TestConnDeadlineUnblocksRead` flakiness observed on `macos-15-intel`.
- `internal/core`: `waitFD` on darwin now checks `Select`'s `n == 0`
  return value (matching the linux implementation). Without this the
  `waitFDTimeout` cap only bounded a single `Select` call, and the
  outer retry loop had no upper bound on macOS.
- `tls.Conn.SetDeadline` / `SetReadDeadline` / `SetWriteDeadline` now
  guard against a nil `*core.SSLConn` for forward-safety (previously
  only `Close`/`Read`/`Write` short-circuited on the closed state).
- `tls`: fixed a `SSL_CTX` leak in `Dial` — the `*core.TLSContext` is now
  released by `Conn.Close()` on the dial path. The previous code leaked one
  context per successful dial.
- `tls`: `Conn.Close` now returns the first non-nil error from the
  underlying raw socket close, the SSL handle close, and the optional
  context close. Previously it always returned `nil`.
- `tls`: **the client now sends SNI (the `server_name` extension) regardless
  of the peer-verification mode.** `DialContext` previously derived the
  hostname only when PEER verification was enabled, and only applied it via
  `SSL_set1_host` (hostname verification) — never via
  `SSL_set_tlsext_host_name`. With `InsecureSkipVerify: true` (the
  `VERIFY_NONE` configuration used by diagnostic/probe tools, where
  self-signed and expired certificates must be inspectable) the ClientHello
  therefore carried **no SNI**, and most real-world endpoints (CDNs, virtual
  hosts, multi-certificate deployments) aborted the handshake with
  `sslv3 alert handshake failure` (alert 40) before any verification could
  run. SNI is routing information and is now derived unconditionally from
  `Config.ServerName` or the dial address; IP literals are not used as SNI
  (RFC 6066 §3). `SSL_set1_host` is still applied only when verifying.
  Verified against `openssl s_client -connect example.com:443
  -noservername`, which reproduces the same alert.
- `internal/native`: added the `X_SSL_set_tlsext_host_name` shim (the
  `SSL_set_tlsext_host_name` macro cannot be called directly from cgo) and
  the `SSL_set_tlsext_host_name` binding.
- `internal/core`: added `SSLConn.SetServerName`, which sets the SNI
  extension only; it does not change the verification mode.
- `internal/core`: **handshake / read / write cancellation now takes effect
  within ~250ms instead of up to 30s.** The poll-based retry loop only
  re-checks the deadline / ctx after `waitFD` returns, and on Linux closing an
  fd from another thread does not reliably wake a blocked `select(2)` — so a
  single `waitFDTimeout` (previously 30s) bounded how long a cancellation
  could take. Measured: with a parent ctx expiring at 300ms, a version-matrix
  probe still took **30.03s** to return, making any caller-side budget
  unenforceable. `waitFDTimeout` is now 250ms and the wait is sliced: a slice
  expiry is **not** terminal (`errWaitFDTimeout` + `waitPlan` / `waitReady`),
  only an expired deadline is. Previously a slice timeout was returned as a
  fatal error, which additionally made `TestDialContextCancelFast` flaky.
  Side effect: the `tls` package test suite dropped from ~60s to ~6s.
- `tls`: `HandshakeContext` now prefers `ctx.Err()` when ctx has already
  ended, instead of racing the background handshake goroutine (which may exit
  on its own once the deadline is set). Keeps `crypto/tls` semantics for
  callers that check `errors.Is(err, context.DeadlineExceeded)`.

### Tests hardened

- `tls` tests: server-side `*Conn` is now `Close()`d in the goroutines of
  `TestDialPeerVerifyReject`, `TestDialInsecureSkipVerify`,
  `TestConnCloseIdempotent`, `TestConnCloseConcurrentWithRead`,
  `TestConnDeadlineUnblocksRead`, `TestReadReturnsAfterCancel`, and
  `TestConfigCipherSuitesMixed`; these previously held the SSL handle open
  until the kernel reaped the `CLOSE_WAIT` socket (~2 h).

### Documentation

- Documented `tls.DialContext` / `tls.Conn.HandshakeContext` cancellation
  semantics in the package GoDoc.

### Known limitations

- `tls`: on the **plain (no-deadline) ctx-cancel path**, an in-flight
  handshake can still take up to `waitFDTimeout` (30 s) to unwind because
  the cgo wait path uses `syscall.Select`, which is not interruptible
  from Go. With a `ctx` that has a deadline (or via the `HandshakeContext`
  / `DialContext` helpers), the deadline-exit fix in `internal/core` now
  surfaces an `i/o timeout` promptly. Callers should prefer
  `context.WithTimeout`/`WithDeadline` over plain `cancel`. A move to
  `epoll` / `poll(2)` is planned for v0.2.x+.

---

## [0.1.1] - 2026-09-10

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
- Added standalone examples for the new algorithms: `examples/ed25519` and
  `examples/x25519`.
- `x509`: added signature introspection to certificates, CSRs, and CRLs
  (`Signature` / `SignatureAlgorithm` / `SignatureAlgorithmOID`).

### Changed

- `internal/core` introduced `core.RandomBytes`, removing `crypto/rand`'s
  dependency on `internal/native`.
- Tightened `internal/core` coding conventions and slimmed down the core
  layer.
- AES / SM4 block-cipher `Block` switched to a template-plus-copy pattern
  to support safe concurrent reuse.
- `internal/core`: added `ZeroBytes` (backed by `OPENSSL_cleanse`) for
  zeroing sensitive buffers; `TLSContext.AddVerifyRoots` no longer
  swallows errors and a `VerifyResultClosed` sentinel was introduced.
- Sunk `EvpPkey` constants down into `internal/core` to restore the
  three-layer architecture.
- SM2 sign / verify now locks the OS thread only for SM2 keys, improving
  concurrency for other key types.
- CI: triggers narrowed to `main`; the test matrix now covers ubuntu +
  macOS × amd64 / arm64 on Go 1.21; Tongsuo is pinned to 8.4.0.
- Release: now reuses the CI workflow via `workflow_call` and derives the
  release notes from the English / Chinese CHANGELOG; binary artifacts are
  no longer uploaded.

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
- EC / SM2 public-key parameters now read the provider affine coordinates
  `qx` / `qy`, fixing empty X / Y when Tongsuo 8.4 exports `pub` as a
  compressed point.
- OCSP: fixed a `defer` loop-variable capture in `Verify`.
- `internal/core`: added closure guards to `signDigest` / `verifyDigest`.
- `tls`: `SplitHostPort` IPv6 tolerance; `SetReadDeadline` and
  `SetWriteDeadline` are now cleared as a pair.
- `x509`: `ChainVerify` intermediate-certificate handling made portable
  across OpenSSL versions.

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

[Unreleased]: https://github.com/blue-cloud-net/tongsuo-go/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/blue-cloud-net/tongsuo-go/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/blue-cloud-net/tongsuo-go/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/blue-cloud-net/tongsuo-go/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/blue-cloud-net/tongsuo-go/releases/tag/v0.1.0
