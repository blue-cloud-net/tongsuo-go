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

## [Unreleased]

---

## [0.3.0] - 2026-09-30

### Added

- `internal/core`: `KeyParams` now exposes the RSA CRT factors
  `Dmp1 = D mod (P-1)`, `Dmq1 = D mod (Q-1)` and `Iqmp = Q^-1 mod P`,
  populated by `(*PKey).Params()` next to the existing `N / E / D / P / Q`
  fields. Values come from the Tongsuo provider parameters
  `rsa-exponent1` / `rsa-exponent2` / `rsa-coefficient1` when exposed
  (Tongsuo 8.5+) and fall back to local derivation from `D / P / Q`
  otherwise; the public key path keeps these fields nil.
- `meta` (new top-level package): Tongsuo version and build information
  (`Version`, `VersionString`, `VersionNum`, `TongsuoVersionNum`,
  `ReadBuildInfo`) plus error-code decoding (`ErrorString`, `ErrorCode`,
  `ParseErrorCode`). Backed by a new `OpenSSLVersionWithIndex(idx int)`
  binding, so every `OpenSSL_version` index is reachable (the previous
  binding hard-coded index `0`).
- `digest`: `SHA-224` and `SHA-384` are now supported —
  `SumSHA224` / `SumSHA384`, `SHA224Size` / `SHA384Size` and the matching
  `New` / `Sum` by-name entries. `EVP_sha224` / `EVP_sha384` were already
  bound, so no new cgo binding was needed.
- `digest` / `mac` / `kdf` / `sym` / `asym`: every package now also offers a
  CLI-style "dispatch by algorithm name" entry point (`Names`,
  `New(name, …)`, `Sum(name, …)`, `Derive(name, …)`,
  `GenerateKey(alg, …)`) next to the idiomatic Go interfaces
  (`hash.Hash` / `cipher.Block` / `cipher.AEAD`).
- `asym`: `LoadPrivateKeyPEM` now falls back to the traditional RSA PKCS#1
  and EC SEC1 encodings before failing.
- `ecdh`: `LoadPrivateKey(asym.PrivateKey)` / `LoadPublicKey(asym.PublicKey)`
  make a key produced by `asym` usable for key agreement.
- `x509`: `CreateSelfSigned(...)` builds a self-signed certificate in one
  call; `(*Certificate).VerifyHostname(host)` checks host names and IP
  addresses; `(*Store).SetTime(t)` pins the verification instant.
- `x509`: `CRLBuilder` / `NewCRLBuilder` / `(*CRLBuilder).Revoke` /
  `(*CRLBuilder).Sign` make CRL issuance public (`internal/core.NewCRL`
  was previously unexported).
- `tls`: `CipherSuiteByName(name)` resolves a cipher suite by name or ID.
- `rand`: `Reader() io.Reader` for `io.Copy` / `io.ReadFull` composition.
- `asym`: package-level `Close(k Key) error` gives the package its first
  explicit release path; until now a key holding a handle could only be
  freed by the finalizer. The `keystore` and `ecdh` suites use it to prove
  a duplicate stays usable after the source key is released.
- `x509`: `(*Store).Close()` adds the release path a trust store never
  had — `Store` was the only handle-owning type in the package with no
  public `Close` and could previously be freed only by the finalizer.
  After `Close`, `AddCert` / `AddCRL` / `SetFlags` / `SetTime` return
  `x509: store closed` and `ChainVerify` fails because the trust anchor
  has been released.

### Changed

- `jwk.Marshal`: an RSA private-key JWK now also carries the RFC 7518
  §6.3.2 CRT fields `dp` / `dq` / `qi` alongside the previously
  populated `p` / `q`. Public-key output and EC/SM2 output are
  unchanged.
- `xml/rsa.MarshalPrivate`: now uses the CRT factors from
  `core.KeyParams` instead of recomputing `Mod(D, P-1)`,
  `Mod(D, Q-1)` and `ModInverse(Q, P)` locally.
- `x509`: the OCSP helpers moved in and were renamed to avoid colliding
  with the new package's own symbols — `ocsp.CreateRequest` →
  `x509.CreateOCSPRequest`, `ocsp.ParseResponse` →
  `x509.ParseOCSPResponse`, and `ocsp.Good` / `Revoked` / `Unknown` →
  `x509.OCSPGood` / `OCSPRevoked` / `OCSPUnknown`.
- `tls`: the package no longer imports `internal/native` directly; the
  cipher-suite and error-code lookups now go through `internal/core`,
  restoring the three-layer separation.
- `meta`: likewise no longer imports `internal/native` — version, build
  information and error-code text now go through `internal/core` (new
  `core.ReadBuildEnv` / `core.ErrorString`). **No API-layer package
  imports the binding layer any more.**
- `meta`'s public signatures (`Version` / `VersionString` / `VersionNum` /
  `TongsuoVersionNum` / `ReadBuildInfo` / `ErrorString`) are unchanged.
- `tls.CipherSuiteByName` matching semantics: names are
  **case-insensitive** and only the primary name reported by enumeration
  is matched (not OpenSSL legacy aliases); an ID is the 16-bit wire ID in
  text form, either decimal (`4865`) or 0x-prefixed hex (`0x1301`).
- `examples/`: all six examples (`sm2` / `ed25519` / `self-signed-cert` /
  `ntls-loopback` / `x25519` / `ecdh`) moved to the 16-package layout; run
  them with `cd examples/<name> && go run .` (each is its own module).
- `xml/rsa`: the implementation still round-trips through PKCS#1 / SPKI
  PEM and `asym.LoadPrivateKeyPEM` / `LoadPublicKeyPEM` — **no new cgo**;
  only the parameter source moved to `asym.Params`.
- `internal/testutil` gains the unified entry points
  `RunOpenSSLCombined` / `RunOpenSSLCombinedIn` / `MustRunOpenSSL` /
  `MustRunOpenSSLInDir`. Eight `*_tongsuocli_test.go` files used to
  duplicate their own openssl wrapper (four of them lacked
  `SkipIfNoOpenSSL` and failed instead of skipping when the CLI was
  missing); all of them now call the shared helpers. Test infrastructure
  only — no public API change.

### Fixed

- `asym` GoDoc for `PrivateKey.Params` / `PublicKey.Params`: the
  private-side listing previously called `P` / `Q` "CRT 因子"; they are
  in fact the RSA prime factors. The doc now distinguishes 素因子
  (`P` / `Q`) and CRT factors (`Dmp1` / `Dmq1` / `Iqmp`).
- `tls` test structure: `mustHandshake` used to call `t.Fatalf` inside a
  goroutine spawned by a test; once the test function has returned, that
  panics with "Fail in goroutine after … has completed" and swallows the
  results of every other test in the package (P1004, defect 2). It is
  replaced by `handshakeErr` (error-returning only) plus
  `serveHandshakeAsync` (assertion from `t.Cleanup`), six tests gained
  explicit handshake-vs-close synchronisation, and a handshake failure
  now fails fast instead of waiting for a timeout. A test-level leak was
  fixed along the way: a server connection abandoned after the handshake
  outlived `defer srv.Close()` (which frees the `SSL_CTX`). Package flake
  rate dropped from 3/20 to 1/20; the remainder turned out to be a
  library-level defect, fixed by the next entry.
- `tls`: **connection fd lifetime (P1011)** — `tls.Conn` used to hand a
  bare fd number to `SSL_set_fd` while the descriptor was owned by the
  underlying `net.Conn`. After `Close()` closed the raw socket the kernel
  could recycle that number for a new connection, and the SSL BIO — still
  holding the stale number — then read from or wrote to **another
  connection's** socket. That is the real cause of the intermittent
  failures (`SSL_connect: unexpected message`, `SSL_read: Bad file
  descriptor`, peer-side `bad record MAC`) and of the residual flake
  above. The socket is now duplicated with `dup(2)` inside the
  `SyscallConn().Control` callback (new `internal/core/fd_unix.go`:
  `DupFD` / `ShutdownFD` / `CloseFD`), `*core.SSLConn` owns the duplicate,
  and a new `Stop()` (state flag + `shutdown(2)`) wakes an in-flight
  `select` and sends FIN even though the duplicate keeps the socket open.
  `Close()` waits for in-flight operations (`inflight.Wait`, registered
  before the `stopped` check) before `SSL_free` and closing the duplicate;
  `tls.Conn.Close()` calls `Stop()` before closing the raw socket.
  Measured after the fix: 50 consecutive `go test -count=1 ./tls/` runs
  with **zero** failures (before: 1/20; a guard-only variant without
  `dup` made it worse at 8/40 and was reverted), with `-race`, the full
  `go test ./...` suite and `-tags tongsuocli` all green.

### Documentation

- `docs/testing-guide.md` §5.1 now lists the CRT parameter invariants
  among the required RSA cases (non-nil, range checks and
  `Iqmp*Q ≡ 1 (mod P)`).
- `docs/refactor-roadmap.md` (new): the full package-structure decision
  record, per-package migration plan, required new bindings, phase/version
  assignment, verification procedure and rollback plan.
- `docs/api-reference.md`: rewritten for the post-refactor 16-package
  layout, with a per-package status marker and a per-symbol marker for
  "already present" / "landing in this release" / "planned".
- `docs/api-reference-internal.md`: adds `§5 internal/keyaccess` and
  updates the layer diagram.
- `docs/architecture.md`: §1.1 / §2 / §3.3 / §4 / §5 / §7 / §10 / §11.
- `AGENTS.md`: directory map, layering red lines, doc-sync table and the
  known-trap list.
- `README.md` + `README.zh.md`: features, code examples and the
  architecture section.
- `docs/refactor-roadmap.md`: the §0 baseline now reads "`0.3.0`
  implemented, tag pending", the §2.1 status column is all-green, and a
  closing footnote records that the tag was never created and that two
  Phase 0 items were still outstanding.
- `docs/api-reference.md` / `docs/api-reference-internal.md` /
  `docs/architecture.md` / `AGENTS.md`: document the
  `internal/certaccess` bridge (only `internal/keyaccess` was listed
  before), correct the keyaccess consumer list to six entries (adds
  `keystore`) and cover the new `internal/testutil` entry points.

### BREAKING / 已知限制

- **API-layer package layout: 27 packages → 16.** The `crypto/` tree and
  the `key/` package are gone, so every public import path changes. See
  `docs/api-reference.md` §0.1 for the package-level old → new mapping and
  `docs/refactor-roadmap.md` §4 for the symbol-level one.
  - `crypto/{sm3,md5,sha1,sha256,sha512}` → `digest`
  - `crypto/hmac` → `mac`
  - `crypto/{aes,sm4}` + the symmetric half of `key` → `sym`
  - `crypto/{sm2,rsa,ecdsa,ed25519,ed448}` + the asymmetric half of `key`
    + key generation from `crypto/{x25519,x448}` → `asym`
  - `crypto/ecdh` + key agreement from `crypto/{x25519,x448}` → `ecdh`
  - `crypto/kdf` + the KDF half of `key` → `kdf`
  - `crypto/rand` → `rand`
  - `key.{Handle,Store,MemoryStore}` → `keystore`
  - `ocsp` → `x509`
  - `crypto/`, `crypto/{x25519,x448}` and `key` are deleted outright.
- **No deprecated forwarding packages.** Callers must migrate in one step.
- **`x509` / `csr` / `crl` / `ocsp` are *not* split.** Splitting them would
  introduce a `x509` ↔ `crl` import cycle (`Store.AddCRL(*crl.CRL)` versus
  `crl.NewBuilder(*x509.Certificate)`), so CSR / CRL / OCSP stay in `x509`.
- **Algorithm-specific methods became package-level functions.** Key types
  are now the interfaces `asym.PrivateKey` / `asym.PublicKey`, so e.g.
  `rsa.GenerateKey(2048)` → `asym.GenerateRSA(2048)` and
  `priv.SignPSS(…)` → `asym.SignPSS(priv, …)`.
- **No `internal/` type appears in a public signature any more.** All
  twelve leaks listed in `docs/refactor-roadmap.md` §5.1 are closed, which
  removes the `Key() *core.PKey`, `Core()`, `PublicKeyPKey()`,
  `Store.Core()` and `jwk.Marshal(*core.PKey)` escape hatches.
  Cross-package handle access now goes through `internal/keyaccess`.
- **`KeyParams` moved to `asym`.** `(*PrivateKey).Params()` now returns
  `*asym.KeyParams` instead of `*core.KeyParams`.
- **`x509` narrow key interfaces removed.** `x509.PublicKey` /
  `x509.PrivateKey` are gone; use `asym.PublicKey` / `asym.PrivateKey`.
- **`x509`'s certificate wrapper is gone and certificate ownership
  changed.** The public `x509.WrapCertificate(*core.Certificate)` both
  leaked an `internal/` type and broke the documented contract (it
  **shared** the underlying handle, so a caller's `Close` released the
  real owner); cross-package wrapping now goes through
  `internal/certaccess.Wrap`, which round-trips DER and yields an **owned**
  handle. Consequently the `*x509.Certificate` values returned by
  `tls.PeerCertificates()` / `tls.PeerEncCertificates()`,
  `pkcs/pkcs7.Extract` and `pkcs/pkcs12.Bundle` are now **per-caller owned
  copies** that must each be closed (the `tls` docs already promised this;
  the implementation now matches).
- **`xml/rsa`'s four public functions take `asym.*`.**
  `MarshalPrivate(asym.PrivateKey)` / `MarshalPublic(asym.PublicKey)` /
  `UnmarshalPrivate(...) (asym.PrivateKey, error)` /
  `UnmarshalPublic(...) (asym.PublicKey, error)`; the old
  `*crypto/rsa.PrivateKey` / `*crypto/rsa.PublicKey` signatures went away
  with the `crypto/rsa` package.
- **`jwk.Marshal(*core.PKey)` removed**; use
  `jwk.MarshalKey(k asym.Key)`. `MarshalKey`'s parameter also changed from
  `key.CoreKey` to `asym.Key`.
- **`pkcs/pkcs12` private-key types became public interfaces**:
  `pkcs12.PrivateKey` (formerly a `key.CoreKey` alias) and
  `pkcs12.Bundle.PrivateKey` (formerly `*core.PKey`) are now
  `asym.PrivateKey`.
- **`key.Algorithm` / `key.Key` replaced.** Use `asym.Algorithm` +
  `asym.Key` (asymmetric) or `sym.Algorithm` + `sym.SymmetricKey`
  (symmetric); note the rename `AlgED25519` → `AlgEd25519`.
- **`tls.Config` key fields retyped**: `Key` / `SignKey` / `EncKey` are
  `asym.PrivateKey` instead of `*sm2.PrivateKey`.
- **RSA OAEP parameter**: `crypto/rsa.EncryptOAEP`'s
  `md *core.Digest` parameter became `hash string` — the old parameter was
  impossible to construct from outside the module anyway.
- Known limitation: `asym` key types are unexported concrete types behind
  interfaces, so a third-party key type can no longer be passed to `x509` /
  `tls`. Such a type could not supply a native handle before either, so no
  functionality is lost.
- Known limitation: `asym.PrivateKey.Public()` returns an object that
  **shares the private key's underlying handle** (pre-existing behaviour,
  not introduced here: the old `crypto/rsa` and `key` did the same), so
  `jwk.MarshalKey(priv.Public())` still exports a JWK **carrying the
  private components**. For a public JWK, load the public key on its own
  (`asym.LoadPublicKeyPEM`) and pass that to `MarshalKey`.
- Known limitation: `TestNTLSLoopback` can still fail under heavy parallel
  load — the client's `Read` fails with `tls: SSL_read (syscall): …
  Broken pipe` (`SSL_ERROR_SYSCALL`). Reproduced 4 times in 90 runs of
  `go test -count=15 -run TestNTLS ./tls/` with six processes in parallel,
  while the same revision is clean on the single-package loop (50/50) and
  on 17 consecutive full `go test ./...` runs. The pre-fix signature of the
  very same test and line was `Bad file descriptor` (the fd-lifetime defect
  fixed above), so this is a residual rather than a regression; the
  remaining cause is not yet pinned. The `tongsuocli` interop job is
  enabled in spite of it, because the library-level defect it covers is
  fixed.

---

## [0.2.0] - 2026-09-18

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

## [0.1.2] - 2026-09-16

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

[Unreleased]: https://github.com/blue-cloud-net/tongsuo-go/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/blue-cloud-net/tongsuo-go/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/blue-cloud-net/tongsuo-go/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/blue-cloud-net/tongsuo-go/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/blue-cloud-net/tongsuo-go/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/blue-cloud-net/tongsuo-go/releases/tag/v0.1.0
