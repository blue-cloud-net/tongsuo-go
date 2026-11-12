# tongsuo-go

[English](README.md) | [简体中文](README.zh.md)

`tongsuo-go` ([`github.com/blue-cloud-net/tongsuo-go`](https://github.com/blue-cloud-net/tongsuo-go), [Apache-2.0](LICENSE)) is a Go wrapper library for Chinese commercial cryptography (国密) algorithms, built on top of [Tongsuo (铜锁)](https://www.tongsuo.net/).
Through cgo it calls the Tongsuo native library directly, exposing **idiomatic Go** APIs
(`hash.Hash`, `cipher.Block`, `cipher.AEAD`, `(T, error)`) for SM2 / SM3 / SM4, along with
X.509 certificate management and TLS / NTLS transport.

**This repository ships only the Go SDK (wrapper) and does not bundle Tongsuo itself** — no
Tongsuo source, headers or binaries are included, so you must install Tongsuo yourself before
building, testing or running (see [Requirements](#requirements)).

- **Module path**: `github.com/blue-cloud-net/tongsuo-go`
- **Native dependency**: Tongsuo **8.4.0 / 8.5.0** validation (Apache-2.0)
- **Reference design**: [blue-cloud-net/tongsuo-csharp](https://github.com/blue-cloud-net/tongsuo-csharp)
- **Positioning**: a brand-new independent implementation, coexisting with the official [tongsuo-project/tongsuo-go-sdk](https://github.com/tongsuo-project/tongsuo-go-sdk)
- **CI/CD**: GitHub Actions ([`.github/workflows/`](.github/workflows/)) — lint + cross-platform tests + automatic releases on tag

---

## Features

The API layer is **16 top-level packages** (`meta` / `digest` / `mac` / `kdf` / `rand` / `sym` /
`asym` / `ecdh` / `keystore` / `x509` / `tls` / `asn1` / `jwk` / `pkcs/pkcs7` / `pkcs/pkcs12` /
`xml/rsa`) with no intermediate `crypto/` directory. Every package exposes both the idiomatic Go
interfaces and a CLI-style by-name entry point; see the
[version roadmap](docs/roadmap.md) for what comes next and
[docs/architecture.md](docs/architecture.md) for the layered design.

- 🔐 **SM2 asymmetric algorithm** (GB/T 32918, `asym`): key generation, PEM serialization, encrypt/decrypt (ASN.1 DER, C1C3C2 internal order),
  SM2withSM3 sign/verify, customizable userId
- 🔑 **SM3 hash algorithm** (GB/T 32905-2016, `digest`): `hash.Hash` interface + fixed-size `SumSM3` + by-name `Sum("SM3", d)`
- 🔒 **SM4 symmetric cipher** (GB/T 32907, `sym`): ECB / CBC / CTR / OFB / CFB / GCM (AEAD), plus SM4-CCM and SM4-XTS
- 🧮 **Message authentication codes** (`mac`): 14 `EVP_MAC` algorithms — HMAC-SM3 / MD5 / SHA1 / SHA224 / SHA256 / SHA384 / SHA512, CMAC, GMAC, KMAC-128/256, SipHash, Poly1305, EIA3
- 🔗 **More hashes** (`digest`): MD5, SHA1, SHA224, SHA256, SHA384, SHA512, SHA-256/192, SHA-512/224, SHA-512/256, SHA3-224/256/384/512, KECCAK-224/256/384/512 and SHAKE128/256 (`hash.Hash` + `Sum`, with `SumSHAKE*` taking an explicit output length)
- 🔄 **AES symmetric cipher** (`sym`): 128 / 192 / 256-bit ECB / CBC / CTR / OFB / CFB / GCM / CCM / OCB / SIV / GCM-SIV / WRAP / WRAP-PAD / CBC-CTS, plus 128/256-bit XTS (`cipher.Block` + `cipher.AEAD`)
- 🗝️ **DES / 3DES compatibility** (`sym`): DES / DES-EDE (two-key) / DES-EDE3 in ECB / CBC — for legacy data only. Single DES is realised as DES-EDE3 with `K‖K‖K`, so no legacy provider is ever loaded
- 🧾 **Padding matrix** (`sym`): `Supports(name, padding)` / `Paddings(name)` answer "is this algorithm × padding combination valid?" without submitting data; invalid combinations return `ErrUnsupportedPadding` instead of silently falling back
- ✍️ **Signature formats and RSA digests** (`asym`): DER ↔ bare `r‖s` conversion for SM2 / ECDSA (`SignatureParts` / `SignatureDER` / `FormatSignature`); RSA-OAEP accepts `sm3`; probe RSA-SM3 signing with `SupportsRSASignatureDigest`, which is unavailable on 8.4.0 and returns `ErrUnsupported`; PKCS#1 v1.5/PSS work on 8.5.0, with separate PSS probing through `SupportsRSAPSSDigest`
- 🌊 **Stream ciphers** (`sym`): ChaCha20, ChaCha20-Poly1305, ZUC-128-EEA3 (native 5-byte IV)
- 🧬 **Key derivation** (`kdf`): 10 KDFs — HKDF / PBKDF2 / scrypt / SSKDF / TLS1-PRF / TLS13-KDF / KBKDF / X942KDF / X963KDF / HMAC-DRBG-KDF, each with a typed entry plus the by-name `Derive`
- 🧰 **CLI-style form entries**: `meta` provides `Source` (bytes / reader / file / stdin), `Sink` (with raw / hex / base64 encoding), `Format` (PEM / DER) and `Passphrase` (`pass:` / `env:` / `file:` / `fd:` / `stdin:`); the primitive packages add one-liners such as `SumSource` / `SumTo` / `EncryptSource` / `DeriveTo` / `MarshalPrivateKeyTo` / `LoadCertificateSource`
- 🗂️ **Algorithm and provider enumeration** (`meta`): `Digests` / `Ciphers` / `MACs` / `KDFs` / `Signatures` / `KeyExchanges` / `KEMs` / `TLSGroups` / `Providers` / `SeedingSource`
- 📝 **Ed25519 / Ed448 signatures** (RFC 8032, `asym`): pure EdDSA plus Ed25519ctx / Ed25519ph / Ed448ph and Ed448 contexts (native prehashing), raw 32B / 57B seed and public-key bytes interoperable with Go standard library, WireGuard; X.509 certificate / CSR / CRL signing via the `X509_sign_ctx` path
- 🤝 **X25519 / X448 ECDH key agreement** (RFC 7748, `ecdh`): 32 / 56-byte shared secret, interoperable with Go `crypto/ecdh` and WireGuard
- 🤝 **Curve-based ECDH** (`ecdh`): NIST P-256 / P-384 / P-521 (X9.63), the OKP curves X25519 / X448 (RFC 7748) and secp256k1; PEM (PKCS#8 / SPKI) round-trip and shared-secret derivation matching Go's standard `crypto/ecdh` semantics; named/explicit EC parameter PEM files and parameter-based key generation; `DeriveSharedSecret` directly adapts asym keys and `DeriveSM2DH` takes explicit static/ephemeral keys, IDs and roles (without key confirmation)
- 🎲 **Cryptographically secure random** (`rand`): based on Tongsuo `RAND_bytes`
- 🗄️ **Key storage and rotation** (`keystore`): key metadata, in-memory / custom stores, version rotation and history; `Load` / `LoadAllFromReader` detect local multiple PEM objects, DER and PKCS#12
- 📜 **X.509 certificate management** (`x509`): parse and issue certificates / CSR / CRL / OCSP, one-line self-signed certificates (`CreateSelfSigned`), step-by-step CRL issuance (`CRLBuilder`), CA-signed certificates (SM2 + SM3 + RSA + ECDSA + Ed25519 + Ed448), arbitrary X.509 v3 extensions by NID or name (`AddExtension` / `AddExtensionByName` / `AddExtensions`), CSR-driven issuance (`IssueCertificateFromRequest`), hostname / IP / e-mail verification (`VerifyHostname` / `CheckEmail`), subject / issuer name hashes (`SubjectHash` / `IssuerHash`) and chain verification with an optional pinned verification instant (`Store.SetTime`); OCSP HTTP/nonces, trusted PEM purposes, unified certificate/CRL loading and named verification error codes
- 🌐 **TLS / NTLS transport** (`tls`): explicit TLS / NTLS and mixed server ports, complete credential chains, SNI selection, ALPN, mutual authentication, three verification policies and copied connection state; independent read/write deadlines and concurrent I/O; RFC 8998 strict TLS 1.3, ordered diagnostics, optional trace/keylog and TLS-extension SCT snapshots; [runnable handshake examples](examples/handshake/)
- 📦 **Containers and formats**: PKCS#7 certificates/CRLs, signing/verification and envelopes (`pkcs/pkcs7`), configurable PKCS#12 PBE/iterations and complex lossless password changes (`pkcs/pkcs12`), PKCS#8 PBE/PRF/PEM/DER and RSA PKCS#1 public keys (`asym`), OKP/oct JWK (`jwk`), PEM splitting (`meta`), ASN.1 DER viewer with configurable limits (`asn1`), .NET-style RSA XML (`xml/rsa`)
- 🧪 **Standard-vector tests**: every algorithm package covers national-standard vectors, round-trips, edge cases and error paths, with bidirectional cross-validation against the openssl CLI

## Scope and non-goals

`tongsuo-go` is a **wrapper** around the Tongsuo native library: it does not bundle Tongsuo
itself, and the Tongsuo installation is a build prerequisite (see [Requirements](#requirements)).

### Not provided

- **ECIES** — the term has no single container format: SEC1 §5.1 defines only the KDF and the
  XOR step, while IEEE 1363a, ISO 18033-2 and ANSI X9.63 each specify a different header and
  KDF, so a self-invented container could never be cross-validated against the openssl CLI.
  For Chinese commercial cryptography use `asym.Encrypt` (SM2 encryption, producing
  C1‖C3‖C2 / C1‖C2‖C3 / DER). The standardized alternatives are RFC 9180 **HPKE** (native in
  Tongsuo 8.5+) and JWE `ECDH-ES` (RFC 7518). These alternatives are not wrapped by this library; a concrete interop target or standard-protocol requirement is needed to reopen the work, with no committed release.
- **Loading the legacy provider** — the library never loads it, because doing so would enable
  RC4 / RC5 / DESX process-wide. Single DES is instead provided as a `K‖K‖K` DES-EDE3
  equivalent (byte-identical output, no provider side effects).
- **DES / 3DES for new protocols** — 56-bit DES is brute-forceable; these entries exist only
  to read and write existing data.

### Implementation baseline and future releases

The released `0.8.0` implements Tongsuo 8.4.0/8.5.0 compatibility, GCM-SIV, EdDSA extensions and SM2DH (released 2026-11-05). AES-SIV empty messages use the verified 8.5.0 path; NTLS signing/encryption certificates must declare their respective KeyUsage.
`0.7.0`: reliability, data integrity and PKCS containers: handle release, parser limits, full serial numbers, DER extensions, trust paths, compressed SM2 input, lossless password changes for complex PKCS#12 containers, and PKCS#7 signing, verification, encryption and decryption.

`0.9.0` was released on 2026-11-06; it covers TLS / NTLS handshakes and authentication, mixed ports, SNI, ALPN, verification policies, connection state and client/server examples.

`0.10.0` was released on 2026-11-12; later releases remain planned:

- `0.10.0`: RFC 8998 ShangMi TLS 1.3, structured handshake diagnostics, optional detailed trace and keylog
- `0.11.0`: Session resumption, caches, import/export, ticket controls and key rotation
- `0.12.0`: HTTP/1.1 client/server integration and OCSP stapling
- `0.13.0` / `0.14.0`: PQC / CMS and RFC 3161 timestamps
- `1.0.0`: Public API convergence and stability

The transport releases deliver SDK APIs and runnable examples for downstream handshake tests similar to `s_client` / `s_server`.
RFC 8998 uses a single signing credential set over TLS 1.3; NTLS uses signing and encryption certificates.
Existing SDK entry-point behavior is preserved; explicit policies support no verification, reporting verification failures while continuing, and aborting on verification failure. Handshake examples default to reporting failures while continuing and expose the verification result separately.


RFC 8998 clients use `&tls.Config{RFC8998: true, Verification: tls.VerifyStrict, RootCAs: roots}`;
servers supply one SM2 `Cert` / `Key` pair. `Diagnostics` explicitly enables ordered events,
trace or keylog; output errors abort the connection. `CaptureSCT` records TLS-extension SCT
wire bytes without CT policy validation. Diagnostic consumers must return promptly and must
not reenter the same connection; callers synchronize shared writers and protect keylog secrets.

STARTTLS, external PSK, 0-RTT and active renegotiation remain deferred without a target version.

See [docs/requirements.md](docs/requirements.md) for functional requirements, technical decisions and acceptance criteria.

The full plan, and the complete "not doing" list with the rationale and the conditions for
revisiting each item, live in [docs/roadmap.md](docs/roadmap.md) §2 and §4.

## Getting Started

### Requirements

- Go 1.21+ (with CGO enabled)
- Tongsuo **8.4.0+**, see the [official Tongsuo README](https://github.com/Tongsuo-Project/Tongsuo#readme) for build instructions
- Default install path: `/opt/tongsuo` (override with the `TONGSUO_HOME` environment variable)
- Platforms: **Linux first, macOS supported** (Windows deferred)

### Configuring the Tongsuo Path

Building and running depend on `cgo` finding Tongsuo headers and libraries. Pick one of the three common ways:

**Option A — environment variables (recommended)**:

```bash
export TONGSUO_HOME=/opt/tongsuo                  # Tongsuo install root
export LD_LIBRARY_PATH=${TONGSUO_HOME}/lib        # Linux
# export DYLD_LIBRARY_PATH=${TONGSUO_HOME}/lib    # macOS

export CGO_CFLAGS="-I${TONGSUO_HOME}/include -Wno-deprecated-declarations"
export CGO_LDFLAGS="-L${TONGSUO_HOME}/lib"
```

**Option B — pkg-config** (inject the output of `pkg-config --cflags --libs openssl` into cgo flags):

```bash
export PKG_CONFIG_PATH=${TONGSUO_HOME}/lib/pkgconfig:${PKG_CONFIG_PATH}
```

**Option C — static link** (suited for distributing standalone binaries):

```bash
go build -tags static ./...
```

> The `-Wno-deprecated-declarations` flag suppresses warnings emitted by Tongsuo over some deprecated OpenSSL declarations; it does not affect functionality.

### Build and Run

```bash
# Build all packages
go build ./...

# Run unit tests (default; excludes openssl CLI comparison)
go test ./...

# Include openssl CLI cross-validation tests
go test -tags tongsuocli ./...

# Coverage
go test -cover ./...
```

### Using It in Your Project

```bash
go get github.com/blue-cloud-net/tongsuo-go
```

Then import the sub-packages you need from your code (see "Code Examples" below).

## Code Examples

### PKCS#7 signatures (`0.7.0`)

Given a signing certificate `cert`, its private `key` and an explicitly populated `roots` store:

```go
signed, err := pkcs7.Sign(data, &pkcs7.SignOptions{SignerCert: cert, SignerKey: key})
if err != nil { panic(err) }
verified, err := pkcs7.Verify(signed, &pkcs7.VerifyOptions{Roots: roots})
if err != nil { panic(err) }
defer verified.Close()
```

Verify checks all signers and their trust by default. Explicit SignatureOnly skips chain verification and reports TrustVerified=false. RSA/ECDSA signing and RSA recipient encryption are supported; CBC envelopes do not authenticate integrity.

ECDH migration: use `pub, err := priv.Public()`, handle the error and `defer pub.Close()`; the public copy owns its handle independently. Full serials use `SerialBigInt` / `SetSerialBigInt`; old int64 write entries now reject zero/negative values. See [runnable examples](examples/README.md) for stepwise DER-extension issuance and PKCS#7.

### AES-OCB (`0.6.0`)

This snippet belongs in a function returning error and imports `sym`; it encrypts one message, and production code must never reuse a nonce with the same key.

```go
key := make([]byte, 16)
aead, err := sym.NewAESOCB(key)
if err != nil {
    return err
}
nonce := make([]byte, aead.NonceSize())
sealed := aead.Seal(nil, nonce, []byte("message"), []byte("header"))
plain, err := aead.Open(nil, nonce, sealed, []byte("header"))
_ = plain
return err
```

### SM3 Hash

```go
package main

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/digest"
)

func main() {
	// Fixed-size entry point (returns [32]byte)
	sum := digest.SumSM3([]byte("abc"))
	fmt.Printf("%x\n", sum)

	// By-name dispatch
	named, err := digest.Sum("SM3", []byte("abc"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x\n", named)

	// Streaming interface (hash.Hash)
	h := digest.NewSM3()
	h.Write([]byte("abc"))
	fmt.Printf("%x\n", h.Sum(nil))
}
```

### SM4 Symmetric Cipher

```go
package main

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/sym"
)

func main() {
	key := []byte("0123456789abcdef")
	iv := []byte("fedcba9876543210")

	// One-shot helpers (CBC + PKCS7 padding)
	ciphertext, err := sym.EncryptSM4CBC(key, iv, []byte("hello tongsuo"))
	if err != nil {
		panic(err)
	}
	plaintext, err := sym.DecryptSM4CBC(key, iv, ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", plaintext)

	// GCM (AEAD)
	nonce := []byte("0123456789ab")
	ct, tag, err := sym.EncryptSM4GCM(key, nonce, []byte("secret"), nil)
	if err != nil {
		panic(err)
	}
	pt, err := sym.DecryptSM4GCM(key, nonce, ct, tag, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", pt)
}
```

### SM2 Asymmetric Algorithm

```go
package main

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

func main() {
	priv, err := asym.GenerateSM2()
	if err != nil {
		panic(err)
	}

	// Sign (SM2withSM3, ASN.1 DER)
	msg := []byte("tongsuo sm2")
	sig, err := asym.Sign(asym.AlgSM2, priv, msg, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("signature: %x\n", sig)

	pub := priv.Public()
	if err := asym.Verify(asym.AlgSM2, pub, msg, sig, nil); err != nil {
		panic(err)
	}
	fmt.Println("verify ok")

	// Encrypt / decrypt (ASN.1 DER, C1C3C2 internal order)
	ciphertext, err := asym.Encrypt(asym.AlgSM2, pub, msg, nil)
	if err != nil {
		panic(err)
	}
	plaintext, err := asym.Decrypt(asym.AlgSM2, priv, ciphertext, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("decrypted: %s\n", plaintext)
}
```

### HMAC

```go
package main

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/mac"
)

func main() {
	sum := mac.SumHMACSM3([]byte("secret-key"), []byte("message"))
	fmt.Printf("%x\n", sum)

	// Streaming interface (hash.Hash)
	h := mac.NewHMACSM3([]byte("secret-key"))
	h.Write([]byte("message"))
	fmt.Printf("%x\n", h.Sum(nil))
}
```

### X.509 Certificate and TLS

```go
package main

import (
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/tls"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

func main() {
	// One-line self-signed CA certificate (equivalent to `req -x509`)
	caKey, _ := asym.GenerateSM2()
	caName := x509.NewName().Add("CN", "tongsuo-go CA")

	ca, err := x509.CreateSelfSigned(caName, 1,
		time.Now(), time.Now().Add(365*24*time.Hour), caKey.Public(), caKey)
	if err != nil {
		panic(err)
	}
	_ = ca

	// Generate a server certificate (signed by the CA)
	serverKey, _ := asym.GenerateSM2()
	serverName := x509.NewName().Add("CN", "localhost")

	serverCert, err := x509.CreateCertificate(serverName, caName, 2,
		time.Now(), time.Now().Add(365*24*time.Hour), serverKey.Public(), caKey)
	if err != nil {
		panic(err)
	}

	// TLS server
	cfg := &tls.Config{Cert: serverCert, Key: serverKey}
	srv, _ := tls.NewServer(cfg)
	_ = srv

	// Tongsuo NTLS dual certificates
	ntlsCfg := &tls.Config{
		NTLS:     true,
		SignCert: serverCert, SignKey: serverKey,
		EncCert: serverCert, EncKey: serverKey,
	}
	_ = ntlsCfg
}
```

For a bounded handshake probe, wrap an already connected TCP socket with `tls.Client(raw, &tls.Config{Protocol: tls.ProtocolTLS, Verification: tls.VerifyReport})`, call `HandshakeContext(ctx)`, then inspect `ConnectionState()` even on failure and always `Close()`. `VerifyReport` may connect to an untrusted peer; use `VerifyStrict` with explicit `RootCAs` for authenticated connections. `ServerName` controls SNI; `VerificationName` separately controls DNS/IP validation.

More runnable examples, including client/server flags and dual-certificate NTLS, live in [examples/handshake/](./examples/handshake/).

## Architecture

```
API layer (16 top-level packages)  ← High-level public API; the only layer external code may import
    ↓ calls
Core layer (internal/core/)        ← Handle/context wrappers; lifetime and ownership management
    ↓ calls
Binding layer (internal/native/)   ← cgo + inline C shim; maps directly to Tongsuo C functions
```

- **Strict layering, one-way dependencies**: the API layer talks to objects only through the core layer, never touching cgo directly
- **16 flat top-level packages**: algorithm primitives and their CLI-style by-name entry points share a package; no intermediate `crypto/` directory and no all-in-one `key/` package
- **Memory safety**: native handles are wrapped by the core layer `handle` (`owned` flag + idempotent `Close()` + `runtime.SetFinalizer` as a safety net); raw native pointers never leak into the public API
- **Error handling**: native failures surface uniformly as `*core.OpError`, carrying the `ERR_get_error()` code
- **Concurrency model**: distinct handles can be used in parallel; serialize ordinary handles, while `tls.Conn` supports concurrent reads, writes and Close with serialized native calls
- **Internal implementation is hidden**: `internal/` is protected by Go's `internal` mechanism and cannot be imported from outside; no `internal/` type appears in a public signature

See [docs/architecture.md](docs/architecture.md) for the detailed design and the dependency graph, and [docs/roadmap.md](docs/roadmap.md) for the `0.7.0`–`1.0.0` version plan.

## License

This project is open-sourced under the [Apache-2.0](LICENSE) license.
