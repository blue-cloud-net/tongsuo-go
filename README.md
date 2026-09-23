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
- **Native dependency**: Tongsuo **8.4.0+** (Apache-2.0)
- **Reference design**: [blue-cloud-net/tongsuo-csharp](https://github.com/blue-cloud-net/tongsuo-csharp)
- **Positioning**: a brand-new independent implementation, coexisting with the official [tongsuo-project/tongsuo-go-sdk](https://github.com/tongsuo-project/tongsuo-go-sdk)
- **CI/CD**: GitHub Actions ([`.github/workflows/`](.github/workflows/)) — lint + cross-platform tests + automatic releases on tag

---

## Features

The API layer is **16 top-level packages** (`meta` / `digest` / `mac` / `kdf` / `rand` / `sym` /
`asym` / `ecdh` / `keystore` / `x509` / `tls` / `asn1` / `jwk` / `pkcs/pkcs7` / `pkcs/pkcs12` /
`xml/rsa`) with no intermediate `crypto/` directory. Every package exposes both the idiomatic Go
interfaces and a CLI-style by-name entry point; see the
[package restructuring roadmap](docs/refactor-roadmap.md).

- 🔐 **SM2 asymmetric algorithm** (GB/T 32918, `asym`): key generation, PEM serialization, encrypt/decrypt (ASN.1 DER, C1C3C2 internal order),
  SM2withSM3 sign/verify, customizable userId
- 🔑 **SM3 hash algorithm** (GB/T 32905-2016, `digest`): `hash.Hash` interface + fixed-size `SumSM3` + by-name `Sum("SM3", d)`
- 🔒 **SM4 symmetric cipher** (GB/T 32907, `sym`): ECB / CBC / CTR / OFB / CFB / GCM (AEAD)
- 🧮 **HMAC message authentication codes** (`mac`): HMAC-SM3 / MD5 / SHA1 / SHA256 / SHA512
- 🔗 **More hashes** (`digest`): MD5, SHA1, SHA224, SHA256, SHA384, SHA512 (`hash.Hash` + `Sum`)
- 🔄 **AES symmetric cipher** (`sym`): ECB / CBC / CTR / GCM (`cipher.Block` + `cipher.AEAD`)
- 🧬 **Key derivation** (`kdf`): HKDF / PBKDF2 / Argon2ID, including the by-name `Derive`
- 📝 **Ed25519 / Ed448 signatures** (RFC 8032, `asym`): pure EdDSA (no pre-hashing), raw 32B / 57B seed and public-key bytes interoperable with Go standard library, WireGuard; X.509 certificate / CSR / CRL signing via the `X509_sign_ctx` path
- 🤝 **X25519 / X448 ECDH key agreement** (RFC 7748, `ecdh`): 32 / 56-byte shared secret, interoperable with Go `crypto/ecdh` and WireGuard
- 🤝 **Curve-based ECDH** (`ecdh`): NIST P-256 / P-384 / P-521 (X9.63), the OKP curves X25519 / X448 (RFC 7748) and secp256k1; PEM (PKCS#8 / SPKI) round-trip and shared-secret derivation matching Go's standard `crypto/ecdh` semantics
- 🎲 **Cryptographically secure random** (`rand`): based on Tongsuo `RAND_bytes`
- 🗄️ **Key storage and rotation** (`keystore`): key metadata, in-memory / custom stores, version rotation and history
- 📜 **X.509 certificate management** (`x509`): parse and issue certificates / CSR / CRL / OCSP, one-line self-signed certificates (`CreateSelfSigned`), CA-signed certificates (SM2 + SM3 + RSA + ECDSA + Ed25519 + Ed448), hostname verification, chain verification
- 🌐 **TLS / NTLS transport** (`tls`): client / server wrappers, supporting Tongsuo NTLS dual certificates (signing certificate + encryption certificate)
- 📦 **Containers and formats**: PKCS#7 (`pkcs/pkcs7`), PKCS#12 (`pkcs/pkcs12`), JWK (`jwk`), ASN.1 DER viewer (`asn1`), .NET-style RSA XML (`xml/rsa`)
- 🧪 **Standard-vector tests**: every algorithm package covers national-standard vectors, round-trips, edge cases and error paths, with bidirectional cross-validation against the openssl CLI

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

More runnable examples live in [examples/](./examples).

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
- **Concurrency model**: distinct handles can be used in parallel; a single handle must be serialized by its caller
- **Internal implementation is hidden**: `internal/` is protected by Go's `internal` mechanism and cannot be imported from outside; no `internal/` type appears in a public signature

See [docs/architecture.md](docs/architecture.md) for the detailed design, and [docs/refactor-roadmap.md](docs/refactor-roadmap.md) for the package-structure decisions and migration path.

## License

This project is open-sourced under the [Apache-2.0](LICENSE) license.
