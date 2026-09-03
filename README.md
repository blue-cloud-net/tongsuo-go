# tongsuo-go

[English](README.md) | [简体中文](README.zh.md)

`tongsuo-go` ([`github.com/blue-cloud-net/tongsuo-go`](https://github.com/blue-cloud-net/tongsuo-go), [Apache-2.0](LICENSE)) is a Go wrapper library for Chinese commercial cryptography (国密) algorithms, built on top of [Tongsuo (铜锁)](https://www.tongsuo.net/).
Through cgo it calls the Tongsuo native library directly, exposing **idiomatic Go** APIs
(`hash.Hash`, `cipher.Block`, `cipher.AEAD`, `(T, error)`) for SM2 / SM3 / SM4, along with
X.509 certificate management and TLS / NTLS transport.

- **Module path**: `github.com/blue-cloud-net/tongsuo-go`
- **Native dependency**: Tongsuo **8.4.0+** (Apache-2.0)
- **Reference design**: [blue-cloud-net/tongsuo-csharp](https://github.com/blue-cloud-net/tongsuo-csharp)
- **Positioning**: a brand-new independent implementation, coexisting with the official [tongsuo-project/tongsuo-go-sdk](https://github.com/tongsuo-project/tongsuo-go-sdk)
- **CI/CD**: GitHub Actions ([`.github/workflows/`](.github/workflows/)) — lint + cross-platform tests + automatic releases on tag

---

## Features

- 🔐 **SM2 asymmetric algorithm** (GB/T 32918): key generation, PEM serialization, encrypt/decrypt (ASN.1 DER, C1C3C2 internal order),
  SM2withSM3 sign/verify, customizable userId
- 🔑 **SM3 hash algorithm** (GB/T 32905-2016): `hash.Hash` interface + one-shot `Sum`
- 🔒 **SM4 symmetric cipher** (GB/T 32907): ECB / CBC / CTR / OFB / CFB / GCM (AEAD)
- 🧮 **HMAC message authentication codes**: HMAC-SM3 / MD5 / SHA1 / SHA256 / SHA512
- 🔗 **More hashes**: MD5, SHA1, SHA256, SHA512 (`hash.Hash` + `Sum`)
- 🔄 **AES symmetric cipher**: ECB / CBC / CTR / GCM (`cipher.Block` + `cipher.AEAD`)
- 🎲 **Cryptographically secure random**: based on Tongsuo `RAND_bytes`
- 📜 **X.509 certificate management**: parse, create, self-signed / CA-signed certificates (SM2 + SM3), CSR generation and verification, BasicConstraints extension
- 🌐 **TLS / NTLS transport**: client / server wrappers, supporting Tongsuo NTLS dual certificates (signing certificate + encryption certificate)
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

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm3"
)

func main() {
	sum := sm3.Sum([]byte("abc"))
	fmt.Printf("%x\n", sum)

	// Streaming interface (hash.Hash)
	h := sm3.New()
	h.Write([]byte("abc"))
	fmt.Printf("%x\n", h.Sum(nil))
}
```

### SM4 Symmetric Cipher

```go
package main

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm4"
)

func main() {
	key := []byte("0123456789abcdef")
	iv := []byte("fedcba9876543210")

	// One-shot helpers (CBC + PKCS7 padding)
	ciphertext, err := sm4.EncryptCBC(key, iv, []byte("hello tongsuo"))
	if err != nil {
		panic(err)
	}
	plaintext, err := sm4.DecryptCBC(key, iv, ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", plaintext)

	// GCM (AEAD)
	nonce := []byte("0123456789ab")
	ct, tag, err := sm4.EncryptGCM(key, nonce, []byte("secret"), nil)
	if err != nil {
		panic(err)
	}
	pt, err := sm4.DecryptGCM(key, nonce, ct, tag, nil)
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

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
)

func main() {
	priv, err := sm2.GenerateKey()
	if err != nil {
		panic(err)
	}

	// Sign (SM2withSM3, ASN.1 DER)
	msg := []byte("tongsuo sm2")
	sig, err := sm2.Sign(priv, msg)
	if err != nil {
		panic(err)
	}
	fmt.Printf("signature: %x\n", sig)

	pub := priv.Public()
	if err := sm2.Verify(pub, msg, sig); err != nil {
		panic(err)
	}
	fmt.Println("verify ok")

	// Encrypt / decrypt (ASN.1 DER, C1C3C2 internal order)
	ciphertext, err := sm2.Encrypt(pub, msg)
	if err != nil {
		panic(err)
	}
	plaintext, err := sm2.Decrypt(priv, ciphertext)
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

	"github.com/blue-cloud-net/tongsuo-go/crypto/hmac"
)

func main() {
	sum := hmac.SumSM3([]byte("secret-key"), []byte("message"))
	fmt.Printf("%x\n", sum)

	// Streaming interface (hash.Hash)
	h := hmac.NewSM3([]byte("secret-key"))
	h.Write([]byte("message"))
	fmt.Printf("%x\n", h.Sum(nil))
}
```

### X.509 Certificate and TLS

```go
package main

import (
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/x509"
	"github.com/blue-cloud-net/tongsuo-go/tls"
)

func main() {
	// Generate a CA key and create a self-signed certificate
	caKey, _ := sm2.GenerateKey()
	caName := x509.NewName().Add("CN", "tongsuo-go CA")

	ca, err := x509.CreateCertificate(caName, caName, 1,
		time.Now(), time.Now().Add(365*24*time.Hour), caKey, caKey)
	if err != nil {
		panic(err)
	}

	// Generate a server certificate (signed by the CA)
	serverKey, _ := sm2.GenerateKey()
	serverName := x509.NewName().Add("CN", "localhost")

	serverCert, err := x509.CreateCertificate(serverName, caName, 2,
		time.Now(), time.Now().Add(365*24*time.Hour), serverKey, caKey)
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
API layer (crypto/)              ← High-level public API; the only layer external code may import
    ↓ calls
Core layer (internal/core/)      ← Handle/context wrappers; lifetime and ownership management
    ↓ calls
Binding layer (internal/native/)← cgo + inline C shim; maps directly to Tongsuo C functions
```

- **Strict layering, one-way dependencies**: the API layer talks to objects only through the core layer, never touching cgo directly
- **Memory safety**: native handles are wrapped by the core layer `handle` (`owned` flag + idempotent `Close()` + `runtime.SetFinalizer` as a safety net); raw native pointers never leak into the public API
- **Error handling**: native failures surface uniformly as `*core.OpError`, carrying the `ERR_get_error()` code
- **Concurrency model**: distinct handles can be used in parallel; a single handle must be serialized by its caller
- **Internal implementation is hidden**: `internal/native` and `internal/core` are protected by Go's `internal` mechanism and cannot be imported from outside

See [docs/architecture.md](docs/architecture.md) for the detailed design.

## License

This project is open-sourced under the [Apache-2.0](LICENSE) license.
