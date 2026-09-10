# tongsuo-go

[English](README.md) | [简体中文](README.zh.md)

`tongsuo-go`（`github.com/blue-cloud-net/tongsuo-go`，[Apache-2.0](LICENSE)）是基于[铜锁 (Tongsuo)](https://www.tongsuo.net/) 的 Go 国密算法封装库。
通过 cgo 直接调用铜锁原生库，向 Go 开发者提供**符合 Go 语言惯例**的国密算法接口
（`hash.Hash`、`cipher.Block`、`cipher.AEAD`、`(T, error)`），覆盖 SM2 / SM3 / SM4 商用密码算法，
并提供 X.509 证书管理与 TLS / NTLS 传输层。

- **模块路径**：`github.com/blue-cloud-net/tongsuo-go`
- **底层依赖**：铜锁 (Tongsuo) **8.4.0+**（Apache-2.0）
- **参考设计**：[blue-cloud-net/tongsuo-csharp](https://github.com/blue-cloud-net/tongsuo-csharp)
- **定位**：全新独立实现，与官方 [tongsuo-project/tongsuo-go-sdk](https://github.com/tongsuo-project/tongsuo-go-sdk) 并存
- **CI/CD**：GitHub Actions（[`.github/workflows/`](.github/workflows/)）— lint + 跨平台测试 + tag 自动发版

---

## 功能

- 🔐 **SM2 非对称算法**（GB/T 32918）：密钥生成、PEM 序列化、加密/解密（ASN.1 DER，内含 C1C3C2）、
  SM2withSM3 签名/验签、自定义 userId
- 🔑 **SM3 哈希算法**（GB/T 32905-2016）：`hash.Hash` 接口 + 一次性 `Sum`
- 🔒 **SM4 对称加密**（GB/T 32907）：ECB / CBC / CTR / OFB / CFB / GCM（AEAD）
- 🧮 **HMAC 消息认证码**：HMAC-SM3 / MD5 / SHA1 / SHA256 / SHA512
- 🔗 **更多哈希**：MD5、SHA1、SHA256、SHA512（`hash.Hash` + `Sum`）
- 🔄 **AES 对称加密**：ECB / CBC / CTR / GCM（`cipher.Block` + `cipher.AEAD`）
- � **Ed25519 / Ed448 签名算法**（RFC 8032）：纯 EdDSA（无预哈希），32B / 57B 原始种子与公钥字节可与 Go 标准库、WireGuard 互操作；通过 `X509_sign_ctx` 路径支持证书 / CSR / CRL 签发
- 🤝 **X25519 ECDH 密钥交换**（RFC 7748）：32 字节共享密钥派生，可与 Go `crypto/ecdh`、WireGuard 互操作，支持证书 / CSR 公钥加载
- 🎲 **安全随机数**：基于铜锁 `RAND_bytes`
- 📜 **X.509 证书管理**：证书解析、创建、自签名 / CA 签发（SM2 + SM3 + RSA + ECDSA + Ed25519 + Ed448）、CSR 生成与验证、BasicConstraints 扩展
- 🌐 **TLS / NTLS 传输层**：客户端 / 服务端封装，支持国密 NTLS 双证书（签名证书 + 加密证书）
- 🧪 **标准向量测试**：每个算法包覆盖国标标准向量、往返、边界与错误路径，并与 openssl CLI 双向交叉验证

## 使用教程

### 环境要求

- Go 1.21+（启用 CGO）
- 铜锁 **8.4.0+**，安装与构建方式见[铜锁官方 README](https://github.com/Tongsuo-Project/Tongsuo#readme)
- 默认安装路径：`/opt/tongsuo`（可通过环境变量 `TONGSUO_HOME` 覆盖）
- 平台：**Linux 优先，macOS 兼容**（Windows 后置）

### 配置 Tongsuo 路径

构建与运行依赖 `cgo` 找到铜锁头文件与库文件。三种常用方式，任选其一即可：

**方式 A — 环境变量（推荐）**：

```bash
export TONGSUO_HOME=/opt/tongsuo                  # 铜锁安装根目录
export LD_LIBRARY_PATH=${TONGSUO_HOME}/lib        # Linux
# export DYLD_LIBRARY_PATH=${TONGSUO_HOME}/lib    # macOS

export CGO_CFLAGS="-I${TONGSUO_HOME}/include -Wno-deprecated-declarations"
export CGO_LDFLAGS="-L${TONGSUO_HOME}/lib"
```

**方式 B — pkg-config**（将 `pkg-config --cflags --libs openssl` 输出注入 cgo flags）：

```bash
export PKG_CONFIG_PATH=${TONGSUO_HOME}/lib/pkgconfig:${PKG_CONFIG_PATH}
```

**方式 C — 静态链接**（适合分发独立二进制）：

```bash
go build -tags static ./...
```

> 编译选项 `-Wno-deprecated-declarations` 用于屏蔽铜锁对部分 OpenSSL 已废弃声明的告警，不影响功能。

### 编译与运行

```bash
# 编译所有包
go build ./...

# 运行单元测试（默认，不包含 openssl CLI 对比）
go test ./...

# 包含 openssl CLI 交叉验证测试
go test -tags tongsuocli ./...

# 覆盖率
go test -cover ./...
```

### 在你的项目中使用

```bash
go get github.com/blue-cloud-net/tongsuo-go
```

然后在代码中按需导入子包（见下文"代码调用示例"）。

## 代码调用示例

### SM3 哈希

```go
package main

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm3"
)

func main() {
	sum := sm3.Sum([]byte("abc"))
	fmt.Printf("%x\n", sum)

	// 流式接口（hash.Hash）
	h := sm3.New()
	h.Write([]byte("abc"))
	fmt.Printf("%x\n", h.Sum(nil))
}
```

### SM4 对称加密

```go
package main

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm4"
)

func main() {
	key := []byte("0123456789abcdef")
	iv := []byte("fedcba9876543210")

	// 一次性便捷函数（CBC + PKCS7 填充）
	ciphertext, err := sm4.EncryptCBC(key, iv, []byte("hello tongsuo"))
	if err != nil {
		panic(err)
	}
	plaintext, err := sm4.DecryptCBC(key, iv, ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", plaintext)

	// GCM（AEAD）
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

### SM2 非对称算法

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

	// 签名（SM2withSM3，ASN.1 DER）
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

	// 加密 / 解密（ASN.1 DER，内含 C1C3C2）
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

	// 流式接口（hash.Hash）
	h := hmac.NewSM3([]byte("secret-key"))
	h.Write([]byte("message"))
	fmt.Printf("%x\n", h.Sum(nil))
}
```

### X.509 证书与 TLS

```go
package main

import (
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/x509"
	"github.com/blue-cloud-net/tongsuo-go/tls"
)

func main() {
	// 生成 CA 密钥并创建自签名证书
	caKey, _ := sm2.GenerateKey()
	caName := x509.NewName().Add("CN", "tongsuo-go CA")

	ca, err := x509.CreateCertificate(caName, caName, 1,
		time.Now(), time.Now().Add(365*24*time.Hour), caKey, caKey)
	if err != nil {
		panic(err)
	}

	// 生成服务端证书（由 CA 签发）
	serverKey, _ := sm2.GenerateKey()
	serverName := x509.NewName().Add("CN", "localhost")

	serverCert, err := x509.CreateCertificate(serverName, caName, 2,
		time.Now(), time.Now().Add(365*24*time.Hour), serverKey, caKey)
	if err != nil {
		panic(err)
	}

	// TLS 服务端
	cfg := &tls.Config{Cert: serverCert, Key: serverKey}
	srv, _ := tls.NewServer(cfg)
	_ = srv

	// 国密 NTLS 双证书
	ntlsCfg := &tls.Config{
		NTLS:     true,
		SignCert: serverCert, SignKey: serverKey,
		EncCert: serverCert, EncKey: serverKey,
	}
	_ = ntlsCfg
}
```

更多可运行示例见 [examples/](./examples)。

## 架构

```
API 层（crypto/）              ← 对外高层 API，仅此层可被外部 import
    ↓ 调用
核心层（internal/core/）       ← 句柄/上下文包装，生命周期与所有权管理
    ↓ 调用
绑定层（internal/native/）     ← cgo + 内嵌 C shim，直接映射铜锁 C 函数
```

- **严格分层、单向依赖**：API 层只经核心层操作对象，不直接接触 cgo
- **内存安全**：原生句柄经核心层 `handle` 包装（`owned` 所有权 + 幂等 `Close()` +
  `runtime.SetFinalizer` 兜底），原生指针不进入公开 API
- **错误处理**：原生失败统一为携带 `ERR_get_error()` 错误码的 `*core.OpError`
- **并发模型**：不同句柄可并行使用；单句柄需调用方串行化
- **内部实现隐藏**：`internal/native` 与 `internal/core` 受 Go `internal` 机制保护，外部不可导入

详细设计见 [docs/architecture.md](docs/architecture.md)。

## 协议

本项目采用 [Apache-2.0](LICENSE) 协议开源。