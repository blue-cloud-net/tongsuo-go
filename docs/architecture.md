# 项目架构

本文档描述 `tongsuo-go` 的整体架构、目录结构、构建依赖与运行模型。开发规范见
[development-guide.md](development-guide.md)，测试规范见 [testing-guide.md](testing-guide.md)。

---

## 1. 项目概述

`tongsuo-go` 是基于[铜锁 (Tongsuo)](https://www.tongsuo.net/) 的 Go 国密算法封装库，
通过 cgo 直接调用铜锁原生库，为 Go 开发者提供**符合 Go 语言惯例**的国密算法接口。

- **模块路径**：`github.com/blue-cloud-net/tongsuo-go`
- **参考设计**：[blue-cloud-net/tongsuo-csharp](https://github.com/blue-cloud-net/tongsuo-csharp)
  （.NET 国密封装库）的三层架构与文档体系
- **定位**：**全新独立实现**，与官方
  [tongsuo-project/tongsuo-go-sdk](https://github.com/tongsuo-project/tongsuo-go-sdk)
  并存，不复用其代码；但其 cgo/shim 构建思路、子包划分、线程锁与静态链接约定作为实现参考
- **底层依赖**：铜锁 (Tongsuo) **8.4.0+**（Apache-2.0；已在 8.4.0 验证）
- **授权**：Apache-2.0（工作区 `LICENSE`）

### 1.1 API 设计取向

- **形态走 Go 惯例**：实现标准库接口（`hash.Hash`、`cipher.Block`、`cipher.AEAD`）、
  返回 `(T, error)`、按子包组织
- **同时提供 CLI 式单一入口**：在标准接口之外，每个算法域还提供「算法名 + 输入 → 输出」
  的按名分发入口（如 `digest.Sum("SM3", data)`、`sym.Encrypt("SM4-CBC", key, iv, data)`），
  对齐铜锁 `openssl` 命令行的使用形态
- **命名语义对齐 C# 参考项目**：算法相关命名与语义遵循 C# 思路（如 `SM3`/`SM4`/`SM2`
  相关概念），不强制与官方 SDK 同名
- **一次性便捷函数**：在标准接口之外，提供直接可用的快捷方法（如 `digest.SumSM3`）

---

## 2. 三层架构概览

```
API 层（16 个顶级包：meta / digest / mac / sym / asym / ecdh / kdf / rand /
        keystore / x509 / tls / asn1 / jwk / pkcs/* / xml-rsa）
    ↓ 调用                          ← 仅此层可被外部 import
核心层（internal/core/）          ← 句柄/上下文包装，生命周期与所有权管理
    ↓ 调用
绑定层（internal/native/）        ← cgo + 内嵌 C shim，直接映射铜锁 C 函数
```

- 严格分层，**禁止跨层调用**：API 层不得直接调用绑定层；绑定层不得包含业务逻辑
- 依赖方向**单向向下**，各层边界清晰，便于测试与替换
- API 层内部：`ecdh → asym`（加载 `asym` 密钥对象）、`x509 → asym`（公钥/私钥接口）、
  `tls/jwk/pkcs12 → x509` + `asym`；算法原语包只依赖 `internal/core`，不互相依赖

---

## 3. 各层职责

### 3.1 绑定层（`internal/native/`）

- **只做**铜锁 C 函数的 cgo 声明与薄包装，不含任何业务逻辑
- 函数名与铜锁原生 C 函数名完全一致（如 `EVP_DigestInit_ex`、`EVP_sm3`）
- 内嵌 `shim.c` / `shim.h` 解决 Go 无法直接使用的 C 宏、可变参数函数与**回调桥接**
  （如 BIO 读写、TLS 回调），shim 包装函数统一加 `X_` 前缀（如 `X_EVP_Digest`）
- 按功能域拆分 Go 绑定文件（对应 C# `partial class` 按功能拆文件的思路，Go 用文件名拆分）：
  `binding_digest.go` / `binding_cipher.go` / `binding_pkey.go` / `binding_bio.go` /
  `binding_ssl.go` / `binding_x509.go` / `binding_pkcs.go` / `binding_ocsp.go` /
  `binding_hmac.go` / `binding_kdf.go` / `binding_rand.go` / `binding_error.go` /
  `binding_version.go`（共 13 个；PEM/DER 相关函数聚合在 `binding_x509.go`）
- 原生调用失败由**核心层**通过 `ERR_get_error()` 捕获错误码，本层不处理错误语义

### 3.2 核心层（`internal/core/`）

- 将铜锁非托管句柄（如 `*C.EVP_MD_CTX`、`*C.EVP_PKEY`）封装为 Go 对象，
  管理生命周期与所有权
- `handle` 基类：`owned` 所有权字段 + 显式 `Close()` + `runtime.SetFinalizer` 兜底
- `OpError` 错误类型：携带 `ERR_get_error()` 错误码，对应 C# `OpenSSLCryptoException`
- 上下文类型：`DigestCtx` / `CipherCtx` / `PKey` 等，封装原生对象的完整操作流程
- 统一处理 OpenSSL 线程锁初始化与需要时的 `runtime.LockOSThread()`

### 3.3 API 层（公开导入面）

对外暴露的公共 API 是**单层扁平**的 **16 个顶级包**（`crypto/` 整目录与 `key/` 已在包结构重构中取消）：

| 分组 | 包 | 职责 |
|------|----|------|
| 元信息 | `meta` | 版本 / 构建信息 / 错误码解析 / 算法枚举（只查询，不持有句柄） |
| 算法原语 | `digest` `mac` `sym` `kdf` `rand` | 摘要 / 消息认证码 / 对称加解密 / 密钥派生 / 随机数 |
| 密钥 | `asym` `ecdh` `keystore` | 非对称密钥与运算 / 密钥协商 / 密钥元数据、存储与轮转 |
| PKI | `x509` | 证书 + CSR + CRL + OCSP + 链验证（**单包**） |
| 传输 | `tls` | TLS / NTLS 客户端与服务端 |
| 格式 | `asn1` `jwk` `pkcs/pkcs7` `pkcs/pkcs12` `xml/rsa` | DER viewer / JWK / PKCS#7 / PKCS#12 / .NET XML |

- 每个包**自带 `*_test.go`** 测试文件（见 [testing-guide.md](testing-guide.md)），并尽量提供
  `example_test.go` 与 `*_tongsuocli_test.go`（CLI 对拍，`//go:build tongsuocli` 隔离）
- 不直接调用绑定层，只通过核心层对象操作
- **职责边界**：算法原语与「按算法名分发」的应用入口同包（如 `digest.Sum("SM3", …)`
  与 `digest.SumSM3(…)` 并存）；ASN.1 / PKCS / TLS / 格式转换等组合层包与算法包平级
- **公开签名不得出现 `internal/` 类型**：这是重构后的硬约束（原先 `*core.PKey` /
  `*core.Digest` / `*core.KeyParams` / `*core.Certificate` 等泄漏到公开签名的 12 处均已收敛）

#### 跨包取原生句柄（`internal/keyaccess`）

API 层内部存在必须先拿到 `*core.PKey` 才能工作的场景（如 `ecdh` 对 `asym` 密钥做
`EVP_PKEY_derive`，`x509` 设置证书公钥 / 签名）。为兼顾「不泄露内部类型」与「不多一次编解码」，
采用**结构化接口断言**而非注册表：

- `asym` 密钥的**具体类型一律非导出**（`*privateKey` / `*publicKey` …），对外只返回
  `PrivateKey` / `PublicKey` 接口；具体类型上实现导出方法 `CorePKey() *core.PKey`
- 该方法**不出现在任何导出接口中**（`asym.Key` / `PrivateKey` / `PublicKey` 均不含它），
  因此不进公开 godoc
- `internal/keyaccess` 只声明形状 `interface{ CorePKey() *core.PKey }` + `PKey(v any) (*core.PKey, bool)`
  并做类型断言：**无注册表、无 `init()` 顺序依赖、无全局状态**；`asym` 也不需要 import 它
- 消费方：`ecdh`、`x509`、`tls`、`jwk`、`pkcs/pkcs12`；拿到句柄后用 `EVP_PKEY_dup` 复制，
  保证两侧生命周期独立
- 验收：`go doc -all ./asym` 输出中不得出现 `CorePKey`；`internal/` 路径规则保证外部模块无法 import

#### tls 包公开 API（v0.2.0+）

`tls/` 在 v0.2.0 引入 ctx 友好的握手与错误分类 API，公共符号：

- 连接入口：`DialContext(ctx, network, addr, cfg)` 同时驱动 TCP 拨号与 TLS/NTLS
  握手受同一 ctx 控制；`Dial` 退化为 `DialContext(context.Background(), …)` 薄包装，
  保持源代码兼容
- 握手：`(*Conn).HandshakeContext(ctx)` 在 goroutine 内执行握手，ctx 触发时通过
  `SetDeadline` + 关闭 raw socket 唤醒在途 `SSL_read` / `SSL_write` 等待；
  `(*Conn).Handshake()` 是 `context.Background()` 包装
- 对端证书：`(*Conn).PeerCertificates()` 返回签名证书链；
  `(*Conn).PeerEncCertificates()` 返回 NTLS 加密证书链（NTLS 专有）
- 套件枚举：`CipherSuites(version uint16) []CipherSuiteInfo`（`0x0301`–`0x0304` 与
  `NTLSVersion = 0x0101`）；`Config.CipherSuites` 同时接受 `TLS_xxx`（TLS 1.3
  `SSL_CTX_set_ciphersuites`）与经典 `SSL_CTX_set_cipher_list` 名字
- 错误：哨兵 `ErrVersionNotSupported` / `ErrNoSharedCipher` / `ErrPeerVerification`
  / `ErrNetwork`；类型化 `*HandshakeError{Op, Kind, Err}` 按 library + reason
  对 OpenSSL 错误分类；`ctx.Err()` 透传不包 `*HandshakeError`
- `(*Server).Accept`：v0.2.0 起仅构造 `*Conn` 即返回，握手推迟到调用方显式调用
  `Handshake` / `HandshakeContext`；未显式调用的调用方需要补上

---

## 4. 术语对照表（C# ↔ Go）

| C# 参考项目 | tongsuo-go | 说明 |
|-------------|------------|------|
| Native 层（LibraryImport P/Invoke） | 绑定层 `internal/native`（cgo + shim） | 原生函数绑定 |
| Core 层（`BaseWapper`） | 核心层 `internal/core`（`handle` 基类） | 句柄包装与生命周期 |
| Crypto 层（高层 API） | API 层（16 个顶级包） | 对外接口 |
| `BaseWapper.IsOwner` 所有权模型 | `handle.owned` 字段 | 防止双重释放 |
| `OpenSSLCryptoException` | `*core.OpError` | 携带原生错误码的 error |
| `LibraryImport` 库路径常量 | `#cgo` LDFLAGS + `TONGSUO_HOME` 环境变量 | 库定位方式 |
| `TongsuoCryptoNative.Version` | `meta` 包（薄封装 `internal/core` 版本查询） | 铜锁版本获取 |
| `SM3Hash` / `SM4Cipher` | `digest` / `sym` | 高层 API |
| `HashData` / `CreateEncryptor` | `digest.SumSM3` / `sym.EncryptSM4ECB` 等便捷函数 | 一次性 API |

---

## 5. 目录结构

**顶层布局原则**：API 层是**单层扁平**的 16 个顶级包——没有 `crypto/` 中间目录，也没有
`key/` 统合包；算法原语、密钥、PKI、传输、格式各自成包，且「算法名 + 输入 → 输出」的
应用入口与算法原语**同包**（对应 CLI 的 `dgst` / `enc` / `mac` / `kdf` 等命令）。

```
tongsuo-go/
├── go.mod                     # module github.com/blue-cloud-net/tongsuo-go（无第三方依赖）
├── LICENSE                    # Apache-2.0
├── README.md  README.zh.md
├── CHANGELOG.md  CHANGELOG.zh.md
├── AGENTS.md
│
├── meta/                      # 【元信息】版本 / 构建信息 / 错误码 / 算法枚举
│   ├── version.go             # Version / VersionString / VersionNum / TongsuoVersionNum
│   ├── build.go               # BuildInfo / ReadBuildInfo
│   ├── error.go               # ErrorString / ErrorCode / ParseErrorCode
│   └── list.go                # （规划中）Digests / Ciphers / MACs / KDFs / Providers …
├── digest/                    # 【原语】摘要
│   ├── digest.go              # 按名分发：Names / New / Sum / SumReader / Size / BlockSize
│   └── typed.go               # 类型化：NewSM3 / SumSM3 / NewSHA256 / SumSHA256 …
├── mac/                       # 【原语】消息认证码
│   └── mac.go                 # 按名分发 + HMAC 类型化入口（CMAC/GMAC/KMAC… 规划中）
├── kdf/                       # 【原语】密钥派生
│   └── kdf.go                 # Hash 常量 / HKDF / PBKDF2 / Argon2ID / Derive
├── rand/                      # 【原语】安全随机数
│   └── rand.go                # Read / Bytes / Reader
├── sym/                       # 【原语】对称加密 + 对称密钥对象
│   ├── sym.go                 # 按名分发：Names / NewCipher / NewGCM / Encrypt / Decrypt
│   ├── aes.go  sm4.go         # 类型化入口：EncryptAESCBC / EncryptSM4ECB …
│   └── key.go                 # SymmetricKey / AESKey / SM4Key / GenerateSymmetricKey
├── asym/                      # 【密钥】非对称密钥、签名验签、加解密、KEM
│   ├── asym.go                # Algorithm / Key / PrivateKey / PublicKey 接口
│   ├── generate.go            # GenerateKey / GenerateRSA / GenerateSM2 / GenerateEC …
│   ├── parse.go               # LoadPrivateKeyPEM / LoadPublicKeyPEM / ParsePEM
│   ├── sign.go  encrypt.go    # Sign / Verify / Encrypt / Decrypt + 算法特定入口
│   ├── register.go            # CorePKey() 契约（供 internal/keyaccess 反查）
│   └── params.go              # KeyParams
├── ecdh/                      # 【密钥】密钥协商
│   └── ecdh.go                # Curve / LoadPrivateKey / LoadPublicKey / SharedSecret
├── keystore/                  # 【密钥】元数据、存储与轮转
│   ├── handle.go              # Handle / NewHandle / MarshalJSON
│   └── store.go               # Store / MemoryStore / Rotate / History
├── x509/                      # 【PKI】证书 + CSR + CRL + OCSP + 链验证（单包）
│   ├── x509.go                # Certificate / Extension / CreateCertificate / CreateSelfSigned
│   ├── name.go                # Name / NameEntry
│   ├── csr.go                 # CertificateRequest
│   ├── crl.go                 # CRL / RevokedEntry / CRLBuilder / RevocationCheck
│   ├── ocsp.go                # Request / Response / CreateOCSPRequest / ParseOCSPResponse
│   ├── store.go               # Store / VerifyError / ChainVerify
│   └── helpers.go             # convertEntries / convertExtensions
├── tls/                       # 【传输】TLS / NTLS
│   ├── tls.go  chain.go  suites.go  errors.go
├── asn1/                      # 【格式】DER viewer（纯 Go，cgo-free）
├── jwk/                       # 【格式】JWK ↔ PEM / JSON
├── pkcs/                      # 【容器】
│   ├── pkcs7/                 # PKCS#7（Build / Extract / MarshalPEM）
│   └── pkcs12/                # PKCS#12（Pack / Parse / ChangePassword）
├── xml/                       # 【格式族】预留命名空间
│   └── rsa/                   # .NET RSAKeyValue XML 序列化
│
├── internal/                  # 【内部实现】外部不可 import
│   ├── native/                # 【绑定层】cgo + shim（C 桥接）
│   │   ├── shim.h  shim.c     # C shim：宏 / 可变参 / 回调桥接（X_ 前缀）
│   │   ├── build.go           # #cgo LDFLAGS（动态库）
│   │   ├── build_static.go    # #cgo LDFLAGS（-tags static，仅 linux）
│   │   ├── init.go            # 铜锁线程锁注册
│   │   ├── binding_digest.go  # EVP_MD / EVP_Digest* 系列
│   │   ├── binding_cipher.go  # EVP_CIPHER / EVP_CIPHER_CTX 系列
│   │   ├── binding_pkey.go    # EVP_PKEY / EVP_PKEY_CTX 系列（SM2 / RSA / EC）
│   │   ├── binding_hmac.go    # HMAC_CTX 系列
│   │   ├── binding_kdf.go     # EVP_KDF（HKDF / PBKDF2）
│   │   ├── binding_rand.go    # RAND_bytes
│   │   ├── binding_bio.go     # BIO 系列
│   │   ├── binding_ssl.go     # SSL_CTX / SSL / TLS 会话
│   │   ├── binding_x509.go    # X509 / X509_REQ / X509_CRL / X509_STORE / PEM / DER
│   │   ├── binding_pkcs.go    # PKCS#7 / PKCS#12 系列
│   │   ├── binding_ocsp.go    # OCSP_REQ / OCSP_RES 系列
│   │   ├── binding_error.go   # ERR_get_error / 错误码
│   │   └── binding_version.go # OpenSSL_version / Tongsuo_version_num
│   ├── core/                  # 【核心层】句柄包装 + 生命周期 + 错误 + 协议编排
│   │   ├── handle.go  error.go  doc.go  version.go
│   │   ├── digest.go  cipher.go  hmac.go  kdf.go
│   │   ├── pkey.go  pkey_id.go  pkcs.go  ocsp.go
│   │   ├── x509.go  ssl.go  rand.go  zero.go
│   │   └── waitfd_linux.go  waitfd_darwin.go
│   ├── keyaccess/             # 【桥接】公开密钥对象 → *core.PKey（结构化接口断言，叶子包）
│   │   └── keyaccess.go       # corePKeyer + PKey(v any)
│   ├── digest/                # 【共享抽象】纯 Go hash.Hash 实现
│   │   └── digest.go          # NewHash：把 *core.Digest 适配为 hash.Hash
│   └── testutil/              # 【测试共享】铜锁 CLI 包装与跳过判定
│       └── openssl.go
│
├── docs/                      # 设计文档（architecture / development-guide / testing-guide /
│                              #   bilingual-doc-guide / api-reference ×2 / refactor-roadmap …）
├── scripts/                   # check-coverage.sh / extract_release_notes.py
└── examples/                  # 示例（对应 C# Demo/），每个示例是独立 Go module
    └── sm2/ self-signed-cert/ ntls-loopback/ ed25519/ x25519/ ecdh/
```

> **内部实现隐藏**：`internal/` 使绑定层、核心层与桥接层对库外部不可见；公开 API 由上述
> 16 个顶级包构成。`internal/keyaccess` 是唯一的「公开对象 → 原生句柄」通道，只被
> `ecdh` / `x509` / `tls` / `jwk` / `pkcs12` 使用。
> 依赖方向单向：算法原语包只依赖 `internal/core`；`ecdh → asym`；`x509 → asym`；
> `tls` / `jwk` / `pkcs12` → `x509` + `asym`。原 `key/` 的统合职责已拆分：
> 非对称抽象 → `asym`、对称抽象 → `sym`、元数据与轮转 → `keystore`、KDF → `kdf`。

---

## 6. 构建与依赖

### 6.1 环境要求

- Go 1.21+（启用 CGO；已在 Go 1.26 验证）
- 铜锁 8.4.0+（已在 8.4.0 验证），安装路径 `/opt/tongsuo`（可通过环境变量覆盖）
- 平台：**Linux 优先，macOS 兼容，Windows 后置**

### 6.2 安装铜锁

```bash
git clone https://github.com/Tongsuo-Project/Tongsuo.git
cd Tongsuo
./config --prefix=/opt/tongsuo --libdir=/opt/tongsuo/lib enable-ntls enable-trace no-shared
make -j$(nproc)
sudo make install
# 配置动态库路径
echo "/opt/tongsuo/lib" | sudo tee /etc/ld.so.conf.d/tongsuo.conf
sudo ldconfig
```

### 6.3 构建

```bash
TONGSUO_HOME=/opt/tongsuo \
LD_LIBRARY_PATH=${TONGSUO_HOME}/lib \
CGO_CFLAGS="-I${TONGSUO_HOME}/include -Wno-deprecated-declarations" \
CGO_LDFLAGS="-L${TONGSUO_HOME}/lib" \
go build ./...
```

- macOS 将 `LD_LIBRARY_PATH` 换为 `DYLD_LIBRARY_PATH`
- 静态链接：`go build -tags static ./...`（`#cgo` 切换为 `-extldflags -static`）

### 6.4 go.mod

- `module github.com/blue-cloud-net/tongsuo-go`
- 无第三方运行时依赖（仅标准库 + cgo）

---

## 7. 内存与生命周期模型

- 所有原生句柄经核心层 `handle` 包装后向上传递，原生指针**不进入公开 API**
- **所有权**：由本对象通过绑定层**创建**的句柄 → `owned = true`；**外部传入**或静态
  描述符（如 `EVP_sm3` 返回的常量算法指针）→ `owned = false`
- **释放**：显式 `Close()` 为主路径，`runtime.SetFinalizer` 作为兜底
- **finalizer 注意**：Go 不保证 finalizer 一定执行（程序退出、对象无法触碰时不会执行），
  **不得依赖 finalizer 作为唯一释放途径**；资源敏感场景（如 TLS 连接）必须显式 `Close()`
- **防双重释放**：`Close()` 幂等；释放后句柄置空，后续使用返回明确错误
- **敏感内存**：本库 Go 侧不在持有方主动清零（Go 编译器允许消除看似无副作用的清零循环）；
  密钥/明文由调用方负责在使用后清零源切片；C 端由 Tongsuo 自身（OPENSSL_cleanse）
  处理会话级密钥缓冲。详见 `sym.NewAESCipher` / `sym.NewSM4Cipher` 等入口的 GoDoc
- **防悬垂指针**：句柄释放后不得再调用绑定层函数

---

## 8. 线程与并发模型

- cgo 调用本身并发安全；**不同句柄**可在多个 goroutine 中并行使用
- **单个句柄不保证并发安全**，需并发使用时由调用方串行化或加锁
- 涉及 TLS 操作 / C 回调的场景使用 `runtime.LockOSThread()` 固定线程
- 初始化阶段注册 OpenSSL 线程锁回调（思路参考官方 SDK 的 `init_posix.go`，
  本项目独立实现，不复制其代码）

---

## 9. 错误处理架构

- 所有可失败操作**返回 `error`**（Go 惯例），不使用异常机制
- 原生层失败：核心层通过 `ERR_get_error()` 捕获错误码，包装为 `*core.OpError`
- 上层用 `fmt.Errorf("...: %w", err)` 追加上下文
- 参数类错误：返回哨兵错误（`ErrXxx`）或带上下文的普通 error
- 约定：库内**不 panic**（仅编程错误除外）

---

## 10. 与官方 SDK / C# 项目的异同

| 维度 | 官方 tongsuo-go-sdk | tongsuo-go（本库） | C# tongsuo-csharp |
|------|--------------------|--------------------|-------------------|
| 绑定方式 | cgo + 内嵌 shim | cgo + 内嵌 shim（同思路，独立实现） | P/Invoke（LibraryImport） |
| 分层 | 两层，绑定与 API 同包混合 | 三层，`internal/native` → `internal/core` → 16 个顶级包 | 三层（Native/Core/Crypto） |
| 实现可见性 | 原生指针暴露到公开 API | `internal/` 隐藏 cgo 与原生句柄 | Native 层 internal |
| 生命周期 | 主要依赖 finalizer | `handle` 基类：Close() + finalizer + owned | `BaseWapper`：IDisposable + 析构器 |
| API 命名 | 自身风格 | 按 C# 语义命名 | BCL 风格 |
| 传输层 | 顶层包 `tongsuogo`（TLCP/TLS） | 顶层包 `tls`（`Dial`/`Server`/`Conn`） | 独立 Ssl 层 |

---

## 11. 相关链接

- [铜锁官网](https://www.tongsuo.net/)
- [铜锁 GitHub](https://github.com/Tongsuo-Project/Tongsuo)
- [参考项目（C# 封装）](https://github.com/blue-cloud-net/tongsuo-csharp)
- [官方 Go SDK](https://github.com/tongsuo-project/tongsuo-go-sdk)
- [与官方 SDK 的功能对比与对齐路线图](official-sdk-comparison.md)
- [包结构重构路线图](refactor-roadmap.md)
- [开发规范](development-guide.md) · [测试规范](testing-guide.md)
- [公开 API 清单](api-reference.md) · [内部 API 清单](api-reference-internal.md)
