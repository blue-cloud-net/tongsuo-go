# 项目架构

本文档描述 `tongsuo-go` 的整体架构、目录结构、构建依赖与运行模型。开发规范见
[development-guide.md](development-guide.md)，测试规范见 [testing-guide.md](testing-guide.md)，
实施计划见 [roadmap.md](roadmap.md)。

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
- **底层依赖**：铜锁 (Tongsuo) **8.4.0+**（Apache-2.0）
- **授权**：Apache-2.0（工作区 `LICENSE`）

### 1.1 API 设计取向

- **形态走 Go 惯例**：实现标准库接口（`hash.Hash`、`cipher.Block`）、返回 `(T, error)`、
  按子包组织（`crypto/sm3`、`crypto/sm4` 等）
- **命名语义对齐 C# 参考项目**：算法相关命名与语义遵循 C# 思路（如 `SM3`/`SM4`/`SM2`
  相关概念），不强制与官方 SDK 同名
- **一次性便捷函数**：在标准接口之外，提供直接可用的快捷方法（如 `sm3.Sum`）

---

## 2. 三层架构概览

```
API 层（crypto/）              ← 对外高层 API，仅此层可被外部 import
    ↓ 调用
核心层（internal/core/）       ← 句柄/上下文包装，生命周期与所有权管理
    ↓ 调用
绑定层（internal/native/）     ← cgo + 内嵌 C shim，直接映射铜锁 C 函数
```

- 严格分层，**禁止跨层调用**：API 层不得直接调用绑定层；绑定层不得包含业务逻辑
- 依赖方向**单向向下**，各层边界清晰，便于测试与替换

---

## 3. 各层职责

### 3.1 绑定层（`internal/native/`）

- **只做**铜锁 C 函数的 cgo 声明与薄包装，不含任何业务逻辑
- 函数名与铜锁原生 C 函数名完全一致（如 `EVP_DigestInit_ex`、`EVP_sm3`）
- 内嵌 `shim.c` / `shim.h` 解决 Go 无法直接使用的 C 宏、可变参数函数与**回调桥接**
  （如 BIO 读写、TLS 回调），shim 包装函数统一加 `X_` 前缀（如 `X_EVP_Digest`）
- 按功能域拆分 Go 绑定文件（对应 C# `partial class` 按功能拆文件的思路，Go 用文件名拆分）：
  `binding_digest.go` / `binding_cipher.go` / `binding_pkey.go` / `binding_bio.go` /
  `binding_pem.go` / `binding_rand.go` / `binding_version.go`
- 原生调用失败由**核心层**通过 `ERR_get_error()` 捕获错误码，本层不处理错误语义

### 3.2 核心层（`internal/core/`）

- 将铜锁非托管句柄（如 `*C.EVP_MD_CTX`、`*C.EVP_PKEY`）封装为 Go 对象，
  管理生命周期与所有权
- `handle` 基类：`owned` 所有权字段 + 显式 `Close()` + `runtime.SetFinalizer` 兜底
- `OpError` 错误类型：携带 `ERR_get_error()` 错误码，对应 C# `OpenSSLCryptoException`
- 上下文类型：`DigestCtx` / `CipherCtx` / `PKey` 等，封装原生对象的完整操作流程
- 统一处理 OpenSSL 线程锁初始化与需要时的 `runtime.LockOSThread()`

### 3.3 API 层（公开导入面）

- 对外暴露的公共 API 由两层组成：
  - **算法引擎层**：`crypto/aes`、`crypto/sm2`、`crypto/sm3`、`crypto/sm4`、
    `crypto/hmac`、`crypto/rand`、`crypto/md5`、`crypto/sha1/256/512`、`crypto/rsa`、
    `crypto/ecdsa`
  - **组合层（顶级）**：`x509/`（证书对象模型）、`asn1/`（DER viewer）、
    `pkcs/pkcs7/`、`pkcs/pkcs12/`、`ocsp/`（协议）、`tls/`（协议）、
    `jwk/`（格式）、`xml/rsa/`（格式族）
- 每个算法子包**自带 `*_test.go`** 测试文件（见 [testing-guide.md](testing-guide.md)）
- 不直接调用绑定层，只通过核心层对象操作
- **职责边界**：`crypto/` 严格限于算法引擎；ASN.1 / PKCS / OCSP / TLS / 格式转换
  等"组合层"包独立顶级化，借鉴 BouncyCastle C# 的命名空间分层原则

---

## 4. 术语对照表（C# ↔ Go）

| C# 参考项目 | tongsuo-go | 说明 |
|-------------|------------|------|
| Native 层（LibraryImport P/Invoke） | 绑定层 `internal/native`（cgo + shim） | 原生函数绑定 |
| Core 层（`BaseWapper`） | 核心层 `internal/core`（`handle` 基类） | 句柄包装与生命周期 |
| Crypto 层（高层 API） | API 层 `crypto/*` 子包 | 对外接口 |
| `BaseWapper.IsOwner` 所有权模型 | `handle.owned` 字段 | 防止双重释放 |
| `OpenSSLCryptoException` | `*core.OpError` | 携带原生错误码的 error |
| `LibraryImport` 库路径常量 | `#cgo` LDFLAGS + `TONGSUO_HOME` 环境变量 | 库定位方式 |
| `TongsuoCryptoNative.Version` | `internal/core` 版本查询 | 铜锁版本获取 |
| `SM3Hash` / `SM4Cipher` | `crypto/sm3` / `crypto/sm4` | 高层 API |
| `HashData` / `CreateEncryptor` | `sm3.Sum` / `sm4.EncryptECB` 等便捷函数 | 一次性 API |

---

## 5. 目录结构（v0.2.0 后）

**顶层布局原则**：借鉴 BouncyCastle C# 命名空间分层——`crypto/` 仅装算法引擎；
ASN.1、PKCS、OCSP、TLS、JWK、XML 与 `crypto/` 平级，不作为其子包。

```
tongsuo-go/
├── go.mod / go.sum            # module github.com/blue-cloud-net/tongsuo-go
├── LICENSE                    # Apache-2.0
├── README.md  CHANGELOG.md
├── docs/                      # 设计文档（architecture / development-guide / roadmap / testing-guide）
│
├── crypto/                    # 【算法引擎层】仅算法子包
│   ├── aes/  ecdsa/  hmac/  md5/  rand/  rsa/
│   ├── sha1/  sha256/  sha512/  sm2/  sm3/  sm4/
├── x509/                      # 【协议】证书核心
│   ├── x509.go                # Certificate / Extension / PublicKey / PrivateKey / CreateCertificate
│   ├── name.go                # Name / NameEntry / NewName
│   ├── csr.go                 # CertificateRequest
│   ├── store.go               # Store / VerifyError / ChainVerify
│   ├── crl.go                 # CRL / RevokedEntry / RevocationCheck
│   └── helpers.go             # convertEntries / convertExtensions（内部辅助）
│
├── asn1/                      # 【编码】DER viewer（纯 Go）
├── pkcs/                      # 【容器】BC pkcs 风格
│   ├── pkcs7/                 # PKCS#7（Build / Extract / MarshalPEM）
│   └── pkcs12/                # PKCS#12（Pack / Parse / ChangePassword）
├── ocsp/                      # 【协议】OCSP 客户端
├── tls/                       # 【协议】TLS / NTLS
├── jwk/                       # 【格式】JWK ↔ PEM
├── xml/                       # 【格式族】预留命名空间
│   └── rsa/                   # .NET RSAKeyValue XML 序列化
│
├── internal/                  # 【内部实现】外部不可 import
│   ├── native/                # 【绑定层】cgo + shim（C 桥接）
│   │   ├── shim.h  shim.c     # C shim：宏/可变参/回调桥接
│   │   ├── binding_digest.go  # EVP_MD / EVP_Digest* 系列
│   │   ├── binding_cipher.go  # EVP_CIPHER / EVP_CIPHER_CTX 系列
│   │   ├── binding_pkey.go    # EVP_PKEY / EVP_PKEY_CTX 系列（SM2/RSA/EC）
│   │   ├── binding_bio.go     # BIO 系列
│   │   ├── binding_pem.go     # PEM / DER 系列
│   │   ├── binding_rand.go    # RAND_* 系列
│   │   └── binding_version.go # OpenSSL_version / Tongsuo_version_num
│   └── core/                  # 【核心层】句柄包装 + 生命周期 + 错误
│       ├── handle.go          # 句柄基类：owned 所有权 + Close() + SetFinalizer
│       ├── error.go           # OpError（携带 ERR_get_error 错误码）
│       ├── version.go         # 版本查询
│       ├── digest.go  cipher.go  pkey.go  bio.go …
│       └── testutil/          # 测试共享工具（openssl CLI 封装、向量加载）
│
├── examples/                  # 示例（对应 C# Demo/）
│   ├── sm3/main.go  sm4/main.go  sm2/main.go …
└── testdata/                  # 测试数据（标准向量、证书等）
```

> **内部实现隐藏**：`internal/` 目录使绑定层与核心层对库外部不可见，公开 API 由
> `crypto/*` 与顶级 `asn1/`、`pkcs/*`、`ocsp/`、`tls/`、`jwk/`、`xml/*` 共同构成。
> `crypto/` 仅限算法；非算法的"组合层"包独立顶级化。

---

## 6. 构建与依赖

### 6.1 环境要求

- Go 1.21+（启用 CGO）
- 铜锁 8.4.0+，安装路径 `/opt/tongsuo`（可通过环境变量覆盖）
- 平台：**Linux 优先，macOS 兼容，Windows 后置**

### 6.2 安装铜锁

```bash
git clone https://github.com/Tongsuo-Project/Tongsuo.git
cd Tongsuo
./config --prefix=/opt/tongsuo --libdir=/opt/tongsuo/lib enable-ntls enable-export-sm4
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
- **敏感内存**：密钥、明文等敏感缓冲区使用后清零
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
| 分层 | 两层，绑定与 API 同包混合 | 三层，`internal/native` → `internal/core` → `crypto/*` | 三层（Native/Core/Crypto） |
| 实现可见性 | 原生指针暴露到公开 API | `internal/` 隐藏 cgo 与原生句柄 | Native 层 internal |
| 生命周期 | 主要依赖 finalizer | `handle` 基类：Close() + finalizer + owned | `BaseWapper`：IDisposable + 析构器 |
| API 命名 | 自身风格 | 按 C# 语义命名 | BCL 风格 |
| 传输层 | 顶层包 `tongsuogo`（TLCP/TLS） | 顶层包 `tls`（Phase 6 已完成：`Dial`/`Server`/`Conn`） | 独立 Ssl 层 |

---

## 11. 相关链接

- [铜锁官网](https://www.tongsuo.net/)
- [铜锁 GitHub](https://github.com/Tongsuo-Project/Tongsuo)
- [参考项目（C# 封装）](https://github.com/blue-cloud-net/tongsuo-csharp)
- [官方 Go SDK](https://github.com/tongsuo-project/tongsuo-go-sdk)
- [开发规范](development-guide.md) · [测试规范](testing-guide.md) · [路线图](roadmap.md)
