# AGENTS.md — tongsuo-go 工作指南

> 本文件面向在本仓库中工作的 AI 编码代理（agent）以及首次接触本仓库的开发者。
> 它回答三件事：**这是什么项目**、**改代码前后必须做什么**、**哪些红线不能碰**。
> 细则以 `docs/` 下的正式规范为准，本文件只做「可直接执行的要点 + 指针」。

**规范唯一事实来源（细则文档）**

| 主题 | 文档 |
|------|------|
| 整体架构、目录结构、构建依赖、生命周期与并发模型 | `docs/architecture.md` |
| GoDoc 注释、命名、cgo、核心层、错误、内存、代码风格 | `docs/development-guide.md` |
| 测试组织、各算法必测用例、标准向量来源 | `docs/testing-guide.md` |
| 双语 GoDoc 段式细则、八条规则、中英对照词典 | `docs/bilingual-doc-guide.md` |
| 历史审计发现（19 份报告） | `docs/issues/2026-09-10/` |

---

## 1. 项目定位（先读这一节）

### 1.1 这是什么

`tongsuo-go`（模块路径 `github.com/blue-cloud-net/tongsuo-go`，[Apache-2.0](LICENSE)）
是**铜锁（Tongsuo）的 Go 语言 SDK / 封装库**：

- 通过 **cgo** 调用铜锁原生 C 库，把底层 `EVP_*` / `X509_*` / `SSL_*` 等接口
  **组合封装为高级方法**，向 Go 开发者提供**符合 Go 语言惯例**的 API：
  `hash.Hash`、`cipher.Block`、`cipher.AEAD`、`(T, error)` 返回形态、一次性便捷函数
  （如 `sm3.Sum`、`sm4.EncryptCBC`）
- 覆盖 SM2 / SM3 / SM4 商用密码算法，以及 AES、RSA、ECDSA、Ed25519 / Ed448、
  X25519 / X448、ECDH、HMAC、KDF、X.509 证书、PKCS#7 / PKCS#12、OCSP、
  JWK、TLS / NTLS（国密双证书）
- 采用 **API 层 → 核心层 → 绑定层** 三层架构，依赖单向向下，`internal/` 隐藏 cgo 细节
- 是**全新独立实现**，与官方 [tongsuo-project/tongsuo-go-sdk](https://github.com/tongsuo-project/tongsuo-go-sdk)
  **并存**，**不复用其代码**；命名语义参考 C# 项目 [blue-cloud-net/tongsuo-csharp](https://github.com/blue-cloud-net/tongsuo-csharp)

一句话：**本仓库是「调用铜锁」的 Go SDK，不是铜锁本身。**

### 1.2 这**不是**什么（最容易搞错的一点）

本仓库**只提供封装层代码**，**不包含铜锁库本体**：

- ❌ 不含铜锁（Tongsuo）C 源码
- ❌ 不含预编译的 `libcrypto` / `libssl` 或铜锁命令行二进制
- ❌ 不做 vendored 依赖，不打包，不产出「开箱即用」的独立二进制
- ✅ 构建、测试、运行**之前**必须由使用者自行安装 **铜锁 8.4.0+**，
  并通过 `TONGSUO_HOME` / `CGO_CFLAGS` / `CGO_LDFLAGS` / `LD_LIBRARY_PATH`
  让 cgo 找到头文件与库（详见 §2.1）
- ✅ 本仓库的发布物**只有 CHANGELOG 文本**，不附任何二进制产物
  （见 `.github/workflows/release.yml`；CI 中的铜锁是运行时从源码编译到 `.tongsuo-install/`，不入库）
- ✅ `go.mod` **无任何第三方依赖**，仅标准库 + cgo

### 1.3 环境里没有铜锁时，正确的反应

缺少铜锁时 cgo 会找不到 `openssl/*.h` 或链接失败，构建/`go vet`/大部分测试都会失败。
**正确做法**：如实报告环境缺失，说明需要安装铜锁并把 `TONGSUO_HOME` 指过去，
或改为只做不依赖构建的改动（纯文档），并**明确声明未运行构建与测试**。

不允许的做法（各配反例，其余章节同此体例）：

- ❌ 反例：把铜锁源码、预编译库或 tar 包下载/复制进仓库，来「让它能编译」
- ❌ 反例：改用系统 OpenSSL 冒充铜锁（算法/provider/行为不同，测试结果失真）
- ❌ 反例：stub 掉 `internal/native`、注释掉 cgo 调用或加 build tag 屏蔽，以「跑通测试」
- ❌ 反例：用 `t.Skip` 掩盖真实失败后宣称「测试通过」
- ❌ 反例：修改 `go.mod` 引入第三方替代实现

---

## 2. 快速上手（命令速查）

### 2.1 环境变量（每个新 shell 都需要）

```bash
export TONGSUO_HOME=/opt/tongsuo                   # 铜锁安装根目录（默认路径）
export LD_LIBRARY_PATH=${TONGSUO_HOME}/lib         # Linux
# export DYLD_LIBRARY_PATH=${TONGSUO_HOME}/lib     # macOS
export CGO_CFLAGS="-I${TONGSUO_HOME}/include -Wno-deprecated-declarations"
export CGO_LDFLAGS="-L${TONGSUO_HOME}/lib"
```

- `-Wno-deprecated-declarations` 仅用于屏蔽铜锁对部分 OpenSSL 已废弃声明的告警，不影响功能
- 也可用 pkg-config 方式：`export PKG_CONFIG_PATH=${TONGSUO_HOME}/lib/pkgconfig:${PKG_CONFIG_PATH}`
- CLI 对拍测试用 `TONGSUO_OPENSSL_BIN` 指定铜锁命令行，默认 `/opt/tongsuo/bin/openssl`

### 2.2 构建与静态检查

```bash
go build ./...            # 动态链接构建（全包）
go vet ./...              # 静态检查，CI 的 lint 阶段就是它
go build -tags static ./...   # 静态链接；仅 Linux 已接线（macOS 未接线）
```

### 2.3 测试

```bash
go test -count=1 ./...            # 默认：单元测试（不含 CLI 对拍），CI 跑的就是这条
go test -tags tongsuocli ./...    # 额外跑铜锁 openssl CLI 逐字节对拍（需铜锁二进制）
go test -cover ./...              # 覆盖率
go test -race ./...               # 并发改动时建议加跑
```

### 2.4 覆盖率 / 模糊 / 基准

```bash
THRESHOLD=80 ./scripts/check-coverage.sh          # 逐包行覆盖门禁（默认阈值 60%）
EXCLUDE="ocsp,jwk" ./scripts/check-coverage.sh    # 排除依赖外部环境的包
go test -bench . ./crypto/sm3                     # 基准（关键路径应有 Benchmark*）
go test -fuzz FuzzRoundTrip ./crypto/sm4          # 模糊测试（会真实跑很久）
```

---

## 3. 目录地图与分层红线

### 3.1 三层架构

```
API 层（crypto/*、key/、x509/、tls/ …）  ← 对外高层 API，仅此层可被外部 import
    ↓ 调用
核心层（internal/core/）                 ← 句柄/上下文包装，生命周期与所有权管理
    ↓ 调用
绑定层（internal/native/）               ← cgo + 内嵌 C shim，直接映射铜锁 C 函数
```

### 3.2 完整目录地图（到文件级）

**顶层**

```
tongsuo-go/
├── go.mod                    # module github.com/blue-cloud-net/tongsuo-go / go 1.21（无第三方依赖）
├── LICENSE                   # Apache-2.0
├── README.md  README.zh.md   # 双语 README（必须成对维护）
├── CHANGELOG.md  CHANGELOG.zh.md   # 双语变更日志（发版从这两份抽取）
├── AGENTS.md                 # 本文件
├── .codecov.yml  .gitignore
├── docs/                     # 设计规范文档（见下表）
├── scripts/                  # check-coverage.sh / extract_release_notes.py
├── examples/                 # 可运行示例（对应 C# Demo/）
└── .github/workflows/        # ci.yml / release.yml
```

**`crypto/` — 算法引擎层（仅算法，不放协议/容器/格式）**

每个子包自带 `{file}.go` + `{file}_test.go` + `example_test.go`，
并尽量提供 `{file}_tongsuocli_test.go`（CLI 对拍）。
子包：`aes/` `ecdh/` `ecdsa/` `ed25519/` `ed448/` `hmac/` `kdf/` `md5/` `rand/` `rsa/`
`sha1/` `sha256/` `sha512/` `sm2/` `sm3/` `sm4/` `x25519/` `x448/`。

**组合层（与 `crypto/` 平级的顶级包）**

```
key/                # 密钥统合抽象：跨算法统一接口 / PEM 解析 / 生命周期 / KDF
├── key.go          # Algorithm / Key 接口 / PEM / 错误 / Close
├── symmetric.go    # SymmetricKey / AESKey / SM4Key
├── generate.go     # GenerateSymmetricKey / ParseSymmetricKey
├── asymmetric.go   # Asymmetric(Private/Public)Key / PrivateKey / PublicKey
├── asym_generate.go# GenerateRSAKey / GenerateSM2Key / GenerateECKey
├── parse.go        # Load*PEM（PKCS#8 / PKCS#1 / SPKI / 加密）
├── handle.go       # Handle 元数据
├── store.go        # Store / MemoryStore（密钥轮转）
└── kdf.go          # Hash / HKDF / PBKDF2 / Argon2ID

x509/               # 证书核心
├── x509.go         # Certificate / Extension / PublicKey / PrivateKey / CreateCertificate
├── name.go         # Name / NameEntry / NewName
├── csr.go          # CertificateRequest
├── store.go        # Store / VerifyError / ChainVerify
├── crl.go          # CRL / RevokedEntry / RevocationCheck
└── helpers.go      # convertEntries / convertExtensions（内部辅助）

tls/                # TLS / NTLS 传输层
├── tls.go          # Dial / DialContext / Server / Conn
├── chain.go        # 证书链构建
├── suites.go       # 套件枚举与命名
└── errors.go       # 错误分类

asn1/               # DER viewer（纯 Go，cgo-free）
pkcs/pkcs7/         # PKCS#7（Build / Extract / MarshalPEM）
pkcs/pkcs12/        # PKCS#12（Pack / Parse / ChangePassword）
ocsp/               # OCSP 客户端（验证 / 自适应 CertID）
jwk/                # JWK ↔ PEM（RFC 7517）
xml/doc.go          # 格式族预留命名空间
xml/rsa/            # .NET RSAKeyValue XML 序列化
```

**`internal/` — 内部实现（外部不可 import）**

```
internal/native/               # 绑定层：cgo + shim
├── shim.h  shim.c             # C shim：宏 / 可变参 / 回调桥接，包装函数统一 X_ 前缀
├── build.go                   # #cgo LDFLAGS（动态库）
├── build_static.go            # #cgo LDFLAGS（-tags static，仅 linux）
├── init.go                    # 铜锁线程锁注册
├── binding_digest.go          # EVP_MD / EVP_Digest* 系列
├── binding_cipher.go          # EVP_CIPHER / EVP_CIPHER_CTX 系列
├── binding_pkey.go            # EVP_PKEY / EVP_PKEY_CTX 系列（SM2 / RSA / EC）
├── binding_hmac.go            # EVP_MAC / HMAC 系列
├── binding_kdf.go             # EVP_KDF（HKDF / PBKDF2 / Argon2ID）
├── binding_rand.go            # RAND_bytes 系列
├── binding_bio.go             # BIO 系列
├── binding_ssl.go             # SSL_CTX / SSL / TLS 会话
├── binding_x509.go            # X509 / X509_CRL / X509_STORE / PEM / DER 系列
├── binding_pkcs.go            # PKCS#7 / PKCS#12 系列
├── binding_ocsp.go            # OCSP_REQ / OCSP_RES 系列
├── binding_error.go           # ERR_get_error / 错误码
└── binding_version.go         # OpenSSL_version / Tongsuo_version_num

internal/core/                 # 核心层：句柄包装 + 生命周期 + 错误
├── handle.go                  # 句柄基类：owned 所有权 + Close() + SetFinalizer
├── error.go                   # OpError（携带 ERR_get_error 错误码）
├── doc.go  version.go         # 包级 GoDoc 概览 / 版本查询
├── digest.go  cipher.go       # Digest / DigestCtx / Cipher / CipherCtx（含 Clone）
├── hmac.go  kdf.go            # HMAC 包装 / KDF（HKDF / PBKDF2 / Argon2ID）
├── pkey.go  pkey_id.go        # PKey 包装 / 默认 ID
├── pkcs.go  ocsp.go           # PKCS#7 与 PKCS#12 / OCSP 自适应 CertID 匹配
├── x509.go  ssl.go            # X509 证书 / CRL / Store / SSL 会话（Close 幂等）
├── rand.go  zero.go           # RandomBytes 包装 / 清零辅助
└── waitfd_linux.go  waitfd_darwin.go   # epoll / kqueue 等待 fd 可读

internal/digest/               # 纯 Go hash.Hash 共享实现（sm3/md5/sha*）
internal/testutil/             # 测试共享：openssl CLI 包装 / 向量加载 / SkipIfNoOpenSSL
```

**`docs/`**

```
docs/architecture.md          # 架构、目录、构建依赖、生命周期、并发、错误
docs/development-guide.md     # GoDoc / 命名 / cgo / 核心层 / 错误 / 内存 / 风格
docs/testing-guide.md         # 测试组织、各算法必测用例、向量来源
docs/bilingual-doc-guide.md   # 双语 GoDoc 段式规则与检查清单
docs/issues/2026-09-10/       # 历史审计报告（BUG / 规范类）
```

**其他**

```
examples/README.md  examples/{sm2,ed25519,x25519,ecdh,self-signed-cert,ntls-loopback}/
scripts/check-coverage.sh  scripts/extract_release_notes.py
.github/workflows/ci.yml  .github/workflows/release.yml
```

### 3.3 分层红线

- 依赖方向**单向向下**：API 层 → 核心层 → 绑定层，**禁止跨层调用与反向依赖**
  - ❌ 反例：在 `crypto/sm4` 或 `x509` 中 `import "github.com/blue-cloud-net/tongsuo-go/internal/native"`
  - ❌ 反例：让 `internal/core` 反过来 import `crypto/*` 或 `key/`
- `import "C"` **只允许**出现在 `internal/native`
  - ❌ 反例：为了省事在 `crypto/aes` 里直接写 cgo 调用
- `crypto/` 只装算法引擎；ASN.1 / PKCS / OCSP / TLS / 格式转换等「组合层」保持顶级包
  - ❌ 反例：把 `pkcs7` 塞进 `crypto/pkcs7`
- 原生句柄**不进入公开 API**；公开结构体不暴露 `unsafe.Pointer` / `*C.xxx`
  - ❌ 反例：让 `sm4.Cipher` 结构体带一个导出字段 `Ctx *C.EVP_CIPHER_CTX`
- `unsafe` 仅限绑定层与核心层，作用域尽量小；**不得**在 Go 与 C 之间直接传 Go 指针
  - ❌ 反例：把 `[]byte` 数据指针交给 C 长期持有（BIO 场景尤其注意 Go pointer pinning）
- 释放铜锁分配的内存必须用对应 `*_free` / `OPENSSL_free`
  - ❌ 反例：`C.free(unsafe.Pointer(p))`
- 平台差异用 build tags + `#cgo` 指令隔离在 `internal/native`，不扩散到 API 层
  - ❌ 反例：在 `crypto/sm3` 里写 `//go:build darwin` 分支

---

## 4. 编码规范要点

细则见 `docs/development-guide.md`，双语注释细则见 `docs/bilingual-doc-guide.md`。

### 4.1 双语 GoDoc（本仓库强制）

- **所有导出符号**（包、类型、函数、方法、常量、变量、`Example*`）必须有注释，
  且**中文段在前、英文段在后**
- 两种体例：
  - **段式**（公共包、`internal/core`、`internal/digest`、`internal/testutil`、包级 doc、`Example*`）：
    中文段 + **一个空 `//` 行** + 英文段；每段以符号名起头，段数中英对称
  - **单行式**（`internal/native/binding_*.go` 中带 `//export` 的函数）：
    中文一行 + 英文一行，**中间不空行**，`//export` 行紧贴函数体
- **不重写已有中文**：新增/修改双语注释时只在中文段之后追加英文段，中文段字符级不动
- **术语保留不翻译**：SM2/SM3/SM4/SM9/PEM/DER/PKCS#7/PKCS#8/PKCS#12/SPKI/CRL/CSR/
  OCSP/NTLS/JWS/JWE/JWK/RFC 7517/openssl/GB/T 329xx 等
- **`// Output:` 行字符级不动**，必须紧贴函数体最后一行（`go test` 工具约束）
- 包级注释：首行 `// Package xxx 中文一句话`，末尾追加
  `// Package xxx does X in English.`
- 新增/修改后自查：段数是否对称、错误包装尾注、安全告警（nonce 唯一 / ECB 弱语义 /
  SHA-1 弃用 / 线程安全）、错误码清单、所有权与 Close 语义是否中英都有

- ❌ 反例：只写中文段，或把中英混在同一行（`// Sum 计算 SM3 digest 摘要。`）
- ❌ 反例：顺手「润色」中文段措辞导致英文段与中文段语义漂移

### 4.2 命名

| 元素 | 约定 | 示例 |
|------|------|------|
| 包名 | 小写单词，无下划线 | `crypto/sm3`、`pkcs/pkcs7`、`internal/core` |
| API 层导出符号 | 遵循 Go 导出约定，语义对齐 C# 参考项目 | `sm3.Sum`、`sm4.NewCipher`、`sm2.Encrypt` |
| 绑定层函数 | 与铜锁 C 函数名**完全一致** | `EVP_DigestInit_ex` |
| shim 包装函数 | `X_` 前缀 | `X_EVP_Digest` |
| 核心层类型 | 去 `EVP_` 前缀，上下文类加 `Ctx` 后缀 | `DigestCtx`、`CipherCtx`、`PKey` |
| 错误变量 | `Err` 前缀 + 语义 | `ErrInvalidKeyLength`、`ErrTagMismatch` |
| 句柄基类 | `handle`（小写，包内） | `internal/core/handle.go` |
| 内部辅助 | 小写不导出 | `zeroMem`、`checkLen` |

### 4.3 错误处理

- 所有可失败函数**返回 `error`**，不使用 panic 传播
- 原生层失败 → 核心层用 `ERR_get_error()` 捕获并包装为 `*core.OpError`
- 上层用 `fmt.Errorf("...: %w", err)` 追加上下文，错误串带操作域（如 `sm4: encrypt: ...`）
- 参数错误 → 哨兵错误（`ErrXxx`）或带上下文的普通 error
- **库内禁止 panic**（仅编程错误如 nil 解引用除外）；GoDoc 中声明可能返回的错误
- ❌ 反例：`_ = err` 吞错；❌ 反例：把 `error` 转成 `panic` 让调用方 recover
- ❌ 反例：为了「更好用」把错误信息翻译成中文（库内错误串保持英文，便于检索与对拍）

### 4.4 生命周期与内存

- 所有句柄经核心层 `handle` 包装：`owned` 所有权字段 + 显式 `Close()` + `runtime.SetFinalizer` 兜底
- `Close()` **必须幂等**；释放后句柄置空，后续使用返回明确错误
- **不得依赖 finalizer 作为唯一释放途径**（Go 不保证执行）；资源敏感场景（TLS 连接等）必须显式 `Close()`
- 防双重释放、防悬垂指针：释放后不得再调用绑定层函数
- **敏感内存清零责任在调用方**：Go 编译器允许消除看似无副作用的清零循环，
  故本库不在持有方主动清零密钥/明文切片；改动的 API 入口（`NewCipher` / `NewGCM` /
  `LoadPrivateKeyPEM` 等）应在 GoDoc 注明「调用方负责清零源切片」
- 导出面最小化：能 unexported 就 unexported

### 4.5 代码风格

- 统一 `gofmt`（推荐 `gofumpt`）；提交前必须通过 `go vet ./...`
- 常量用命名常量（`iota` 或显式值），不写魔法数字
- 每个包提供包文档（`doc.go` 或包注释）
- 表驱动测试优先；合理使用 `t.Parallel()`
- **CI 的 lint 阶段只跑 `go vet`**：历史上 `golangci-lint` 与本项目的 cgo 函数名
  （`EVP_xxx`）和 `defer x.Close()` 惯例大量冲突，已退场。
  ❌ 反例：提交里顺手新增 `.golangci.yml` 或把 golangci-lint 加回 CI

---

## 5. 测试规范要点

细则与各算法必测用例见 `docs/testing-guide.md`。

### 5.1 组织

- 测试与源码**同包同目录**，命名 `{file}_test.go`
- 每个算法包提供两类测试：
  1. **单元测试**：标准向量、往返、边界、错误路径、交叉验证 → 默认 `go test` 跑
  2. **CLI 对拍测试**：调铜锁 `openssl` 命令行逐字节比对 → 文件头 `//go:build tongsuocli`
     隔离，默认**不**运行
- 共享工具放 `internal/testutil`（`RunOpenSSL(args, stdin)`，**不含断言逻辑**）
- 提供 `Example*`（会被 `go doc` 展示）与关键路径 `Benchmark*`；加密往返提供 `Fuzz*`

### 5.2 覆盖要求（摘要）

- **哈希类**：输出位宽、空输入、标准向量逐条、幂等、唯一性、一次性 vs 流式、Reset、
  nil/空输入、与 Go 标准库同算法对拍
- **对称加密**：每种模式（ECB/CBC/CTR/OFB/CFB/GCM）独立「加密 + 解密 + 往返」；
  标准向量、PKCS7 填充、错误密钥、空数据、非法 key/IV 长度、多块数据；
  AEAD 另加 tag 校验、AAD 一致/不一致、篡改检测、nonce 长度
- **非对称**：密钥生成随机性、PEM/DER 往返、签名验签（含篡改与自定义 userId）、
  加解密（含不同密钥失败、密文随机性）、标准向量、openssl 双向交叉验证
- **TLS / NTLS**：TLS 回环、NTLS 双证书回环、`Version()`/`CipherName()` 断言、
  与 `openssl s_client` / `s_server` 双向互操作

### 5.3 标准向量来源

| 算法 | 标准 |
|------|------|
| SM3 | GB/T 32905-2016 附录 A |
| SM4 | GB/T 32907-2016 附录 A |
| SM2 | GB/T 32918 系列 |
| AES | NIST FIPS 197 附录 B/C |
| Ed25519 / Ed448 | RFC 8032 §7.1 / §7.2 |
| X25519 / X448 | RFC 7748 §5.2 / §6.1 |
| ECDH（P-256/384/521） | NIST SP 800-56A（对拍 Go `crypto/ecdh`） |
| secp256k1 | SEC 2（对拍铜锁 `openssl` CLI） |

### 5.4 测试红线

- **不得为通过而放宽断言**——断言强度就是本项目的安全边界
  - ❌ 反例：`t.Errorf` 改 `t.Logf`；把逐字节比对改成「长度相等即通过」
- **不得删改标准向量或期望值**（含为了适配实现而改正期望密文）
  - ❌ 反例：实现输出与 GB/T 附录不符时，改测试里的期望值
- **不得无理由 `t.Skip`**；CLI 对拍缺铜锁时用 `internal/testutil` 的
  `SkipIfNoOpenSSL` / `OpenSSLAvailable` 统一跳过并说明原因
  - ❌ 反例：给失败的用例挂 `t.Skip("flaky")` 后提交
- **覆盖率只是参考**：`scripts/check-coverage.sh` 默认阈值 60%（路线图目标 80%），
  **CI 不做覆盖率门禁**
  - ❌ 反例：为了凑覆盖率写没有断言的空测试
- 改动传输层/密钥生命周期时，建议加跑 `go test -race ./...`

---

## 6. 提交与发版规范

> 本节规则仅在本文件定义（`docs/` 未收录），实施时以本文件为准。

### 6.1 commit message

采用 **Conventional Commits**，**主题用中文**，不加句号：

```
<type>(<scope>): <中文主题>
```

- **type**（本仓库实际使用）：`feat` / `fix` / `docs` / `test` / `chore` / `ci` /
  `refactor` / `perf` / `release`
- **scope**：用「层-包」或模块名，例如 `crypto-rsa`、`core-pkey`、`native-binding`、
  `crypto-x509`、`x509`、`tls`、`key`、`architecture`、`changelog`、`workflows`、`scripts`
- 真实历史示例（可对齐风格）：
  - `feat(crypto-rsa): 新增 RSA 算法 API（生成/PEM/签名验签/加解密/参数提取）`
  - `refactor(crypto-x509): x509 接口泛化支持 SM2/RSA/ECDSA 任意密钥`
  - `docs(architecture): 同步 §3.1 / §3.2 / §5 目录结构与版本号`
  - `perf(core-pkey): LockOSThread 仅 SM2 加锁（性能修复）`
  - `ci(workflows): 触发收敛 main + workflow_call 复用 + 矩阵扩到 amd64/arm64`
- **一个逻辑变更一个 commit**：不要「顺手重构」，不要把无关格式化混进功能提交
- ❌ 反例：`update code`、`fix bug`、`临时提交`、`WIP` 这类无信息量的 message
- ❌ 反例：一次提交同时改 `crypto/sm4` 算法与 README 排版

### 6.2 分支

- `main` 为发布分支；日常开发在 `dev`（或特性分支）上进行
- **CI 只在 push / PR 到 `main` 时触发**，`dev` 不触发；改动需要合并到 `main` 才会跑 CI
- 发版：推送 `v*` 标签（如 `v0.1.2`）触发 `release.yml`

### 6.3 CHANGELOG（双语成对）

- `CHANGELOG.md`（英文）与 `CHANGELOG.zh.md`（中文）**必须同步更新同一版本段**
- 格式遵循 [Keep a Changelog 1.1.0](https://keepachangelog.com/)，
  版本号遵循 [SemVer 2.0.0](https://semver.org/)
- 分类标题：`新增功能` / `行为变化与重构` / `Bug 修复` / `文档` / `BREAKING / 已知限制`
- 待发布版本用 `## [0.2.0] - TBD`
- 术语保留英文（SM2 / SM4 / PEM / DER / PKCS#8 / NTLS / RFC xxxx …）
- ❌ 反例：只改 `CHANGELOG.zh.md` 而不改 `CHANGELOG.md`（发版会被脚本拦下）

### 6.4 发版

- `release.yml` 复用 `ci.yml`（`workflow_call`），保证发布测试与 CI 完全同源
- `scripts/extract_release_notes.py` 从两份 CHANGELOG 抽取当前 tag 版本段，
  **任一缺失即 `exit 1`，发版中断**；拼接格式为「英文 + 3 空行 + 中文」
- 发布物**只有 CHANGELOG 文本**，不上传二进制

### 6.5 git 权限（agent 行为约定）

- ✅ **允许**：`git add` / `git commit`（message 须符合 §6.1）
- ❌ **禁止**：`git push`、`git push --force`、`git rebase`/`filter-branch` 等重写历史操作、
  删除远端分支、`git reset --hard` 丢弃他人提交
- ❌ 反例：为了「让仓库干净」而 `git checkout -- .` / `git clean -fd` 抹掉未提交改动
- 需要推送或改历史时，交给用户手动执行，并说明理由

---

## 7. 文档同步要求

**代码改动必须连带同步文档，成对文件必须一起改：**

| 改动内容 | 必须同步 |
|----------|----------|
| 任何功能/行为/API 变化 | `CHANGELOG.md` + `CHANGELOG.zh.md`（同一版本段） |
| 新增算法包、新增公开 API | `README.md` + `README.zh.md` 的功能列表与示例（如适用） |
| 目录结构、分层、依赖、构建方式变化 | `docs/architecture.md` |
| 注释/命名/cgo/错误/内存约定变化 | `docs/development-guide.md`（+ `docs/bilingual-doc-guide.md`） |
| 测试组织或新增必测用例 | `docs/testing-guide.md` |
| 新增示例 | `examples/README.md` + 示例目录内代码 |

- **`README.md` 与 `README.zh.md` 结构必须严格对称**（章节、段落数、代码块一一对应）
  - ❌ 反例：只在中文 README 里加一节「常见问题」
- 双语正文同样遵循「术语保留英文」约定
- 本文件（`AGENTS.md`）与上述文档**同源**：若规范变更，先改 `docs/` 细则，
  再更新本文件的摘要与指针，避免两处规则打架
- 不要在没有明确要求时改动 `docs/issues/` 下的历史审计报告、CHANGELOG 的既有版本段
  - ❌ 反例：顺手「订正」`docs/issues/2026-09-10/` 里旧报告的结论

---

## 8. 已知陷阱清单

| # | 陷阱 | 处置 |
|---|------|------|
| 1 | **NTLS 命令行对拍**：`openssl s_server` / `s_client` 只传 `-ntls` 会在状态机报 `state_machine:internal error` | 必须 **`-ntls` 与 `-enable_ntls` 同传** |
| 2 | **macOS 静态链接未接线**：`internal/native/build_static.go` 只提供 linux LDFLAGS | 静态构建仅在 Linux 验证，不要在 macOS 上「修」它 |
| 3 | **Windows 后置**：平台支持为 Linux 优先、macOS 兼容、Windows 后置 | 不要为 Windows 新增未验证的构建路径 |
| 4 | **CI 不跑 golangci-lint**（cgo 命名与 `defer x.Close()` 惯例冲突已退场） | 本地门禁用 `go vet ./...`；不要擅自加回 lint 工具 |
| 5 | `-Wno-deprecated-declarations` 只是屏蔽铜锁对 OpenSSL 废弃声明的告警 | 不要删除，也不要据此认为 API 已废弃 |
| 6 | `crypto/rand` 与标准库 `crypto/rand` **同名** | 使用时注意 import 别名，避免误用；本包基于铜锁 `RAND_bytes` |
| 7 | `runtime.LockOSThread()` 仅对 SM2 路径必要 | 不要无差别给所有算法加锁（会显著掉性能，见 `perf(core-pkey)` 修复） |
| 8 | OCSP 测试依赖外部 responder | 覆盖率脚本默认豁免 `ocsp`；对拍用例缺失环境时统一 `SkipIfNoOpenSSL` |
| 9 | `.gitignore` 当前包含 `docs/issues` | 在该目录**新增**文件需 `git add -f`，或先调整 `.gitignore` |
| 10 | CI 固定铜锁 `TONGSUO_REF: 8.4.0`，缓存键为 `tongsuo-v3-<os>-<arch>-<ref>-<workflows hash>` | 升级铜锁版本时必须同步 bump `TONGSUO_REF` 与缓存键前缀 |
| 11 | `go test ./...` 默认**不**编译 `*_tongsuocli_test.go` | 需要 CLI 对拍时显式加 `-tags tongsuocli`，否则会误以为「已覆盖」 |
| 12 | `internal/` 受 Go 机制保护 | 外部包无法 import；新增内部包不要试图对外暴露 |
| 13 | 铜锁需带 `enable-ntls` 编译才有 NTLS 能力 | CI 配置为 `--prefix=... --libdir=... enable-ntls enable-trace no-shared`，本地安装需一致 |

---

## 9. Agent 工作流约定

### 9.1 改动前：按此顺序建立上下文

1. 读本文件 `AGENTS.md`（定位 + 红线）
2. 读相关细则：架构改动 → `docs/architecture.md`；API/注释改动 →
   `docs/development-guide.md` + `docs/bilingual-doc-guide.md`；测试改动 → `docs/testing-guide.md`
3. 读目标包源码 **+ 相邻同类包**作为模板（如做 `crypto/x448` 时先看 `crypto/x25519`；
   做 `pkcs/pkcs12` 时先看 `pkcs/pkcs7`）
4. 若涉及既有问题清单，先看 `docs/issues/2026-09-10/` 是否已记录同类问题

### 9.2 改动后：必须执行并如实汇报

```bash
gofmt -l .                # 应为空；有输出则先格式化
go vet ./...              # 必须 0 输出
go build ./...            # 必须成功
go test -count=1 ./...    # 必须 ok（无铜锁环境则如实说明未能运行）
```

- 涉及 cgo/绑定时额外跑：`go build -tags static ./...`（Linux）
- 涉及并发/生命周期时额外跑：`go test -race ./...`
- 涉及 CLI 对拍时额外跑：`go test -tags tongsuocli ./...`
- 涉及双语注释时自查 §4.1 清单（段数对称、`// Output:` 未动）
- **禁止**在未运行上述命令的情况下宣称「已完成 / 已修复」

### 9.3 新增算法包对齐清单

以 `crypto/x25519` 或 `crypto/sm3` 为模板，逐项落实：

- [ ] `crypto/<alg>/<alg>.go`：包级双语 doc + 导出符号双语段式注释
- [ ] `crypto/<alg>/<alg>_test.go`：标准向量 + 往返 + 边界 + 错误路径（§5.2）
- [ ] `crypto/<alg>/example_test.go`：`Example*` + `// Output:`（紧贴函数体）
- [ ] `crypto/<alg>/<alg>_tongsuocli_test.go`：`//go:build tongsuocli` CLI 对拍
- [ ] 如需新 C 接口：`internal/native/binding_*.go`（单行式注释 + `X_` shim）
- [ ] 如需新句柄：`internal/core/` 包装（`handle` 基类 + 幂等 `Close()`）
- [ ] `key/` 是否需要对应的 `Alg*` 常量与 `Generate*Key`（跨算法统一抽象）
- [ ] `docs/architecture.md` §3.3 / §5 目录与包列表
- [ ] `docs/testing-guide.md` 用例表
- [ ] `README.md` + `README.zh.md` 功能列表（成对）
- [ ] `CHANGELOG.md` + `CHANGELOG.zh.md`（成对，`## [x.y.z] - TBD` 段）

---

## 10. 安全与禁止事项（硬红线）

**密码学正确性与用户密钥安全高于一切**，以下条目无例外：

1. **不得打印、记录或写入文件**任何私钥、对称密钥、明文、共享密钥、口令
   - ❌ 反例：`fmt.Printf("%x\n", key)`；把私钥写进错误信息
   - ❌ 反例：在测试里硬编码真实生产密钥
2. **不得削弱任何校验**：验签、证书链、吊销、AEAD tag、AAD、填充校验一律不得跳过或放宽
   - ❌ 反例：`InsecureSkipVerify` 式的默认值；「先返回成功再补校验」
3. **不得引入第三方依赖**：`go.mod` 只允许标准库 + cgo，不加 `require`
   - ❌ 反例：为了图方便引入 `golang.org/x/crypto`
4. **不得改动** `go.mod` 中的 module path、`LICENSE`、`README` 的项目署名与协议声明
5. **不得把铜锁本体或任何原生二进制提交进仓库**（见 §1.2）
   - ❌ 反例：把 `.so` / `.a` / `openssl` 可执行文件放进 `internal/native/`
6. **不得提交测试数据大文件**；测试向量以代码内常量或运行时生成为准
7. **不得为通过测试而放宽断言、删改期望值、跳过用例**（见 §5.4）
8. **不得做破坏性文件操作**：不删无关文件、不清理他人未提交改动、不重写 git 历史（见 §6.5）
9. **不得扩大导出面**：新增导出符号必须有充分理由，并同步双语注释与文档
10. **不得声称做了没做的事**：未运行的构建/测试不要写成「已验证通过」；
    无法验证的环境缺失要明确说明

---

## 附：常用路径速查

| 用途 | 路径 |
|------|------|
| 双语注释规则 | `docs/bilingual-doc-guide.md` |
| 三层边界与目录 | `docs/architecture.md` §2 / §3 / §5 |
| 生命周期与所有权 | `docs/architecture.md` §7 / §8 |
| 各算法必测用例 | `docs/testing-guide.md` §3～§5.1 |
| CLI 对拍工具 | `internal/testutil/openssl.go` |
| 覆盖率脚本 | `scripts/check-coverage.sh` |
| 发版说明抽取 | `scripts/extract_release_notes.py` |
| CI / 发版流程 | `.github/workflows/ci.yml` / `.github/workflows/release.yml` |
| 示例程序 | `examples/`（见 `examples/README.md`） |
