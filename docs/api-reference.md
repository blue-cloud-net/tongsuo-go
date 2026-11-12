# 公开 API 清单

> **用途**：列出本仓库**包结构重构后**的公开 API 层全部导出 API（签名 + 一句话说明），作为实现与使用时的速查参考。
>
> **口径**：
> 1. 只列**公开 API 层**（外部可 `import` 的包）；`internal/core`、`internal/native`、`internal/digest`、`internal/keyaccess`、`internal/testutil` 见 `docs/api-reference-internal.md`；
> 2. 每项格式为「完整签名 — 中文一句话」，说明取自源码中的中文 GoDoc 段；
> 3. **不含** `Example*` 函数与测试辅助函数；
> 4. 类型给出导出字段；未导出字段以「（内部字段）」表示其存在；
> 5. 本文描述的是**重构后的目标形态**：`crypto/` 整目录与 `key/` 已被 `digest` / `mac` / `sym` / `asym` / `ecdh` / `kdf` / `rand` / `keystore` 取代；`csr` / `crl` / `ocsp` **未拆**，全部留在 `x509`。
>
> **范围**：**16 个包**。实现基线：`0.8.0`（2026-11-05 定版，待标签发布）；未来目标均以 🧭 标注。
> **版本归属**：本文件不负责版本分配，哪个 🧭 符号落在哪个版本见 [roadmap.md](roadmap.md) §2。
>
> **状态标记**：
> - ✅ **已有** — 已实现（`0.8.0` 及之前；发布状态以版本标签为准）；
> - 🚧 **变更中** — 目标版本另标，尚不可用；
> - 🧭 **规划中** — 仅表达**目标 API 形态**，尚不可用；**目标版本以 [roadmap.md](roadmap.md) §2 为准**，
>   下表的版本列仅为速查，若与该文冲突以 roadmap 为准。
>
> 符号行前缀：`🆕` 新增（`0.3.0`、`0.5.0`、`0.6.0` 、`0.7.0` 与 `0.8.0` 沿用；所在小节标题已注明版本） / `✨` `0.4.0` 新增 /
> `♻️` 迁移自其他包（附原名） / `🧭` 规划中。
> `0.4.0` 与 `0.5.0` 的**行为变更**（非新增符号）写在对应行内，如 `Certificate.Sign` /
> `CertificateRequest.Sign` 收紧为单向终态。

---

## 0. 包索引

| # | 包 | 状态 | 用途 | 旧包来源 |
|---|---|---|---|---|
| 1 | `meta` | ✅ | 铜锁运行环境与元信息（版本 / 构建信息 / 错误码 / 算法枚举） | —（新增） |
| 2 | `digest` | ✅ | 摘要算法（by-name 分发 + 类型化入口） | `crypto/{sm3,md5,sha1,sha256,sha512}` |
| 3 | `mac` | ✅ | 消息认证码（HMAC / CMAC / GMAC / KMAC / SipHash / Poly1305 / EIA3） | `crypto/hmac` |
| 4 | `kdf` | ✅ | 密钥派生（HKDF / PBKDF2 / Argon2ID / scrypt / …） | `crypto/kdf` + `key` 的 KDF |
| 5 | `rand` | ✅ | 安全随机数（铜锁 `RAND_bytes`） | `crypto/rand` |
| 6 | `sym` | ✅ | 对称加密与对称密钥对象（AES / SM4，六种模式 + AEAD） | `crypto/{aes,sm4}` + `key` 对称部分 |
| 7 | `asym` | ✅ | 非对称密钥、签名验签、加解密、KEM | `crypto/{sm2,rsa,ecdsa,ed25519,ed448}` + `crypto/{x25519,x448}` 生成 + `key` 非对称部分 |
| 8 | `ecdh` | ✅ | 密钥协商（NIST / secp256k1 / OKP / SM2DH），可加载 `asym` 密钥对象 | `crypto/ecdh` + `crypto/{x25519,x448}` 协商 |
| 9 | `keystore` | ✅ | 密钥元数据、存储与轮转 | `key` 的 `Handle`/`Store`/`Rotate` |
| 10 | `x509` | ✅ | 证书 + CSR + CRL + OCSP + 链验证（**单包**） | `x509` + `ocsp`（未拆） |
| 11 | `tls` | ✅ | TLS / NTLS 传输层 | `tls` |
| 12 | `asn1` | ✅ | 纯 Go DER viewer（cgo-free） | `asn1` |
| 13 | `jwk` | ✅ | JWK（RFC 7517）↔ PEM / JSON | `jwk` |
| 14 | `pkcs/pkcs7` | ✅ | PKCS#7 证书袋构建与提取 | `pkcs/pkcs7` |
| 15 | `pkcs/pkcs12` | ✅ | PKCS#12 打包、解析、改密 | `pkcs/pkcs12` |
| 16 | `xml/rsa` | ✅ | .NET `RSAKeyValue` XML 互转（签名改收 `asym.*`） | `xml/rsa` |

---

## 0.1 旧包 → 新包迁移对照

| 旧包 | 新归属 |
|---|---|
| `crypto/sm3` `crypto/md5` `crypto/sha1` `crypto/sha256` `crypto/sha512` | `digest`（5 → 1） |
| `crypto/hmac` | `mac` |
| `crypto/kdf` | `kdf` |
| `crypto/rand` | `rand` |
| `crypto/aes` `crypto/sm4` | `sym`（2 → 1）+ `key` 的对称密钥对象 |
| `crypto/sm2` `crypto/rsa` `crypto/ecdsa` `crypto/ed25519` `crypto/ed448` | `asym`（5 → 1） |
| `crypto/x25519` `crypto/x448` | `asym`（密钥生成）+ `ecdh`（密钥协商）；包本身删除 |
| `crypto/ecdh` | `ecdh` |
| `key` | `asym`（非对称密钥抽象）+ `sym`（对称密钥抽象）+ `keystore`（Handle / Store / 轮转）+ `kdf`（KDF）；包本身删除 |
| `x509` `ocsp` | `x509`（Certificate / CSR / CRL / OCSP / Store / 链验证）；**未拆分** |
| `tls` `asn1` `jwk` `pkcs/pkcs7` `pkcs/pkcs12` `xml/rsa` | 保留原包路径 |

> 与本次重构同步收敛的破坏性变更（内部类型泄露，共 12 项）见各包节末尾的「破坏性变更」小节；跨包取原生句柄的机制说明见 `internal/keyaccess`。

---

## 1. `meta` — 铜锁运行环境与元信息

✅ **已有**｜整包新增（`0.3.0`）

承载 CLI 的 `version` / `info` / `errstr` / `list` 所对应的**元信息查询**能力：运行库版本、构建与运行环境快照、原生错误码解析、可用算法枚举。本包**只做查询**，不含任何密码学运算，也不持有原生句柄，因此**无需 `Close`**。

> 与 `docs/cli-comparison-todo.md` 的两处差异（该文 §1 列 4 条版本 API）：
> 1. 该文的 `meta.LibraryVersion()` 由本包的 `Version()`（完整 banner）+ `VersionString()`（纯版本号）覆盖；
> 2. 该文的 `meta.BuildInfo() BuildInfo` 与类型名 `BuildInfo` **同名冲突**（Go 不允许同包内类型与函数同名），故读取函数改名 `ReadBuildInfo()`，对齐标准库 `debug.ReadBuildInfo` 惯例。

**函数（版本）**

- 🆕 `func Version() string` — 运行库完整版本 banner（等价 `tongsuo version`），如 `"Tongsuo 8.5.0-pre2 22 Sep 2026"`
- 🆕 `func VersionString() string` — 纯版本号（无产品名前缀与构建日期），如 `"3.5.4"`
- 🆕 `func VersionNum() uint64` — OpenSSL 兼容版本号（`OpenSSL_version_num`）
- 🆕 `func TongsuoVersionNum() uint64` — 铜锁自有版本号（`Tongsuo_version_num`）；原生 OpenSSL 上通常为 0

**类型与函数（构建信息）**

- 🆕 `type BuildInfo struct { Version string; VersionString string; VersionNum uint64; TongsuoVersionNum uint64; Compiler string; BuiltOn string; Platform string; OpenSSLDir string; EnginesDir string; ModulesDir string; CPUInfo string }` — 构建与运行环境快照；取不到的字段为空串，`ReadBuildInfo` 不会失败
- 🆕 `func ReadBuildInfo() *BuildInfo` — 一次性读取全部构建信息（对应 `tongsuo version -a`）
- 🆕 `func (i *BuildInfo) String() string` — 文本视图（对应 `tongsuo version -a` 的排版）

**函数（错误码）**

- 🆕 `func ErrorString(code uint64) string` — 错误码 → 文本（`ERR_error_string`）；未知码返回带该码的占位文本，不 panic
- 🆕 `func ErrorCode(err error) (uint64, bool)` — 从任意 `error` 提取铜锁错误码（识别 `core.OpError` 及 `fmt.Errorf("%w")` 包装链）
- 🆕 `func ParseErrorCode(s string) (uint64, error)` — 解析十六进制 / 十进制错误码字符串（对应 `tongsuo errstr <code>`）

**函数（算法枚举，`0.5.0` 起）**

> 前置绑定均已就位：`EVP_{MD,CIPHER,MAC,KDF,SIGNATURE,KEYEXCH,KEM}_do_all_provided`
> 加 fetch 过滤、`OSSL_PROVIDER_*`、`OPENSSL_info(OPENSSL_INFO_SEED_SOURCE)`、
> `SSL_get1_groups` / `SSL_group_to_name`。所有列表**去重并按字典序**返回，
> 内容取决于当前已加载的 provider。

- 🆕 `func Digests() []string` — 可用摘要算法名（等价 `list -digest-algorithms`）
- 🆕 `func Ciphers() []string` — 可用对称算法名（等价 `list -cipher-algorithms`）
- 🆕 `func MACs() []string` — 可用 MAC 算法名（等价 `list -mac-algorithms`）
- 🆕 `func KDFs() []string` — 可用 KDF 算法名（等价 `list -kdf-algorithms`）
- 🆕 `func Signatures() []string` — 可用签名算法名（等价 `list -signature-algorithms`）
- 🆕 `func KeyExchanges() []string` — 可用密钥交换算法名（等价
  `list -key-exchange-algorithms`）
- 🆕 `func KEMs() []string` — 可用 KEM 算法名（等价 `list -kem-algorithms`）
- 🆕 `func TLSGroups() []string` — 可用 TLS 组（等价 `list -tls-groups`）
- 🆕 `func Providers() []ProviderInfo` — 活跃 provider 名称 / 版本 / 状态（等价
  `list -providers`）
- 🆕 `type ProviderInfo struct { Name string; Version string; Status string }` —
  provider 描述
- 🆕 `func SeedingSource() string` — 随机种子来源（`version -a` 的
  `Seeding source` 行）；构建不支持时返回空串

**类型与函数（形态词汇，`0.5.0` 起）**

> 这四个维度是「CLI 式调用」的词汇表：入口取 `Source`、出口取 `Sink`，
> 编码与格式由 `Encoding` / `Format` 描述，口令由 `Passphrase` 抽象。
> 各原语包（`digest` / `mac` / `sym` / `kdf` / `asym` / `x509`）的形态入口
> 以本节的类型为参数。

- 🆕 `type Source struct{…}` — 输入源：bytes / `io.Reader` / 文件 / stdin；
  `nil` 接收者等价于标准输入
  - 🆕 `func NewBytesSource(data []byte) *Source` — 构造时复制 data
  - 🆕 `func NewReaderSource(r io.Reader) *Source` — **一次性**，二次 `Open` 返回
    `ErrSourceConsumed`
  - 🆕 `func NewFileSource(path string) (*Source, error)` — 每次 `Open` 重新打开；
    `path == "-"` 表示 stdin
  - 🆕 `func StdinSource() *Source` — 一次性标准输入
  - 🆕 `func (s *Source) Open() (io.ReadCloser, error)` / 🆕
    `func (s *Source) ReadAll() ([]byte, error)` / 🆕 `func (s *Source) Path() string`
- 🆕 `var ErrSourceConsumed` — 一次性源被重复打开
- 🆕 `type Sink struct{…}` — 输出端：bytes / `io.Writer` / 文件 / stdout；
  `nil` 接收者等价于标准输出
  - 🆕 `func NewBytesSink() *Sink` / 🆕 `func NewWriterSink(w io.Writer) *Sink` /
    🆕 `func NewFileSink(path string) (*Sink, error)` / 🆕 `func StdoutSink() *Sink`
  - 🆕 `func (s *Sink) SetEncoding(enc Encoding) error` — 只能在首次写入前设置
  - 🆕 `func (s *Sink) Write(p []byte) (int, error)` — 实现 `io.Writer`
  - 🆕 `func (s *Sink) Bytes() []byte` / 🆕 `func (s *Sink) Close() error`（幂等）/
    🆕 `func (s *Sink) Encoding() Encoding` / 🆕 `func (s *Sink) Path() string`
- 🆕 `type Encoding int` 与常量 `EncodingRaw` / `EncodingHex` / `EncodingBase64` —
  输出编码（hex 忽略输入空白，base64 忽略 CRLF，流式写出与一次性等价）
- 🆕 `func ParseEncoding(s string) (Encoding, error)` / 🆕
  `func Encode(data []byte, enc Encoding) ([]byte, error)` / 🆕
  `func Decode(data []byte, enc Encoding) ([]byte, error)`
- 🆕 `func Hex(data []byte) string` / 🆕 `func Base64(data []byte) string` /
  🆕 `func Dump(data []byte) string` — `xxd` 风格十六进制转储
- 🆕 `type Format int` 与常量 `FormatPEM` / `FormatDER`；🆕
  `func ParseFormat(s string) (Format, error)` / 🆕
  `func (f Format) String() string`
- 🆕 `type Passphrase struct{…}` — 口令来源抽象：
  `pass:<明文>` / `env:<变量名>` / `file:<路径>` / `fd:<n>` / `stdin:`；
  构造时立即读取（file / fd / stdin 会剥掉行尾换行）
  - 🆕 `func NewPassphrase(spec string) (*Passphrase, error)` /
    🆕 `func (p *Passphrase) Bytes() []byte` / 🆕 `func (p *Passphrase) IsEmpty() bool`
  - 🆕 `func (p *Passphrase) String() string` — **脱敏**（`pass:***`）


---

## 2. `digest` — 摘要

✅ **已有**｜旧包：`crypto/sm3` `crypto/md5` `crypto/sha1` `crypto/sha256` `crypto/sha512`

把 5 个摘要包合并为一个包，并补上 `SHA-224` / `SHA-384`（底层 `EVP_sha224` / `EVP_sha384` **已绑定**，零新增 cgo）。保留 Go `hash.Hash` 惯例接口，同时提供「按算法名分发」的 CLI 式入口。

**常量｜尺寸**

- ♻️ `SM3Size = 32`、`SM3BlockSize = 64` — 原 `crypto/sm3.Size` / `sm3.BlockSize`
- ♻️ `MD5Size = 16`、`MD5BlockSize = 64` — 原 `crypto/md5.Size` / `md5.BlockSize`
- ♻️ `SHA1Size = 20`、`SHA1BlockSize = 64` — 原 `crypto/sha1.Size` / `sha1.BlockSize`
- 🆕 `SHA224Size = 28`、`SHA224BlockSize = 64`
- ♻️ `SHA256Size = 32`、`SHA256BlockSize = 64` — 原 `crypto/sha256.Size` / `sha256.BlockSize`
- 🆕 `SHA384Size = 48`、`SHA384BlockSize = 128`（SHA-512 家族）
- ♻️ `SHA512Size = 64`、`SHA512BlockSize = 128` — 原 `crypto/sha512.Size` / `sha512.BlockSize`

**函数｜按算法名分发（新增）**

- 🆕 `var ErrUnknownAlgorithm` — 哨兵错误：算法名不在 `Names()` 内
- 🆕 `func Names() []string` — 返回本版已支持的摘要算法名（顺序稳定）
- 🆕 `func Size(name string) (int, error)` — 摘要长度；未知算法名返回 `ErrUnknownAlgorithm`
- 🆕 `func BlockSize(name string) (int, error)` — 分组长度
- 🆕 `func New(name string) (hash.Hash, error)` — 按名返回流式哈希（实现 `hash.Hash`）
- 🆕 `func Sum(name string, data []byte) ([]byte, error)` — 按名一次性计算摘要
- 🆕 `func SumReader(name string, r io.Reader) ([]byte, error)` — 从 `io.Reader` 流式计算摘要

**函数｜类型化入口（迁移自旧包的 Go 惯例形式）**

- ♻️ `func NewSM3() hash.Hash` / ♻️ `func SumSM3(data []byte) [SM3Size]byte` — 原 `crypto/sm3.New` / `crypto/sm3.Sum`
- ♻️ `func NewMD5() hash.Hash` / ♻️ `func SumMD5(data []byte) [MD5Size]byte` — 原 `crypto/md5.New` / `crypto/md5.Sum`
- ♻️ `func NewSHA1() hash.Hash` / ♻️ `func SumSHA1(data []byte) [SHA1Size]byte` — 原 `crypto/sha1.New` / `crypto/sha1.Sum`
- 🆕 `func NewSHA224() hash.Hash` / 🆕 `func SumSHA224(data []byte) [SHA224Size]byte`
- ♻️ `func NewSHA256() hash.Hash` / ♻️ `func SumSHA256(data []byte) [SHA256Size]byte` — 原 `crypto/sha256.New` / `crypto/sha256.Sum`
- 🆕 `func NewSHA384() hash.Hash` / 🆕 `func SumSHA384(data []byte) [SHA384Size]byte`
- ♻️ `func NewSHA512() hash.Hash` / ♻️ `func SumSHA512(data []byte) [SHA512Size]byte` — 原 `crypto/sha512.New` / `crypto/sha512.Sum`

> 安全提示：MD5 与 SHA-1 已不适用于数字签名，仅用于兼容既有格式与完整性校验。

**函数｜形态入口（`0.5.0` 新增，配合 `meta.Source` / `meta.Sink`）**

- 🆕 `func SumSource(name string, src *meta.Source) ([]byte, error)` — 读 `Source`
  全流计算摘要（`src` 为 `nil` 等价 stdin）
- 🆕 `func SumFile(name, path string) ([]byte, error)` — 文件便捷入口（`"-"` 读 stdin）
- 🆕 `func SumTo(name string, src *meta.Source, sink *meta.Sink) error` — 结果按
  `sink` 的编码写出（`nil` 等价 stdout）
- 🆕 `func SumReaderTo(name string, r io.Reader, sink *meta.Sink) error` — 直接持
  有 `io.Reader` 时的等价入口

**函数｜扩展摘要（`0.6.0` 新增）**

注册表从 7 项扩到 20 项（顺序稳定）：`SM3`、`MD5`、`SHA1`、`SHA224`、`SHA256`、
`SHA384`、`SHA512`、`SHA256-192`、`SHA512-224`、`SHA512-256`、`SHA3-224/256/384/512`、
`SHAKE128/256`、`KECCAK-224/256/384/512`。

- 🆕 尺寸常量：`SHA256_192Size`、`SHA512_224Size`、`SHA512_256Size`、`SHA3_*Size` /
  `SHA3_*BlockSize`、`KECCAK*Size` / `KECCAK*BlockSize`、`SHAKE128Size` / `SHAKE256Size`
- 🆕 类型化入口：`SumSHA256_192` / `NewSHA256_192`、`SumSHA512_224` / `NewSHA512_224`、
  `SumSHA512_256` / `NewSHA512_256`、`SumSHA3_224/256/384/512` 与对应 `New*`、
  `SumKECCAK224/256/384/512` 与对应 `New*`
- 🆕 `func SumSHAKE128(data []byte, outLen int) ([]byte, error)` / 🆕 `func SumSHAKE256(data []byte, outLen int) ([]byte, error)`
  — XOF 必须显式给出输出长度；`Sum("SHAKE128", …)` / `New("SHAKE128")` 返回 `ErrXOFNeedsLength`
- 🆕 `func Available(name string) bool` — 运行时能力探测；典型差异：铜锁 8.4.0（OpenSSL 3.0.3 底座）
  不提供 `KECCAK-*` 与 `SHA256-192`（走 `EVP_MD_fetch`），此时对应入口返回 `ErrUnsupported`
- 🆕 `var ErrUnsupported` / 🆕 `var ErrXOFNeedsLength` — 哨兵错误

**破坏性变更**

- 删除 `crypto/{sm3,md5,sha1,sha256,sha512}` 5 个包：`sm3.Sum(data)` → `digest.SumSM3(data)`（定长）或 `digest.Sum("SM3", data)`（按名）
- 尺寸常量加算法前缀（`Size` → `SM3Size` 等），否则合并后重名

---

## 3. `mac` — 消息认证码

✅ **已有**｜旧包：`crypto/hmac`

把 HMAC 从独立的 `crypto/hmac` 提升为“按算法名分发”的 MAC 包，并预留 CMAC / GMAC / KMAC / SipHash / Poly1305 / EIA3 的位置。签名与验签**不属本包**（见 `asym`）。

**变量**

- 🆕 `var ErrUnknownAlgorithm` — 哨兵错误：算法名不在 `Names()` 内

**类型**

- 🆕 `type Options struct { Cipher string; IV []byte; AAD []byte; Custom []byte; OutputLen int; Digest string }` — 算法参数（覆盖 CLI 的 `-macopt cipher: / hexiv: / aad: / custom: / size: / digest:`）；置 nil 表示用默认值

**函数｜按算法名分发（新增）**

- 🆕 `func Names() []string` — 返回本版已支持的 MAC 算法名
- 🆕 `func New(name string, key []byte, opts *Options) (hash.Hash, error)` — 按名返回流式 MAC（实现 `hash.Hash`）
- 🆕 `func Sum(name string, key, data []byte, opts *Options) ([]byte, error)` — 按名一次性计算
- 🆕 `func SumReader(name string, key []byte, r io.Reader, opts *Options) ([]byte, error)` — 从 `io.Reader` 流式计算

**函数｜HMAC 类型化入口（迁移自 `crypto/hmac`，并补齐 SHA-224）**

- ♻️ `func NewHMACSM3(key []byte) hash.Hash` / ♻️ `func SumHMACSM3(key, data []byte) []byte` — 原 `hmac.NewSM3` / `hmac.SumSM3`
- ♻️ `func NewHMACMD5(key []byte) hash.Hash` / 🆕 `func SumHMACMD5(key, data []byte) []byte` — 原 `hmac.NewMD5`（一次性为新增）
- ♻️ `func NewHMACSHA1(key []byte) hash.Hash` / 🆕 `func SumHMACSHA1(key, data []byte) []byte` — 原 `hmac.NewSHA1`
- 🆕 `func NewHMACSHA224(key []byte) hash.Hash` / 🆕 `func SumHMACSHA224(key, data []byte) []byte`
- ♻️ `func NewHMACSHA256(key []byte) hash.Hash` / ♻️ `func SumHMACSHA256(key, data []byte) []byte` — 原 `hmac.NewSHA256` / `hmac.SumSHA256`
- ♻️ `func NewHMACSHA384(key []byte) hash.Hash` / ♻️ `func SumHMACSHA384(key, data []byte) []byte` — 原 `hmac.NewSHA384` / `hmac.SumSHA384`
- ♻️ `func NewHMACSHA512(key []byte) hash.Hash` / 🆕 `func SumHMACSHA512(key, data []byte) []byte` — 原 `hmac.NewSHA512`

> 实现说明：`0.5.0` 起全部入口走 provider `EVP_MAC_*` 路径（`internal/native/binding_mac.go` + `internal/core/mac.go`）。`New(name, …)` 接受 14 种算法：`HMAC-SM3` / `HMAC-SHA1` / `HMAC-SHA224` / `HMAC-SHA256` / `HMAC-SHA384` / `HMAC-SHA512` / `HMAC-MD5` / `CMAC` / `GMAC` / `KMAC-128` / `KMAC-256` / `SIPHASH` / `POLY1305` / `EIA3`。

**函数｜家族类型化入口（`0.5.0` 新增）**

- 🆕 `func CMAC(cipherName string, key, data []byte) ([]byte, error)` — `cipherName` 取 `SM4` / `AES-128` / `AES-192` / `AES-256`（内部补 `-CBC`）
- 🆕 `func GMAC(cipherName string, key, iv, aad, data []byte) ([]byte, error)` — 内部补 `-GCM`
- 🆕 `func KMAC128(key, data, custom []byte, outLen int) ([]byte, error)` / 🆕 `func KMAC256(key, data, custom []byte, outLen int) ([]byte, error)` — 输出长度参与域分隔
- 🆕 `func SipHash(key, data []byte) ([]byte, error)` — 返回 16 字节（64 位标签的 provider 版本）
- 🆕 `func Poly1305(key, data []byte) ([]byte, error)`
- 🆕 `func EIA3(key, count, data []byte) ([]byte, error)` — 铜锁独有

**函数｜形态入口（`0.5.0` 新增，配合 `meta.Source` / `meta.Sink`）**

- 🆕 `func SumSource(name string, key []byte, src *meta.Source, opts *Options) ([]byte, error)`
- 🆕 `func SumFile(name string, key []byte, path string, opts *Options) ([]byte, error)` — `"-"` 读 stdin
- 🆕 `func SumTo(name string, key []byte, src *meta.Source, sink *meta.Sink, opts *Options) error`

**破坏性变更**

- 删除 `crypto/hmac` 包；`hmac.NewSM3` → `mac.NewHMACSM3`（显式 HMAC 前缀，避免与 CMAC/GMAC 混淆）
- `hmac.SumSM3` / `hmac.SumSHA256` / `hmac.SumSHA384` → `mac.SumHMAC*`（语义不变，改名）

---

## 4. `kdf` — 密钥派生

✅ **已有**｜旧包：`crypto/kdf` + `key` 的 KDF 部分

合并 `crypto/kdf`（仅 HKDF/PBKDF2）与 `key` 包里的 `HKDF` / `PBKDF2` / `Argon2ID`，并补上 CLI `kdf` 的按名分发形态。

**类型与常量**

- ♻️ `type Hash string` — 摘要算法标识（原 `key.Hash`）
- ♻️ `HashMD5` `HashSHA1` `HashSHA224` `HashSHA256` `HashSHA384` `HashSHA512` `HashSM3` — 取值（原 `key.Hash*`）
- 🆕 `HashMD5SHA1` — 组合摘要，仅用于 `TLS1PRF`（TLS 1.0/1.1 PRF 的默认选择）
- 🆕 `type Options struct { … }` — 按名分发的参数包。除原有的 `Digest` / `Secret` / `Salt` / `Info` / `Password` / `Iterations` / `Length` / `TimeCost` / `Memory` / `Threads` 外，`0.5.0` 新增：`Mode string`（HKDF、TLS13-KDF 取 `EXTRACT_ONLY` / `EXPAND_ONLY`；KBKDF 取 `COUNTER` / `FEEDBACK`）、`Label` / `Prefix` / `Data []byte`（TLS13-KDF）、`Seed []byte`（TLS1-PRF）、`UKM []byte` 与 `CEKAlg string`（X942KDF）、`MAC string`（KBKDF）、`Entropy` / `Nonce []byte`（HMAC-DRBG-KDF）、`N` / `R` / `P` / `MaxMem uint64`（scrypt，`R` 亦用作 KBKDF 计数器宽度）、`UseL` / `UseSeparator`（KBKDF）、`UseKeyBits`（X942KDF）

**函数**

- ♻️ `func HKDF(md Hash, secret, salt, info []byte, length int) ([]byte, error)` — HKDF（RFC 5869）；原 `key.HKDF`
- ♻️ `func PBKDF2(md Hash, password, salt []byte, iter, keyLen int) ([]byte, error)` — PBKDF2；原 `key.PBKDF2`
- ♻️ `func Argon2ID(password, salt []byte, timeCost, memory, threads uint32, keyLen int) ([]byte, error)` — Argon2ID；原 `key.Argon2ID`（铜锁未编译 argon2 时返回 `ErrUnsupported`）
- ♻️ `func Argon2IDAvailable() bool` — 探测铜锁是否带 Argon2ID 支持；原 `crypto/kdf.Argon2IDAvailable`
- 🆕 `var ErrUnknownAlgorithm` / 🆕 `var ErrUnsupported` — 哨兵错误
- 🆕 `func Names() []string` — 返回本版已支持的 KDF 算法名
- 🆕 `func Derive(name string, opts *Options) ([]byte, error)` — 按名分发派生（对应 `tongsuo kdf HKDF -kdfopt …`）

**函数｜类型化入口（`0.5.0` 新增）**

| 符号 | 算法 / 标准 |
|---|---|
| 🆕 `func Scrypt(password, salt []byte, n, r, p uint32, maxMem, keyLen int) ([]byte, error)` | scrypt（RFC 7914） |
| 🆕 `func SSKDF(md Hash, secret, salt, info []byte, length int) ([]byte, error)` | 单步 KDF（SP 800-56C / X9.63 家族） |
| 🆕 `func TLS1PRF(md Hash, secret, seed []byte, length int) ([]byte, error)` | TLS 1.0/1.1 PRF（RFC 2246） |
| 🆕 `func TLS13KDFExtract(md Hash, secret, salt []byte) ([]byte, error)` | TLS 1.3 HKDF-Extract（RFC 8446 §7.1） |
| 🆕 `func TLS13KDFExpand(md Hash, secret []byte, label string, context []byte, length int) ([]byte, error)` | TLS 1.3 HKDF-Expand-Label |
| 🆕 `func X963KDF(md Hash, secret, info []byte, length int) ([]byte, error)` | ANSI X9.63 KDF |
| 🆕 `func X942KDF(md Hash, secret, ukm []byte, cekAlg string, useKeyBits bool, length int) ([]byte, error)` | ANSI X9.42 KDF（RFC 2631） |
| 🆕 `type KBKDFOptions struct { Digest Hash; MAC string; Mode string; Secret, Label, Context []byte; R int; UseL, UseSeparator bool }` 与 🆕 `func KBKDF(opts *KBKDFOptions, length int) ([]byte, error)` | SP 800-108 KBKDF |
| 🆕 `func HMACDRBG(md Hash, entropy, nonce []byte, length int) ([]byte, error)` | SP 800-90A HMAC-DRBG |

**函数｜形态入口（`0.5.0` 新增）**

- 🆕 `func DeriveTo(name string, opts *Options, sink *meta.Sink) error` — 派生结果按 `sink` 编码写出

**函数｜运行时能力探测（`0.5.0` 新增）**

- 🆕 `func Available(name string) bool` — 本机铜锁的 provider 是否真的提供该算法（
  `Names()` 是编译期清单，本函数是运行时事实）。典型差异：Tongsuo 8.4.0 没有
  `HMAC-DRBG-KDF`
- 🆕 `func KBKDFCounterWidthSupported() bool` — 本构建的 KBKDF 是否接受 `R`
  （计数器宽度）参数；仅 OpenSSL 3.2+ 支持，Tongsuo 8.4.0 下 `R` 被忽略（固定 32 位）

**规划中（后续版本）**

> 下列 KDF 是未分配版本的候选，不列入本轮已确认的交付范围；已排期能力见 [roadmap.md](roadmap.md) §2。

| 符号 | 前置（需新增 `internal/native` 绑定） |
|---|---|
| 🧭 `KRB5KDF`、`PKCS12KDF`、`SSHKDF` | 同类 `EVP_KDF_fetch`，无需新 shim，仅补参数映射与向量 |

**破坏性变更**

- 删除 `crypto/kdf` 包；`crypto/kdf.HKDF("SM3", …)` → `kdf.Derive("HKDF", &kdf.Options{Digest: kdf.HashSM3, …})`
- `key.HKDF` / `key.PBKDF2` / `key.Argon2ID` → `kdf.HKDF` / `kdf.PBKDF2` / `kdf.Argon2ID`（签名不变）
- `Hash` 类型与常量由 `key` 移入 `kdf`

---

## 5. `rand` — 安全随机数

✅ **已有**｜旧包：`crypto/rand`

基于铜锁 `RAND_bytes`，与标准库实现独立。

**函数**

- ♻️ `func Read(b []byte) (int, error)` — 填充 `b` 并返回写入字节数（满足 `io.Reader` 语义）；原 `crypto/rand.Read`
- ♻️ `func Bytes(n int) ([]byte, error)` — 返回 `n` 字节随机数据；原 `crypto/rand.Bytes`
- 🆕 `func Reader() io.Reader` — 返回无限随机源，便于 `io.Copy` 与 `io.ReadFull` 组合

> 包路径由 `crypto/rand` 换为 `rand` 后，**包名仍是 `rand`**：同一文件中同时 import 标准库 `crypto/rand` 与本包时仍需别名。

**破坏性变更**

- 删除 `crypto/rand` 包；`crypto/rand.Read` → `rand.Read`（签名不变，仅路径变化）

---

## 6. `sym` — 对称加密与对称密钥对象

✅ **已有**｜旧包：`crypto/aes` `crypto/sm4` + `key` 对称部分

把 AES 与 SM4 合并为一个“按算法名 + 模式”分发的对称加密包（对应 CLI `enc`）。所有 ECB/CBC 一次性入口均为 **PKCS#7 填充**；`NewCipher` 返回**无填充**的 `cipher.Block`。

**常量**

- ♻️ `BlockSize = 16` — 分组长度（原 `aes.BlockSize` / `sm4.BlockSize`）
- ♻️ `NonceSize = 12` — GCM 推荐 nonce 长度（原两包同名常量）
- ♻️ `TagSize = 16` — GCM tag 长度（原两包同名常量）
- ♻️ `AES128KeySize = 16`、♻️ `AES256KeySize = 32` — AES 密钥长度（原为 `crypto/aes` 的隐式约束）
- ♻️ `SM4KeySize = 16` — SM4 密钥长度（原 `sm4.KeySize`）

**类型与变量**

- 🆕 `type Options struct { Padding string; AAD []byte; Tag []byte; Order string }` — 按名分发的参数包（`Padding` 取 `"pkcs7"` / `"zero"` / `"none"`）
  - ⚠️ **语义变化（`0.6.0`）**：现状下 `Padding` 仅对 SM4-CBC / ECB 生效，AES-CBC / ECB **静默忽略**该参数，且无法识别的填充名静默退化为 `pkcs7`。`0.6.0` 起 `Padding` 对所有分组模式一致生效，非法组合返回 `ErrUnsupportedPadding`；各名字 × 填充的合法组合见本节末尾「规划中」的 `Supports` / `Paddings`。
- 🆕 `var ErrUnknownAlgorithm` / 🆕 `var ErrInvalidKeyLength` / 🆕 `var ErrUnsupported` — 哨兵错误

**类型与函数｜对称密钥对象（迁移自 `key`）**

- 🆕 `type Algorithm string` — 对称算法标识；🆕 `AlgAES128 = "AES-128"`、`AlgAES256 = "AES-256"`、`AlgSM4 = "SM4"`（原 `key.Alg*` 的对称部分）
- ♻️ `type SymmetricKey interface { Algorithm() Algorithm; Bytes() []byte; Size() int; Marshal() ([]byte, error); Equal(other SymmetricKey) bool }` — 对称密钥统一接口（原 `key.SymmetricKey`；无原生句柄，**无需 `Close`**）
- ♻️ `type AESKey struct { …（内部字段） }` — AES 对称密钥（16 / 32 字节）（原 `key.AESKey`）
- ♻️ `type SM4Key struct { …（内部字段） }` — SM4 对称密钥（16 字节）（原 `key.SM4Key`）
- ♻️ `func NewAESKey(raw []byte) (*AESKey, error)` — 由原始字节构造 AES 密钥（原 `key.NewAESKey`）
- ♻️ `func NewSM4Key(raw []byte) (*SM4Key, error)` — 由原始字节构造 SM4 密钥（原 `key.NewSM4Key`）
- ♻️ `func GenerateSymmetricKey(alg Algorithm) (SymmetricKey, error)` — 按算法生成随机对称密钥（原 `key.GenerateSymmetricKey`）
- ♻️ `func ParseSymmetricKey(p []byte) (SymmetricKey, error)` — 从自身导出的 PEM 块还原对称密钥（原 `key.ParseSymmetricKey`）
- ♻️ `func (k *AESKey) Algorithm() Algorithm` / `Size() int` / `Bytes() []byte` / `Marshal() ([]byte, error)` / `Equal(other SymmetricKey) bool` — AES 密钥方法（`SM4Key` 同名同签名）

**函数｜按算法名分发（新增）**

> `name` 取值形如 `"AES-128-CBC"` / `"AES-256-GCM"` / `"SM4-CBC"` / `"SM4-GCM"`，与铜锁 `enc -<name>` 命名对齐。
> `0.6.0` 起将增补 `"AES-{128,192,256}-{OFB,CFB}"`（CFB 为全字节反馈即 CFB128）、`"DES-{ECB,CBC}"`、
> `"DES-EDE-{ECB,CBC}"`（2 密钥）、`"DES-EDE3-{ECB,CBC}"`。

- 🆕 `func Names() []string` — 返回本版已支持的「算法-模式」名
- 🆕 `func NewCipher(name string, key []byte) (cipher.Block, error)` — 无填充分组密码（实现 `cipher.Block`）
- 🆕 `func NewGCM(name string, key []byte) (cipher.AEAD, error)` — GCM AEAD（实现 `cipher.AEAD`）
- 🆕 `func Encrypt(name string, key, iv, data []byte, opts *Options) ([]byte, error)` / 🆕 `func Decrypt(name string, key, iv, data []byte, opts *Options) ([]byte, error)` — 按名一次性加解密
- 🆕 `func EncryptGCM(name string, key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error)` — 按名 GCM 加密，tag 单独返回
- 🆕 `func DecryptGCM(name string, key, nonce, ciphertext, tag, aad []byte) ([]byte, error)` — 按名 GCM 解密，tag 不匹配时报错

**函数｜AES 类型化入口（迁移自 `crypto/aes`）**

- ♻️ `func NewAESCipher(key []byte) (cipher.Block, error)` / ♻️ `func NewAESGCM(key []byte) (cipher.AEAD, error)` — 原 `aes.NewCipher` / `aes.NewGCM`
- ♻️ `func EncryptAESECB(key, data []byte) ([]byte, error)` / ♻️ `func DecryptAESECB(key, data []byte) ([]byte, error)` — 原 `aes.EncryptECB` / `aes.DecryptECB`
- ♻️ `func EncryptAESCBC(key, iv, data []byte) ([]byte, error)` / ♻️ `func DecryptAESCBC(key, iv, data []byte) ([]byte, error)` — 原 `aes.EncryptCBC` / `aes.DecryptCBC`
- ♻️ `func EncryptAESCTR(key, iv, data []byte) ([]byte, error)` / ♻️ `func DecryptAESCTR(key, iv, data []byte) ([]byte, error)` — 原 `aes.EncryptCTR` / `aes.DecryptCTR`
- ♻️ `func EncryptAESGCM(key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error)` / ♻️ `func DecryptAESGCM(key, nonce, ciphertext, tag, aad []byte) ([]byte, error)` — 原 `aes.EncryptGCM` / `aes.DecryptGCM`

**函数｜SM4 类型化入口（迁移自 `crypto/sm4`）**

- ♻️ `func NewSM4Cipher(key []byte) (cipher.Block, error)` / ♻️ `func NewSM4GCM(key []byte) (cipher.AEAD, error)` — 原 `sm4.NewCipher` / `sm4.NewGCM`
- ♻️ `func EncryptSM4ECB(key, data []byte) ([]byte, error)` / ♻️ `func DecryptSM4ECB(key, data []byte) ([]byte, error)`（PKCS#7）— 原 `sm4.EncryptECB` / `sm4.DecryptECB`
- ♻️ `func EncryptSM4CBC(key, iv, data []byte) ([]byte, error)` / ♻️ `func DecryptSM4CBC(key, iv, data []byte) ([]byte, error)`（PKCS#7）— 原 `sm4.EncryptCBC` / `sm4.DecryptCBC`
- ♻️ `func EncryptSM4ECBZero(key, data []byte) ([]byte, error)` / ♻️ `func DecryptSM4ECBZero(key, data []byte) ([]byte, error)` — 原 `sm4.EncryptECBZero` / `sm4.DecryptECBZero`
- ♻️ `func EncryptSM4CBCZero(key, iv, data []byte) ([]byte, error)` / ♻️ `func DecryptSM4CBCZero(key, iv, data []byte) ([]byte, error)` — 原 `sm4.EncryptCBCZero` / `sm4.DecryptCBCZero`
- ♻️ `func EncryptSM4CTR(key, iv, data []byte) ([]byte, error)` / ♻️ `func DecryptSM4CTR(key, iv, data []byte) ([]byte, error)` — 原 `sm4.EncryptCTR` / `sm4.DecryptCTR`
- ♻️ `func EncryptSM4OFB(key, iv, data []byte) ([]byte, error)` / ♻️ `func DecryptSM4OFB(key, iv, data []byte) ([]byte, error)` — 原 `sm4.EncryptOFB` / `sm4.DecryptOFB`
- ♻️ `func EncryptSM4CFB(key, iv, data []byte) ([]byte, error)` / ♻️ `func DecryptSM4CFB(key, iv, data []byte) ([]byte, error)` — 原 `sm4.EncryptCFB` / `sm4.DecryptCFB`
- ♻️ `func EncryptSM4GCM(key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error)` / ♻️ `func DecryptSM4GCM(key, nonce, ciphertext, tag, aad []byte) ([]byte, error)` — 原 `sm4.EncryptGCM` / `sm4.DecryptGCM`

> 安全提示：ECB 无扩散语义，不建议用于多块数据；CTR/OFB/CFB 为流式模式，**同一密钥下 nonce/IV 必须唯一**。`*Block` 实现并发安全（内部使用 `EVP_CIPHER_CTX_copy` 模板副本）。

**函数｜`0.5.0` 新增算法（AES-192 / SM4-CCM / SM4-XTS / ChaCha20）**

- 🆕 `AES192KeySize = 24`、`SM4XTSKeySize = 32`、`ChaCha20KeySize = 32`、`ChaCha20IVSize = 16`、`SM4CCMNonceSize = 12`
- 🆕 `type Algorithm string` 新增 `AlgAES192 = "AES-192"`；`NewAESKey` / `GenerateSymmetricKey` 接受 24 字节
- 🆕 `func NewAEAD(name string, key []byte) (cipher.AEAD, error)` / 🆕
  `func EncryptAEAD(name string, key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error)` / 🆕
  `func DecryptAEAD(name string, key, nonce, ciphertext, tag, aad []byte) ([]byte, error)` — 按名覆盖
  GCM / CCM / ChaCha20-Poly1305
- 🆕 `func NewSM4CCM(key []byte) (cipher.AEAD, error)` / 🆕
  `func EncryptSM4CCM(key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error)` / 🆕
  `func DecryptSM4CCM(key, nonce, ciphertext, tag, aad []byte) ([]byte, error)` — 12 字节 nonce、16 字节 tag
- 🆕 `func EncryptSM4XTS(key, data []byte) ([]byte, error)` / 🆕
  `func DecryptSM4XTS(key, data []byte) ([]byte, error)` — 32 字节双子密钥；允许 CTS（数据 ≥ 16 字节）
- 🆕 `func EncryptChaCha20(key, iv, data []byte) ([]byte, error)` / 🆕
  `func DecryptChaCha20(key, iv, data []byte) ([]byte, error)`
- 🆕 `func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error)` / 🆕
  `func EncryptChaCha20Poly1305(key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error)` / 🆕
  `func DecryptChaCha20Poly1305(key, nonce, ciphertext, tag, aad []byte) ([]byte, error)`

**函数｜形态入口（`0.5.0` 新增，配合 `meta.Source` / `meta.Sink`）**

- 🆕 `func EncryptSource(name string, key, iv []byte, src *meta.Source, sink *meta.Sink) error` — 流式加密
- 🆕 `func DecryptSource(name string, key, iv []byte, src *meta.Source, sink *meta.Sink) error` — 流式解密
  - 仅接受 ECB / CBC（PKCS#7 填充）与 CTR / OFB / CFB / ChaCha20（无填充）；
    AEAD 与 XTS 需一次性持有全部数据，返回 `ErrUnsupported`
  - 解密时坏填充返回错误（不放宽校验），此时 `sink` 中可能已有部分明文

**函数｜运行时能力探测（`0.5.0` 新增）**

- 🆕 `func Available(name string) bool` — 本机铜锁是否真的提供该「算法-模式」名
  （`Names()` 是编译期清单，本函数是运行时事实）。典型差异：Tongsuo 8.4.0
  没有 SM4-XTS（走 `EVP_CIPHER_fetch`），此时 `EncryptSM4XTS` 返回
  「unavailable in this build」

**函数｜新增模式与填充矩阵（`0.6.0` 新增）**

- 🆕 `AES-{128,192,256}-{OFB,CFB}` 名字（CFB 为 CFB128）
- 🆕 `func EncryptAESOFB(key, iv, data []byte) ([]byte, error)` / 🆕 `func DecryptAESOFB(key, iv, data []byte) ([]byte, error)` — OFB 加解密为同一运算
- 🆕 `func EncryptAESCFB(key, iv, data []byte) ([]byte, error)` / 🆕 `func DecryptAESCFB(key, iv, data []byte) ([]byte, error)` — CFB128，iv 为 `BlockSize`
- 🆕 `DESKeySize = 8`、`DESEDEKeySize = 16`、`DESEDE3KeySize = 24`、`DESBlockSize = 8`
- 🆕 `DES-{ECB,CBC}`、`DES-EDE-{ECB,CBC}`（2 密钥）、`DES-EDE3-{ECB,CBC}` 名字；🆕 `func EncryptDES{ECB,CBC}` / `DecryptDES{ECB,CBC}` / `EncryptDESEDE{ECB,CBC}` / `DecryptDESEDE{ECB,CBC}` / `EncryptDESEDE3{ECB,CBC}` / `DecryptDESEDE3{ECB,CBC}` / `NewDESCipher`
  - 单 DES 以 `K‖K‖K` 驱动 DES-EDE3 实现，输出与真单 DES 逐字节相同；**不加载 legacy provider**（见 [roadmap.md](roadmap.md) §4 第 10 条）
- 🆕 `PaddingPKCS7` / `PaddingZero` / `PaddingNone`；🆕 `var ErrUnsupportedPadding`
- 🆕 `func Supports(name, padding string) (bool, error)` — 静态判定「算法名 × 填充」是否合法（未知名返回 `ErrUnknownAlgorithm`，未知填充名返回 `(false, nil)`）
- 🆕 `func Paddings(name string) ([]string, error)` — 分组模式返回 `pkcs7/zero/none`，流模式与 XTS 返回 `none`，AEAD 返回空切片

**函数｜AES 扩展与 ZUC（`0.6.0` 新增）**

- `AES-{128,192,256}-{CCM,OCB,SIV,WRAP,WRAP-PAD,CBC-CTS}`、`AES-{128,256}-XTS`、`ZUC-128-EEA3` 登记于 `Names`，共 58 项（含 0.8.0 的三个 GCM-SIV 名称）；`Available` 探测本地 provider。
- `func NewAESCCM(key []byte) (cipher.AEAD, error)` / `NewAESOCB` / `NewAESSIV` — 亦可用 `NewAEAD`。
- `func EncryptAESCCM(key, nonce, plaintext, aad []byte) ([]byte, []byte, error)` / `EncryptAESOCB` / `EncryptAESSIV`
- `func DecryptAESCCM(key, nonce, ciphertext, tag, aad []byte) ([]byte, error)` / `DecryptAESOCB` / `DecryptAESSIV`
- `func EncryptAESXTS(key, iv, data []byte) ([]byte, error)` / `DecryptAESXTS`；`EncryptAESWrap` / `DecryptAESWrap`；`EncryptAESWrapPad` / `DecryptAESWrapPad`；`EncryptAESCBCCTS` / `DecryptAESCBCCTS`。
- `func EncryptZUC(key, iv, data []byte) ([]byte, error)` / `DecryptZUC` — 16 字节 key、5 字节原生 EEA3 IV。
- `cipher.AEAD` 的 `NonceSize` / `Overhead` / `Seal` / `Open` 行为沿用现有模式；`Seal` 失败返回 nil，`Open` 失败不返回部分明文。
- CCM/OCB 的 AEAD `NonceSize` 为 12；一次性 CCM 接受 7..13 字节、OCB 为 1..15。
  SIV 使用 32/48/64 字节双密钥，AEAD 的 `NonceSize` 为 0（确定性），一次性入口将非空 nonce 作为最后一个 AAD 分量；8.4.0 上拒绝空消息并返回 `ErrUnsupported`，0.8.0 在铜锁 8.5.0 上支持空消息并校验认证。
  XTS 使用 32/64 字节双密钥，支持不少于 16 字节的数据；CBC-CTS 默认 CS1。
  WRAP/WRAP-PAD 的 nil IV 使用 RFC 3394/5649 标准值，后两者校验包装完整性；其余非 AEAD 模式不提供消息认证。
- 新增模式的填充：XTS/WRAP/WRAP-PAD/CBC-CTS/ZUC 仅 `none`；CCM/OCB/SIV 无外部填充。
  `EncryptSource`/`DecryptSource` 对上述一次性模式返回 `ErrUnsupported`。

**规划中**

| 符号 | 目标版本 | 前置（需新增 `internal/native` 绑定） |
|---|---|---|
| 🆕 AES-GCM-SIV | `0.8.0` | NewAESGCMSIV / EncryptAESGCMSIV / DecryptAESGCMSIV；128/192/256 位，12 字节 nonce、16 字节 tag，8.4 返回 ErrUnsupported |

> **DES 的实现方式与安全口径**：单 DES 在铜锁中只注册在 legacy provider，本库不加载 legacy（见
> [roadmap.md](roadmap.md) §4 第 10 条），改以 `K‖K‖K`（三份相同密钥）驱动 DES-EDE3 实现——
> 两者输出逐字节相同。对外仍以 `DES-ECB` / `DES-CBC` 命名，GoDoc 已写明这是等价变换。
> DES 的 56-bit 密钥已可穷举，**仅用于兼容既有数据**，不建议用于新协议。

**破坏性变更**

- 删除 `crypto/aes` 与 `crypto/sm4`：`aes.EncryptCBC` → `sym.EncryptAESCBC`；`sm4.EncryptCBC` → `sym.EncryptSM4CBC`
- 尺寸常量统一到包级（`KeySize` → `SM4KeySize` / `AES128KeySize` / `AES256KeySize`）
- `key.AESKey` / `key.SM4Key` / `key.NewAESKey` / `key.NewSM4Key` / `key.GenerateSymmetricKey` / `key.ParseSymmetricKey` → `sym.*`；`key.SymmetricKey` → `sym.SymmetricKey`（签名不变，仅换包）

---

## 7. `asym` — 非对称密钥、签名与加解密

✅ **已有**｜旧包：`crypto/sm2` `crypto/rsa` `crypto/ecdsa` `crypto/ed25519` `crypto/ed448` + `crypto/{x25519,x448}`（仅密钥生成）+ `key`（非对称部分）

把 5 个非对称算法包与 `key` 包的非对称部分合并为一个“按算法名分发”的包（对应 CLI `genpkey` + `pkey` + `pkeyutl`）。**密钥协商不属本包**（见 `ecdh`）。

**类型与常量**

- ♻️ `type Algorithm string` — 密钥算法标识（原 `key.Algorithm`）
- ♻️ `AlgRSA` `AlgSM2` `AlgECDSA` `AlgEd25519` `AlgEd448` `AlgX25519` `AlgX448` — 取值（原 `key.Alg*`；注意 `AlgED25519` → `AlgEd25519` 改名）
- 🆕 `type Options struct { Hash string; SaltLen int; ID []byte; Order string; Curve string; Bits int }` — 按名分发的参数包
- 🆕 `type KeyParams struct { Bits int; Curve string; N, E, D, P, Q, Dmp1, Dmq1, Iqmp, X, Y []byte }` — 密钥参数视图（替代 `*core.KeyParams`，修复 E1-3；RSA 用 N/E/D/P/Q/Dmp1/Dmq1/Iqmp，EC/SM2 用 Curve/X/Y，Ed/X 系仅 Bits）
- ♻️ `type PEM struct { Type string; Headers map[string]string; Bytes []byte }` — 已解码的 PEM 块（原 `key.PEM`）
- ♻️ `var DefaultID = []byte("1234567812345678")` — SM2 默认签名 userId（原 `crypto/sm2.DefaultID`）
- ♻️ `PSSSaltLenDigest = -1` / ♻️ `PSSSaltLenAuto = -2` / ♻️ `PSSSaltLenMax = -3` — PSS 盐长度取值（原 `crypto/rsa`）
- 🆕 `var ErrUnknownAlgorithm` / 🆕 `var ErrUnsupported` / 🆕 `var ErrInvalidSeedLength` / 🆕 `var ErrInvalidPublicKeyLength` / 🆕 `var ErrInvalidKeyLength` — 哨兵错误

**接口**

- ♻️ `type Key interface { Algorithm() Algorithm; Equal(other Key) bool }` — 所有非对称密钥的共同接口（原 `key.Key` 的非对称部分）
- ♻️ `type PrivateKey interface { Key; Public() PublicKey; Marshal() ([]byte, error); MarshalEncrypted(pass string) ([]byte, error); MarshalPKCS1() ([]byte, error) }` — 私钥（原 `key.AsymmetricPrivateKey`，已去除 `Key() *core.PKey`）
- ♻️ `type PublicKey interface { Key; Marshal() ([]byte, error) }` — 公钥（原 `key.AsymmetricPublicKey`，已去除 `Key() *core.PKey`）

**函数｜密钥生成**

- 🆕 `func GenerateKey(alg Algorithm, opts *Options) (PrivateKey, error)` — 按算法名生成（对应 `genpkey -algorithm`）
- ♻️ `func GenerateRSA(bits int) (PrivateKey, error)` — 原 `crypto/rsa.GenerateKey` / `key.GenerateRSAKey`（`bits` 必须 ≥ 1024）
- ♻️ `func GenerateSM2() (PrivateKey, error)` — 原 `crypto/sm2.GenerateKey` / `key.GenerateSM2Key`
- ♻️ `func GenerateEC(curve string) (PrivateKey, error)` — 原 `crypto/ecdsa.GenerateKey` / `key.GenerateECKey`（`curve` 取 `"prime256v1"` / `"secp384r1"` / `"secp521r1"` / `"secp256k1"` / `"sm2"`）
- ♻️ `func GenerateEd25519() (PrivateKey, error)` / ♻️ `func GenerateEd448() (PrivateKey, error)` — 原 `crypto/ed25519|ed448.GenerateKey`
- ♻️ `func GenerateX25519() (PrivateKey, error)` / ♻️ `func GenerateX448() (PrivateKey, error)` — 原 `crypto/x25519|x448.GenerateKey`
- 🆕 `func GenerateKeyFromSeed(alg Algorithm, seed []byte) (PrivateKey, error)` — 由原始种子/字节构造（Ed25519 32B / Ed448 57B / X25519 32B / X448 56B；原 4 个包的 `PrivateKeyFromSeed` / `PrivateKeyFromBytes`）
- 🆕 `func PublicKeyFromBytes(alg Algorithm, raw []byte) (PublicKey, error)` — 由原始公钥字节构造（同上四算法）

**函数｜PEM 解析与口令**

- ♻️ `func LoadPrivateKeyPEM(p []byte) (PrivateKey, error)` — 加载未加密私钥（PKCS#8；**本版新增回退 RSA 传统 PKCS#1 与 EC SEC1**）；原 `key.LoadPrivateKeyPEM`
- ♻️ `func LoadPrivateKeyPEMEncrypted(p []byte, pass string) (PrivateKey, error)` — 加载加密私钥；原 `key.LoadPrivateKeyPEMEncrypted`
- ♻️ `func LoadPublicKeyPEM(p []byte) (PublicKey, error)` — 加载 SPKI 公钥；原 `key.LoadPublicKeyPEM`
- ♻️ `func ParsePEM(p []byte) (*PEM, error)` — 仅解码首个 PEM 块（不解析语义）；原 `key.ParsePEM`
- ♻️ `func ChangePassword(pemBytes []byte, oldPass, newPass string) ([]byte, error)` — 更换加密私钥口令；原 `crypto/{rsa,ecdsa,ed25519,ed448,x25519}.ChangePassword`

**函数｜运算（按算法名分发，新增）**

- 🆕 `func Sign(alg Algorithm, priv PrivateKey, data []byte, opts *Options) ([]byte, error)` — 签名（RSA 走 PKCS#1 v1.5；SM2 走 SM2withSM3；可选 `opts.Hash` / `opts.ID` / `opts.SaltLen`）
- 🆕 `func Verify(alg Algorithm, pub PublicKey, data, sig []byte, opts *Options) error` — 验签
- 🆕 `func Encrypt(alg Algorithm, pub PublicKey, data []byte, opts *Options) ([]byte, error)` — 加密（RSA PKCS#1 v1.5 / SM2）
- 🆕 `func Decrypt(alg Algorithm, priv PrivateKey, data []byte, opts *Options) ([]byte, error)` — 解密

**函数｜RSA 类型化入口（迁移自 `crypto/rsa`）**

- ♻️ `func SignPKCS1v15(priv PrivateKey, data []byte, hash string) ([]byte, error)` / ♻️ `func VerifyPKCS1v15(pub PublicKey, data, sig []byte, hash string) error` — 原 `(*rsa.PrivateKey).SignPKCS1v15` / `(*rsa.PublicKey).VerifyPKCS1v15`（改为包级函数）
- ♻️ `func SignPSS(priv PrivateKey, data []byte, saltLen int, hash string) ([]byte, error)` / ♻️ `func VerifyPSS(pub PublicKey, data, sig []byte, saltLen int, hash string) error` — 原 RSA 方法
- ♻️ `func EncryptPKCS1v15(pub PublicKey, data []byte) ([]byte, error)` / ♻️ `func DecryptPKCS1v15(priv PrivateKey, data []byte) ([]byte, error)` — 原 `crypto/rsa` 同名函数
- ♻️ `func EncryptOAEP(pub PublicKey, data []byte, hash string) ([]byte, error)` / ♻️ `func DecryptOAEP(priv PrivateKey, data []byte, hash string) ([]byte, error)` — 原 `crypto/rsa` 同名函数；**参数由 `md *core.Digest` 改为 `hash string`（修复 E1-2）**
- `hash` 参数的取值范围（`0.6.0` 起含 `sm3`）：`""`（默认 SHA-256）/ `"sha1"` / `"sha224"` / `"sha256"` / `"sha384"` / `"sha512"` / `"sm3"`。`sm3` 适用于 PKCS#1 v1.5、PSS 与 OAEP（OAEP 的摘要同时用作 MGF1 哈希）。

**函数｜SM2 类型化入口（迁移自 `crypto/sm2`）**

- ♻️ `func SignWithID(priv PrivateKey, data, id []byte) ([]byte, error)` / ♻️ `func VerifyWithID(pub PublicKey, data, sig, id []byte) error` — 原 SM2 同名函数
- ♻️ `func EncryptWithOrder(pub PublicKey, data []byte, order string) ([]byte, error)` / ♻️ `func DecryptWithOrder(priv PrivateKey, data []byte, order string) ([]byte, error)` — 原 SM2 同名函数（`order` 取 `"c1c3c2"` / `"c1c2c3"`）
- ♻️ `func Format(ct []byte, from, to string) ([]byte, error)` — 密文格式互转（`"der"` / `"c1c3c2"` / `"c1c2c3"`）；原 `crypto/sm2.Format`
  - 注：此函数只处理 **SM2 密文**；**签名**的 DER ↔ 裸 `r‖s` 互转为 `0.6.0` 新增的 `SignatureParts` / `SignatureDER` / `FormatSignature`（见下方「规划中」）。

**方法**

- ♻️ `func (k) Algorithm() Algorithm` — 算法标识
- ♻️ `func (k) Public() PublicKey` — 返回配对公钥
- ♻️ `func (k) Marshal() ([]byte, error)` — 私钥导 PKCS#8 PEM、公钥导 SPKI PEM
- ♻️ `func (k) MarshalEncrypted(pass string) ([]byte, error)` — 导出加密 PKCS#8 PEM（AES-256-CBC + PBKDF2）
- ♻️ `func (k) MarshalPKCS1() ([]byte, error)` — 导出传统 PKCS#1 PEM（非 RSA 返回 `ErrUnsupported`）
- ♻️ `func (k) Equal(other Key) bool` — 是否同一密钥
- ♻️ `func (k) Params() *KeyParams` — 密钥参数（**返回类型由 `*core.KeyParams` 改为 `*KeyParams`，修复 E1-3**）
- ♻️ `func (k) Match(other Key) bool` — 判断是否同一密钥（**参数由 `*core.PKey` 改为 `Key`，修复 E1-5**）
- 🆕 `func Seed(priv PrivateKey) ([]byte, error)` / 🆕 `func Bytes(pub PublicKey) ([]byte, error)` — 原始种子/公钥字节（仅 Ed25519 / Ed448 / X25519 / X448；其余返回 `ErrUnsupported`）

> 安全提示：SM2 签名的 userId 影响验签结果，跨系统交互时必须显式约定；RSA 密钥长度下限 1024 位，生产建议 ≥ 2048。

**内部契约（供 `internal/keyaccess` 反查）**

- 🆕 密钥的**具体类型一律非导出**（`*privateKey` / `*publicKey` …），对外只返回 `PrivateKey` / `PublicKey` 接口
- 🆕 具体类型上实现导出方法 `func (k *privateKey) CorePKey() *core.PKey`，返回持有的原生句柄
- 🆕 该方法**不得**出现在任何导出接口中（`Key` / `PrivateKey` / `PublicKey` 均不含它）—— 否则即成为公开 API
- 契约为**结构化接口**：`internal/keyaccess` 只声明形状（`interface{ CorePKey() *core.PKey }`）并做类型断言，**无注册表、无全局状态、无 `init()` 顺序依赖**；`asym` **不需要** import `keyaccess`

**生命周期**

- ➕ `func Close(k Key) error` — 释放密钥持有的底层原生句柄（幂等；`k` 为 nil 或未持句柄时返回 nil）。之前本包**完全没有释放入口**，释放只能靠 finalizer 兜底，违反 AGENTS.md §4.4；缺口记录见 `docs/issues/2026-09-24/P1006`
  - ⚠️ **别名陷阱**：`priv.Public()` 返回的公钥**共享同一底层句柄**（不做 Dup），对二者之一 `Close` 即释放该共享句柄、另一个随之失效；需要「销毁别名不影响原件」时请经 `internal/keyaccess` 取句柄后自行 `EVP_PKEY_dup`（`ecdh` 即如此），而不要依赖 `Public()`
  - 取包级函数而非接口方法的理由：三个接口刻意保持最小，把 `Close` 做成接口方法会让「可关闭」成为公开契约并需在 14 个具体类型上各补实现；包级函数返回值只有 `error`、**不暴露句柄**，导出面最小

**函数｜形态入口（`0.5.0` 新增，配合 `meta.Source` / `meta.Sink` / `meta.Passphrase`）**

- 🆕 `func LoadPrivateKeySource(src *meta.Source, passphrase *meta.Passphrase) (PrivateKey, error)`
  — 从 `Source` 读 PEM；`passphrase` 为 nil 或空时按未加密私钥解析，否则按口令解密
- 🆕 `func LoadPublicKeySource(src *meta.Source) (PublicKey, error)` — 从 `Source` 读 SPKI PEM
- 🆕 `func MarshalPrivateKeyTo(priv PrivateKey, sink *meta.Sink, passphrase *meta.Passphrase) error`
  — 未加密 → PKCS#8 PEM；带口令 → 加密 PEM，结果按 `sink` 编码写出
- 🆕 `func MarshalPublicKeyTo(pub PublicKey, sink *meta.Sink) error` — SPKI PEM 写出

**函数｜签名表示转换与 RSA-SM3（`0.6.0` 新增）**

- 🆕 `func SignatureParts(sig []byte) (r, s []byte, err error)` — DER `SEQUENCE{INTEGER r, INTEGER s}` → 两个大端分量（最小长度，不补齐）
- 🆕 `func SignatureDER(r, s []byte) ([]byte, error)` — 两个分量 → 最短形式 DER
- 🆕 `func FormatSignature(sig []byte, from, to string, width int) ([]byte, error)` — `der` ↔ `raw`；`width` 为每分量字节数（SM2 / P-256 = 32，P-384 = 48，P-521 = 66），从 der 转出时必填，从 raw 转出时可传 0 自动推断
- 适用范围：**仅 SM2 与 ECDSA**；RSA 签名本身即裸字节串，Ed25519 / Ed448 恒为定长裸签名，三者不适用
- `SignPKCS1v15` / `VerifyPKCS1v15` / `SignPSS` / `VerifyPSS` / `EncryptOAEP` / `DecryptOAEP` 的 `hash` 参数新增 `"sm3"`

**函数｜密钥格式与检查（`0.6.0` 新增）**

- `type PKCS8Options struct { Encrypt bool; Version int; Cipher, PRF string; Iterations int; Passphrase string }`
- `func MarshalPKCS8(priv PrivateKey, format meta.Format, opts *PKCS8Options) ([]byte, error)`
- `func LoadPKCS8(data []byte, format meta.Format, encrypted bool, pass string) (PrivateKey, error)`
- `func MarshalRSAPublicKeyPKCS1PEM(pub PublicKey) ([]byte, error)` / `func LoadRSAPublicKeyPKCS1PEM(data []byte) (PublicKey, error)`
- `func Check(priv PrivateKey) error` / `func PublicCheck(pub PublicKey) error`
- `func SupportsRSASignatureDigest(key Key, hash string) (bool, error)` — 铜锁 8.4.0 的 RSA-SM3 签名不可用，签/验返回 `ErrUnsupported`；OAEP-SM3 可用。`0.8.0` 已在固定 8.5.0 验证 PKCS#1 v1.5 / PSS 与 CLI 双向互验。
- PKCS#8 Version 选择 PBE 方案：1 为 PBE-SHA1-3DES；2 为 PBES2（默认 AES-256-CBC / hmacWithSHA256 / 2048 次迭代），可选 AES-128/192/256-CBC 与 HMAC-SHA1/224/256/384/512。
  它不改变 ASN.1 PrivateKeyInfo 的版本。私钥结果由调用方 `asym.Close`；源密钥与口令缓冲由调用方清零。

**规划中**

| 符号 | 目标版本 | 前置（需新增 `internal/native` 绑定） |
|---|---|---|
| 🆕 现有 `Format` / `DecryptWithOrder` 已接受 SM2 压缩 C1 输入 | `0.7.0` | 经 core 调用铜锁点解码与校验；不增加压缩输出 |
| 🆕 RSA 签名格式说明与双向互验 | `0.7.0` | 保持模数长度字节串，不能改成 SM2/ECDSA DER |
| 🆕 现有 PKCS#1 v1.5 / PSS 的 SM3 签名可运行支持 | `0.8.0` | 8.5.0 签验与 CLI 双向互验通过；8.4.0 返回 ErrUnsupported；新增 SupportsRSAPSSDigest(key Key, hash string, saltLen int) (bool, error) |
| 🆕 ED25519ph / ED25519ctx / ED448ph / Ed448 上下文 | `0.8.0` | 独立 Sign/Verify 函数，原消息输入；SupportsEdDSAInstance(key Key, instance string, context []byte) (bool, error) |
| 🧭 ML-DSA-44 / 65 / 87 | `0.13.0` | 铜锁已启用（`signature-algorithms`），需新增 `EVP_PKEY` 解封装路径 |
| 🧭 SLH-DSA 12 变体 | `0.13.0` | 同上 |
| 🧭 `func Encapsulate` / `func Decapsulate`（KEM） | `0.13.0` | `EVP_PKEY_encapsulate` / `EVP_PKEY_decapsulate` |

> 明确不做：DSA、DH、EC-ElGamal、Paillier（见 `docs/cli-comparison.md` §9）。

**破坏性变更**

- 删除 `crypto/{sm2,rsa,ecdsa,ed25519,ed448}` 5 个包与 `key` 包
- 所有算法特有的类型化函数改为**包级函数 + `PrivateKey`/`PublicKey` 接口**（不再是方法），如 `rsa.GenerateKey(2048)` → `asym.GenerateRSA(2048)`、`priv.SignPSS(…)` → `asym.SignPSS(priv, …)`
- `(*rsa.PrivateKey).Key() *core.PKey` 等 16 个句柄逃生口全部移除（修复 E1-4）
- `sm2.PublicKeyFromPKey(*core.PKey)` 移除（修复 E1-6）；`x25519` / `x448` 包的 `SharedSecret` 迁至 `ecdh`

---

**`0.8.0` EdDSA 独立入口**：

- `SignEd25519ctx` / `SignEd25519ph` / `SignEd448ph` / `SignEd448WithContext`：
  `(priv PrivateKey, msg, context []byte) ([]byte, error)`。
- `VerifyEd25519ctx` / `VerifyEd25519ph` / `VerifyEd448ph` / `VerifyEd448WithContext`：
  `(pub PublicKey, msg, sig, context []byte) error`。
- 输入为原消息；ph 在原生层完成预哈希，context 最长 255 字节，ctx 必须非空。
  错误实例/上下文/签名不互认；不可用返回 ErrUnsupported，验签失败返回 ErrSignature。
  旧 pure 入口与密钥编码保持，不新增证书/CSR/CRL 变体签发能力。

## 8. `ecdh` — 密钥协商

✅ **已有**｜旧包：`crypto/ecdh` + `crypto/{x25519,x448}`（协商部分）

语义对齐 Go 标准库 `crypto/ecdh`，并将 `crypto/x25519` / `crypto/x448` 的协商能力（`SharedSecret`）并入。**本包只做密钥协商**；密钥生成、PEM 导入导出、签名验签均在 `asym`。

**类型**

- ♻️ `type Curve struct { …（内部字段） }` — 曲线标识（原 `crypto/ecdh.Curve`）
- ♻️ `type PrivateKey struct { …（内部字段） }` — ECDH 私钥（原 `crypto/ecdh.PrivateKey`）
- ♻️ `type PublicKey struct { …（内部字段） }` — ECDH 公钥（原 `crypto/ecdh.PublicKey`）

**曲线构造**

- ♻️ `func P256() *Curve` — NIST P-256（`prime256v1`；原名不变）
- ♻️ `func P384() *Curve` — NIST P-384（`secp384r1`；原名不变）
- ♻️ `func P521() *Curve` — NIST P-521（`secp521r1`；原名不变）
- ♻️ `func Secp256k1() *Curve` — secp256k1（原名不变）
- ♻️ `func X25519() *Curve` — OKP X25519（原 `crypto/ecdh.X25519`，同时吞并 `crypto/x25519` 包）
- ♻️ `func X448() *Curve` — OKP X448（原 `crypto/ecdh.X448`，同时吞并 `crypto/x448` 包）
- 🆕 `func Curves() []string` — 返回可用曲线名（对应 `ecparam -list_curves`）
- 🆕 `func CurveByName(name string) (*Curve, error)` — 按名构造曲线（`"P-256"` / `"X25519"` / …）；未知名返回 `ErrUnknownCurve`

**函数｜由 `asym` 密钥对象构造（本版新增）**

> 机制：`asym` 的密钥**具体类型非导出**，并在其上实现导出方法 `CorePKey() *core.PKey`；该契约由 `internal/keyaccess` 以**结构化接口断言**识别（无注册表、无全局状态）。`ecdh` 取到句柄后用 `EVP_PKEY_dup` 复制，因此两侧生命周期完全独立，且公开签名中不出现任何 `internal` 类型。

- 🆕 `func LoadPrivateKey(k asym.PrivateKey) (*PrivateKey, error)` — 由 `asym` 私钥对象构造（仅 NIST / secp256k1 / OKP；RSA / Ed 系与 SM2 返回 `ErrUnsupportedKey`）
- 🆕 `func LoadPublicKey(k asym.PublicKey) (*PublicKey, error)` — 由 `asym` 公钥对象构造（协商需对端公钥）
- 🆕 `var ErrUnsupportedKey` — 哨兵错误：密钥不是可协商的曲线算法

**函数｜PEM 与口令**

- ♻️ `func LoadPrivateKeyPEM(c *Curve, pemBytes []byte) (*PrivateKey, error)` — 加载私钥 PEM（支持 PKCS#8 与传统 SEC1）
- ♻️ `func LoadPublicKeyPEM(c *Curve, pemBytes []byte) (*PublicKey, error)` — 加载 SPKI 公钥 PEM
- ♻️ `func LoadEncryptedPEM(c *Curve, pemBytes []byte, pass string) (*PrivateKey, error)` — 加载加密私钥 PEM
- ♻️ `func ChangePassword(pemBytes []byte, oldPass, newPass string) ([]byte, error)` — 更换口令
- 🆕 `func SharedSecret(priv *PrivateKey, peer *PublicKey) ([]byte, error)` — 派生共享密钥的包级形式（原 `crypto/x25519.SharedSecret` / `crypto/x448.SharedSecret`）；返回值应视为敏感数据
- 🆕 `var ErrUnknownCurve` — 哨兵错误：曲线名不在 `Curves()` 内

**方法**

- ♻️ `func (c *Curve) Name() string` — 曲线名（如 `"P-256"` / `"X25519"`）
- ♻️ `func (k *PrivateKey) ECDH(peer *PublicKey) ([]byte, error)` — 派生共享密钥（方法形式）
- ♻️ `func (k *PrivateKey) Public() (*PublicKey, error)` — 返回独立持有的配对公钥，调用方 Close
- ♻️ `func (k *PrivateKey) MarshalPEM() ([]byte, error)` — 导出私钥 PEM
- ♻️ `func (k *PrivateKey) MarshalEncryptedPEM(pass string) ([]byte, error)` — 导出加密私钥 PEM
- ♻️ `func (k *PublicKey) MarshalPEM() ([]byte, error)` — 导出 SPKI 公钥 PEM

> 安全提示：派生出的共享密钥必须经 KDF（见 `kdf`）后才能用作对称密钥；X25519/X448 的低阶点输入应视为非法并拒绝。

> 与 `asym` 的分工：**生成在 `asym`（`asym.GenerateKey(asym.AlgX25519, nil)`），协商在 `ecdh`**。`ecdh.LoadPrivateKey` / `LoadPublicKey` 负责把 `asym` 密钥对象转成 `ecdh` 对象；也可用 PEM 往返完成同样的事（`asym` 侧导出 → `ecdh.LoadPrivateKeyPEM`）。

**函数｜参数文件（`0.6.0` 新增）**

- `func MarshalParametersPEM(c *Curve, explicit bool) ([]byte, error)`
- `func LoadParametersPEM(data []byte) (*Curve, error)` / `func LoadParametersFile(path string) (*Curve, error)`
- `func GenerateKeyFromParameters(data []byte) (asym.PrivateKey, error)` — 复用 `asym` 生成，调用方用 `asym.Close` 释放。
- `func (c *Curve) Check() error` — 命名/显式参数均支持；支持 P-256/384/521 与 secp256k1，X25519/X448 无 EC 参数文件。

**`0.7.0` 已实现与后续规划**

| 符号 | 版本 | 语义 / 后续前置 |
|---|---|---|
| 🆕 `func (k *PrivateKey) Close() error` / `func (k *PublicKey) Close() error` | `0.7.0` | nil/零值/已关闭均幂等；关闭后可失败操作返回错误，查询返回约定零值 |
| 🆕 `func (k *PrivateKey) Public() (*PublicKey, error)` | `0.7.0` | BREAKING：复制为独立句柄，公私钥及源 asym 密钥独立关闭；复制失败返回 error，调用方释放返回公钥 |
| 🆕 `func DeriveSharedSecret(priv asym.PrivateKey, pub asym.PublicKey) ([]byte, error)` | `0.8.0` | 六条现有曲线，复用桥接/derive，释放临时副本，不接受 SM2DH 隐式默认参数 |
| 🆕 `func DeriveSM2DH(opts *SM2DHOptions) ([]byte, error)` | `0.8.0` | 原生 SM3 参数化派生；不是曲线名入口，不生成或验证密钥确认消息 |

**破坏性变更**

- 删除 `crypto/x25519` 与 `crypto/x448` 两个包：`x25519.SharedSecret` → `ecdh.SharedSecret` 或 `(*PrivateKey).ECDH`
- **删除 `(*Curve).GenerateKey()`**：曲线密钥生成统一走 `asym`，再用 `ecdh.LoadPrivateKey` 加载
- 删除 `crypto/ecdh` 中的 `Key() *core.PKey`（修复 E1-4）；不再对外交出原生句柄
- `LoadPrivateKey` / `LoadPublicKey` / `Curves` / `CurveByName` 为新增，无破坏性

---

**`0.8.0` SM2DH 选项**：`StaticKey` / `EphemeralKey` 为 `asym.PrivateKey`，
`PeerStaticKey` / `PeerEphemeralKey` 为 `asym.PublicKey`；`SelfID` / `PeerID` 为
`[]byte`（各 1..8191 字节），`Role SM2DHRole` 必须为 `SM2DHInitiator` 或
`SM2DHResponder`，`OutputLen int` 为 1..2147483647。摘要固定 SM3，调用期间不并发
Close 输入密钥，调用方负责认证静态公钥、重新生成临时私钥及清零输出。
`ErrUnsupported` 表示原生协商能力不可用；原通用曲线加载器仍拒绝 SM2。

## 9. `keystore` — 密钥元数据、存储与轮转

✅ **已有**｜旧包：`key`（`Handle` / `Store` / `Rotate` / `Close` 部分）

从 `key` 拆出的**算法无关**部分：密钥元数据条目、内存存储与轮转。非对称密钥抽象在 `asym`，对称密钥抽象在 `sym`，KDF 在 `kdf`。

**类型与接口**

- ♻️ `type Handle struct { ID string; Alias string; Algorithm string; Version uint32; Generation uint64; CreatedAt time.Time; Key any }` — 密钥元数据条目（原 `key.Handle`，`Algorithm` 由 `key.Algorithm` 改为 `string`，`Key` 由 `key.Key` 改为 `any`）
- ♻️ `type Store interface { Get(id string) (*Handle, error); Put(h *Handle) error; Delete(id string) error; List() ([]*Handle, error); Rotate(id string, newKey any) (*Handle, error) }` — 密钥存储（不接管密钥所有权；`newKey` 由 `key.Key` 改为 `any`）
- ♻️ `type MemoryStore struct { …（内部字段） }` — 线程安全的内存实现（原 `key.MemoryStore`）

**函数**

- ♻️ `func NewHandle(id string, key any) (*Handle, error)` — 构造密钥条目（`id` 非空、`key` 非 nil；`Algorithm` 自动填充，`Version` 起始 1，`Generation` 起始 0）
- ♻️ `func (h *Handle) Close() error` — 释放条目持有的句柄（幂等）
- ♻️ `func Close(h *Handle) error` — 包级形式（原 `key.Close(k Key)`）
- ♻️ `func (h *Handle) MarshalJSON() ([]byte, error)` / ♻️ `func (h *Handle) UnmarshalJSON(data []byte) error` — JSON 序列化（内嵌 PEM）；`UnmarshalJSON` 需先经 `SetDecoder` 注入解码器，否则返回 `ErrNoDecoder`
- ♻️ `func NewMemoryStore() *MemoryStore` — 创建空的内存密钥存储
- ♻️ `func (s *MemoryStore) Get(id string) (*Handle, error)` / `Put(h *Handle) error` / `Delete(id string) error` / `List() ([]*Handle, error)` — CRUD
- ♻️ `func (s *MemoryStore) Rotate(id string, newKey any) (*Handle, error)` — 轮转为 `Version+1` 并归档旧条目
- ♻️ `func (s *MemoryStore) History(id string) ([]*Handle, error)` — 查询被覆盖 / 轮转归档的历史版本

**错误**

- ♻️ `var ErrNotFound` — 存储中不存在该 ID（原 `key.ErrNotFound`）
- ♻️ `var ErrClosed` — 密钥已关闭（原 `key.ErrClosed`；本包 `Handle.Close` 幂等，不返回它，保留供调用方自有生命周期复用）
- ➕ `var ErrUnsupported` — 密钥类型不支持该操作（如导出 PEM）
- ➕ `var ErrNoDecoder` — 未注入 PEM 解码器，无法从 JSON 还原密钥对象

**PEM 解码器注入（因 `Key any` 带来的必要补充）**

`keystore` 不 import `asym` / `sym`（避免反向依赖），因此 **`PEM → 密钥` 这一步无法在本包内部完成**，必须由调用方注入：

- ➕ `type KeyDecoder func(pemBytes []byte) (any, error)` — 典型实现按 PEM 块类型分派到 `asym.LoadPrivateKeyPEM` / `asym.LoadPublicKeyPEM` / `sym.ParseSymmetricKey`
- ➕ `func (h *Handle) SetDecoder(d KeyDecoder) *Handle` — 注入解码器，使 `json.Unmarshal(data, h)` 可用
- ➕ `func UnmarshalHandle(data []byte, decode KeyDecoder) (*Handle, error)` — 推荐入口，无须先构造 `Handle`

`MarshalJSON` 方向不需要注入：包内窄接口 `Marshal() / MarshalPrivateKeyPEM() / MarshalPublicKeyPEM()` 已覆盖 `sym` 与 `asym` 的导出方法。

> ⚠️ **待确认的设计点**：`Handle.Key` 用 `any`，以避免 `keystore` 反向依赖 `asym`/`sym`（算法已由 `Handle.Algorithm` 字段承载）。备选方案：让 `asym` / `sym` 的 `Algorithm()` 返回 `string`，则 `keystore` 可定义 `type Key interface{ Algorithm() string }` 获得静态约束。
>
> ⚠️ **安全提示**：`MarshalJSON` 内嵌 PEM，**私钥未加密、对称密钥明文**，仅适合配置分发与本地落盘，不得用于不可信信道。

**破坏性变更**

- 删除 `key` 包；`key.Handle` / `key.Store` / `key.MemoryStore` / `key.NewHandle` / `key.Close` → `keystore.*`
- `key.Algorithm` / `key.Alg*` → `asym.Algorithm`（非对称）/ `sym.Algorithm`（对称）；`key.Hash` / `key.Hash*` → `kdf.Hash` / `kdf.Hash*`
- `key.CoreKey` 公开接口移除（修复 E1-1）：`jwk.MarshalKey(key.CoreKey)` 与 `pkcs12.PrivateKey` 别名均需改用 `asym.PrivateKey`
- `key.PEM` / `key.ParsePEM` → `asym.PEM` / `asym.ParsePEM`

---

**函数｜本地统一加载（`0.6.0` 新增）**

- `func Load(uri string) (asym.Key, error)` / `func LoadAll(uri string) ([]asym.Key, error)`
- `func LoadWithPassphrase(uri string, pass *meta.Passphrase) (asym.Key, error)`
- `func LoadFromReader(r io.Reader) (asym.Key, error)` / `func LoadAllFromReader(r io.Reader, pass *meta.Passphrase) ([]asym.Key, error)`
- 只接受本地路径、file URI、`-`（stdin）；自动识别 PEM 多对象、PKCS#8/PKCS#1/SEC1/SPKI DER、PKCS#12；PEM 证书/CRL 忽略，未知块报错；单对象入口遇多密钥报错。
  失败不返回部分密钥，成功结果由调用方逐个 `asym.Close`。

## 10. `x509` — 证书 / CSR / CRL / OCSP 与链验证

✅ **已有**｜旧包：`x509` + `ocsp`（**撤回拆分**，CSR / CRL / OCSP 均不独立成包）

把 `Certificate` / `CertificateRequest` / `CRL` / OCSP 收回同一个包（对应 CLI `x509` + `req` + `crl` + `ocsp` + `verify`）。**直接动因**：拆分后 `x509.Store.AddCRL(*crl.CRL)` 与 `crl.NewBuilder(issuer *x509.Certificate)` 构成**循环依赖**，Go 无法编译。文件组织沿用现有布局：`x509.go` / `csr.go` / `crl.go` / `ocsp.go` / `name.go` / `store.go` / `helpers.go`。

> 注：`ocsp → x509` 本身是**单向无环**，合并 OCSP 并非解决循环依赖所必需；此处按决策一并合并，收益是少一个包、PKI 家族收口。

**类型｜证书与名字**

- ♻️ `type Certificate struct { …（内部字段） }` — X.509 证书
- ♻️ `type Extension struct { Nid int; Field string; OID string; Critical bool; Value string; Data []byte }` — 单个 X.509 扩展（`Value` 为构建用的 `X509V3_EXT_conf` 配置串，`Data` 为读取到的 DER 值）
- ✨ `type CertificatePolicy struct { OID string; CPSURIs []string; UserNotice *UserNotice }` — certificatePolicies 扩展中的一条策略（`OID` 为策略标识符；`CPSURIs` 为 id-qt-cps 限定符的策略声明 URL 列表；`UserNotice` 为 id-qt-unotice 限定符）
- ✨ `type UserNotice struct { Organization string; NoticeNumbers []int; ExplicitText string }` — certificatePolicies 的 userNotice 限定符（RFC 5280 §4.2.1.4）
- ♻️ `type Name struct { …（内部字段） }` — 证书 subject / issuer 名字（RDN 值按 **UTF-8** 写入，非 ASCII 字符原样保存为 `UTF8String`；非法 UTF-8 报错；`Add` 按**调用顺序追加**，DER 顺序 = 书写顺序，与 `openssl -subj` 一致；`Entries()` / `Get()` 不再受 256 字节缓冲限制）
- ♻️ `type NameEntry struct { Nid int; Field string; Value string }` — 名字中的单个 RDN 条目

**类型｜CSR / CRL / OCSP**

- ♻️ `type CertificateRequest struct { …（内部字段） }` — PKCS#10 证书请求（原 `x509.CertificateRequest`）
- ♻️ `type CRL struct { …（内部字段） }` — 证书吊销列表（原 `x509.CRL`）
- ♻️ `type RevokedEntry struct { SerialHex string; Serial int64; RevocationDate time.Time; ReasonCode int; Reason string }` — CRL 记录，Serial 仅为受限兼容视图
- 🆕 `type CRLBuilder struct { …（内部字段） }` — CRL 构建器（原拟名 `crl.Builder`，加 `CRL` 前缀避免与本包其他构建器混淆）
- 🆕 `type RevocationReason int` — 吊销原因码（对应 `crl -crl_reason`）
- ♻️ `type Response struct { Status int; StatusText string; ProducedAt time.Time; CertStatus int; CertStatusText string; RevocationTime time.Time; RevocationReason int; ReasonText string; ThisUpdate time.Time; NextUpdate time.Time; ResponderCerts []*Certificate }` — OCSP 响应

> ℹ️ **不引入 `type Request`**（修正）：本文件早期版本在类型清单里列过
> `type Request struct{…}`，但同节 `CreateOCSPRequest` 的签名是 `(cert, issuer
> *Certificate, hash string) ([]byte, error)`，不返回 `*Request`；而原 `ocsp` 包也
> 不存在所谓「隐式请求类型」（`ocsp.CreateRequest` 返回的就是 `[]byte`）。二者矛盾，
> 已按可执行的那一条收敛：**OCSP 请求在公开层就是一段 DER 字节**，调用方直接 POST，
> 无需句柄语义。详见 `docs/issues/2026-09-24/P1007`。

**类型｜链验证**

- ♻️ `type Store struct { …（内部字段） }` — 信任锚 / CRL 存储
- ♻️ `type VerifyError struct { Code int; Depth int; Message string }` — 链验证失败（`Code` 为 `X509_V_ERR_*` 码）

**常量｜OCSP 证书状态（加重前缀以免与同包其他符号相撞）**

- ♻️ `OCSPGood = 0` / ♻️ `OCSPRevoked = 1` / ♻️ `OCSPUnknown = 2` — 原 `ocsp.Good` / `ocsp.Revoked` / `ocsp.Unknown`

**常量｜CRL 吊销原因码（RFC 5280 §5.3.1，对应 `openssl crl -crl_reason`）**

- 🆕 `ReasonUnspecified = 0` / `ReasonKeyCompromise = 1` / `ReasonCACompromise = 2` /
  `ReasonAffiliationChanged = 3` / `ReasonSuperseded = 4` / `ReasonCessationOfOperation = 5` /
  `ReasonCertificateHold = 6` / `ReasonRemoveFromCRL = 8` / `ReasonPrivilegeWithdrawn = 9` /
  `ReasonAACompromise = 10` — 类型为 `RevocationReason`；7 为 RFC 5280 保留值，
  刻意不提供常量且 `Revoke` 会拒绝

**证书加载与导出**

- ♻️ `func LoadCertificatePEM(pemBytes []byte) (*Certificate, error)` — 从 PEM 加载
- ♻️ `func LoadCertificateDER(der []byte) (*Certificate, error)` — 从 DER 加载
- ♻️ `func (c *Certificate) MarshalPEM() ([]byte, error)` / `MarshalDER() ([]byte, error)` — 导出
- ♻️ `func (c *Certificate) Close() error` — 释放底层句柄（幂等）

**证书读取**

- ♻️ `func (c *Certificate) Subject() string` / `Issuer() string` — 单行 subject / issuer
- ♻️ `func (c *Certificate) NotBefore() time.Time` / `NotAfter() time.Time` — 有效期
- ♻️ `func (c *Certificate) Serial() int64` / `Version() int` — 序列号与版本
- ♻️ `func (c *Certificate) SubjectName() *Name` / `IssuerName() *Name` — 结构化名字
- ♻️ `func (c *Certificate) SubjectEntries() []NameEntry` / `IssuerEntries() []NameEntry` — RDN 条目
- ♻️ `func (c *Certificate) SubjectText() string` / `IssuerText() string` — OpenSSL 风格文本
- ♻️ `func (c *Certificate) SAN() []string` — 主题备用名
- ♻️ `func (c *Certificate) KeyUsage() []string` / `ExtendedKeyUsage() []string` — 用途
- ♻️ `func (c *Certificate) IsCA() bool` / `PathLen() int64` — BasicConstraints
- ♻️ `func (c *Certificate) SubjectKeyID() []byte` / `AuthorityKeyID() []byte` — SKID / AKID
- ♻️ `func (c *Certificate) CertificateType() string` — 公钥算法名（如 `"SM2"` / `"RSA"` / `"EC"`）
- ♻️ `func (c *Certificate) Extensions() []Extension` — 全部扩展
- ✨ `func (c *Certificate) SerialHex() string` — 序列号大写十六进制（超出 int64 范围时用它代替 `Serial`；对应 `-serial`）
- ✨ `func (c *Certificate) SubjectHash() uint32` / `IssuerHash() uint32` — `X509_NAME_hash`（对应 `-subject_hash` / `-issuer_hash`，也是 CA 目录 `hash.N` 的那个 hash）
- ✨ `func (c *Certificate) CheckEmail(email string) error` — 邮箱校验（对应 `verify -verify_email`；只做名字匹配，不验链）
- ♻️ `func (c *Certificate) Fingerprint(hash string) (string, error)` — 指纹（十六进制；参数名由 `alg` 改为 `hash`，与全局取向一致）

**证书加载与落盘**

- ♻️ `func LoadCertificatePEM(pemBytes []byte) (*Certificate, error)` / `LoadCertificateDER(der []byte) (*Certificate, error)`
- ✨ `func LoadCertificatePEMFile(path string) (*Certificate, error)` — 从文件加载（对应 `openssl x509 -in <path>`）
- ✨ `func SaveCertificatePEMFile(path string, c *Certificate, perm os.FileMode) error` — 写入 PEM 文件（对应 `-out`；显式 chmod，因为 `os.WriteFile` 不改已存在文件的权限）

**证书构建与签发**

- ♻️ `func NewCertificate() *Certificate` — 创建空证书
- ♻️ `func (c *Certificate) SetVersion(v int) error` / `SetSerial(serial int64) error` / `SetIssuer(n *Name) error` / `SetSubject(n *Name) error` / `SetValidity(notBefore, notAfter time.Time) error` / `SetPublicKey(pub asym.PublicKey) error` — 分步设置
- ♻️ `func (c *Certificate) AddBasicConstraints(isCA bool) error` / `AddSubjectAltName(value string) error` / `AddKeyUsage(value string) error` / `AddExtendedKeyUsage(value string) error` / `AddSubjectKeyID() error` / `AddAuthorityKeyID(issuer *Certificate) error` — 预置扩展
- ✨ `func (c *Certificate) AddExtension(nid int, value string) error` — 任意扩展（按 NID，`value` 为 OpenSSL `X509V3_EXT_conf` 配置串）
- ✨ `func (c *Certificate) AddExtensionByName(name, value string) error` — 任意扩展（按短名 / 长名 / 点分 OID，内部走 `OBJ_txt2nid`）
- ✨ `func (c *Certificate) AddExtensions(exts ...Extension) error` — 批量添加（只用 `Extension` 的 `Nid` / `Value`）
- ✨ `func (c *Certificate) HasExtension(name string) bool` — 扩展是否存在（只读，已签名证书可调用）
- ✨ `func (c *Certificate) RemoveExtension(name string) error` — 删除扩展（**须在 `Sign` 之前**）
- ✨ `func (c *Certificate) ReplaceExtension(name, value string) error` — 覆盖扩展并保持原位置（不存在时报错，语义对齐 BouncyCastle `X509ExtensionsGenerator`）

  > **重复扩展规则**：`AddExtension*` 遇到已存在的 NID 时，可重复 OID
  > （`subjectAltName` / `issuerAltName` / `subjectDirectoryAttributes` / `certificateIssuer`）
  > 会把新值**合并**进同一条目（OpenSSL 不接受两个同 NID 条目——那会让 `SAN()` 与
  > `VerifyHostname()` 全部失效）；其余 OID 返回 `x509: extension already present (nid N)`，
  > 需覆盖请改用 `ReplaceExtension`。

**证书策略扩展（certificatePolicies，OID `2.5.29.32`）**

> 证书策略的 **CPS / userNotice 限定符**无法用 OpenSSL 的扩展配置串表达——那个语法
> 只认配置文件的 `@section` 形式（本库不读配置文件）。本组 API 不经过 OpenSSL 的
> 扩展配置解析，由库内纯 Go 的 DER 编解码器直接构造/解析扩展值。

- ✨ `func (c *Certificate) AddCertificatePolicies(policies []CertificatePolicy, critical bool) error` — 写入 certificatePolicies 扩展（列表不可为空、OID 不可重复；须在 `Sign` 之前）
- ✨ `func (r *CertificateRequest) AddCertificatePolicies(policies []CertificatePolicy, critical bool) error` — CSR 侧对称入口（须在 `Sign` 之前）
- ✨ `func (b *CRLBuilder) AddCertificatePolicies(policies []CertificatePolicy, critical bool) error` — CRL 侧入口（`certificatePolicies` 非 RFC 5280 §5.2 定义的 CRL 扩展，仅为对齐 `openssl ca -crlexts` 产物）
- ✨ `func (c *Certificate) CertificatePolicies() ([]CertificatePolicy, error)` — 读回策略列表（无该扩展时返回 `(nil, nil)`）
- ✨ `func (r *CertificateRequest) CertificatePolicies() ([]CertificatePolicy, error)` — CSR 侧读回
- ✨ `func (c *CRL) CertificatePolicies() ([]CertificatePolicy, error)` — CRL 侧读回

  > **编码差异**：CPS 限定符按 RFC 5280 用 IA5String；`organization` / `explicitText`
  > 用 UTF8String（RFC 5280 的 DisplayText CHOICE 允许）。铜锁 openssl 的配置文件路径
  > 用 VisibleString，对非 ASCII 内容会产出**不合规**的 DER；本库的 UTF8String 产出合规
  > DER，且铜锁能正常读回。读侧四种 DisplayText 分支（UTF8String / VisibleString /
  > IA5String / BMPString）均接受，因此由 openssl 生成的证书也能读回。
- ♻️ `func (c *Certificate) Sign(signer asym.PrivateKey) error` — 用签发者私钥签名（**单向终态**：成功后所有 `Set*` / `Add*` / 再次 `Sign` 均返回 `x509: certificate already signed`）
- ♻️ `func CreateCertificate(subject, issuer *Name, serial int64, notBefore, notAfter time.Time, pub asym.PublicKey, signer asym.PrivateKey) (*Certificate, error)` — 一步创建并签发
- 🆕 `func CreateSelfSigned(subject *Name, serial int64, notBefore, notAfter time.Time, pub asym.PublicKey, signer asym.PrivateKey) (*Certificate, error)` — 一行生成自签证书（等价 `req -x509`；内部自动设 issuer = subject 并补 SKID/AKID）

**证书验签与公钥**

- ♻️ `func (c *Certificate) Verify(signerPub asym.PublicKey) error` — 用公钥验证签名
- ♻️ `func (c *Certificate) SelfSigned() (bool, error)` — 判断是否自签
- 🆕 `func (c *Certificate) PublicKey() (asym.PublicKey, error)` — 以 `asym.PublicKey` 返回公钥（**替代原 `PublicKey() (*sm2.PublicKey, error)` 与 `PublicKeyPKey() (*core.PKey, error)`，修复 E1-9**）
- ♻️ `func (c *Certificate) Signature() []byte` — 原始签名值
- ♻️ `func (c *Certificate) SignatureAlgorithm() string` / `SignatureAlgorithmOID() string` — 签名算法名 / OID
- 🆕 `func (c *Certificate) VerifyHostname(host string) error` — 主机名 / IP 校验（对应 `verify -verify_hostname`；`cli-comparison.md` §6.B B8，P1）
- ✨ `func (c *Certificate) ToCertificateRequest(priv asym.PrivateKey) (*CertificateRequest, error)` — 证书转 CSR（对应 `x509 -x509toreq`；**不迁移扩展**，与 openssl 一致）

**CSR**

- ♻️ `func NewCertificateRequest(subject *Name, pub asym.PublicKey, priv asym.PrivateKey) (*CertificateRequest, error)` — 一步创建并签名 CSR（回到原 `x509` 名称）
- ♻️ `func NewEmptyCertificateRequest() *CertificateRequest` — 空白 CSR（供分步构建）
- ♻️ `func LoadCertificateRequestPEM(pemBytes []byte) (*CertificateRequest, error)` / `LoadCertificateRequestDER(der []byte) (*CertificateRequest, error)` — 加载
- ♻️ `func (r *CertificateRequest) SetSubject(n *Name) error` / `SetPublicKey(pub asym.PublicKey) error` / `Sign(priv asym.PrivateKey) error` / `Verify() error` — 构建与自校验
- ♻️ `func (r *CertificateRequest) MarshalPEM() ([]byte, error)` / `MarshalDER() ([]byte, error)` — 导出
- ♻️ `func (r *CertificateRequest) SubjectName() *Name` / `SubjectEntries() []NameEntry` / `SubjectText() string` — subject 读取
- ♻️ `func (r *CertificateRequest) SetChallengePassword(pwd string) error` / `ChallengePassword() string` — challengePassword 属性（`pwd` 按 **UTF-8** 写入；内含 `\x00` 仍按 C 字符串截断）
- ♻️ `func (r *CertificateRequest) AddExtensions(exts ...Extension) error` / `AddExtension(nid int, value string) error` / `AddSubjectAltName(value string) error` / `Extensions() []Extension` — 扩展
- ✨ `func (r *CertificateRequest) AddExtensionByName(name, value string) error` — 任意扩展（按短名 / 长名 / 点分 OID）
- ✨ `func (r *CertificateRequest) AddKeyUsage(value string) error` / `AddExtendedKeyUsage(value string) error` / `AddBasicConstraints(isCA bool) error` — 与 `Certificate` 对称的便利方法

  > 注：CSR 侧**不提供** `AddSubjectKeyID`——OpenSSL 在 `X509_REQ` 上没有 subject 公钥
  > 上下文，`"hash"` 会报 `s2i_skey_id: no subject details`。
- 🆕 `func (r *CertificateRequest) PublicKey() (asym.PublicKey, error)` — 公钥（**替代原 `(*sm2.PublicKey, error)` 与 `PublicKeyPKey() (*core.PKey, error)`**）
- ♻️ `func (r *CertificateRequest) Signature() []byte` / `SignatureAlgorithm() string` / `SignatureAlgorithmOID() string` — 签名信息

**CA 签发入口**

- ✨ `func IssueCertificateFromRequest(req *CertificateRequest, issuer *Certificate, signer asym.PrivateKey, opts *IssueOptions) (*Certificate, error)` — 依据 CSR 签发（等价 `openssl ca` 的最小可用子集）
- ✨ `type IssueOptions struct { SerialBigInt *big.Int; Serial int64; NotBefore, NotAfter time.Time; Extensions []Extension; CopyRequestExtensions bool }`

  > `CopyRequestExtensions` 默认为 `false`（对齐 `openssl ca` 的 `copy_extensions none`）；
  > 开启时也**只拷白名单**（SAN / KeyUsage / EKU / BasicConstraints），且 `Extensions`
  > 优先——避免请求方自选 SAN 拿到任意域名的证书。

**CRL**

- ♻️ `func ParseCRL(data []byte) (*CRL, error)` / ♻️ `func LoadCRLPEM(pemBytes []byte) (*CRL, error)` / ♻️ `func LoadCRLDER(der []byte) (*CRL, error)` — 解析与加载
- ♻️ `func (c *CRL) MarshalPEM() ([]byte, error)` / `MarshalDER() ([]byte, error)` / `Close() error` — 导出与释放
- ♻️ `func (c *CRL) Issuer() *Name` / `IssuerEntries() []NameEntry` / `IssuerText() string` — 颁发者
- ♻️ `func (c *CRL) Version() int` / `Number() int64` — 版本与 CRL 号
- ♻️ `func (c *CRL) LastUpdate() time.Time` / `NextUpdate() time.Time` — 本次 / 下次更新
- ♻️ `func (c *CRL) RevokedEntries() []RevokedEntry` — 吊销记录
- ♻️ `func (c *CRL) IsRevoked(cert *Certificate) bool` — 查询某证书是否被吊销
- ♻️ `func (c *CRL) Extensions() []Extension` — 全部扩展
- ♻️ `func (c *CRL) Signature() []byte` / `SignatureAlgorithm() string` / `SignatureAlgorithmOID() string` / `AuthorityKeyID() []byte` — 签名信息
- ♻️ `func (c *CRL) Verify(issuer *Certificate) error` — 用颁发者证书校验 CRL 签名
- 🆕 `func NewCRLBuilder(issuer *Certificate) (*CRLBuilder, error)` — 创建构建器（自动取 issuer、补 AKID）
- 🆕 `func (b *CRLBuilder) SetNumber(n int64) error` / `SetThisUpdate(t time.Time) error` / `SetNextUpdate(t time.Time) error` — 设置元数据
- 🆕 `func (b *CRLBuilder) Revoke(cert *Certificate, at time.Time, reason RevocationReason) error` — 追加一条吊销记录
- ✨ `func (b *CRLBuilder) AddExtension(nid int, value string) error` — 追加任意 CRL 扩展（按 NID，`value` 为 OpenSSL `X509V3_EXT_conf` 配置串；issuer 取自构建器）
- ✨ `func (b *CRLBuilder) AddExtensionByName(name, value string) error` — 追加任意 CRL 扩展（按短名 / 长名 / 点分 OID）
- 🆕 `func (b *CRLBuilder) Sign(signer asym.PrivateKey) (*CRL, error)` — 签发并返回可导出的 CRL
- 🆕 `func (b *CRLBuilder) Close() error` — 释放尚未签发的句柄（幂等；已签发后为 no-op，因句柄已转移给 `*CRL`）
- ♻️ `func RevocationCheck(cert *Certificate, crls []*CRL) error` — 在给定 CRL 集合中检查吊销状态

**OCSP**

- ♻️ `func CreateOCSPRequest(cert, issuer *Certificate, hash string) ([]byte, error)` — 构造 OCSP 请求（DER）；`hash` 取 `"sha1"` / `"sha256"` / `"sm3"`，空值等价 sha1。原 `ocsp.CreateRequest`，加 `OCSP` 前缀（与 `internal/core.CreateOCSPRequest` 同名）
- ♻️ `func ParseOCSPResponse(der []byte, cert, issuer *Certificate) (*Response, error)` — 解析响应并查找目标证书状态（原 `ocsp.ParseResponse`）
- ♻️ `func (r *Response) Verify(roots *Store, intermediates []*Certificate) error` — 校验响应签名链
- ♻️ `func (r *Response) Close() error` — 释放底层响应（幂等）

**链验证**

- ♻️ `func NewStore() *Store` — 创建信任锚存储
- ♻️ `func (s *Store) AddCert(c *Certificate) error` — 加入受信证书
- ♻️ `func (s *Store) AddCRL(c *CRL) error` — 加入 CRL（**同包参数，不再构成循环依赖**）
- ♻️ `func (s *Store) SetCRLCheck() error` / `SetCRLCheckAll() error` — 启用 CRL 检查（叶子 / 全链）
- ♻️ `func (s *Store) SetFlags(flags uint64) error` — 设置 `X509_V_FLAG_*`
- 🆕 `func (s *Store) SetTime(t time.Time) error` — 指定验证时刻（对应 `verify -attime`）
- ♻️ `func ChainVerify(cert *Certificate, roots *Store, intermediates []*Certificate) ([]*Certificate, error)` — 验证链并返回完整链（索引 0 为叶证书）；失败返回 `*VerifyError`

> 安全提示：`RevocationCheck` 不阻止链上其他校验；若需在链验证阶段强制 CRL 检查，用 `Store.SetCRLCheck*`。OCSP 只做「请求构造 + 响应解析与验签」，**不含 HTTP 传输**（调用方自行发送）。CertID 匹配采用自适应摘要（sha1 → sha256 → sm3）。

**函数｜形态入口（`0.5.0` 新增，配合 `meta.Source` / `meta.Sink` / `meta.Format`）**

- 🆕 `func MarshalFormat(c *Certificate, format meta.Format) ([]byte, error)` — 按 `FormatPEM` / `FormatDER` 序列化
- 🆕 `func LoadCertificateSource(src *meta.Source) (*Certificate, error)` — 自动识别 PEM / DER
  （内容首个非空白字节为 `-----BEGIN` 即按 PEM，前导空白会被剔除）
- 🆕 `func MarshalCertificateTo(c *Certificate, sink *meta.Sink, format meta.Format) error`
- 🆕 `func MarshalCSRTo(r *CertificateRequest, sink *meta.Sink, format meta.Format) error`

**函数｜OCSP、信任属性与加载（`0.6.0` 新增）**

- `func CreateOCSPRequestWithNonce(cert, issuer *Certificate, hash string, nonce []byte) ([]byte, error)` — nil nonce 随机生成 32 字节，非 nil 须 1..32 字节。
- `func FetchOCSP(url string, req []byte, timeout time.Duration) (*Response, error)` — HTTP POST、4 MiB 限制、不跟随重定向、零 timeout 为 10 秒；匹配请求 CertID 与 nonce。仍须 `Verify` 并检查状态/时间；返回响应与其 `ResponderCerts` 均由调用方 `Close`。
- `func (r *Response) CheckNonce(req []byte) error` — 请求包含 nonce 时，响应缺失或不匹配均报错；不验证响应签名。
- `func LoadTrustedCertificatePEM(data []byte) (*Certificate, error)` / `func (c *Certificate) MarshalTrustedPEM() ([]byte, error)`
- `func (c *Certificate) AddTrust(purpose string) error` / `AddReject` / `ClearTrust() error` / `ClearReject() error` — 用途为 OpenSSL 名称或点分 OID；AUX 属性不属于签名内容，普通 PEM/DER 不包含这些属性。
- `func LoadFromURI(uri string) ([]*Certificate, []*CRL, error)` / `func LoadFromReader(r io.Reader) ([]*Certificate, []*CRL, error)` — 本地 PEM 多对象/单 DER，忽略密钥块，错误时释放全部部分结果；成功由调用方逐个 `Close`。
- `ToCertificateRequest`、`SubjectHash`、`Store.SetTime`/`ChainVerify` 与任意扩展入口为既有能力，不引入重复签名。

**`0.7.0` 已实现与后续规划**

| 符号 | 版本 | 语义 / 后续前置 |
|---|---|---|
| 🆕 `func (r *CertificateRequest) Close() error` | `0.7.0` | 复用 core Close；幂等，关闭后可失败操作返回错误 |
| 🆕 `func (c *Certificate) SerialBigInt() (*big.Int, error)` | `0.7.0` | 无损读取；结果为独立对象，已关闭/缺失序列号及转换失败返回错误，不以 int64 溢出值代替 |
| 🆕 `func (c *Certificate) SetSerialBigInt(serial *big.Int) error` | `0.7.0` | 复制输入；正整数，DER INTEGER 内容含符号补零不超过 20 octets；仍禁止签名后修改 |
| 🆕 旧 SetSerial 等 int64 写入口收紧校验 | `0.7.0` | 保留签名，统一拒绝零和负数；交付时记录行为变化与迁移 |
| 🆕 `IssueOptions.SerialBigInt *big.Int` | `0.7.0` | CSR 签发无损序列号；非 nil 且旧 Serial 非零时报冲突，nil 保留旧路径，调用时复制 |
| 🆕 `RevokedEntry.SerialHex string` | `0.7.0` | 无损读取完整 ASN.1 INTEGER；旧 `Serial int64` 保留为受限兼容视图 |
| 🆕 `func (e RevokedEntry) SerialBigInt() (*big.Int, error)` | `0.7.0` | 从完整 SerialHex 取得独立大整数；缺失或无效时明确报错，不回退到受限 Serial 字段 |
| 🆕 `func (b *CRLBuilder) RevokeSerial(serial *big.Int, at time.Time, reason RevocationReason) error` | `0.7.0` | 无需被吊销证书；复制输入并校验序列号、原因码与构建器状态，归属与授权由调用方确认 |
| 🆕 `func (b *CRLBuilder) RevokeSerialHex(serial string, at time.Time, reason RevocationReason) error` | `0.7.0` | hex 适配入口，复用 RevokeSerial 的完整值与校验路径 |
| 🆕 现有 `Revoke(cert)` / `IsRevoked(cert)` / `RevocationCheck` 使用完整序列号 | `0.7.0` | 不经 int64 中转，按整数值匹配，保持各入口既有 issuer/信任边界；见 I-23/I-24 |
| 🆕 `func (c *Certificate) AddExtensionDER(oid string, critical bool, der []byte) error` | `0.7.0` | 按已知/自定义 OID 写入原始扩展值，保持签名后不可变 |
| 🆕 `func (s *Store) SetDefaultPaths() error` | `0.7.0` | `X509_STORE_set_default_paths`；铜锁默认路径不等于平台原生信任库 |
| 🆕 `func (s *Store) LoadLocations(caFile, caDir string) error` | `0.7.0` | `X509_STORE_load_locations`；不隐式信任输入链根 |
| 🆕 带扩展的分步证书签发示例与入口说明 | `0.7.0` | 复用 `NewCertificate` → Set/Add → Sign，不新增重复便捷入口 |
| 🧭 CRL 配置式签发与应用级组合入口 | `1.0.0` | 复用现有内存构建流程，与公开面收敛一并设计 |
| 🧭 `ca` 式数据库化签发 / 吊销 / 续期 | 暂缓，不承诺版本 | 文件系统状态机不列入容器/协议里程碑 |

完整序列号入口为 I-23/I-24 与 I-18/I-20 的同一工作项，已在 0.7.0 实现；`big.Int`
来自标准库 `math/big`。现有 `CreateCertificate` / `CreateSelfSigned` 的 int64 签名保留，
大整数签发使用 `NewCertificate` → `SetSerialBigInt` → Set/Add → `Sign`；
不为每个便捷函数平行扩充所有序列号表示。输入边界与兼容性验收见
[功能需求记录 §3](requirements.md#3-crl-与完整序列号职责判断与排期)。

**破坏性变更**

- **撤回**原「拆 `csr` / `crl` / `ocsp`」方案：三者并入 `x509`（`x509.Store.AddCRL(*crl.CRL)` ↔ `crl.NewBuilder(*x509.Certificate)` 的循环依赖是直接动因）
- **删除** `x509.PublicKey` / `x509.PrivateKey` 窄接口（`Key() *core.PKey`）；公开签名一律直接用 `asym.PublicKey` / `asym.PrivateKey`（修复 E1-11）。代价：`x509` 不再接受第三方自定义密钥类型（实际上也拿不到原生句柄，无损失）
- `ocsp.Good` / `Revoked` / `Unknown` → `x509.OCSPGood` / `OCSPRevoked` / `OCSPUnknown`；`ocsp.CreateRequest` → `x509.CreateOCSPRequest`；`ocsp.ParseResponse` → `x509.ParseOCSPResponse`
- `Certificate.Core()` / `Store.Core()` / `WrapCertificate(*core.Certificate)` 全部移除（修复 E1-8 / E1-10）

---

**验证错误码（`0.9.0` 新增）**

- 🆕 `func VerifyErrorMessage(code int) string` — 返回铜锁验证码解释，包括未命名的未知码。
- 🆕 `VerifyOK` 及 `Verify*` 常量 — 覆盖铜锁 8.4.0 的全部 X509_V_OK / X509_V_ERR_*（0–94），不代表某次连接确实执行过验证；TLS 请另查 ConnectionState.Verification。

| 验证码 | 公开常量（按值递增） |
|---|---|
| 0–16 | `VerifyOK` / `VerifyUnspecified` / `VerifyUnableToGetIssuerCert` / `VerifyUnableToGetCRL` / `VerifyUnableToDecryptCertSignature` / `VerifyUnableToDecryptCRLSignature` / `VerifyUnableToDecodeIssuerPublicKey` / `VerifyCertSignatureFailure` / `VerifyCRLSignatureFailure` / `VerifyCertNotYetValid` / `VerifyCertHasExpired` / `VerifyCRLNotYetValid` / `VerifyCRLHasExpired` / `VerifyErrorInCertNotBeforeField` / `VerifyErrorInCertNotAfterField` / `VerifyErrorInCRLLastUpdateField` / `VerifyErrorInCRLNextUpdateField` |
| 17–28 | `VerifyOutOfMem` / `VerifyDepthZeroSelfSignedCert` / `VerifySelfSignedCertInChain` / `VerifyUnableToGetIssuerCertLocally` / `VerifyUnableToVerifyLeafSignature` / `VerifyCertChainTooLong` / `VerifyCertRevoked` / `VerifyNoIssuerPublicKey` / `VerifyPathLengthExceeded` / `VerifyInvalidPurpose` / `VerifyCertUntrusted` / `VerifyCertRejected` |
| 29–46 | `VerifySubjectIssuerMismatch` / `VerifyAKIDSKIDMismatch` / `VerifyAKIDIssuerSerialMismatch` / `VerifyKeyUsageNoCertSign` / `VerifyUnableToGetCRLIssuer` / `VerifyUnhandledCriticalExtension` / `VerifyKeyUsageNoCRLSign` / `VerifyUnhandledCriticalCRLExtension` / `VerifyInvalidNonCA` / `VerifyProxyPathLengthExceeded` / `VerifyKeyUsageNoDigitalSignature` / `VerifyProxyCertificatesNotAllowed` / `VerifyInvalidExtension` / `VerifyInvalidPolicyExtension` / `VerifyNoExplicitPolicy` / `VerifyDifferentCRLScope` / `VerifyUnsupportedExtensionFeature` / `VerifyUnnestedResource` |
| 47–61 | `VerifyPermittedViolation` / `VerifyExcludedViolation` / `VerifySubtreeMinMax` / `VerifyApplicationVerification` / `VerifyUnsupportedConstraintType` / `VerifyUnsupportedConstraintSyntax` / `VerifyUnsupportedNameSyntax` / `VerifyCRLPathValidationError` / `VerifyPathLoop` / `VerifySuiteBInvalidVersion` / `VerifySuiteBInvalidAlgorithm` / `VerifySuiteBInvalidCurve` / `VerifySuiteBInvalidSignatureAlgorithm` / `VerifySuiteBLoSNotAllowed` / `VerifySuiteBCannotSignP384WithP256` |
| 62–78 | `VerifyHostnameMismatch` / `VerifyEmailMismatch` / `VerifyIPAddressMismatch` / `VerifyDANENoMatch` / `VerifyEEKeyTooSmall` / `VerifyCAKeyTooSmall` / `VerifyCAMDTooWeak` / `VerifyInvalidCall` / `VerifyStoreLookup` / `VerifyNoValidSCTS` / `VerifyProxySubjectNameViolation` / `VerifyOCSPVerifyNeeded` / `VerifyOCSPVerifyFailed` / `VerifyOCSPCertUnknown` / `VerifyUnsupportedSignatureAlgorithm` / `VerifySignatureAlgorithmMismatch` / `VerifySignatureAlgorithmInconsistency` |
| 79–94 | `VerifyInvalidCA` / `VerifyPathLenInvalidForNonCA` / `VerifyPathLenWithoutKUKeyCertSign` / `VerifyKUKeyCertSignInvalidForNonCA` / `VerifyIssuerNameEmpty` / `VerifySubjectNameEmpty` / `VerifyMissingAuthorityKeyIdentifier` / `VerifyMissingSubjectKeyIdentifier` / `VerifyEmptySubjectAltName` / `VerifyEmptySubjectSANNotCritical` / `VerifyCABasicConstraintsNotCritical` / `VerifyAuthorityKeyIdentifierCritical` / `VerifySubjectKeyIdentifierCritical` / `VerifyCACertMissingKeyUsage` / `VerifyExtensionsRequireVersion3` / `VerifyECKeyExplicitParams` |

---

## 11. `tls` — TLS / NTLS 传输层

✅ **已有**｜旧包：`tls`

客户端与服务端共享 `Config`；`0.9.0` 新增显式 `Protocol` 与 `Verification`，旧 `NTLS` 字段仍可用。
零值验证策略保留旧入口实际行为：客户端 `RootCAs` 非空或 `ServerName` 非空且未
`InsecureSkipVerify` 时开启验证，否则不验证；显式策略见下。

**常量**

- ♻️ `TLS1Version uint16 = 0x0301`、`TLS1_1Version = 0x0302`、`TLS1_2Version = 0x0303`、`TLS1_3Version = 0x0304` — 供 `Config.MinVersion` / `MaxVersion` 使用
- ♻️ `NTLSVersion uint16 = 0x0101` — NTLS（TLCP）协议版本

**类型**

- ♻️ `type Config struct { Cert *x509.Certificate; Key asym.PrivateKey; NTLS bool; SignCert *x509.Certificate; SignKey asym.PrivateKey; EncCert *x509.Certificate; EncKey asym.PrivateKey; MinVersion uint16; MaxVersion uint16; CipherSuites []string; RootCAs []*x509.Certificate; InsecureSkipVerify bool; ServerName string }` — TLS / NTLS 配置（**三个密钥字段由 `*sm2.PrivateKey` 改为 `asym.PrivateKey`**）
- ♻️ `type Server struct { …（内部字段） }` — 服务端
- ♻️ `type Conn struct { …（内部字段） }` — TLS / NTLS 连接（实现 `net.Conn`）
- ♻️ `type CipherSuiteInfo struct { Name string; ID uint16; MinVersion uint16; MaxVersion uint16 }` — 套件描述
- ♻️ `type HandshakeErrorKind int` — 握手失败的语义分类
- ♻️ `type HandshakeError struct { Op string; Kind HandshakeErrorKind; Err error; SSLCode int; VerifyCode int; NativeErrors []uint64 }` — 分类后的握手错误（`Is` / `Unwrap` 可用）

**错误**

- ♻️ `ErrClosed` / ♻️ `ErrVersionNotSupported` / ♻️ `ErrNoSharedCipher` / ♻️ `ErrPeerVerification` / ♻️ `ErrNetwork` — 哨兵错误
- ♻️ `HandshakeErrorOther` / `HandshakeErrorVersion` / `HandshakeErrorCipher` / `HandshakeErrorPeerVerify` / `HandshakeErrorNetwork` — `HandshakeErrorKind` 取值

**客户端与服务端**

- ♻️ `func Dial(network, addr string, config *Config) (net.Conn, error)` — 建立连接并完成握手
- ♻️ `func DialContext(ctx context.Context, network, addr string, config *Config) (net.Conn, error)` — 由 `ctx` 统一控制拨号与握手
- ♻️ `func NewServer(config *Config) (*Server, error)` — 创建服务端
- ♻️ `func (s *Server) Accept(raw net.Conn) (net.Conn, error)` — 包装已接受的原始连接（**惰性握手**，须再调 `Handshake`）
- ♻️ `func (s *Server) Close() error` — 释放服务端上下文（幂等）

**连接**

- ♻️ `func (c *Conn) Handshake() error` / `HandshakeContext(ctx context.Context) error` — 执行握手（幂等 / 受 `ctx` 控制）
- ♻️ `func (c *Conn) Read(b []byte) (int, error)` / `Write(b []byte) (int, error)` — 首次 I/O 自动握手；读与写可并发，多个读/多个写分别串行
- ♻️ `func (c *Conn) Close() error` — 关闭（幂等；先停止 SSL、shutdown 唤醒在途调用，再释放句柄和 socket）
- ♻️ `func (c *Conn) LocalAddr() net.Addr` / `RemoteAddr() net.Addr` — 地址
- ♻️ `func (c *Conn) SetDeadline(t time.Time) error` / `SetReadDeadline(t time.Time) error` / `SetWriteDeadline(t time.Time) error` — 截止时间
- ♻️ `func (c *Conn) Version() string` / `CipherName() string` — 协商结果
- ♻️ `func (c *Conn) PeerCertificates() ([]*x509.Certificate, error)` — 对端叶证书与中间证书
- ♻️ `func (c *Conn) PeerEncCertificates() ([]*x509.Certificate, error)` — NTLS 加密证书链

**套件枚举**

- ♻️ `func CipherSuites(version uint16) []CipherSuiteInfo` — 枚举指定协议版本下铜锁支持的套件
- 🆕 `func CipherSuiteByName(name string) (CipherSuiteInfo, error)` — 名称/ID → 套件信息（对应 `ciphers -convert` / `-stdname`）。名称**大小写不敏感**且只匹配枚举报告的**主名**（不含 OpenSSL 旧式别名）；ID 为 16 位 wire ID 的文本形式，接受十进制（`4865`）或 `0x` 前缀十六进制（`0x1301`）；空串/未命中返回错误

**服务端监听器（`0.5.0` 新增）**

- 🆕 `type Listener struct{…}` — 实现 `net.Listener`，`Accept` 内完成 TLS / NTLS 握手
  - 🆕 `func NewListener(config *Config, ln net.Listener) (*Listener, error)` — 等价
    `crypto/tls.Listen`；构建时即校验服务端凭证（TLS 需 `Cert` + `Key`，NTLS 需
    `SignCert` / `SignKey` / `EncCert` / `EncKey`），失败返回错误且**不关闭** `ln`
  - 🆕 `func (l *Listener) Accept() (net.Conn, error)` — 返回的连接**已握手**，
    可直接读写；握手失败关闭底层连接并返回分类错误（不返回半握手连接）
  - 🆕 `func (l *Listener) Close() error` — 幂等且并发安全；关闭后 `Accept` 返回
    底层 `net.ErrClosed`
  - 🆕 `func (l *Listener) Addr() net.Addr` — 委托底层监听器（`Close` 后仍可用）

**`0.9.0` 新增（已发布，2026-11-06）**

- 🆕 `type ProtocolMode uint8`：`ProtocolDefault` / `ProtocolTLS` / `ProtocolNTLS` / `ProtocolMixed`；客户端只可选择 TLS 或 NTLS，不自动回退；混合模式用于服务端同端口接入。
- 🆕 `type VerificationPolicy uint8`：`VerifyDefault` / `VerifyNone` / `VerifyReport` / `VerifyStrict`；分别为旧行为、完全不执行信任验证、记录失败继续、失败终止。VerifyNone 仍执行协议必需的凭证/签名检查。
- 🆕 `type ClientAuthType uint8`：`NoClientCert` / `RequestClientCert` / `RequireAnyClientCert` / `VerifyClientCertIfGiven` / `RequireAndVerifyClientCert`；最后两种强制严格验证，与 VerifyNone/VerifyReport 冲突。请求/要求凭证与验证策略独立；NTLS ECDHE 仍要求客户端双凭证。
- 🆕 `type Certificate struct { Leaf *x509.Certificate; PrivateKey asym.PrivateKey; Chain []*x509.Certificate }`、`type NTLSCertificate struct { Sign Certificate; Enc Certificate }`；Chain 仅含按签发顺序排列的中间证书，源对象仍由调用方管理。
- 🆕 `type ClientHelloInfo struct { ServerName string; NTLS bool }`；服务端在版本/套件选择前获取本连接 SNI 与实际协议。
- 🆕 `type HostnameOptions struct { Flags uint32; Email string }`；flags：`HostnameAlwaysCheckSubject` / `HostnameNoWildcards` / `HostnameNoPartialWildcards` / `HostnameMultiLabelWildcards` / `HostnameSingleLabelSubdomains` / `HostnameNeverCheckSubject`。
- 🆕 `OptionNoCompression` / `OptionCipherServerPreference` / `OptionNoRenegotiation`（uint64）；`ModeEnablePartialWrite` / `ModeAcceptMovingWriteBuffer`（int64）。其他位报错，不承诺任意原生选项透传。
- 🆕 `func (cfg *Config) Clone() *Config` — 复制容器和切片，不复制源证书/密钥句柄；nil 接收者产生空配置。
- 🆕 `func Client(raw net.Conn, config *Config) (*Conn, error)` — 包装已连接的 `*net.TCPConn`，不立即握手；成功后由 Conn 关闭 raw，构造失败时调用方仍须关闭 raw。
- 🆕 `func (c *Conn) ConnectionState() ConnectionState` — 独立复制的最后状态，失败握手及 Close 后仍可读取。
- 🆕 `func (c *Conn) VerifyHostname(host string) error` / `CheckEmail(email string) error` — 仅检查对端签名叶名称，不替代链验证。
- 🆕 `func (c *Conn) UnderlyingConn() net.Conn` — 用于地址/期限管理，不得绕过 SSL 读写加密流量。

`Config` 在上述历史字段之外新增以下字段：

| 字段 | 类型 | 行为 |
|---|---|---|
| `Protocol` / `Verification` / `ClientAuth` | `ProtocolMode` / `VerificationPolicy` / `ClientAuthType` | 显式选择协议、信任验证与客户端认证 |
| `ClientCAs` | `[]*x509.Certificate` | 服务端客户端信任根及发送的 CA 名称 |
| `CertChain` / `SignChain` / `EncChain` | `[]*x509.Certificate` | TLS 及 NTLS 双身份的中间证书链；NTLS 两链按 DER 合并去重后发送为共享中间池 |
| `NextProtos` | `[]string` | ALPN，服务端按自身顺序选择；有列表但无交集时失败 |
| `CurvePreferences` / `SignatureAlgorithms` | `[]string` | 铜锁命名组及签名算法列表，不支持名称报错 |
| `DHParameters` | `[]byte` | PEM 编码的 DH 参数；非法/非 DH 参数报错 |
| `Options` / `Modes` / `StrictConfig` | `uint64` / `int64` / `bool` | 命名选项；StrictConfig 拒绝无效套件并精确限制显式集合，空集合保持原生默认 |
| `VerificationName` / `DisableSNI` / `HostnameOptions` | `string` / `bool` / `HostnameOptions` | DNS/IP 验证名称与 SNI 分开；IP 不发送 SNI；非空 Email 额外验证邮箱 |
| `GetConfigForClient` | `func(*ClientHelloInfo) (*Config, error)` | 选择完整配置，nil 结果沿用当前配置 |
| `GetCertificate` | `func(*ClientHelloInfo) (*Certificate, error)` | TLS 凭证选择，nil 凭证报错 |
| `GetNTLSCertificate` | `func(*ClientHelloInfo) (*NTLSCertificate, error)` | NTLS 完整双凭证选择，nil 凭证报错 |
| `VerifyPeerCertificate` | `func(rawCerts [][]byte, verifiedChains [][][]byte) error` | 协议握手后检查独立 DER 副本；错误始终终止 |
| `VerifyConnection` | `func(ConnectionState) error` | 内建验证及前一回调后检查独立状态；错误始终终止 |

`ConnectionState` 包含 `HandshakeComplete bool`、`Version uint16`、`NTLS bool`、
`CipherSuite uint16`、`CipherName` / `ServerName` / `NegotiatedProtocol` /
`NegotiatedGroup` / `PeerSignatureAlgorithm string`、`PeerCertificates [][]byte`、
`VerifiedChains [][][]byte`、`Verification VerificationState` 与
`VerificationErrors []CertificateVerificationError`。DER 无须 Close，修改返回值不影响连接。
规划中的状态字段（SCT、安全重协商、会话复用、OCSP 装订）见下表。
`VerificationState` 为 `VerificationNotPerformed` / `VerificationPassed` /
`VerificationFailed`；只在原生验证确实执行后标记通过/失败。NTLS 的原始链包含双证书，
但原生 verified chain 仅报告最近一次验证链；任何失败时不填充 VerifiedChains。
`CertificateVerificationError{Code int; Depth int; Certificate []byte}` 实现 error，保留失败码、深度与 DER。
`HandshakeError.SSLCode`、`VerifyCode`、`NativeErrors` 保留本次原生线程的失败详情；`SSLErrorNone` / `SSLErrorSSL` /
`SSLErrorWantRead` / `SSLErrorWantWrite` / `SSLErrorWantX509Lookup` / `SSLErrorSyscall` /
`SSLErrorZeroReturn` / `SSLErrorWantConnect` / `SSLErrorWantAccept` / `SSLErrorWantAsync` /
`SSLErrorWantAsyncJob` / `SSLErrorWantClientHelloCB` / `SSLErrorWantRetryVerify` 为 SSLCode 命名值（0–12）。
验证码解释/常量见 `x509.VerifyErrorMessage` 与 `x509.Verify*`，原生错误码用 `meta.ErrorString`。

验证名称依次取 `VerificationName`、`ServerName`、拨号地址 host；SNI 依次取
`ServerName`、拨号地址 host，`DisableSNI` 可关闭。显式验证与 InsecureSkipVerify 冲突即报错；
VerifyReport/VerifyStrict 无根时加载铜锁默认信任路径，不等同于平台原生信任库。
VerifyReport 握手成功仍可能 VerificationFailed，不可据此认定可信；VerifyNone 不产生受信任链。

配置构造后不可修改；选择回调可能并发执行，须及时返回，不得重入同一连接。
源凭证在构造/选择期间保持有效，原生引用建立后连接独立使用；回调错误始终终止。
混合模式及 SNI 服务端每次 ClientHello 都执行选择，须将其源凭证保留至服务端关闭且在途选择结束；证书用 Close、密钥用 asym.Close 释放。
基础配置限制组时，所选配置必须显式提供 CurvePreferences（可 Clone 基础配置），
避免无法从原生 SSL 对象清除的旧组限制。混合模式的 MinVersion/MaxVersion 仅限制 TLS 一侧，NTLS 保持自身版本。`NewListener` 允许仅回调凭证，静态混合模式须提供两类凭证。
原生写入开始后的错误/超时会使后续写入保持失败，应关闭连接；只在写入前过期的 deadline 可重置。

[握手示例](../examples/handshake/) 默认 VerifyReport，支持 TLS/NTLS/混合端口、严格/不验证、
证书链、ALPN、客户端认证和数据回显；这是 SDK 使用示例，不新增正式 CLI 产品。

**传输能力交付状态（公开面收敛归 `1.0.0`）**

> 下表 `0.10.0` 条目已实现、待发布；其后版本仍为规划，涉及原生能力经 core 管理生命周期。
> 交付 SDK API + 可运行示例；候选名称不代表签名冻结。基础状态快照与验证失败记录已在
> `0.9.0` 提供；`0.10.0` 增加事件流、详细 trace、keylog 与 RFC 8998 严格模式。

| 符号 / 能力 | 说明 | 版本 | 实施前置 |
|---|---|---|---|
| 🆕 RFC 8998 严格配置 | TLS 1.3 单套签名凭证，两个 SM4 套件、curveSM2、sm2sig_sm3 与证书约束，区别于 NTLS 双证书 | `0.10.0` | 原生严格模式及配置/状态验证 |
| 🆕 结构化握手诊断 | 状态、消息、Alert 与证书验证事件；失败握手仍保留已发生的信息 | `0.10.0` | 消息/状态/验证回调及数据复制 |
| 🆕 详细 trace / keylog | 可选输出、默认关闭；TLS / NTLS / RFC 8998 分别验收，缺少原生能力明确报错 | `0.10.0` | `SSL_trace`、keylog 回调与输出错误传播 |
| 🆕 `ConnectionState.SecureRenegotiation` / `SignedCertificateTimestamps` | RFC 5746 支持标志；SCT 列表仅在 `Config.CaptureSCT` 开启时填充，只记录不执行 CT 策略校验 | `0.10.0` | `SSL_get_secure_renegotiation_support`、`SSL_get0_peer_scts` 与来源过滤 |
| 🧭 会话复用 / 票据 | `Config.SessionCache`、`Conn.SessionState()` | `0.11.0` | `SSL_SESSION_*`、`SSL_CTX_set_tlsext_ticket_key_cb` |
| 🧭 会话导入导出、票据控制与密钥轮换 | 处理 TLS 1.3 握手后票据；缓存按协议、服务/客户端身份和验证配置隔离 | `0.11.0` | 新会话回调、序列化、票据与实际复用状态 |
| 🧭 `ConnectionState.SessionReused` | 区分首次与恢复握手；与 `Conn.SessionState()` 同版交付 | `0.11.0` | `SSL_session_reused` |
| 🧭 `ListenAndServeTLS` / `ServeTLS`、HTTP/1.1 客户端/服务端集成 | 复用现有 `NewListener`；不承诺 HTTP/2 集成 | `0.12.0` | 标准库 HTTP 集成 |
| 🧭 OCSP stapling | 配置、请求与读取 staple；提供响应有效性与证书状态验证示例 | `0.12.0` | status 回调与 OCSP 响应绑定 |
| 🧭 `ConnectionState.OCSPStapled` / `OCSPResponse` | 装订标志与 DER 原文，可直接交 `x509.ParseOCSPResponse` | `0.12.0` | `SSL_get_tlsext_status_ocsp_resp` |

示例默认“验证并记录失败后继续”，另提供严格验证与完全不验证选项；连接成功不能
代替证书可信。RFC 8998 的版本、套件、组、签名、证书及 SM2 ID 验收条件见
[路线图 §2.4](roadmap.md#24-0100--rfc-8998-与完整握手诊断已实现待发布)。
STARTTLS、外部 PSK、0-RTT、主动重协商继续暂缓，不归入以上四版。

**`0.10.0` 新增 API（已实现，待发布）**

| 目标形态 | 语义与实施位置 |
|----------|----------------|
| `Config.RFC8998 bool` | 独立于 `StrictConfig`；限定 TLS 1.3 单证书、SM4 套件、curveSM2 与 sm2sig_sm3；拒绝冲突及 SNI 降级 |
| `Config.Diagnostics *DiagnosticsConfig` | nil 关闭；配置事件函数、trace/keylog Writer 与有界暂存限额 |
| `DiagnosticsConfig.OnEvent func(HandshakeEvent) error` | 每连接同步有序派发，离开原生调用锁后执行；载荷为副本，不可重入同一连接 |
| `DiagnosticsConfig.TraceWriter` / `KeyLogWriter io.Writer` | 分别显式开启；短写和错误传播；keylog 不进入通用事件或普通日志 |
| `DiagnosticsConfig.MaxEvents` / `MaxBytes int` | 每次派发暂存上限，零值为 256 项 / 1 MiB；负值拒绝，超限使当前操作失败 |
| `HandshakeEvent` | 序号、种类、方向、原生状态/类型、Alert、验证信息及独立数据；字段为 `Sequence uint64`、`Kind string`、`Write bool`、`Version`/`ContentType`/`Code`/`Depth`/`AlertLevel`/`AlertDescription int`、`Data []byte`、`Err error` |
| `Config.CaptureSCT bool` / `ConnectionState.SignedCertificateTimestamps [][]byte` | 默认关闭；逐项 TLS wire 编码（`i2o_SCT`），按原生列表顺序保留 TLS 扩展来源及重复项；getter 补全快照，只采集，不执行 CT 策略校验 |
| `ConnectionState.SecureRenegotiation bool` | 原生 RFC 5746 支持标志，不提供主动重协商入口 |
| `ErrUnsupported` / `ErrDiagnosticLimit` | 可匹配错误；区分能力缺失、诊断超限与原生握手/验证失败 |

详细配置归一、输出错误、锁/生命周期及分批依赖以
[路线图 §2.4.1–2.4.4](roadmap.md#241-实施基线与范围冻结) 为准。
`Kind` 为 start/end/state/message/alert/verify/verify_callback；不把 keylog 混入事件。
诊断和 SCT 选项在连接构造时固定，SNI 替换凭证/验证配置不替换基础诊断消费者。

**破坏性变更**

- `Config` 的 `Key` / `SignKey` / `EncKey` 字段类型由 `*sm2.PrivateKey` 改为 `asym.PrivateKey`
- `tls` 公共层仅经 core 调用 native（`0.3.0` 已修复 suites/errors 的跨层引用）

---

## 12. `asn1` — 纯 Go DER viewer

✅ **已有**（`asn1` 未变）｜旧包：`asn1`

cgo-free 的只读 DER 解析与转储；`Parse` 对深度设上限（`maxDERDepth = 128`）以防栈溢出。

**类常量**

- `ClassUniversal = 0`、`ClassApplication = 1`、`ClassContextSpecific = 2`、`ClassPrivate = 3`

**Tag 常量**

- `TagBoolean = 1`、`TagInteger = 2`、`TagBitString = 3`、`TagOctetString = 4`、`TagNull = 5`、`TagOID = 6`
- `TagUTF8String = 12`、`TagSequence = 16`、`TagSet = 17`、`TagPrintableString = 19`、`TagT61String = 20`、`TagIA5String = 22`、`TagUTCTime = 23`、`TagGeneralizedTime = 24`

**类型与函数**

- `type Node struct { Offset int; Tag byte; Class int; Number int; Constructed bool; Length int; Value []byte; Children []*Node }` — 单个 TLV 元素
- `func Parse(der []byte) (*Node, error)` — 解析完整 DER（拒绝空输入、截断、非法长度、不定长与尾部多余字节）
- `func Dump(n *Node) string` — 生成带缩进的文本视图

**`0.7.0` 已实现**

| 符号 | 目标版本 | 边界 |
|---|---|---|
| 🆕 `func ParseWithLimits(der []byte, maxDepth, maxNodes int) (*Node, error)` | `0.7.0` | 可配置深度和节点数限额；保留现有 Parse 的固定 128 层保护和行为 |
| 🆕 `ErrDepthLimit` / `ErrNodeLimit` | `0.7.0` | errors.Is 识别；限额须为正数，根计入节点数，深度沿用构造层数；原 Parse 的错误文本与 128 层行为保留 |

---

## 13. `jwk` — JWK（RFC 7517）

✅ **已有**｜旧包：`jwk`

支持 **RSA / EC / OKP / oct**；OKP 与对称密钥入口已在 `0.6.0` 实现，见下文。`0.3.0` 已去除 `*core.PKey` 参数（修复 E1-7）。

**类型**

- ♻️ `type Key struct { Kty string; Kid string; Use string; Alg string; N string; E string; D string; P string; Q string; DP string; DQ string; QI string; Crv string; X string; Y string }` — JWK 密钥（各参数为 base64url 字符串）

**函数**

- ♻️ `func MarshalKey(k asym.Key) (*Key, error)` — 由非对称密钥（私钥或公钥）导出 JWK（参数由 `key.CoreKey` 改为 `asym.Key`）
- ♻️ `func Parse(data []byte) (*Key, error)` — 解析 JWK JSON
- ♻️ `func FromPEM(pemBytes []byte) (*Key, error)` — 由 PEM 直接得到 JWK

**方法**

- ♻️ `func (k *Key) MarshalJSON() ([]byte, error)` — 序列化为 JWK JSON
- ♻️ `func (k *Key) IsPrivate() bool` — 是否含私钥参数
- ♻️ `func (k *Key) ToPEM() ([]byte, error)` — 转换为私钥 PEM（PKCS#8）
- ♻️ `func (k *Key) ToPublicPEM() ([]byte, error)` — 转换为公钥 PEM（SPKI）

**函数｜OKP 与对称密钥（`0.6.0` 新增）**

- 🆕 `CrvEd25519` / `CrvEd448` / `CrvX25519` / `CrvX448` — OKP 的 JWK crv 常量
- 🆕 `type Key` 新增 `K string`（`Kty: "oct"` 的密钥字节）；`Kty` 接受 `"OKP"` / `"oct"`
- 🆕 `func MarshalSymmetric(k sym.SymmetricKey) (*Key, error)` — 对称密钥 → `Kty: "oct"` JWK
- 🆕 `func (k *Key) ToOKPKey() (asym.Key, error)` — OKP JWK → `asym` 密钥（有 `d` 为私钥，否则公钥；`x` 与种子不一致时报错）
- 🆕 `func (k *Key) ToSymmetricKey() (sym.SymmetricKey, error)` — `oct` JWK → 对称密钥（`alg` 缺省时按长度推断）
- `MarshalKey` / `ToPEM` / `ToPublicPEM` 支持 OKP：PEM 路径走 `asym` 序列化，覆盖标准库不支持的 Ed448 / X448

**规划中**

_（本包已无待实现项）_

**破坏性变更**

- `jwk.Marshal(key *core.PKey)` 移除（修复 E1-7），统一用 `jwk.MarshalKey(k asym.Key)`
- `jwk.MarshalKey` 参数类型由 `key.CoreKey` 改为 `asym.Key`（`core.PKey` 不再出现于公开签名）

---

## 14. `pkcs/pkcs7` — PKCS#7

✅ **已有**（`pkcs/pkcs7` 未变）｜旧包：`pkcs/pkcs7`

支持证书/CRL 容器、附带/分离签名及多 RSA 接收者 EnvelopedData；CMS 仍为后续规划。

**函数**

- `func Build(certs []*tx509.Certificate) ([]byte, error)` — 由证书列表构建 PKCS#7（DER）
- `func MarshalPEM(der []byte) []byte` — DER → PEM
- `func Extract(data []byte) ([]*tx509.Certificate, error)` — 从 PKCS#7（DER 或 PEM）提取证书

**函数｜CRL 支持（`0.6.0` 新增）**

- 🆕 `func FromCRL(crls []*tx509.CRL) ([]byte, error)` — 把 CRL 列表打包为 PKCS#7 SignedData（无签名者），对应 `crl2pkcs7` 的 CRL 侧
- 🆕 `func ExtractCRLs(data []byte) ([]*tx509.CRL, error)` — 从 PKCS#7（DER 或 PEM）提取 CRL；容器无 CRL 时返回空切片

**`0.7.0` 已实现与后续规划**

| 符号 | 版本 | 语义 / 后续前置 |
|---|---|---|
| 🆕 `Sign(data []byte, opts *SignOptions) ([]byte, error)` | `0.7.0` | SignerCert/SignerKey、ExtraCerts、Digest、Detached；默认 SHA-256、附带内容，返回 DER |
| 🆕 `Verify(data []byte, opts *VerifyOptions) (*SignedData, error)` | `0.7.0` | Roots 为显式信任存储，ExtraCerts 补链，DetachedContent 提供分离内容；仅显式 SignatureOnly 可不验信任 |
| 🆕 `Encrypt(data []byte, opts *EncryptOptions) ([]byte, error)` | `0.7.0` | Recipients 为多个 RSA 证书，Cipher 默认 AES-256-CBC；返回 DER |
| 🆕 `Decrypt(data []byte, opts *DecryptOptions) ([]byte, error)` | `0.7.0` | RecipientCert/RecipientKey，失败无输出 |
| 🆕 `SignOptions` / `VerifyOptions` / `EncryptOptions` / `DecryptOptions` | `0.7.0` | 证书用 x509.Certificate，私钥用 asym.PrivateKey，Roots 用 x509.Store；不暴露 internal 类型 |
| 🆕 `SignedData` 与幂等 `Close() error` | `0.7.0` | Content、Signers、TrustVerified；返回证书资源归结果持有者释放 |
| 🧭 CMS 族（`cms` 命令） | `0.14.0` | 新增 `CMS_*` 绑定 |

`0.7.0` 覆盖附带/分离签名和多接收者 EnvelopedData。Verify 默认要求显式 Roots，
验证全部签名者及其信任；SignatureOnly=true 时仍验签，结果 TrustVerified=false。
SignedData.Signers 为签名者证书；验证失败不返回内容，Close 幂等释放结果持有的证书。
Verify/Decrypt 接受 DER/PKCS7 PEM，二进制输入不做换行转换；分离内容缺失与空内容
必须可区分。8.4.0 必须支持 RSA/ECDSA 签名与 RSA 接收者加密，SM2 和其他不支持的
组合明确报错；非认证加密不承诺检测全部篡改。CLI 双向互通使用 smime -sign/-verify
和 -encrypt/-decrypt；CMS 扩展归 `0.14.0`，不混同为同一格式。

**规划中｜新顶级包 `ts`（`0.14.0`，尚不存在）**

- 🧭 RFC 3161 时间戳请求/响应与 HTTP 传输；需新增 `TS_*` 绑定并复用 CMS 基础设施。
- 实施时同步包索引、依赖图与逐符号 API；当前公开包数仍为 16。


---

## 15. `pkcs/pkcs12` — PKCS#12

✅ **已有**｜旧包：`pkcs/pkcs12`

去除 `key.CoreKey` 与 `*core.PKey`（修复 E1-12），并保留现有的打包/解析/改密三项能力。

**类型与函数**

- ♻️ `type Bundle struct { PrivateKey asym.PrivateKey; Certificate *x509.Certificate; CACerts []*x509.Certificate }` — 解析结果（`PrivateKey` 由 `*core.PKey` 改为公开接口；调用方负责 `Close`）
- ♻️ `func Pack(cert *x509.Certificate, key asym.PrivateKey, ca []*x509.Certificate, password, name string) ([]byte, error)` — 打包为 PKCS#12（DER）
- ♻️ `func Parse(data []byte, password string) (*Bundle, error)` — 解析
- ♻️ `func ChangePassword(data []byte, oldPass, newPass string) ([]byte, error)` — 更换口令

> 既有 `Pack` 保持兼容 PBE；新增 `PackWithOptions` 默认 AES-256-CBC。

**`0.6.0` 新增配置入口**

- `type Options struct { PBE string; Iterations int; FriendlyName, ReadPass, WritePass string }`
- `func PackWithOptions(cert *x509.Certificate, key PrivateKey, ca []*x509.Certificate, opts *Options) ([]byte, error)`
- `func ParseWithOptions(data []byte, opts *Options) (*Bundle, error)`
- `func ChangePasswordWithOptions(data []byte, opts *Options) ([]byte, error)`
- PBE：AES-128/192/256-CBC 或 PBE-SHA1-3DES；默认 AES-256-CBC、2048 次加密/MAC 迭代。
  ReadPass 读取输入，WritePass 保护输出；两者不表示同一容器内分设加密/MAC 口令。
- 0.6.0 的 `ChangePasswordWithOptions` 曾经通过 Parse + Pack 重打包；0.7.0 已改为下述无损路径。

**`0.7.0` 已实现**

| 符号/行为 | 目标版本 | 边界 |
|---|---|---|
| 🆕 现有 `ChangePassword` 的复杂容器无损改密 | `0.7.0` | 保留原算法/派生/MAC 策略；多私钥、多 safe、嵌套与全部内容/顺序/属性保留，更新盐/IV |
| 🆕 现有 `ChangePasswordWithOptions` 改为无损路径 | `0.7.0` | 应用 PBE/迭代/读写口令，保留全部内容；空 FriendlyName 保留名称，非空在多密钥时拒绝歧义 |

两入口均先验证 MAC；必须覆盖 PBES2/AES-128/192/256 与可用 3DES，不自动加载 legacy。
无 MAC、不同 MAC/加密口令、签名保护及其他无法完整处理的结构/算法明确失败，失败无输出，
不再以 Bundle 重打包兜底。以上为 0.7.0 已实现行为；无损指内容与属性保留，不保证随机加密 DER 相同。


**破坏性变更**

- 移除 `pkcs12.PrivateKey = key.CoreKey` 类型别名（修复 E1-12）；`Pack` 改为直接接受 `asym.PrivateKey`
- `Bundle.PrivateKey` 字段类型由 `*core.PKey` 改为 `asym.PrivateKey`

---

## 16. `xml/rsa` — .NET `RSAKeyValue` XML

✅ **已有**（`0.3.0` 签名变更）｜旧包：`xml/rsa`

与 .NET `RSAKeyValue` 格式双向互转。**密钥参数由 `*crypto/rsa.PrivateKey` /
`*crypto/rsa.PublicKey` 改为 `asym.PrivateKey` / `asym.PublicKey`**——原签名直接
引用本库自己的 `crypto/rsa`（commit 21 删除），不换不可能；实现内部仍以 PKCS#1 /
SPKI PEM 往返 + `asym.Load*KeyPEM` 落地，**零新增 API、零新增 cgo**（详见
`docs/issues/2026-09-24/P1009`）。

**函数**

- ♻️ `func MarshalPrivate(priv asym.PrivateKey) ([]byte, error)` — RSA 私钥 → XML（`Modulus` / `Exponent` / `D` / `P` / `Q` / `DP` / `DQ` / `InverseQ`）
- ♻️ `func MarshalPublic(pub asym.PublicKey) ([]byte, error)` — RSA 公钥 → XML（仅 `Modulus` / `Exponent`）
- ♻️ `func UnmarshalPrivate(data []byte) (asym.PrivateKey, error)` — XML → RSA 私钥（缺 `Modulus` / `Exponent` / `D` 报错）
- ♻️ `func UnmarshalPublic(data []byte) (asym.PublicKey, error)` — XML → RSA 公钥（缺 `Modulus` / `Exponent` 报错）

> 参数读取经 `asym.Params`（`N/E/D/P/Q/Dmp1/Dmq1/Iqmp`），与 `asym` 不再「解耦」；
> 非 RSA 密钥（`Params().Type != "RSA"`）返回错误。包名仍为 `rsa`，与**标准库**
> `crypto/rsa` 同名，调用方同时使用时需给其中之一取别名。
