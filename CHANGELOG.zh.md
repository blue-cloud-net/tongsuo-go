# 更新日志

[English](CHANGELOG.md) | [简体中文](CHANGELOG.zh.md)

本文件记录 `tongsuo-go` 的所有显著变更。格式遵循
[Keep a Changelog 1.1.0](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本 2.0.0](https://semver.org/lang/zh-CN/)。

> 本项目主版本号为 `0`，期间 API 视不预稳定，下游升级前请阅读本文件。分类
> 标题（`新增功能` / `行为变化与重构` / `Bug 修复` / `文档` /
> `BREAKING / 已知限制` 等）取 Keep a Changelog 约定。术语（SM2 / SM3 /
> SM4 / PEM / DER / PKCS#7 / PKCS#8 / PKCS#12 / openssl / CRL / CSR / OCSP /
> NTLS / JWK / RFC xxxx 等）保留英文原文，不做翻译。
>
> 英文版位于 [CHANGELOG.md](CHANGELOG.md)。

---

## [0.1.2] - 2026-09-10

### 新增功能

- `crypto/ecdh` 新增 OKP 曲线 `X25519()` 与 `X448()`（RFC 7748），与既有
  P-256 / P-384 / P-521 并列。
- `crypto/ecdh` 新增 `Secp256k1()` 曲线；可用性取决于运行时铜锁 provider。
- 新增 `crypto/x448` 包（X448 ECDH，RFC 7748）：密钥生成、PEM（PKCS#8 /
  SPKI）往返、56 字节原始密钥互操作与 `SharedSecret`。
- `key` 包新增 `AlgX448` 与 `GenerateX448Key`。
- `tls`：新增 `DialContext(ctx, network, addr, cfg)`，TCP 拨号与 TLS/NTLS
  握手统一受同一 ctx 控制；`Dial` 改为 `DialContext(context.Background(),
  ...)` 的薄包装，源代码兼容。
- `tls.Conn`：新增 `HandshakeContext(ctx)` 在 goroutine 内执行握手，
  ctx 触发时通过 `SetDeadline` + 关闭 raw socket 唤醒在途的
  `SSL_read` / `SSL_write` 等待；对外暴露的 `Handshake()` 是
  `context.Background()` 的包装。
- `tls.Conn`：新增 `PeerCertificates() ([]*x509.Certificate, error)` 返回
  对端的叶子证书与所有中间证书；NTLS 另提供 `PeerEncCertificates()
  ([]*x509.Certificate, error)` 返回加密证书链。
- `tls`：新增 `CipherSuites(version uint16) []CipherSuiteInfo`，
  按协议版本（`0x0301`–`0x0304` 与 `NTLSVersion = 0x0101`）枚举
  `SSL_CTX` 支持的算法套件，每项返回 `{Name, ID, MinVersion, MaxVersion}`。
- `tls`：新增 `NTLSVersion uint16 = 0x0101` 常量用于 NTLS 协议探测。
- `tls.Config.CipherSuites`：以 `TLS_` 开头的名字走 Tongsuo TLS 1.3
  路径 `SSL_CTX_set_ciphersuites`，其余（无前缀）走经典路径
  `SSL_CTX_set_cipher_list`。任一名字未匹配时不视为致命错误（直接
  跳过）；最终空集返回 `ErrNoSharedCipher`。
- `tls`：新增哨兵错误 `ErrVersionNotSupported` / `ErrNoSharedCipher` /
  `ErrPeerVerification` / `ErrNetwork`，以及类型化错误
  `*HandshakeError`（`Op` / `Kind` / `Err`），按 library + reason 对
  OpenSSL 错误分类（`SSL_R_NO_SHARED_CIPHER` /
  `SSL_R_UNSUPPORTED_PROTOCOL` / `X509_R_CERT_VERIFY_FAILED` 等），同时
  保留 `ctx.Err()` 直传语义。
- `x509.Certificate`：新增 `Close() error` 释放证书持有的 cgo 资源，
  多次调用幂等。

### 行为变化与重构

- `internal/core`：`Derive` 拒绝 OKP 低阶点（RFC 7748 §6.1）产生的全零共享
  密钥，与 Go 标准库 `crypto/ecdh` 语义对齐。
- `crypto/ecdh`：OKP 曲线改用类型化曲线族分派（不再比较展示名），且 `ECDH`
  显式拒绝非 EC 的算法组合。
- `tls.Server.Accept`：现仅构造 `*Conn` 即返回，TLS/NTLS 握手推迟到
  在返回的连接上显式调用 `Handshake()` / `HandshakeContext()`；原有
  调用方若没有主动调用 `Handshake` 则需补上，已显式调用的不受影响。

### Bug 修复

- `crypto/ecdh`：`*_tongsuocli_test.go` 现在真正调用铜锁 `openssl` CLI；
  此前仅调用 `internal/core`。
- `internal/testutil`：新增 `OpenSSLAvailable` 与 `SkipIfNoOpenSSL`，使 CLI
  对拍测试在缺少铜锁二进制时跳过而不是失败。
- `tls`：修复 `Dial` 路径的 `SSL_CTX` 泄漏——`*core.TLSContext` 现由
  `Conn.Close()` 在拨号侧负责释放；先前每次成功拨号都泄漏一个上下文。
- `tls`：`Conn.Close` 现返回底层 raw socket close、SSL 句柄 close
  以及可选 ctx close 中的首个非 nil 错误；此前始终返回 `nil`。

### 文档

- 在 `crypto/ecdh` 中补充 X25519 / X448 / secp256k1 说明，并同步
  `docs/architecture.md` 与 `docs/testing-guide.md`。
- 在包 GoDoc 中补充 `tls.DialContext` / `tls.Conn.HandshakeContext` 的取
  消语义说明。

### 已知限制

- `tls`：在 Linux 平台，握手阶段的 ctx 取消最多需等待内部
  `waitFDTimeout`（30 s）才能返回——cgo 等待路径使用 `syscall.Select`，
  该调用无法从 Go 侧直接打断。建议调用方给 ctx 携带 deadline，而
  非依赖纯 `cancel`。完整的 `epoll` / `poll(2)` 改造计划在 v0.1.3+。

---

## [0.1.1] - 2026-09-10

### 新增功能

- 新增 EdDSA 算法包 `crypto/ed25519` 与 `crypto/ed448`（RFC 8032）：32B / 57B
  种子与公钥字节与 Go 标准库、WireGuard 互通。
- 新增 X25519 ECDH 包 `crypto/x25519`（RFC 7748）：32 字节共享密钥，与 Go
  `crypto/ecdh`、WireGuard 互通。
- 新增 ECDH 包 `crypto/ecdh`：曲线密钥协商。
- 新增 KDF 包 `crypto/kdf`：HKDF / PBKDF2 派生与可用性探测。
- 新增统一 `key/` 包：跨算法密钥接口（对称 / 非对称）、PEM 自动嗅探解析、
  密钥生命周期管理（`Handle` / `Store`）、KDF 派生 — **v0.1.1 已交付**，非
  路线图。
- `crypto/rsa` 新增按 hash 选择摘要的签名 API。
- `x509` 新增 `CRL.Verify` 验签；`Extension` 增加 OID 字段返回扩展点分 OID；
  EdDSA 密钥支持证书 / CSR / CRL 无摘要签名与验签。
- `tls` 客户端对端证书验证与超时语义。
- 新增内部辅助包 `internal/digest`、`internal/testutil`。
- 新增 Ed25519 / X25519 独立示例：`examples/ed25519`、`examples/x25519`。
- `x509` 新增证书 / CSR / CRL 签名信息读取（`Signature` /
  `SignatureAlgorithm` / `SignatureAlgorithmOID`）。

### 行为变化与重构

- `internal/core` 引入 `core.RandomBytes`，解除 `crypto/rand` 对
  `internal/native` 的依赖。
- `internal/core` 编码规范与核心层瘦身。
- AES / SM4 分组加密 `Block` 改为模板 + 副本以支持并发复用。
- `internal/core` 新增 `ZeroBytes`（基于 `OPENSSL_cleanse`）用于敏感缓冲区清零；
  `TLSContext.AddVerifyRoots` 不再静默吞错，并引入 `VerifyResultClosed` 哨兵。
- `EvpPkey` 常量下沉到 `internal/core`，恢复三层架构。
- SM2 签名 / 验签仅对 SM2 密钥加锁（`LockOSThread`），提升其他密钥类型的并发性能。
- CI：触发收敛到 `main`；测试矩阵扩展为 ubuntu + macOS × amd64 / arm64（Go 1.21）；
  Tongsuo 固定 8.4.0。
- Release：通过 `workflow_call` 复用 CI 工作流，发布说明由中英 CHANGELOG 自动抽取；
  不再上传二进制产物。

### Bug 修复

- `internal/core`：访问器添加 nil / closed 防御性检查；修复 `ChainVerify`
  栈容器泄漏。
- `internal/native`：修复 `X509_CRL_get0_authority_key_id` 的 use-after-free。
- AES / SM4-GCM 强制 nonce 长度为 12 字节。
- RSA / SM2 / `key` 包非对称加解密语义与 PEM 加载的类型安全修正。
- `asn1` DER 解析增加嵌套深度上限。
- `ocsp.Check` 自适应匹配证书状态哈希。
- EC / SM2 公钥参数改以 provider 仿射坐标 `qx` / `qy` 读取，修复 Tongsuo 8.4
  以压缩点导出 `pub` 时 X / Y 为空的问题。
- OCSP：修复 `Verify` 中 `defer` 循环变量捕获问题。
- `internal/core`：`signDigest` / `verifyDigest` 补充闭包守卫。
- `tls`：`SplitHostPort` IPv6 容错；`SetReadDeadline` / `SetWriteDeadline`
  配对清零。
- `x509`：`ChainVerify` 中间证书处理跨 OpenSSL 版本可移植。

### 文档

- 补充 `key` 包架构说明（v0.1.1 已合入）。
- 清理路线图与注释中的 Phase 阶段标记。
- 删除 `ci-cd.md` 与 `roadmap.md`，同步其他文档引用。
- `docs/architecture.md` 同步目录结构与版本号。
- 落实敏感缓冲区清零的务实说明。
- 同步 Ed25519 / Ed448 / X25519 支持文档。
- 将 `README.md` 改造为中英双语版本。

---

## [0.1.0] - 2026-09-03

### 新增功能

#### 算法引擎（`crypto/`）

- SM3 哈希算法。
- SM4 对称加密（ECB / CBC / CTR / OFB / CFB / GCM），含 Zero 填充便捷函数。
- SM2 非对称（GenerateKey / Encrypt / Decrypt / Sign / Verify），新增 SM2
  密文格式互转 DER ↔ C1C3C2 ↔ C1C2C3 及 `EncryptWithOrder` /
  `DecryptWithOrder`。
- AES（ECB / CBC / CTR / GCM，含 `cipher.AEAD` 接口）。
- HMAC（SM3 / SHA256 / SHA384，含 `SumSM3` / `SumSHA256` / `SumSHA384`
  便捷函数）。
- 哈希：MD5 / SHA1 / SHA256 / SHA512。
- 安全随机数生成（`Read` / `Bytes`）。

#### 密钥体系

- RSA：GenerateKey / Load / Marshal（PKCS#8 / PKCS#1 / 加密 PEM）/ Sign
  （PKCS1v15 / PSS）/ Verify / Encrypt+Decrypt（PKCS1v15 / OAEP）/ Params /
  ChangePassword / Match。
- ECDSA：GenerateKey / Load / Marshal / Sign / Verify / Params。
- `CreateCertificate` / CSR 泛化为 `PublicKey` / `PrivateKey` 接口，SM2 /
  RSA / ECDSA 均可签发，摘要按密钥类型自动选择。
- 私钥加密 PEM / 改密 / 提公钥 / 密钥匹配。

#### 证书与协议

- X.509 证书解析 / 创建 / 自签 / CA 签发（SM2 + SM3 + RSA + ECDSA）。
- 证书结构化解析：完整 RDN / SAN / KeyUsage / EKU / SKID / AKID。
- 证书指纹：sha1 / sha256 / sm3 / md5 / sha384 / sha512。
- PEM ↔ DER 交换（证书 / CSR）。
- CSR 构建（`NewEmptyCertificateRequest`：SetSubject / SetPublicKey /
  SetChallengePassword / AddExtensions / Sign）。
- 证书链验证（Store / `ChainVerify`，失败映射 `*VerifyError`）。
- CRL 解析（吊销条目含原因）与 `RevocationCheck`。
- TLS / NTLS 传输层（`Dial` / Server / Conn / Config，NTLS 双证书
  `Config.SignCert` / `EncCert`）。

#### 容器与格式

- PKCS#12（Pack / Parse / `ChangePassword`）。
- PKCS#7（Build / Extract / `MarshalPEM`）。
- OCSP（`CreateRequest` / `ParseResponse` / `Verify`）。
- ASN.1 DER 解析树与 hex dump。
- JWK ↔ PEM（RSA / EC）。
- RSA XML ↔ PEM（.NET `RSAKeyValue`）。

#### 工程化

- 顶层包结构重组（BC 命名空间分层）：
  - `crypto/*` 仅装算法引擎（`aes` / `ecdsa` / `hmac` / `md5` / `rand` /
    `rsa` / `sha1` / `sha256` / `sha512` / `sm2` / `sm3` / `sm4`）。
  - 6 个非算法包顶级化：`asn1` / `jwk` / `ocsp` / `tls` / `x509`；`pkcs`
    （`pkcs7`, `pkcs12`）与 `xml`（`rsa`）子命名空间。
  - `crypto/x509` 按职责拆为 `x509` / `name` / `csr` / `store` / `crl` /
    `helpers` 共 6 个文件并顶级化为 `x509/`。
- 3 个可运行最小示例：`examples/{sm2, self-signed-cert, ntls-loopback}`。
- 56 个公开 API `Example*` 测试函数（godoc 友好）。
- 段式双语 GoDoc 注释覆盖公共 API。
- 设计文档：架构 / 开发指南 / 测试指南 / 双语 GoDoc 规范 / 路线图。

### Bug 修复

- 首次公开发版前累计的稳定性改进，未在此处逐条列出，详见 git 历史。

### BREAKING / 已知限制

- **BREAKING**：MAJOR=0 期间 API 不稳定，下游升级需阅读 CHANGELOG。
- `crypto/rand` 与标准库 `crypto/rand` 同名（保留路径，文档已警示）。
- 假定 Tongsuo 8.4 ABI。
- `-tags tongsuocli` 集成测试依赖 `/opt/tongsuo`。

---

[Unreleased]: https://github.com/blue-cloud-net/tongsuo-go/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/blue-cloud-net/tongsuo-go/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/blue-cloud-net/tongsuo-go/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/blue-cloud-net/tongsuo-go/releases/tag/v0.1.0
