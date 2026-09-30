# 官方 tongsuo-go-sdk 与本库功能对比

> 本文件回答：**与官方 [Tongsuo-Project/tongsuo-go-sdk](https://github.com/Tongsuo-Project/tongsuo-go-sdk) 相比，本仓库还有哪些能力没有对齐？是否要把对侧分阶段补齐？**
>
> 口径：**只对齐「能力」，不对齐「命名」**——本库以 Go 惯例 API（`hash.Hash` / `cipher.Block` / `cipher.AEAD` / `Config` 字段 / `(T, error)` 返回）面向使用者，而官方 SDK 几乎是 [`gost`](https://github.com/gostc/go) 的 Tongsuo fork、把 `SSL_CTX`/`SSL` 的 OpenSSL 原生配置 1:1 暴露出去，命名上无必要一一对应。
>
> 报告**不写代码改动**。所有「涉及文件 / 验收方式」推迟到具体 PR 的实施阶段另行设计。
>
> **包名口径**：本文件的「本库现状」列使用**重构前**包名（`crypto/*` / `key`）；重构后的 16 包名与逐符号签名见 [api-reference.md](api-reference.md)，包级对照见 [refactor-roadmap.md](refactor-roadmap.md) §2 / §4。

---

## 1. 摘要与结论

| 维度 | 结论 |
|---|---|
| **算法原语与容器格式** | 本库**反超**官方（见 §7）。官方 README 自报的 Features 只有 SM3/MD5/SHA1/SHA256、SM4、SM2 加解密/签名、HMAC、SM2 证书、TLCP + TLSv1.0–1.3。 |
| **TLS/NTLS 传输层能力** | 本库**落后**官方，且差距集中在「OpenSSL 原生配置的全量暴露」（见 §6.A）：服务端 SNI 选证书、ALPN、会话复用、会话票据、自定义证书校验回调、`Options`/`Modes`、`net.Listener` 包装、HTTP 集成。 |
| **基础设施小件** | 本库**小幅落后**官方（见 §6.B）：`SplitPEM`、`Engine`、DH 参数、`CheckHost/CheckIP`、`AddExtension(nid, text)`、`GenerateRSAKeyWithExponent`、AES-192 等；这些改动小、风险低，可批量补齐。 |
| **不做对齐** | 公开 BIO 桥接、原生 `HMAC_CTX`、`NID` 常量表等若干点**有意不做**，理由见 §9。 |
| **优先级** | Phase 1 基础设施小件 → Phase 2 密钥协商/通用原语 → Phase 3 TLS/NTLS 协议能力 → Phase 4 `net.Listener`/HTTP/`examples` 扩展（详见 §8）。 |

一句话：本库算法侧已经**完整且惯例化**，TLS 侧**与官方之间的差距是「工程深度」而非「设计」**，分阶段补齐是合理的路线。

---

## 2. 对比方法与基线

| 项 | 值 |
|---|---|
| **对比基线（官方）** | [`Tongsuo-Project/tongsuo-go-sdk`](https://github.com/Tongsuo-Project/tongsuo-go-sdk) `main` @ [`002a0963`](https://github.com/Tongsuo-Project/tongsuo-go-sdk/commit/002a09631de785f2d984d9e0b3a7f1e9a169940c)（2025-01-14，Merge PR #40 Update README.md） |
| **官方 README 自报能力** | Hash（SM3/MD5/SHA1/SHA256）、SM4、SM2 加解密、SM2withSM3 签名、HMAC、SM2 证书、TLCP + TLSv1.0/1.1/1.2/1.3（详见 README §Features） |
| **官方内部文件基线** | 顶层 `ctx.go` / `ssl.go` / `conn.go` / `net.go` / `http.go` / `tickets.go` / `pem.go` / `init.go`；`crypto/`（`bio.go` `cert.go` `ciphers.go` `ciphers_gcm.go` `dh.go` `dhparam.go` `digest.go` `engine.go` `hmac.go` `hostname.go` `key.go` `mapping.go` `nid.go`）；`crypto/{md5,sha1,sha256,sm2,sm3,sm4}/` 子包；`utils/{errors,future}.go`；`test/`；`examples/{cert_gen,hmac_sm3,sm2_encrypt,sm2_keygen,sm2_sign,sm2_signasn1,sm3,sm4,tlcp_client,tlcp_server}` |
| **本库基线** | `tongsuo-go` `0.3.0`（2026-09-30 发布） |
| **检索方式** | 全仓库 `grep`/`ripgrep` 导出符号 + `internal/native/binding_*.go` + 现有 `docs/architecture.md` §3、§5 目录地图；结论字段「本库现状」均可在源码中校验 |
| **环境声明** | 本机未安装 Tongsuo C 库，因此本次仅做静态比对；后续具体 PR 的实施必须 `gofmt -l .` / `go vet ./...` / `go build ./...` / `go test -count=1 ./...` 通过后才能合入 |

---

## 3. 架构与定位对比

扩写 `docs/architecture.md` §10 表格，从「两个仓库的设计目标」层面补充：

| 维度 | 官方 tongsuo-go-sdk | 本库 tongsuo-go |
|---|---|---|
| **设计目标** | Tongsuo 原生 C API 的 Go 1:1 暴露，让 Go 端代码尽量接近 OpenSSL 程序员直觉 | 给 Go 开发者提供 Go 惯例 API（`hash.Hash`/`cipher.Block`/`cipher.AEAD`/`(T,error)`），原层细节封进 `internal/` |
| **绑定方式** | cgo + 内嵌 `shim.{c,h}`（`X_` 前缀） | cgo + 内嵌 `shim.{c,h}`（同思路，**独立实现不复制官方代码**） |
| **分层** | 两层，绑定与 API 同包混合；`crypto/` 同时持原生指针与高层包装 | 三层，`internal/native`（绑定） → `internal/core`（句柄） → 16 个顶级包（API 层，见 [api-reference.md](api-reference.md) §0；重构后已无 `crypto/` 与 `key/`） |
| **可见性** | 原生指针（`*C.EVP_PKEY`、`*C.X509`、`*C.BIO`）暴露到公开 API（`Certificate.GetCert()` 等） | `internal/` 隐藏 cgo 与原生句柄；公开层只暴露 Go 侧安全抽象 |
| **生命周期** | 主要依赖 `runtime.SetFinalizer`（`ctx.go`/`cert.go`/`key.go`）；少数显式 `Close()` | `handle` 基类：`owned` 所有权 + 显式 `Close()` + finalizer 兜底；`Close()` 幂等 |
| **API 命名** | `gost` 风格（`NewCtx`/`UseCertificate`/`SetVerify`/`DialSession`/`VerifyHostname`/`SplitPEM`） | 按 C# 参考项目语义命名（重构后：`asym.Encrypt` / `sym.NewSM4Cipher` / `tls.Dial` / `x509.NewCertificate`） |
| **传输层** | 顶层包 `tongsuogo`，TLCP/TLS 共享同一 `Ctx`（含 `UseSignCertificate`/`UseEncryptCertificate` 双证书） | 顶层包 `tls`，TLCP 通过 `Config.NTLS` 字段切换 |
| **代码规模** | ~30 个 `.go` 文件 + `crypto/{md5,sha1,sm3,sm4}` 各一份 | ~120 个 `.go` 文件（重构后：16 个顶级包 + `internal/` 三层） |

本库「三层 + `internal/`」的代价是「需要做更多适配代码」（详见 §6.B）来把官方那一堆 OpenSSL 配置项以 Go 惯例形态补齐；收益是「暴露面收敛到 Go 惯例类型」。
重构前 `crypto/rand` / `crypto/aes` 这类与标准库/常识**同名的包**对 Go 开发者有认知摩擦，
现由 [refactor-roadmap.md](refactor-roadmap.md) §2 的 16 包扁平结构消解（本包改为 `rand` / `sym`）。

---

## 4. 官方 SDK 能力清单（基线 §2 所列范围）

> 完整 API 面摘录自官方 `main` 分支（基线 SHA `002a0963`）。本节列出**导出符号**以解释 §6 矩阵中「官方有」一列；本节不展开函数语义。

### 4.1 顶层包 `tongsuogo`（包级 API）

| 文件 | 导出符号（节选） |
|---|---|
| `ctx.go` | `Ctx`、`NewCtx`/`NewCtxWithVersion`/`NewCtxFromFiles`、`SSLVersion` 常量（`SSLv3`/`TLSv1`/`TLSv1_1`/`TLSv1_2`/`TLSv1_3`/`NTLS`/`AnyVersion`）、`UseCertificate`/`UseSignCertificate`/`UseEncryptCertificate`、`UsePrivateKey`/`UseSignPrivateKey`/`UseEncryptPrivateKey`、`AddChainCertificate`、`GetCertificateStore`、`CertificateStore`/`NewCertificateStore`/`AddCertificate`/`LoadCertificatesFromPEM`、`CertificateStoreCtx{VerifyResult,Err,Depth,GetCurrentCert}`、`SetDHParameters`、`SetEllipticCurve`、`LoadVerifyLocations`、`Options`（`NoCompression`/`NoSSLv2`/`NoSSLv3`/`NoTLSv1`/`CipherServerPreference`/`NoSessionResumptionOrRenegotiation`/`NoTicket`）、`Modes`（`ReleaseBuffers`）、`SetOptions`/`ClearOptions`/`GetOptions`/`SetMode`/`GetMode`、`VerifyOptions`（`VerifyNone`/`VerifyPeer`/`VerifyFailIfNoPeerCert`/`VerifyClientOnce`）、`VerifyCallback`、`SetVerify`/`SetVerifyMode`/`SetVerifyCallback`/`GetVerifyCallback`/`VerifyMode`/`SetVerifyDepth`/`GetVerifyDepth`、`TLSExtServernameCallback`、`SetTLSExtServernameCallback`、`TLSExtAlpnCallback`、`SetServerALPNProtos`/`SetClientALPNProtos`、`SetSessionID`、`SetCipherList`/`SetCipherSuites`、`SessionCacheModes`（`SessionCacheOff`/`Client`/`Server`/`Both`）、`SetSessionCacheMode`/`SetTimeout`/`GetTimeout`/`SessSetCacheSize`/`SessGetCacheSize` |
| `ssl.go` | `SSL`/`SSLTLSExtErr`（`SSLTLSExtErrOK`/`AlertWarning`/`AlertFatal`/`NoAck`）、`NPNNegotiated`/`NPNNoOverlap`、`SetVerify`/`SetVerifyMode`/`SetVerifyCallback`/`GetVerifyCallback`/`VerifyMode`/`SetVerifyDepth`/`GetVerifyDepth`、`SetOptions`/`ClearOptions`/`GetOptions`、`SetSSLCtx`、`GetServername` |
| `conn.go` | `Conn`/`VerifyResult` 常量全量（`X509_V_OK`/`...CertSignatureFailure`/`...CRL`/`...PathLengthExceeded`/`...InvalidPurpose`/`...CertUntrusted`/`...CertRejected`/`...AKID-SKID-Mismatch`/`...UnhandledCriticalExtension`/`...InvalidPolicyExtension`/`...ApplicationVerification` 等约 60 个）、`Client(conn, ctx)`/`Server(conn, ctx)`、`GetCtx`、`CurrentCipher`/`GetVersion`、`fillInputBuffer`/`flushOutputBuffer`/`getErrorHandler`/`handshake`/`Handshake`/`shutdown`/`shutdownLoop`/`Close`、`PeerCertificate`/`loadCertificateStack`/`PeerCertificateChain`、`ConnectionState`（`Certificate`/`CertificateError`/`CertificateChain`/`CertificateChainError`/`SessionReused`）、`Read`/`Write`、`VerifyHostname`（内部再走 `crypto.CheckHost`/`CheckIP`）、`LocalAddr`/`RemoteAddr`/`SetDeadline`/`SetReadDeadline`/`SetWriteDeadline`/`UnderlyingConn`、`SetTLSExtHostName`、`VerifyResult`/`SessionReused`、`GetSession`/`setSession`、`GetALPNNegotiated` |
| `net.go` | `listener`/`NewListener`/`Listen`、`DialFlags`（`InsecureSkipHostVerification`/`DisableSNI`）、`Dial(network,addr,ctx,flags,host)`/`DialSession` |
| `http.go` | `ListenAndServeTLS(addr,certFile,keyFile,handler)`/`ServerListenAndServeTLS(srv,certFile,keyFile)`（仅 server 侧，client 侧 TODO 注释保留） |
| `tickets.go` | `KeyNameSize`、`TicketCipherCtx`、`TicketDigestCtx`、`TicketName`、`TicketKey`（`Name`/`CipherKey`/`HMACKey`/`IV`）、`TicketKeyManager`（`New`/`Current`/`Lookup`/`Expired`/`ShouldRenew`）、`TicketStore`（`CipherCtx`/`DigestCtx`/`Keys`）、`SetTicketStore` |
| `pem.go` | `SplitPEM(data) [][]byte` |
| `init.go` | 仅 `init()` 调 `C.X_tongsuogo_init()` |

### 4.2 子包 `crypto`（绑定层 + 部分高层 API）

| 文件 | 导出符号（节选） |
|---|---|
| `bio.go` | `SSLRecordSize`、`WriteBio`/`ReadBio`/`anyBio`（`asAnyBio`）、`nonCopyGoBytes`/`nonCopyCString`、`WriteBio{WriteTo,SetRelease,Disconnect,MakeCBIO}`、`ReadBio{ReadFromOnce,SetRelease,MakeCBIO,Disconnect,MarkEOF}`、`anyBio{Read,Write}`、`writeBioMapping`/`readBioMapping` |
| `cert.go` | `DigestAlgo`（`DigestNull`/`MD5`/`MD4`/`SHA`/`SHA1`/`DSS`/`DSS1`/`MDC2`/`Ripemd160`/`SHA224`/`SHA256`/`SHA384`/`SHA512`/`SM3`）、`GMDoubleCertKey`（`SignCertFile`/`SignKeyFile`/`EncCertFile`/`EncKeyFile`）、`X509Version`（`X509V1`/`X509V3`）、`Certificate`（`Issuer`/`ref`/`pubKey`）、`CertificateInfo`（`Serial`/`Issued`/`Expires`/`Country`/`Organization`/`CommonName`）、`Name`（`AddTextEntry`/`AddTextEntries`/`GetEntry`）、`NewCertWrapper`/`NewCertificate`/`Certificate.GetCert`/`GetSubjectName`/`GetIssuerName`/`SetSubjectName`/`SetIssuer`/`SetIssuerName`/`SetSerial`/`SetIssueDate`/`SetExpireDate`/`SetPubKey`/`Sign`/`AddExtension(nid,text)`/`AddExtensions(map[NID]string)`/`LoadCertificateFromPEM`/`MarshalPEM`/`PublicKey`/`GetSerialNumberHex`/`GetVersion`/`SetVersion`、`LoadPEMFromFile`/`SavePEMToFile` |
| `ciphers.go` | `GCMTagMaxLen`、`CipherMode{ECB,CBC,CFB,OFB,CTR,GCM,CCM}`、`CipherCtx` 接口（`Ctx`/`Cipher`/`BlockSize`/`KeySize`/`IVSize`/`SetKeyAndIV`/`SetPadding`/`SetCtrl`/`SetCtrlBytes`/`GetCtrlInt`/`GetCtrlBytes`）、`Cipher`（`Ptr`/`Nid`/`ShortName`/`BlockSize`/`KeySize`/`IVSize`）、`Nid2ShortName`、`GetCipherByName`/`GetCipherByNid`、`EncryptionCipherCtx`（`EncryptUpdate`/`EncryptFinal`）、`DecryptionCipherCtx`（`DecryptUpdate`/`DecryptFinal`）、`NewEncryptionCipherCtx`/`NewDecryptionCipherCtx` |
| `ciphers_gcm.go` | `AuthenticatedEncryptionCipherCtx`（`ExtraData`/`GetTag`）、`AuthenticatedDecryptionCipherCtx`（`ExtraData`/`SetTag`）、`NewGCMEncryptionCipherCtx(blocksize,engine,key,iv)`/`NewGCMDecryptionCipherCtx`（**AES-128/192/256-GCM 三档都在**) |
| `dh.go` | `DeriveSharedSecret(private, public) ([]byte, error)`（`EVP_PKEY_derive`，对 ECDH/EC/DH/通用 KEX 统一） |
| `dhparam.go` | `DH`（`GetDH`）、`LoadDHParametersFromPEM(pemBlock)` |
| `digest.go` | `Digest`（`Ptr`）、`GetDigestByName`/`GetDigestByNid` |
| `engine.go` | `Engine`（`Engine()`）、`EngineByID(name)` |
| `hmac.go` | `HMAC`（`Close`/`Write`/`Reset`/`Final`，带 Engine）、`NewHMAC(key,digest)`/`NewHMACWithEngine(key,digest,engine)` |
| `hostname.go` | `CheckFlags`（`AlwaysCheckSubject`/`NoWildcards`）、`Certificate.CheckHost(host,flags)`/`CheckEmail(email,flags)`/`CheckIP(ip,flags)`/`VerifyHostname(host)` |
| `key.go` | `Method(*C.EVP_MD)`、`SHA1Method`/`SHA256Method`/`SHA512Method`/`SM3Method`、密钥类型常量 `KeyTypeNone/RSA/RSA2/DSA/DSA1/DSA2/DSA3/DSA4/DH/DHX/EC/HMAC/CMAC/TLS1PRF/HKDF/X25519/X448/ED25519/ED448/SM2`、`PublicKey`/`PrivateKey` 接口（`VerifyPKCS1v15`/`Encrypt`/`MarshalPKIXPublicKeyPEM`/`MarshalPKIXPublicKeyDER`/`KeyType`/`BaseType`/`EvpPKey` 等）、`pKey`（`SignPKCS1v15`/`VerifyPKCS1v15`/`MarshalPKCS1/8PrivateKeyPEM/DER`/`MarshalPKIXPublicKeyPEM/DER`/`Encrypt`/`Decrypt`）、`LoadPrivateKeyFromPEM`/`LoadPrivateKeyFromPEMWithPassword`/`LoadPrivateKeyFromPEMWidthPassword`（typo 兼容别名）、`LoadPrivateKeyFromDER`/`LoadPublicKeyFromPEM`/`LoadPublicKeyFromDER`、`GenerateRSAKey`/`GenerateRSAKeyWithExponent(bits, exponent)`、`EllipticCurve`（`Prime256v1`/`Secp384r1`/`Secp521r1`/`SM2Curve`）、`GenerateECKey(curve)`、`GenerateED25519Key`、`SupportEd25519()` |
| `mapping.go` | 内部 `mapping`/`token`/`newMapping`（Go→C BIO 句柄映射表） |
| `nid.go` | `NID int` 常量（`NidUndef`/`...`/`NidSM2 = 1172`、`NidX25519 = 1034`、`NidX448 = 1035`、`NidEd25519 = 1087`、`NidEd448 = 1088`、`NidHkdf = 1036`、`NidTLS1Prf = 1021`、`NidHmac = 855`、`NidCmac = 894` 等约 200 个） |
| `init_posix.go`/`init_windows.go`/`init.go` | 注册 OpenSSL 线程锁回调 |
| 子包 `md5`/`sha1`/`sha256`/`sm2`/`sm3`/`sm4` | 各自 `.go` 提供「该算法独立顶层包」的最小便利函数（如 `sm2.Sign/Verify/SignASN1/VerifyASN1/Encrypt/Decrypt/GenerateKey`） |

### 4.3 子包 `utils`

`utils/errors.go`：`ErrorGroup`（`Add`/`Finalize`，错误聚合）。`utils/future.go`：`Future`（`NewFuture`/`Get`/`Fired`/`Set`，多收单发）。两者均为 `conn.go`/`tickets.go` 内部基础设施，未导出对外算法 API。

---

## 5. 本库能力清单

本库完整能力面已分述于：

- 三层结构、目录地图、生命周期：`docs/architecture.md` §3、§5、§7、§8
- 各算法的导出符号、模式覆盖、AEAD 形式：上表 §1 引用过的内部调研表
- `key/` 统一抽象、`x509/` 证书与 CSR/CRL、`tls/` 客户端/服务端、`asn1/` DER viewer、`pkcs/pkcs7`、`pkcs/pkcs12`、`ocsp/`、`jwk/`、`xml/rsa/`：同 §1 调研表
- 测试组织与各算法必测用例：`docs/testing-guide.md` §3–§7

要点摘录：

- **算法原语侧**：SM2/SM3/SM4、Ed25519/Ed448、X25519/X448、ECDH（P-256/384/521、secp256k1、X25519/X448）、RSA、ECDSA、AES-128/256、MD5/SHA-1/SHA-256/SHA-512、SM3；SM4 覆盖 ECB/CBC（含零填充变体）/CTR/OFB/CFB/GCM；AES 覆盖 ECB/CBC/CTR/GCM
- **格式与容器侧**：CSR（含 challengePassword、自定义扩展）、CRL（解析+校验+`RevocationCheck`）、PKCS#7（证书集合 Build/Extract）、PKCS#12（Pack/Parse/ChangePassword）、OCSP（请求构造+响应解析+验签+自适应 CertID）、JWK（RSA/EC↔PEM/JSON）、XML RSAKeyValue、ASN.1 DER viewer
- **传输侧**：客户端+服务端、NTLS 双证书、`Handshake`/`HandshakeContext`、`SetDeadline` 系列、`*HandshakeError` 错误分类、`CipherSuites(version)` 探测

---

## 6. 缺口矩阵：官方有、本库无

> 字段：`#` / `官方能力（符号）` / `本库现状` / `优先级` / `做或不做的理由`
>
> 优先级三档：**P0**（高：影响典型 TLS 场景）/ **P1**（中：补齐典型用法即可）/ **P2**（低：边缘场景或被现有 API 间接覆盖）。

### 6.A TLS/NTLS 传输层（10 项）

| # | 官方能力（符号） | 本库现状 | 优先级 | 做或不做的理由 |
|---|---|---|---|---|
| A1 | **服务端 SNI 选证书**：`Ctx.SetTLSExtServernameCallback`、`SSL.SetSSLCtx`、`SSL.GetServername` | ❌ 仅有客户端发 SNI（`SSLConn.SetServerName`），无 SNI 回调、无按名切 ctx | **P0** | **做**。CDN / 虚拟主机 / 多证书部署的服务端必备；官方建议替换为 Go 惯例的 `tls.Config.GetCertificate func(*ClientHelloInfo) (*Certificate, error)`（等价于 `Config.GetConfigForClient`）。 |
| A2 | **ALPN**：`SetServerALPNProtos` / `SetClientALPNProtos` / `Conn.GetALPNNegotiated` | ❌ `tls.Config` 无 `NextProtos`，`internal/native` 无 `SSL_CTX_set_alpn_*` | **P0** | **做**。HTTP/2、gRPC、所有现代应用层协议都依赖；命名替换为 `Config.NextProtos []string`（与 Go `crypto/tls` 一致）+ `Conn.NegotiatedProtocol() string`。 |
| A3 | **会话复用**：`SetSessionCacheMode` / `SessSetCacheSize` / `SessGetCacheSize` / `SetTimeout` / `SetSessionID` / `Conn.GetSession` / `DialSession` / `SessionReused` | ❌ 完全无 `SSL_SESSION` 绑定；每次握手都是 fresh | **P0** | **做**。TLS 性能基础（0-RTT 之外的复用）；命名替换为 `Config.SessionCache` + `tls.DialSession` / `Conn.GetSession() []byte`，符合 Go 惯例。 |
| A4 | **会话票据（Ticket Key Manager）**：`TicketStore` / `TicketKeyManager` / `SetTicketStore` | ❌ 无 `SSL_CTX_set_tlsext_ticket_key_cb` | **P0** | **做**。与服务端会话复用配合；命名替换为 `Config.SessionTicketKey [32]byte`（与 `crypto/tls` 一致）或 `Config.TicketKeyManager`，让运维可定期轮转。 |
| A5 | **自定义证书校验回调**：`SetVerify(opts, VerifyCallback)` + `CertificateStoreCtx{VerifyResult,Err,Depth,GetCurrentCert}` | ❌ shim `X_SSL_CTX_set_verify` 强制 `callback = NULL` | **P0** | **做**。Pin 证书指纹、内网私有 CA、证书透明度检查都依赖；命名替换为 `Config.VerifyPeerCertificate func([][]byte, [][]*x509.Certificate) error`，与 Go `crypto/tls` 一致。 |
| A6 | **`LoadVerifyLocations(caFile, caPath)`**（含空参回落系统默认路径） + **`Options` 全量**（`NoSSLv2`/`NoSSLv3`/`NoTLSv1`/`NoCompression`/`CipherServerPreference`/`NoSessionResumptionOrRenegotiation`/`NoTicket`） + **`Modes`（`ReleaseBuffers`）** | ⚠️ 仅有 `SetDefaultVerifyPaths`、`SetVerifyDepth`、`SetMin/MaxProtoVersion`、`SetCipherList`、`SetCipherSuites`；缺 options/modes 整套开关 | **P1** | **做**。最小/最大协议版本已做；剩下 `NoSSLv2/v3`、`NoCompression`、`CipherServerPreference` 等用 `Config` 字段表达（与 Go `crypto/tls` 对齐）；`ReleaseBuffers` 是性能旋钮，建议一并加 `Config.SessionTicketsDisabled` 等价于 `NoTicket`。 |
| A7 | **tmp ECDH / tmp DH**：`SetEllipticCurve`（tmp ECDH）、`SetDHParameters`（tmp DH） | ❌ 无 | **P1** | **做**。经典 RSA/ECDHE 协商所必需；命名替换为 `Config.ECDHCurve string` 与 `Config.DHParameters *DHParams`，与 BCL/GCM 风格接近。 |
| A8 | **`net.Listener` 集成**：`Listen` / `NewListener`；**包装任意 `net.Conn`**：`Client(conn,ctx)` / `Server(conn,ctx)` | ❌ `NewSSLConn` 只接受 `*net.TCPConn` 的 fd；服务端只有 `Server.Accept(raw)` 形式 | **P1** | **做**。命名替换为 `tls.NewListener(inner net.Listener, cfg *Config)` / `tls.Client(conn net.Conn, cfg *Config)` / `tls.Server(conn net.Conn, cfg *Config)`，与 Go `crypto/tls` 一致；底层继续吃 `*net.TCPConn` 但暴露 `net.Conn` 接口。 |
| A9 | **HTTP 集成**：`ListenAndServeTLS` / `ServerListenAndServeTLS`（仅 server 侧） | ❌ | **P2** | **做**。服务端一行起 HTTP + TLCP/TLS 对运维意义大；命名 `tls.ListenAndServeTLS` / `tls.ServeTLS(...)`，仅 server 侧（client 侧官方也只 TODO）。 |
| A10 | **`Conn.VerifyHostname`** / `UnderlyingConn()` / `SetTLSExtHostName` / `ConnectionState`（`Certificate`+`CertificateError`+`Chain`+`ChainError`+`SessionReused`） / **`VerifyResult` 全量错误码常量表** | ⚠️ 有 `VerifyResult() int`、`Version()`、`CipherName()`、`PeerCertificates()`；无其余 | **P1** | **做**。与 `x509.VerifyError` 配合可暴露完整错误码；命名替换为 `Conn.VerifyHostname(host) error` / `Conn.UnderlyingConn() net.Conn` / `Conn.ConnectionState() ConnectionState`，与 Go `crypto/tls` 一致。 |

### 6.B 组合层与基础设施（17 项）

| # | 官方能力（符号） | 本库现状 | 优先级 | 做或不做的理由 |
|---|---|---|---|---|
| B1 | **`SplitPEM(data) [][]byte`**（公开 PEM 切分） | ❌ 公开面缺失 | **P1** | **做**。所有 PEM 处理都需要它；建议放在 `key/`（与 `key.ParsePEM` 并列）`func SplitPEM(data []byte) [][]byte`。 |
| B2 | **`crypto.Engine` / `EngineByID(name)`**（ENGINE 加载与生命周期） | ❌ 无 | **P2** | **待定**。ENGINE 在 3.0 后由 provider 取代；若要做，应以 provider 形态补；现阶段可暂缓。 |
| B3 | **`crypto.DH` / `LoadDHParametersFromPEM`** | ❌ 无 DH 参数 API | **P1** | **做**。与 A7 配合；命名 `crypto/dh.DH` + `LoadDHParametersPEM(data []byte)`，独立子包对齐 `crypto/ecdh` 形态。 |
| B4 | **`crypto.DeriveSharedSecret(priv, pub) ([]byte, error)`**（通用 `EVP_PKEY_derive`，对 ECDH/EC/DH/SM2 等统一） | ⚠️ 各算法各自实现（`x25519.SharedSecret`、`ecdh.(*PrivateKey).ECDH`、`sm2` 无 KE） | **P1** | **做**。补在 `key/` 或 `crypto/ecdh` 顶层；不改各算法现有 API，作为「跨算法 KEX 适配点」与未来 SM2-KE 的预留。 |
| B5 | **`Certificate.CheckHost` / `CheckEmail` / `CheckIP` / `VerifyHostname` + `CheckFlags`** | ❌ 无公开主机名/邮箱/IP 匹配 API | **P0** | **做**。客户端链校验的常用配套；命名替换为 `x509.Certificate.VerifyHostname(host string) error` + `x509.HostnameOptions`（与 Go `crypto/x509` 兼容形态）。 |
| B6 | **`Certificate.AddExtension(nid, textValue)` / `AddExtensions(map[NID]string)`**（任意 X509v3 扩展按 NID+文本构建） | ⚠️ `x509.Certificate` 只有固定 helper（SAN/KeyUsage/EKU/SKID/AKID/BasicConstraints）；`CSR` 已有通用 `AddExtension` | **P0** | **做**。`CSR` 已证明方案可复用；扩到 `x509.Certificate.AddExtension(nid int, value string) error`，文档明示「value 是 OpenSSL v3 ext 配置语法」。 |
| B7 | **`LoadPEMFromFile` / `SavePEMToFile`** | ❌ | **P2** | **做**。小工具；放 `key/` 或新 `pkcs/pem` 子包；用户也可自行 `os.ReadFile` + `os.WriteFile`，价值中等。 |
| B8 | **`CertificateInfo` + `NewCertificate`**（便捷自签） | ⚠️ 本库是低层 `Set*` 逐步构建 + `CreateCertificate` | **P2** | **不做**（或推迟）。本库自签路径示例完整（`examples/self-signed-cert`），便捷 API 价值不高；待用户呼声出现时再加。 |
| B9 | **`GMDoubleCertKey`**（双证书文件路径组合） | ⚠️ 用 `tls.Config` 四个独立字段（`SignCert`/`SignKey`/`EncCert`/`EncKey`） | **P2** | **不做**。本库已经用 `Config` 字段表达，引入结构体反而割裂；如需便利函数可在 `tls` 包提供 `dialWithDoubleCertFiles(addr, signCert, signKey, encCert, encKey)` 等一两个便利函数。 |
| B10 | **`DigestAlgo` 枚举 + `crypto.Digest` / `DigestCtx` 通用摘要对象** | ⚠️ 按算法分包，无统一摘要对象 | **P2** | **不做**。本库按 Go `hash.Hash` 惯例分包，加通用 `Digest` 对象会与 §9「不做」项重合；如确有需要，作为 `internal/core` 内部使用即可。 |
| B11 | **`NID` 常量表 + `KeyType*` + `PublicKey.KeyType()/BaseType()` 统一密钥抽象** | ⚠️ 本库是各算法独立类型 + `key/` 层接口 | **P2** | **不做**。`key/` 已有 `AsymmetricKey.Algorithm() Algorithm` 接口提供等价能力；公开 NID 常量表会扩大导出面（违反 AGENTS.md §10.9）。 |
| B12 | **通用 `Cipher` 按名取**（`GetCipherByName` / `GetCipherByNid`） + **`SetCtrl/GetCtrl/SetCtrlBytes/GetCtrlBytes`** + **`CipherModeCCM`**；**AES-192 / AES-192-GCM** | ⚠️ `crypto/aes` **明确不支持 AES-192**（仅 16B/32B 密钥）；其余 `SetCtrl` 等是 ctx 内部 API，已被各算法的 AEAD/封装覆盖 | **P1** | **做**。补 AES-192 是必须（按 NIST FIPS 197 完整覆盖）；`GetCipherByName`/`CipherModeCCM` 不做（被各算法 mode 函数覆盖；CCM/GCM 之外无需新 ctx 控制）。 |
| B13 | **`GenerateRSAKeyWithExponent(bits, exponent)`**（自定义公钥指数） | ❌ 固定 65537 | **P2** | **不做**。65537 是事实上标准，自定义指数属小众；如需可让 `GenerateRSAKey(bits)` 加变体。 |
| B14 | **`SupportEd25519()`** | ❌ | **P2** | **不做**。构造即知结果（`ed25519.GenerateKey` 直接返回，provider 探测已在 `key.Generate*` / `crypto/ecdh` 路径体现）。 |
| B15 | **`EllipticCurve` 枚举**（本库用字符串曲线名） | ⚠️ 用字符串曲线名（`GenerateECKey("prime256v1")`） | **P2** | **不做**。字符串名可读性更高、消除导出常量爆炸；不必改。 |
| B16 | **公开 BIO 桥接**（`ReadBio` / `WriteBio` / `MakeCBIO`） | ⚠️ 封在 `internal/native` | **P2** | **不做**（见 §9）。 |
| B17 | **`HMAC`（`HMAC_CTX`，带 Engine）** | ⚠️ 本库用 `hash.Hash` 惯例实现（`crypto/hmac.NewSHA256` 等） | **P2** | **不做**（见 §9）。 |

合计 27 项：**P0 共 6 项**（A1、A2、A3、A4、A5、B5、B6）、**P1 共 7 项**（A6、A7、A8、A10、B1、B3、B4、B12）、**P2 共 14 项**（其余）。

---

## 7. 本库反超清单（官方完全没有）

> 官方 README 只自报：Hash（SM3/MD5/SHA1/SHA256）、SM4、SM2 加解密、SM2withSM3 签名、HMAC、SM2 证书、TLCP + TLSv1.0/1.1/1.2/1.3。下面这些都是**官方目前没有**的能力。

- **算法原语**
  - SM4 完整模式（ECB / CBC（含零填充）/ CTR / OFB / CFB / GCM）——官方只有 SM4（无模式列举）
  - SM2 加解密（DER 与裸格式） + SM2 签名验签（含 `userId`） + C1C3C2 ↔ C1C2C3 顺序转换
  - **Ed448**（RFC 8032）——官方无
  - **X25519 + X448**（RFC 7748）——官方无独立 API（仅作 KeyType 常量）
  - **统一 ECDH 抽象**（P-256/384/521、secp256k1、X25519/X448）——官方无
  - **KDF（HKDF + PBKDF2）**——官方无
  - **RSA-PSS / RSA-OAEP**——官方只有 `Encrypt`/`SignPKCS1v15`（PKCS#1 v1.5）
  - **RSA CRT 参数**（`Dmp1`/`Dmq1`/`Iqmp`，0.3.0 发布）——官方未提供
  - **AES-128 / AES-256 + 完整模式**（ECB/CBC/CTR/GCM）——官方无 AES 模块
  - **SHA-512**（独立子包）——官方只有 SHA-256/SHA1
- **容器与协议**
  - **X.509 CSR**（含 `challengePassword`、自定义扩展）——官方 `cert.go` 没有 CSR
  - **X.509 CRL 解析 + 校验 + `RevocationCheck`**——官方无
  - **X.509 证书链验证**（`Store.ChainVerify` + `VerifyError{Code,Depth,Message}`）——官方无等价抽象
  - **PKCS#7**（证书集合 `Build`/`Extract`/`MarshalPEM`）——官方无
  - **PKCS#12**（`Pack`/`Parse`/`ChangePassword`）——官方无
  - **OCSP**（请求构造 + 响应解析 + 验签 + 自适应 CertID）——官方无
  - **JWK**（RFC 7517，RSA/EC ↔ PEM/JSON，含 CRT 字段）——官方无
  - **XML `RSAKeyValue`**（.NET 兼容互转）——官方无
  - **ASN.1 DER viewer**（`asn1.Parse`/`Dump`，纯 Go，cgo-free）——官方无
  - **`key.Store` / `MemoryStore` + 密钥轮转 + `History`**——官方无
  - **`key.Handle{ID,Algorithm,Key,PEM,CreatedAt}`** + JSON 序列化——官方无
- **惯例与可编程性**
  - **`hash.Hash` / `cipher.Block` / `cipher.AEAD` 实现**（与 Go `crypto/*` 标准库一致）——官方走自己的 `HMAC.Write/Final` + `EncryptionCipherCtx.EncryptUpdate/Final`
  - **`(T, error)` 返回形态** —— 官方不少函数只返回 `(C.int)`/`(unsafe.Pointer, error)`
  - **`HandshakeContext(ctx)` / `DialContext`** —— 官方无
  - **`*HandshakeError` 错误分类**（`Op`/`Kind`/`Err`，含 `Is/Unwrap`）——官方错误链平铺
  - **CLI 对拍测试**（`//go:build tongsuocli`，与铜锁 `openssl` 逐字节对拍）——官方没有这层
  - **覆盖率门禁脚本**（`scripts/check-coverage.sh`）——官方无
  - **静态链接**（`-tags static`，Linux 已接线）——官方有 `build_static.go` 但目录结构上不可插拔

---

## 8. 全量对齐路线图（能力级）

> 本节**只列能力 + 优先级**。每个 PR 自行设计「涉及文件 / 验收方式」，按 §10 的验证与维护约定走。
>
> 包结构重构（`0.3.0`）与本节的能力补全（`0.4.0` 起）分开排期：结构重构见 [refactor-roadmap.md](refactor-roadmap.md) §7，两者合并后的版本归属以该节为准。

### Phase 1 — 基础设施小件（风险低、价值高、几乎不动 native shim）

来源：**B1、B5、B6、B3**（部分）。

| 能力 | 缺口编号 | 优先级 |
|---|---|---|
| PEM 公开切分（`key.SplitPEM` 或 `pkcs/pem`） | B1 | P1 |
| X.509 主机名/邮箱/IP 校验（`x509.Certificate.VerifyHostname` + `HostnameOptions`） | B5 | **P0** |
| 任意 X509v3 扩展按 NID 构建（`x509.Certificate.AddExtension(nid,value)`） | B6 | **P0** |
| DH 参数加载（`crypto/dh` 子包 + `LoadDHParametersPEM`） | B3 | P1 |
| AES-192（含 AES-192-GCM）补齐 | B12 部分 | P1 |

### Phase 2 — 密钥协商与通用原语

来源：**A7、B4**。

| 能力 | 缺口编号 | 优先级 |
|---|---|---|
| tmp ECDH / tmp DH（`Config.ECDHCurve` + `Config.DHParameters`） | A7 | P1 |
| 通用 KEX 适配点（`DeriveSharedSecret(priv, pub)`） | B4 | P1 |

### Phase 3 — TLS/NTLS 协议能力（依赖 `internal/native` shim 扩展 + `internal/core/ssl.go` 重构）

来源：**A1、A2、A3、A4、A5、A6、A8、A10**。

| 能力 | 缺口编号 | 优先级 |
|---|---|---|
| 服务端 SNI 选证书（`Config.GetCertificate` + `GetConfigForClient`） | A1 | **P0** |
| ALPN（`Config.NextProtos` + `Conn.NegotiatedProtocol`） | A2 | **P0** |
| 会话复用（`Config.SessionCache` + `DialSession`/`Conn.GetSession`） | A3 | **P0** |
| 会话票据（`Config.SessionTicketKey` 或 `Config.TicketKeyManager`） | A4 | **P0** |
| 自定义证书校验回调（`Config.VerifyPeerCertificate` + `VerifyConnection`） | A5 | **P0** |
| `Options`/`Modes` 开关（`Config.NoCompression`/`CipherServerPreference`/...） | A6 | P1 |
| `net.Listener` 包装 + 任意 `net.Conn` 入口（`tls.NewListener`/`Client`/`Server`） | A8 | P1 |
| 完整 `ConnectionState` + `VerifyHostname`/`UnderlyingConn` + 错误码常量表 | A10 | P1 |

### Phase 4 — 传输生态与示例

来源：**A9、B1、B7**（部分示例）。

| 能力 | 缺口编号 | 优先级 |
|---|---|---|
| `tls.ListenAndServeTLS` / `tls.ServeTLS`（仅 server 侧） | A9 | P2 |
| `examples/ntls-loopback`、`examples/self-signed-cert` 补 mTLS / SNI / ALPN / 票据复用演示 | — | — |

### 命名对照表（官方符号 → 本库拟用 Go 惯例 API）

> 这是路线图「能力级」的关键交付物。**本库采用 Go 惯例命名**，不与官方 1:1 对应。

| 官方符号（官方语义） | 本库拟用 API | 缺口编号 |
|---|---|---|
| `Ctx.SetTLSExtServernameCallback` | `tls.Config.GetCertificate func(*ClientHelloInfo) (*Certificate, error)` / `GetConfigForClient` | A1 |
| `Ctx.SetServerALPNProtos` / `SetClientALPNProtos` / `Conn.GetALPNNegotiated` | `tls.Config.NextProtos []string` + `tls.Conn.NegotiatedProtocol() string` | A2 |
| `Ctx.SetSessionCacheMode` / `SessSetCacheSize` / `SetTimeout` / `Conn.GetSession` / `DialSession` / `SessionReused` | `tls.Config.SessionCache` + `tls.DialSession` / `tls.Conn.GetSession() []byte` / `tls.Conn.Reused() bool` | A3 |
| `Ctx.SetTicketStore` + `TicketStore`/`TicketKeyManager` | `tls.Config.SessionTicketKey [32]byte` 或 `tls.Config.TicketKeyManager` | A4 |
| `Ctx.SetVerify(opts, VerifyCallback)` + `CertificateStoreCtx` | `tls.Config.VerifyPeerCertificate func([][]byte, [][]*x509.Certificate) error` + `tls.Config.VerifyConnection` | A5 |
| `Ctx.{SetEllipticCurve, SetDHParameters}` | `tls.Config.ECDHCurve string` + `tls.Config.DHParameters *dh.DH` | A7 |
| `net.Listener`/`Listen` / `Client(conn,ctx)` / `Server(conn,ctx)` | `tls.NewListener(inner net.Listener, cfg *Config)` / `tls.Client(conn net.Conn, cfg *Config)` / `tls.Server(conn net.Conn, cfg *Config)` | A8 |
| `Conn.VerifyHostname` / `UnderlyingConn` / `ConnectionState` | `tls.Conn.VerifyHostname(string) error` / `UnderlyingConn() net.Conn` / `ConnectionState() ConnectionState` | A10 |
| `http.ListenAndServeTLS` | `tls.ListenAndServeTLS(addr, certFile, keyFile, handler)` / `tls.ServeTLS(srv, certFile, keyFile)` | A9 |
| `SplitPEM` | `key.SplitPEM(data) [][]byte`（或新建 `pkcs/pem`） | B1 |
| `crypto.Engine` / `EngineByID` | 暂缓（详见 §6.B.B2） | B2 |
| `crypto.DH` / `LoadDHParametersFromPEM` | `crypto/dh.DH` + `crypto/dh.LoadDHParametersPEM([]byte)` | B3 |
| `crypto.DeriveSharedSecret` | `key.DeriveSharedSecret(priv key.PrivateKey, pub key.PublicKey) ([]byte, error)`（或放 `crypto/ecdh` 顶层） | B4 |
| `Certificate.CheckHost`/`CheckEmail`/`CheckIP`/`VerifyHostname` + `CheckFlags` | `x509.Certificate.VerifyHostname(host string) error` + `x509.HostnameOptions{NoWildcards, AlwaysCheckSubject, ...}` | B5 |
| `Certificate.AddExtension(nid, text)` / `AddExtensions(map[NID]string)` | `x509.Certificate.AddExtension(nid int, value string) error` + `AddExtensions(...)` | B6 |
| `crypto.ciphers_gcm.NewGCMEncryptionCipherCtx(blocksize,...)` AES-192-GCM | `crypto/aes.NewGCMWithKeySize(keyLen int) (cipher.AEAD, error)` + `aes.NewCipher` 支持 24B 密钥 | B12 |
| `DeriveSharedSecret(priv, pub)` | `key.DeriveSharedSecret(priv key.PrivateKey, pub key.PublicKey) ([]byte, error)` | B4 |

---

## 9. 明确不实现清单

以下项目**有意不实现**，理由如下：

| 项 | 不做理由 |
|---|---|
| **公开 BIO 桥接**（`ReadBio` / `WriteBio` / `MakeCBIO`） | 违反本库分层红线（`import "C"` 只在 `internal/native`，参见 AGENTS.md §3.3）；BIO 是 cgo 互操作的内部细节，不应进入公开 API；如有需要，使用 `crypto/io`（标准库 `io.Reader` / `io.Writer`）即可。 |
| **原生 `HMAC`/`HMAC_CTX` 接口（带 Engine）** | 本库 HMAC 走 Go `hash.Hash` 惯例（`crypto/hmac.NewSHA256(...)`），更可组合、便于复用 `encoding/binary`/`io`；暴露 `HMAC_CTX` 与 Engine 一类差。 |
| **`NID` 常量表** | 扩大导出面（约 200 个常量）但用途狭窄（只与 `AddExtension(nid,text)` 配合）；本库在 `internal/core` 内部维护等价 NID 表，对外只暴露语义化 helper（如 `x509.NIDServerAuth`）。 |
| **`EllipticCurve` 枚举** | 本库使用字符串曲线名（`GenerateECKey("prime256v1")`）；导出常量集会让 `crypto/ecdh` 公开面膨胀，且与 NID 常量表同问题。 |
| **通用 `Digest` / `DigestCtx` 对象** | 本库按算法分包 + `hash.Hash` 惯例实现；统一对象只能服务边缘场景，且会让 `crypto/{md5,sha1,sha256,sm3,sha512}` 之间重复。 |
| **`CipherMode*` 常量枚举** | 各算法直接提供 `EncryptECB`/`EncryptCBC`/`EncryptCTR`/`EncryptGCM` 等高层函数（与官方 ctx 内部 `CipherModeECB=1` 等价的数值常量不需要暴露）。 |
| **`GMDoubleCertKey` 结构体** | 用 `tls.Config` 四个字段已足够。 |
| **`CertificateInfo` + `NewCertificate` 便捷自签** | 自签场景示例完整（`examples/self-signed-cert`），API 价值低；可由用户在 `key.Store` 基础上自行组合。 |
| **`GenerateRSAKeyWithExponent`** | 65537 是事实上的标准，自定义指数属小众场景。 |
| **`SupportEd25519`** | 构造即知结果（`GenerateKey` 直接返回），冗余检测 API。 |
| **`crypto.Engine` / `EngineByID`** | Tongsuo 8.x 已迁向 OpenSSL 3.0 provider 体系；ENGINE 是 OpenSSL 1.x 兼容概念。如要做，应以 `crypto.Provider` 形态补（待 v0.4+ 评估）。 |

---

## 10. 验证与维护约定

- **基线记录**：本对比基于官方 `main @ 002a0963 (2025-01-14)`；每次本报告更新或重新评估前，请用 `git ls-remote https://github.com/Tongsuo-Project/tongsuo-go-sdk.git refs/heads/main` 拉取最新 commit 并 bump 此基线。
- **本机环境**：本次仅做静态比对（仓库无 Tongsuo C 库）。任何具体 PR 的合入必须执行：
  ```bash
  gofmt -l .            # 应为空
  go vet ./...          # 0 输出
  go build ./...        # 成功
  go test -count=1 ./...# 全部 ok
  ```
  涉及 cgo/绑定时额外：`go build -tags static ./...`（Linux）；涉及并发/生命周期：`go test -race ./...`；涉及 CLI 对拍：`go test -tags tongsuocli ./...`。无铜锁环境须**如实声明未运行**，不得写成「已验证通过」。
- **升级 Tongsuo C 库后**：执行 `scripts/check-coverage.sh`（默认阈值 60%，路线图目标 80%）+ `go test -count=1 ./...`，同步 bump `.github/workflows/ci.yml` 中的 `TONGSUO_REF` 与缓存键前缀。
- **本报告后续维护**：若官方 SDK 新增能力或本库新增能力导致矩阵变化，按以下顺序更新：
  1. 校基线 SHA（§2）
  2. 更新 §4 官方能力清单（按文件列）
  3. 更新 §5 本库能力清单（指向 `docs/architecture.md`）
  4. 更新 §6 缺口矩阵（增/删/改 4 列：能力/现状/优先级/理由）
  5. 更新 §8 路线图与命名对照表
  6. 更新 §11 符号对照表（新增条目）
- **不要触碰**：`docs/issues/2026-09-18/**` 历史审计报告；`CHANGELOG.md` / `CHANGELOG.zh.md`（不在本次改动范围）；任何 `.go` 源代码（本次仅产出文档）。

---

## 11. 符号对照表

> 本节集中列出「官方符号 ↔ 本库等价物 / 缺口编号」，便于在具体 PR 中查阅。

### 11.1 本库已覆盖（官方有，本库有等价 API 或更好）

### 11.2 本库已覆盖但命名不同（推荐）

| 官方符号 | 本库等价物 |
|---|---|
| `crypto.Certificate` | `x509.Certificate`（无原生指针暴露，`Close()` 幂等） |
| `crypto.Name` | `x509.Name` / `x509.NewName()` |
| `crypto.DigestAlgo` | 各算法子包 `New() hash.Hash` |
| `crypto.GenerateRSAKey` | `crypto/rsa.GenerateKey(bits)` + `key.GenerateRSAKey(bits)` |
| `crypto.GenerateECKey` | `crypto/ecdsa.GenerateKey(curve)` + `crypto/ecdh.(*Curve).GenerateKey()` |
| `crypto.GenerateED25519Key` | `crypto/ed25519.GenerateKey()` + `key.GenerateEd25519Key()` |
| `crypto.MarshalPKCS1PrivateKeyPEM` | `crypto/rsa.(*PrivateKey).MarshalPKCS1PEM()` |
| `crypto.MarshalPKCS8PrivateKeyPEM` | `crypto/rsa.(*PrivateKey).MarshalPEM()` 等 |
| `crypto.LoadPrivateKeyFromPEM` | 各算法 `LoadPrivateKeyPEM(pem)` + `key.LoadPrivateKeyPEM`（跨算法） |
| `crypto.LoadPrivateKeyFromPEMWithPassword` | `LoadEncryptedPEM(pem, pass)` |
| `crypto.Encrypt`/`Decrypt` (SM2) | `crypto/sm2.Encrypt`/`Decrypt` |
| `crypto.sm2.Sign`/`Verify` | `crypto/sm2.Sign`/`Verify` + `SignWithID`/`VerifyWithID` |
| `crypto.sm2.SignASN1`/`VerifyASN1` | `crypto/sm2.Sign`/`Verify`（默认返回 ASN.1 DER 签名） |
| `crypto.sm2.GenerateKey` | `crypto/sm2.GenerateKey()` + `key.GenerateSM2Key()` |
| `tls.Client(conn, ctx)` / `Server(conn, ctx)` | `tls.Client` / `tls.Server`（仅签名连接） + `Dial`/`Dinner` |
| `tls.Listen` / `NewListener` | **未实现**（见 §6.A.A8） |
| `tls.Dial` | `tls.Dial(ctx, network, addr, cfg)` + `DialContext` |

### 11.3 本库明确缺口（见 §6）

参见 §6.A / §6.B 矩阵的 `#` 列。