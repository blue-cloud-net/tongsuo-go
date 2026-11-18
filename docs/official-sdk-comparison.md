# 官方 tongsuo-go-sdk 与本库能力对比

> 复核日期：2026-11-18 ｜ 本库：`0.12.0` 定版，待标签发布。
> 官方基线：`Tongsuo-Project/tongsuo-go-sdk` main @
> [`002a09631de785f2d984d9e0b3a7f1e9a169940c`](https://github.com/Tongsuo-Project/tongsuo-go-sdk/tree/002a09631de785f2d984d9e0b3a7f1e9a169940c)。
> 本次用 `git ls-remote` 确认远端 main 未变，并只读核对该提交源码；未运行官方 SDK。
> 以下是源码能力对比，不是两库性能、安全性或完整协议一致性的评测。

## 1. 结论与方法

典型 TLS/NTLS 的 SNI、ALPN、认证、证书链、参数配置、Listener 与诊断不再是本库的
历史缺口。会话缓存/恢复与票据管理已在 0.11.0 实现，
HTTP/1.1 与 OCSP stapling 已在 0.12.0 实现。另有两个具体边界：官方传输通过 BIO
接入 `net.Conn`，本库目前要求 TCP；官方支持自定义 RSA 公钥指数，本库固定 65537。
两项先保留候选需求，不为符号对齐扩大公开面。

对比按能力而非函数同名判断。官方 README 没提到某项，不作为“官方不支持”的证据；
官方通用 `GetCipherByName` / `GetDigestByName` 也能调用原生算法，不能因为没有独立
AES/SHA-512 包便判为缺失。相反，存在算法常量或原生指针出口，也不代表已有完整高层流程。

本库实现位置见 [公开 API 清单](api-reference.md)；已决定的交付范围见
[路线图](roadmap.md)，待确认价值的功能见 [需求台账](requirements.md)。

## 2. TLS / NTLS 对比

官方符号取自固定提交的
[ctx.go](https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/002a09631de785f2d984d9e0b3a7f1e9a169940c/ctx.go)、
[conn.go](https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/002a09631de785f2d984d9e0b3a7f1e9a169940c/conn.go)、
[net.go](https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/002a09631de785f2d984d9e0b3a7f1e9a169940c/net.go)、
[tickets.go](https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/002a09631de785f2d984d9e0b3a7f1e9a169940c/tickets.go)
与 [http.go](https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/002a09631de785f2d984d9e0b3a7f1e9a169940c/http.go)。

| 能力 | 官方固定基线 | 本库 `0.12.0` | 结论 / 后续 |
|---|---|---|---|
| TLS / TLCP 双证书 | Ctx、UseSign/EncryptCertificate、Dial / Server | `tls.Config` 单证书/双证书、Dial / Client / Server | 均有公开入口；各自协议与构建支持需实际验收 |
| SNI 多证书 / 配置切换 | `SetTLSExtServernameCallback` / `SetSSLCtx` | `GetCertificate` / `GetConfigForClient` | 本库已交付，不再作为缺口 |
| ALPN | `SetServerALPNProtos` / `SetClientALPNProtos` / `GetALPNNegotiated` | `NextProtos` / `ConnectionState.NegotiatedProtocol` | 均支持；不等于任一库已集成 HTTP/2 |
| 客户端认证 / 自定义验证 | `SetVerify` / `VerifyCallback`、证书存储 | `ClientAuth` / `ClientCAs`、`VerifyPeerCertificate` / `VerifyConnection` 与显式验证策略 | 本库已交付；回调和配置语义不承诺逐项相同 |
| 信任、组、签名、DH 参数、Options/Modes | 原生风格 Ctx 配置 | Config 受约束字段、严格参数检查、HostnameOptions | 核心场景已有；不映射任意控制码 |
| Listener | `Listen` / `NewListener` | `net.Listen` + `tls.NewListener` | 均有入口，握手与 Accept 错误语义以各自文档为准 |
| 底层连接 | `Client` / `Server` 存储 net.Conn，经 ReadBio/WriteBio 传输 | API 接收 net.Conn，但 `connFD` 只接受 `*net.TCPConn` | 真正的剩余差异；I-40 暂缓通用流后端 |
| 会话恢复 | `SetSessionCacheMode`、大小/超时/ID、`GetSession` / `DialSession` / `SessionReused` | 0.11.0 已实现公开缓存、DER/PEM 与实际恢复 | I-31，0.11.0；独立验证 TLS 1.3 握手后票据，不能由官方存在这些符号推断其完整行为 |
| 票据轮换 | `TicketStore` / `TicketKeyManager` / `SetTicketStore` | 0.11.0 已实现共享密钥管理与自动/显式轮换 | I-31，0.11.0；复用能力，不照搬原生 CipherCtx/HMAC_CTX |
| HTTP 服务 | `ListenAndServeTLS` / `ServerListenAndServeTLS`；客户端仍为 TODO | Listener 可供组合，尚无专用 HTTP 便捷入口 | 0.12.0 补 HTTP/1.1 客户端/服务端；不把官方 server helper 描述成全套 HTTP 集成 |
| 超时、取消、错误与状态 | net.Conn deadline、Handshake、ConnectionState、UnderlyingConn | 独立 deadline、HandshakeContext / DialContext、HandshakeError 与验证状态 | 两者均有基础传输接口，本库另有显式 context 入口 |
| RFC 8998、结构化事件、trace/keylog、SCT | 本次未见对应的专用高层配置/诊断交付面 | `RFC8998` / `Diagnostics` / `CaptureSCT` / `SecureRenegotiation` | 本库已有专门 API；不据此否定官方底层扩展或原生库能力 |

本库源码定位：[tls/config.go](../tls/config.go)、[tls/tls.go](../tls/tls.go)、
[tls/listener.go](../tls/listener.go)、[tls/diagnostics.go](../tls/diagnostics.go)。

## 3. 密码算法、证书与工具

官方依据为固定提交的 `crypto/` 源码目录，重点文件：
[key.go](https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/002a09631de785f2d984d9e0b3a7f1e9a169940c/crypto/key.go)、
[ciphers.go](https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/002a09631de785f2d984d9e0b3a7f1e9a169940c/crypto/ciphers.go)、
[cert.go](https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/002a09631de785f2d984d9e0b3a7f1e9a169940c/crypto/cert.go)。

| 能力 | 官方固定基线 | 本库 `0.12.0` | 判断 |
|---|---|---|---|
| 摘要 | SM3/MD5/SHA1/SHA256 便利包，通用摘要描述符 | `digest.New` / `Sum`、XOF 与流式/形态入口 | API 形态与封装范围不同，不按子包数量计能力 |
| 对称与 AES-192-GCM | 按名 Cipher、加解密上下文、GCM 上下文，含 AES 三种位宽 | `sym` 按名与类型化入口，Block/AEAD 及扩展模式 | 本库 AES-192 已交付；官方有通用 AES 能力，旧文档“官方无 AES”撤销 |
| MAC | HMAC，含可指定 Engine 的 legacy 上下文 | `mac` 基于 EVP_MAC，多种 MAC + `hash.Hash` | 本库提供更广的专门 MAC 接口；不补公开 HMAC_CTX |
| RSA / EC / Ed25519 与编码 | 通用密钥接口、RSA、EC、Ed25519、PKCS#1/8/SPKI | `asym` 加 RSA-PSS/OAEP、Ed448、EdDSA 变体与密钥检查 | 只比较专门公开入口，不推断官方原生指针路径能或不能完成全部算法 |
| RSA 自定义指数 | `GenerateRSAKeyWithExponent` | `GenerateRSA` 固定 65537 | I-44 暂缓，有明确存量互通对象后评估 |
| 通用 derive | `crypto.DeriveSharedSecret`，直接调用 EVP_PKEY_derive | `ecdh.DeriveSharedSecret` 与六曲线 ECDH、专门 SM2DH | 已补通用适配；本库不承诺任意 DH/SM2 参数可由同一个裸 derive 入口推断 |
| KDF / KEM / PQC | 本次未见专门公开 KDF/KEM/PQC 工作流 | KDF 已有；KEM/PQC 仍规划 | KDF 对比见 CLI 文档；PQC 以 0.13.0 实现验收为准 |
| 证书、扩展与名称校验 | Certificate / Name、按 NID 扩展、CheckHost/Email/IP | `x509` 证书、配置/DER 扩展、名称校验、完整序列号及验证存储 | 常用场景均有；本库新增 DER 扩展等，不能将官方 TLS 链验证误写成不存在 |
| CSR / CRL / OCSP / PKCS 容器 | 本次未见与本库相同的独立高层流程 | `x509` CSR/CRL/OCSP、PKCS#7 签验/信封、PKCS#12 无损改密 | 本库已有专门模块；不承诺其覆盖原生所有格式与算法 |
| PEM / 文件工具 | `SplitPEM`、证书文件读写 | `meta.SplitPEM` / `DecodePEMFirst` 等、Source/Sink 与本地多对象加载 | 已覆盖工具需求，不再创建重复 API |
| JWK / XML / ASN.1 viewer / keystore | 本次未见对应专门模块 | `jwk`、`xml/rsa`、纯 Go `asn1`、`keystore` | 属本库专门提供的应用接口，不以此宣称整体优于官方 |

## 4. 设计差异与不对齐项

| 维度 | 官方固定基线 | 本库约束 |
|---|---|---|
| 组织 | 顶层 TLS + crypto 子包，公开层直接调用 cgo | API → internal/core → internal/native；16 个顶级包 |
| 原生出口 | `EvpPKey`、`GetCert`、Cipher/Engine/BIO 等公开底层访问 | 原生类型不进入公开签名；跨包桥接只在 internal |
| 生命周期 | 部分对象依赖 finalizer，部分有 Close | 核心句柄幂等 Close + finalizer 兜底；是否需释放按各公开类型说明 |
| 惯例 | 原生上下文和配置方法较多 | hash.Hash / cipher.Block / cipher.AEAD 与 Config/Options |
| 构建 | 有动态与静态构建文件，依赖外部铜锁 | 同样依赖外部铜锁；Linux static 已接线，不能宣称官方没有静态链接 |

不复制官方实现，不为了逐符号对齐公开 BIO、Engine、HMAC_CTX、NID 或原生指针。
provider/硬件支持若有需求，应另按 I-42 设计隔离与所有权，不能由 Engine API 直接迁移推断。
不以代码行数、README 篇幅、测试文件数量或“未见高层入口”评价两库安全性和性能。

## 5. 复核流程

```bash
git ls-remote https://github.com/Tongsuo-Project/tongsuo-go-sdk.git refs/heads/main
# 在临时目录读取源码，固定提交后核对 ctx/conn/net/tickets/http 与 crypto 实现。
```

本次未运行官方 SDK 的 build/test、协议回环、性能或跨库互通；本库历史验收记录见
[testing-guide.md](testing-guide.md)。官方提交变化后重新比较源码，不把本文推断为其最新
版本的永久能力清单。剩余任务入口统一见 [cli-comparison-todo.md](cli-comparison-todo.md)。
