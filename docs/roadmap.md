# 版本路线图（`0.5.0` 及以后）

> **用途**：本文件是本仓库**唯一的版本归属来源**——某个能力落在哪个 `0.x` 版本，以本文件 §2 为准。
>
> **口径**：
> 1. **只写未做的事**。`0.4.0`（2026-10-23 发布）及其之前已发布的能力不在本文范围内，
>    其符号清单见 [api-reference.md](api-reference.md)，其变更记录见 [CHANGELOG.md](../CHANGELOG.md)；
> 2. 本文件**不重复**能力级判定与优先级。缺口编号与「本库现状」列见
>    [cli-comparison.md](cli-comparison.md)（对铜锁 CLI）、[official-sdk-comparison.md](official-sdk-comparison.md)（对官方 SDK）、
>    逐条待实现 API 见 [cli-comparison-todo.md](cli-comparison-todo.md)；
> 3. 逐符号的**目标 API 形态**以 [api-reference.md](api-reference.md) 的 🧭 行为准；
>    若该行标注的版本与本文件 §2 冲突，以本文件为准并回改 api-reference；
> 4. 「需新增 cgo 绑定」是实施前置条件，统一列在 §3，§2 各表以「前置」列引用。
>
> **基线**：`0.4.0`（2026-10-23 发布）——16 个顶级包形态已定格，见 [architecture.md](architecture.md) §2 / §3。

---

## 1. 里程碑总览

| 版本 | 主题 | 关键内容 | 破坏性 |
|------|------|----------|--------|
| `0.5.0` | **形态地基 + 高频算法** | 文件 / stdio / `io.Reader` 入口与出口；统一任务入口（`dgst`/`enc`/`mac`/`kdf` 四条主命令）；`meta` 算法枚举与 provider；`mac` 的 CMAC/GMAC/KMAC 家族；AES-192、SM4-CCM/XTS、ChaCha20(-Poly1305)；`kdf` 扩到 10 种；`tls.NewListener` | 否 |
| `0.6.0` | **算法覆盖主体 + 格式容器** | SHA-512/224·256、SHA3、SHAKE、KECCAK、SHA-256/192；AES 扩展模式（OFB/CFB/OCB/SIV/WRAP/…）与 ZUC；上下文签名（ED25519ph/ctx）；`x509` 的 `-x509toreq`、OCSP HTTP 与 nonce；`jwk` 的 OKP/oct；`crl2pkcs7`；PKCS#12 PBE/iter | 部分（按名分发入口收敛） |
| `0.7.0` | **容器协议 + PQC** | `pkcs7` 签名/验签/加密/解密族；ML-DSA-44/65/87、SLH-DSA 12 变体、KEM（`-encap`/`-decap`）；SM2DH 密钥协商；通用 KEX 适配点 | 否 |
| `0.8.0` | **协议族与 CA 形态** | CMS 族、RFC 3161 `ts`；`ca` 工作流（形态待定，见 §4）；`storeutl` 统一加载器 | 否 |
| `1.0.0` | **传输深度 + 公开面收敛** | 服务端 SNI 选证书、ALPN、会话复用与票据、客户端证书认证、`Options`/`Modes`、完整 `ConnectionState`、自定义证书校验回调、DH/ECDHE 曲线配置、`net.Listener` 与 HTTP 集成；§6.E 的 E2/E3 公开面收敛（破坏性，需迁移指南） | **是** |

> **节奏原则**：`0.x` 阶段只做**能力增补**（加符号、加算法），不动既有公开面；`1.0.0` 集中做
> **破坏性收敛**，让 API 一次性稳定。这样 `0.x` 期间下游可以只按需升级补丁版本。
>
> **例外（安全 / 一致性修复）**：当既有行为会**静默产出错误结果**（例如签名后仍可改字段，
> 导致签名与证书内容不符）时，允许在 `0.x` 做破坏性收紧——但**必须**在同一版本的
> [CHANGELOG](../CHANGELOG.md) 中单列 `BREAKING` 段，写明新语义与迁移方式。
> 先例：`0.4.0` 把 `x509` 的 `Sign` / `CertificateRequest.Sign` 收紧为**单向终态**。

---

## 2. 分版本范围

### 2.1 `0.5.0` — 形态地基与高频算法补齐

> 本版目标是让本库**用起来像 CLI 一样直接**：调用方给出「算法名 + 输入源 + 输出编码」即可拿到结果。

| 领域 | 内容 | 对应缺口 | 前置（§3） |
|------|------|----------|-------------|
| 形态 | 文件 / stdin / stdout 入口与出口；`io.Reader` / `io.Writer` 流式 | cli-comparison §6.C C1 / C2 / C3 / C11 | 无（Go 侧） |
| 形态 | 统一任务入口：按「算法名 + 输入源 + 输出编码」一次调用完成 **摘要 / 加解密 / MAC / KDF** | §6.A 8 / 15 / 26 / 24 | 无 |
| 形态 | hex / base64 / hexdump 编码助手；统一 `Format` 维度（PEM / DER）；口令来源抽象（`pass:` / `env:` / `file:` / `fd:` / `stdin`） | §6.C C5 / C6 / C4 / C8 | 无 |
| 形态 | 一行生成自签证书、一行由密钥生成 CSR | §6.A 40、§6.B B4 / B5 | 无（`x509.CreateSelfSigned` 已具备） |
| `meta` | 算法枚举：`Digests` / `Ciphers` / `MACs` / `KDFs` / `Signatures` / `KeyExchanges` / `KEMs` / `TLSGroups` | §6.A 25、§6.B B16 | 算法枚举、Provider、TLS 组 |
| `meta` | `Providers` / `ProviderInfo` / `SeedingSource` | §6.A 23 | Provider、环境信息 |
| `mac` | CMAC、GMAC、KMAC-128/256、SipHash、Poly1305、EIA3（`EVP_MAC_*` 全家族，`New(name, …)` 同时接受非 HMAC） | §6.A 26 | MAC |
| `sym` | AES-192 全模式（含 GCM）；SM4-CCM / SM4-XTS；ChaCha20 / ChaCha20-Poly1305 | §6.B B12、§6.A 15 | AES-192、SM4 扩展模式、流密码 |
| `kdf` | scrypt、SSKDF、TLS1-PRF、TLS13-KDF、X9.42 / X9.63、KBKDF、HMAC-DRBG-KDF | §6.A 24 | KDF 泛化 |
| `tls` | `NewListener(config, ln)`（`net.Listener` 包装） | §6.B A8 | 无（Go 侧） |
| `x509` | RDN 写入顺序修正（**BREAKING**）：`Name.Add` 由前插改为追加，DER 顺序 = 书写顺序，与 `openssl req -subj` / `crypto/x509` 的 `pkix.Name` 一致 | — | 无（`internal/native` 的 `loc` 参数） |

**验收要点**：四个主命令（`dgst` / `enc` / `mac` / `kdf`）对 `dgst -sm3 -hex`、`mac -macopt hexkey:… HMAC-SM3`、
`enc -sm4-cbc`、`kdf -kdfopt digest:SM3 … HKDF` 的 CLI 对拍逐字节一致（注意 `mac` 本版起走
provider `EVP_MAC_*`，与旧版 HMAC legacy 路径需双向验证一致）。

### 2.2 `0.6.0` — 算法覆盖主体与格式容器

| 领域 | 内容 | 对应缺口 | 前置（§3） |
|------|------|----------|-------------|
| `digest` | SHA-512/224、SHA-512/256、SHA3-224/256/384/512、SHAKE128/256（需输出长度参数）、KECCAK-224/256/384/512、SHA-256/192 | §6.A 8 | 算法枚举（`EVP_sha3_*` / `EVP_shake_*` / `EVP_keccak_*`） |
| `sym` | AES-OFB / CFB / CCM / XTS / OCB / SIV / GCM-SIV / WRAP / CBC-CTS；ZUC-128-EEA3 | §6.A 15 | AES 扩展模式、流密码（ZUC） |
| `asym` | 上下文签名：ED25519ph / ED25519ctx / ED448ph（`EVP_DigestSignInit_ex` 的 `context-string`） | — | 上下文签名 |
| `ecdh` | 曲线参数文件读写（`ecparam -param_out`） | §6.A 14 | 无（走现有 EC 参数序列化） |
| `x509` | `-x509toreq`（证书 → CSR）、信任属性、`subject_hash`、`-attime` 链输出 | §6.A 54 / 56 | 无 |
| `x509` | OCSP HTTP 客户端 `FetchOCSP`；OCSP 请求 / 响应 nonce | §6.A 28、§6.B B13 | OCSP nonce |
| `x509` | `AddExtension(nid int, value string)` / `AddExtensions(map[int]string)` —— 任意 X509v3 扩展按 NID 构建 | §6.B B6 | 无（`X509V3_EXT_conf_nid` 已绑定） |
| `jwk` | OKP（`Kty: "OKP"`：Ed25519 / Ed448 / X25519 / X448）；对称密钥（`Kty: "oct"`） | — | 无（需 `asym` 曲线标识 + `sym` base64url 导出） |
| `pkcs/pkcs7` | `FromCRL` / `ExtractCRLs`（`crl2pkcs7`） | §6.A 7 | 无 |
| `pkcs/pkcs12` | `Options{ PBE, Iterations, FriendlyName, ReadPass, WritePass }` —— PBE 算法与迭代次数、读写口令分离 | §6.A 31、§6.B B11 | `X_PKCS12_create` shim 扩展 |
| `pkcs/pkcs12` | PKCS#8 `-topk8` 双向转换、版本与 PRF 选择 | §6.A 33、§6.B B10 | 无 |
| `pkcs/pkcs12` | PKCS#1 公钥（`-RSAPublicKey_in/out`）、`-check` / `-pubcheck` | §6.A 41 / 34 | 无 |
| 格式 | PEM 公开切分（`SplitPEM`） | §6.B B1 | 无 |
| 形态 | 统一加载器（覆盖 `storeutl` 的使用场景） | §6.A 52 | 无 |

**已知限制（沿用）**：铜锁 8.4 的 HKDF 实现与 `kdf` 命令行输出存在差异
（`kdf/kdf_tongsuocli_test.go` 记录过该 known bug），本版维持既有的降级断言策略，不改期望值。

### 2.3 `0.7.0` — 容器协议与 PQC

| 领域 | 内容 | 对应缺口 | 前置（§3） |
|------|------|----------|-------------|
| `pkcs/pkcs7` | 签名 / 验签 / 加密 / 解密族（`Sign` / `Verify` / `Encrypt` / `Decrypt`） | §6.A 32、§6.B B12 | PKCS#7 签名族 |
| `asym` | ML-DSA-44 / 65 / 87；SLH-DSA 12 变体 | — | 需新增 `EVP_PKEY` 解封装路径（铜锁已启用 `signature-algorithms`） |
| `asym` | KEM：`Encapsulate` / `Decapsulate`（`-encap` / `-decap`） | — | KEM |
| `ecdh` | SM2DH 密钥协商（`CurveByName("SM2DH")`） | §6.A 29 | 铜锁已启用 `key-exchange-algorithms`；`EVP_PKEY_derive*` 已绑定，需补 SM2 派生参数 |
| `ecdh` | 通用 KEX 适配点（`DeriveSharedSecret(priv, pub)`） | §6.B B4 | 无 |

### 2.4 `0.8.0` — 协议族与 CA 形态

| 领域 | 内容 | 对应缺口 | 前置（§3） |
|------|------|----------|-------------|
| `pkcs/pkcs7` | CMS 族（`cms` 命令） | §6.A 5 | CMS / TS |
| 新包 `ts` | RFC 3161 时间戳（`ts` 命令）：ASN.1 结构 + HTTP 传输 | §6.A 53 | CMS / TS |
| `x509` | CRL 应用级签发入口（配置驱动） | §6.A 6、§6.B B9 | 无（`CRLBuilder` 已在 `0.3.0` 具备） |
| `x509` | `ca` 式签发 / 吊销 / 续期工作流 | §6.A 2 | **形态待定**，见 §4 第 2 条 |

> `ts` 的体量与 `x509` 相当，建议作为独立顶级包 `ts`，与 `x509` 平级而非塞进 `x509`。

### 2.5 `1.0.0` — 传输深度与公开面收敛

> 本版是**集中做破坏性收敛**的版本，需配迁移指南（`BREAKING` 段写法参照 `0.4.0` 与 `0.3.0`）。

**传输深度（`tls`）**

| 能力 | 对应缺口 | 前置（§3） |
|------|----------|-------------|
| 服务端 SNI 多证书（`Config.GetCertificate func(*ClientHelloInfo) (*Certificate, error)` / `GetConfigForClient`） | §6.B A1 | TLS 深度 |
| ALPN（`Config.NextProtos` + `Conn.NegotiatedProtocol()`） | §6.B A2 | TLS 深度 |
| 会话复用（`Config.SessionCache` + `DialSession` / `Conn.SessionState()`） | §6.B A3 | TLS 深度 |
| 会话票据（`Config.SessionTicketKey` 或 `TicketKeyManager`） | §6.B A4 | TLS 深度 |
| 客户端证书认证（`Config.ClientAuth` + `Config.ClientCAs`） | §6.B A8 | TLS 深度 |
| 自定义证书校验回调（`Config.VerifyPeerCertificate` / `VerifyConnection`） | §6.B A5 | TLS 深度 |
| `Options` / `Modes` 开关（`NoCompression` / `CipherServerPreference` / …） | §6.B A6 | 无 |
| 完整 `ConnectionState` + `VerifyHostname` / `UnderlyingConn` + 错误码常量表 | §6.B A10 | 无 |
| DH 参数加载与 ECDHE 曲线配置（`Config.DHParameters` / `Config.ECDHCurve`） | §6.B B3、A7 | 无（DH **参数**加载，非 DH 密钥交换，见 §4 第 3 条） |
| 握手上下文增强（`HostnameOptions`：`CheckEmail` / `NoWildcards` / `AlwaysCheckSubject`） | §6.B B5 | 需 `X509_check_email` 等 flags |
| `ListenAndServeTLS` / `ServeTLS`；OCSP stapling；keylog；HTTP 集成 | §6.A 9 / 43 | 无 |

**公开面收敛（破坏性）**

- **E2 原语级公开面**：把按名分发入口的签名收敛为统一的 `Options` 结构体（消除 `0.5.0`–`0.6.0`
  逐步加参数造成的签名膨胀）
- **E3 多步组装面**：把需要调用方自己串联多步的流程（如自签证书 + CSR 链）收成应用级函数
- 两项都需同步：迁移对照表、`CHANGELOG` 的 `BREAKING` 段、`docs/` 全套规范

---

## 3. 实施前置：需新增的 cgo 绑定

> 每项标注目标版本；**未列版本的项即其所属版本对应表中的「前置」**。已在 `0.3.0` 落地的绑定单列于文末。

| 家族 | 需要的 C 接口 | 服务对象 | 目标版本 |
|------|--------------|----------|----------|
| MAC | `EVP_MAC_fetch` / `EVP_MAC_new` / `EVP_MAC_init` / `EVP_MAC_update` / `EVP_MAC_final` | `mac` 的 CMAC / GMAC / KMAC-128/256 / SipHash / Poly1305 / EIA3 | `0.5.0` |
| AES-192 | `EVP_aes_192_{ecb,cbc,ctr,gcm}` | `sym` | `0.5.0` |
| SM4 扩展模式 | `EVP_sm4_ccm` / `EVP_sm4_xts` | `sym` | `0.5.0` |
| 流密码 | `EVP_chacha20` / `EVP_chacha20_poly1305` | `sym` | `0.5.0` |
| KDF 泛化 | 现有 shim 仅 `HKDF` / `PBKDF2`；其余需 `EVP_KDF_fetch(alg)` 泛化 | `kdf` | `0.5.0` |
| 算法枚举 | `EVP_{MD,CIPHER,MAC,KDF,SIGNATURE,KEYEXCH,KEM}_do_all_provided` | `meta` | `0.5.0` |
| Provider | `OSSL_PROVIDER_*` | `meta` | `0.5.0` |
| 环境信息 | `OPENSSL_info(OPENSSL_INFO_SEED_SOURCE)` | `meta` | `0.5.0` |
| TLS 组 | `SSL_get1_groups` / `SSL_group_to_name` | `meta` | `0.5.0` |
| 扩展摘要 | `EVP_sha512_224` / `EVP_sha512_256` / `EVP_sha3_*` / `EVP_shake_*` / `EVP_keccak_*` | `digest` | `0.6.0` |
| AES 扩展模式 | `EVP_aes_*_{ofb,cfb,ccm,xts,ocb,siv,wrap,cbc-cts}` | `sym` | `0.6.0` |
| ZUC | `EVP_zuc` | `sym` | `0.6.0` |
| 上下文签名 | `EVP_DigestSignInit_ex` 的 `context-string` 选项 | `asym` 的 ED25519ph / ctx | `0.6.0` |
| OCSP nonce | `OCSP_REQUEST_add1_nonce` / `OCSP_check_nonce` | `x509` | `0.6.0` |
| PKCS#12 | `X_PKCS12_create` shim 扩展（`PKCS12_create` 已接受 PBE / iter 参数） | `pkcs/pkcs12` | `0.6.0` |
| KEM | `EVP_PKEY_encapsulate` / `EVP_PKEY_decapsulate` | `asym` | `0.7.0` |
| PQC | ML-DSA / SLH-DSA 的 `EVP_PKEY` 解封装路径（铜锁已启用 `signature-algorithms`） | `asym` | `0.7.0` |
| SM2DH | `EVP_PKEY_derive*` 的 SM2 派生参数（已绑定，需泛化） | `ecdh` | `0.7.0` |
| PKCS#7 签名族 | `PKCS7_sign` / `PKCS7_verify` / `PKCS7_encrypt` / `PKCS7_decrypt`（`PKCS7_set_type` 已绑定） | `pkcs/pkcs7` | `0.7.0` |
| CMS / TS | `CMS_*` / `TS_*` | `pkcs/pkcs7`（CMS）、`ts` | `0.8.0` |
| TLS 深度 | `SSL_CTX_set_alpn_protos` / `SSL_get0_alpn_selected`、`SSL_SESSION_*`、`SSL_CTX_set_tlsext_servername_callback`、`SSL_CTX_set_client_CA_list` | `tls` | `1.0.0` |
| 主机名校验 flags | `X509_check_host` 的 flags 扩展 / `X509_check_email` 等 | `tls` 的 `HostnameOptions` | `1.0.0` |

**已在 `0.3.0` 落地的相关绑定**（列此便于对照，避免重复规划）：
`OpenSSLVersionWithIndex`（`meta` 版本/构建信息）、`X509_REVOKED_*` / `X509_CRL_add0_revoked` /
`X509_CRL_sort`（`x509.CRLBuilder`）、`X509_check_host` / `X509_check_ip_asc`（`Certificate.VerifyHostname`）、
`X509_STORE_set_verify_time`（`Store.SetTime`）。

**`0.4.0` 未新增 C 接口**：本版只修正既有 `X509_sk_X509_EXTENSION_push` / `X509_sk_X509_push`
的返回值语义（OpenSSL 3 的 `sk_TYPE_push` 返回压入后的**栈长度**，原实现按 0/1 布尔判断），
未引入新的绑定。

**已在 `0.4.0` 落地的相关绑定**：`X_X509_EXTENSION_create_by_NID_der`（按调用方给出的
DER 值构造扩展，绕开 OpenSSL 的扩展配置语法）、`X509_CRL_add_ext`（向 CRL 追加扩展）、
`OBJ_nid2oid`（NID → 点分 OID）——均服务于 `x509` 的类型化 certificatePolicies 入口。

---

## 4. 明确不做 / 暂缓

| # | 项 | 处置 | 理由 |
|---|----|------|------|
| 1 | `engine`（provider 的前身机制） | 不做 | 已被 provider 机制取代 |
| 2 | `ca` 式数据库化 CA 工作流 | **暂缓**（列在 `0.8.0` 但形态未定） | 本质是文件系统状态机，与本库内存模型冲突；需先定「内存模型 vs 文件系统绑定」。若最终定为文件系统形态，则整体移出本库 |
| 3 | DSA / DH **密钥交换算法** | 不做 | 非国密目标场景。但**为 TLS 握手加载 DH 参数**（`Config.DHParameters`）与算法本身无关，仍在 `1.0.0` 做 |
| 4 | EC-ElGamal / Paillier（同态） | 不做 | 非国密目标场景 |
| 5 | 需重编铜锁方可验证的六项 | 不做（标注保留） | 本机构建未启用，无法验证：白盒 SM4（`wbsm4` / `wbsm4kdf`）、Bulletproofs、SM2 门限签名/解密（`sm2_threshold`）、SDF 密码设备接口、SMTC 模块管理（`mod`）、Delegated Credential（`decred`）。见 [cli-comparison.md](cli-comparison.md) §6.D |
| 6 | 把 `internal/core` 的类型提升为公开句柄 | 不做 | 与「公开签名不得出现 `internal/` 类型」的硬约束冲突。跨包取句柄走 `internal/keyaccess` / `internal/certaccess`，见 [architecture.md](architecture.md) §3.3 |
| 7 | 公开 BIO 桥接、原生 `HMAC_CTX`、`NID` 常量表 | 不做 | 与 Go 惯例封装的目标冲突；理由见 [official-sdk-comparison.md](official-sdk-comparison.md) §9 |
| 8 | `crypto/*` deprecated 转发包 | 不做 | 转发层会让公开面收敛永远做不完；`0.3.0` 已一次性完成破坏性迁移 |

---

## 附录 A. 包结构重构决策记录（`0.3.0` 已落地，历史归档）

> 以下决策是 `0.3.0` 把 27 个 API 层包收敛为 **16 个顶级包**（取消 `crypto/` 整目录与 `key/`）的依据。
> **已全部实施完毕**，保留于此仅为解释现状形态的由来，不再构成待办。逐符号清单见
> [api-reference.md](api-reference.md) §0 / §0.1，依赖方向见 [architecture.md](architecture.md) §2。

| # | 决策项 | 结论 | 理由 |
|---|--------|------|------|
| 1 | 重构力度 | **一步到位迁移并删除旧包**，不做 deprecated 转发 | 转发层会让「公开面收敛」永远做不完；`0.3.0` 尚未发布，可直接改 |
| 2 | 命名与层级 | **Go 惯例名 + 全部顶级**，`crypto/` 与 `key/` 取消 | 现有 `crypto/` 下既有算法也有组合层，边界已经模糊；扁平后职责清晰 |
| 3 | 对称包名 | `sym` | 与 `asym` 对称、3 字母等长；避免与标准库 `crypto/cipher` 同名 |
| 4 | `ec` 与 `ecdh` | **不拆**：曲线密钥生成归 `asym`，密钥协商归 `ecdh` | 避免为「曲线参数」单独建包 |
| 5 | 非对称包 | 单个 `asym`，按算法名分发 | 合并 `genpkey` / `pkey` / `pkeyutl` 三命令的职责 |
| 6 | `x25519` / `x448` | **删除包**：生成 → `asym`，协商 → `ecdh` | `ecdh.Curve` 已覆盖 OKP 曲线，独立包只剩重复 |
| 7 | `mac` 范围 | **仅 MAC**（HMAC / CMAC / GMAC / KMAC / SipHash / Poly1305 / EIA3） | 签名/验签归 `asym`；MAC 管「带密钥的摘要」 |
| 8 | `rand` / `kdf` | 各自保留顶级包 | 两者都是 CLI 子命令，且无更合适的归属 |
| 9 | PKI 家族 | **不拆**：`csr` / `crl` / `ocsp` 全部留在 `x509` | 拆分会让 `x509 ↔ crl` 成环（`Store.AddCRL` 需 `crl`，`crl.NewBuilder` 需 `x509`），Go 无法编译；改用文件维度拆开缓解体量 |
| 10 | `key` 归宿 | 拆四块：`asym` + `sym` + `keystore` + `kdf` | 「各自抽象、各自实现」，不再有一个包同时持有对称与非对称 |
| 11 | Go 惯例接口 | **保留** `hash.Hash` / `cipher.Block` / `cipher.AEAD`，同时叠加 CLI 式按名入口 | 保住 Go 生态可组合性，又不丢「一次调用完成一件事」 |
| 12 | 内部类型泄露 | **E1 十二项全部收敛** | 公开签名不得出现 `internal/core` 类型；这是重构的硬约束 |
| 13 | 跨包取句柄 | **`internal/keyaccess` + 结构化接口断言**（无注册表） | 见 [architecture.md](architecture.md) §3.3 |
| 14 | 命名收尾 | `tongsuo` → `meta`；`symmetric` → `sym` | 前者避免 `tongsuo-go/tongsuo` 的 stutter；后者见决策 3 |
| 15 | `pkcs/` | **不扁平**，保留 `pkcs/pkcs7`、`pkcs/pkcs12` | 为将来 `pkcs/#8` 等预留命名空间 |
| 16 | 版本归属 | 全部并入 **`0.3.0`** | 一次性落地破坏性变更，避免分批 |
| 17 | 路线图口径 | 全列（含需新增 cgo 绑定 / 需重编铜锁的项） | 便于排期时不遗漏前置条件 |

**副作用（正向）**：`crypto/rand` 与标准库 `crypto/rand` 的「同路径同名」问题消失。

---

## 附录 B. 相关文档

| 用途 | 文档 |
|------|------|
| 公开 API 逐符号清单（含 🧭 规划中形态） | [api-reference.md](api-reference.md) |
| 内部 API 清单（`internal/*`） | [api-reference-internal.md](api-reference-internal.md) |
| 分层、目录、依赖方向、桥接设计 | [architecture.md](architecture.md) |
| 与铜锁 CLI 的能力对比（缺口编号来源） | [cli-comparison.md](cli-comparison.md) |
| 待实现 API 逐条清单 | [cli-comparison-todo.md](cli-comparison-todo.md) |
| 与官方 SDK 的能力对比 | [official-sdk-comparison.md](official-sdk-comparison.md) |
| 开发规范 / 测试规范 | [development-guide.md](development-guide.md) · [testing-guide.md](testing-guide.md) |
| 变更记录 | [CHANGELOG.md](../CHANGELOG.md) · [CHANGELOG.zh.md](../CHANGELOG.zh.md) |