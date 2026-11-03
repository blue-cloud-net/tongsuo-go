# 版本路线图（`0.7.0` 至 `1.0.0`）

> **用途**：本文件是本仓库**唯一的版本归属来源**。未来能力的目标版本以 §2 为准；
> 逐符号目标形态见 [api-reference.md](api-reference.md) 的 🧭 行，实施前置见 §3。
>
> **基线**：`0.6.0` 已完成实现、尚未发 tag，以 `feat/v0.6.0` 工作树为准；
> `dev` 的 `0.5.0` 基线不能用于判定 `0.6.0` 的能力。现有实现及行为变化见
> [公开 API 清单](api-reference.md) 与 [CHANGELOG](../CHANGELOG.md#060---tbd)。
> `0.6.0` 以铜锁 8.4.0 验证；后续规划不等于已经实现或验证。
>
> **需求来源**：Toolbit 的 22 项下游需求处置见
> [下游需求复核台账](downstream-requirements.md)；CLI 与官方 SDK 的缺口编号分别见
> [cli-comparison.md](cli-comparison.md)、[official-sdk-comparison.md](official-sdk-comparison.md)。

---

## 1. 里程碑总览

| 版本 | 主题 | 关键内容 | 破坏性 |
|------|------|----------|--------|
| `0.7.0` | **下游可靠性与数据完整性** | 显式释放、解析限额、完整序列号、DER 扩展、信任路径、SM2 压缩输入、PKCS#12 改密互通 | 以增补为主；错误结果修复需说明迁移 |
| `0.8.0` | **PKCS#7 容器** | 签名 / 验签 / 加密 / 解密，附带与分离签名、SignedData、EnvelopedData | 否 |
| `0.9.0` | **铜锁 8.5 兼容与经典算法扩展** | 8.4/8.5 矩阵、RSA-SM3 签名、GCM-SIV、EdDSA 上下文/预哈希、SM2DH、通用 KEX | 否 |
| `0.10.0` | **PQC** | ML-DSA、SLH-DSA、原生 KEM，密钥生命周期与序列化、能力探测 | 否 |
| `0.11.0` | **CMS 与时间戳** | CMS 扩展、独立顶级包 `ts` 的 RFC 3161 能力 | 否 |
| `0.12.0` | **TLS 能力完善** | SNI、ALPN、双向认证、会话复用/票据、校验回调、连接状态、曲线配置与 HTTP 集成 | 否 |
| `1.0.0` | **公开 API 收敛与稳定** | 统一 Options、应用级组合入口、CRL 配置式签发、迁移指南与兼容性承诺 | **是** |

**节奏原则**：先解决下游可靠性，再交付容器，随后扩充原生版本和算法；各版本按
验收条件交付，不承诺日历日期。`0.x` 优先增补 API，`1.0.0` 集中收敛公开面。
安全或一致性修复若改变既有行为，必须在实际交付版本的双语 CHANGELOG 中写明
`BREAKING` 与迁移方式；纯排期调整不新增 CHANGELOG 条目。

**兼容原则**：`0.7.0`、`0.8.0` 保持铜锁 **8.4.0** 发布基线。`0.9.0` 增加固定
8.5 版本构建与运行验证，保留 8.4 构建兼容；新能力须通过编译保护与运行时探测报告
支持情况，不以 master、替代密码实现或自动加载 legacy provider 兜底。

---

## 2. 分版本范围

### 2.1 `0.7.0` — 下游可靠性与数据完整性

| 领域 | 交付内容与边界 | 下游需求 | 前置（§3） |
|------|----------------|----------|-------------|
| 生命周期 | ECDH 公私钥与 CSR 公开幂等 `Close()`；关闭 ECDH 副本不影响原 `asym` 密钥，关闭后可失败操作返回错误 | I-09 / I-15 | 复用 core 句柄关闭与 `EVP_PKEY_dup` |
| `asn1` | `ParseWithLimits` 与可识别的深度/节点数超限错误；保留 `Parse` 的固定 128 层保护和既有行为 | I-16 | 无（纯 Go） |
| `x509` 序列号 | 新增 `RevokedEntry.SerialHex`、`CRLBuilder.RevokeSerialHex`；旧 `Serial int64` 保留为受限兼容视图。现有 `Revoke(cert)` 改走完整序列号，不得再经 `int64` 截断；读写至少覆盖 20 字节 | I-18 / I-20 | 完整 ASN.1 INTEGER 读写 |
| `x509` 扩展 | 公开按 OID 写入 DER 的入口，支持已知和自定义 OID；`Data` 保留原始扩展值，不还原任意配置串，不放开签名后修改 | I-19 | 按 OID 构造 DER 扩展 |
| `x509` 信任路径 | `Store.SetDefaultPaths`、`LoadLocations`；默认路径属于铜锁配置，不等同于各平台原生信任库，不隐式信任输入链的自签根 | I-17 | 默认路径与 CA 文件/目录加载 |
| `asym` SM2 | 经 native → core → API 解码、校验压缩 C1，支持转换与解密；保持既有输出形式，不新增压缩输出选项 | I-10 | EC 点解码与校验 |
| `pkcs/pkcs12` | safe/bag 层重加密，保留密钥、证书链与属性；覆盖外部默认 PBES2/AES 和可用 3DES 容器，不用丢失属性的解析后重打包兜底 | I-22 | PKCS#12 safe/bag 重加密 |
| 文档与互通 | 说明 RSA 签名为模数长度字节串并补双向互验；补带扩展的分步签发示例，保留签名后不可变约束 | I-08 / I-21 | 无 |

RSA 的签名格式符合 [RFC 8017 §8](https://www.rfc-editor.org/rfc/rfc8017.html#section-8)，
不改成 SM2/ECDSA 的 `SEQUENCE { r, s }`。`0.6.0` 的 PKCS#12
`ChangePasswordWithOptions` 是解析后重打包，不代表已经完成 I-22 的无损改密。
实现必须明确报告不支持的容器/算法，不能静默丢失 bag 或属性。

### 2.2 `0.8.0` — PKCS#7 容器

| 领域 | 内容 | 对应缺口 | 前置（§3） |
|------|------|----------|-------------|
| `pkcs/pkcs7` | `Sign` / `Verify`：带 signerInfo 的 SignedData，附带与分离签名，明确区分签名有效与证书受信任 | I-11、§6.A 32 / §6.B B12 | PKCS#7 签名族 |
| `pkcs/pkcs7` | `Encrypt` / `Decrypt`：EnvelopedData，覆盖错误密钥与篡改检测，不宣称非认证加密可检测所有篡改 | I-11、§6.A 32 | PKCS#7 加密族 |

复用现有证书袋与 CRL 容器能力；CMS 扩展留给 `0.11.0`，不以一个模糊的
“CMS/PKCS#7”格式参数混同两阶段的交付。算法支持以铜锁原生能力和互通验收为准。

### 2.3 `0.9.0` — 铜锁 8.5 兼容与经典算法扩展

| 领域 | 内容 | 前置（§3） |
|------|------|-------------|
| 兼容性 | 固定 8.4.0 / 8.5 版本分别构建、运行单元测试与 CLI 对拍；头文件、链接库与 CLI 必须对应，master 仅作前瞻验证 | 独立安装与 CI 矩阵 |
| `sym` | AES-GCM-SIV；评估新 provider 的 AES-SIV 空消息边界，旧基线仍明确拒绝 | 新版 provider、能力探测与标准向量 |
| `asym` | ED25519ph / ED25519ctx / ED448ph；RSA-PKCS#1 v1.5 / PSS 的 SM3 签名可运行支持（I-06） | 上下文签名、RSA provider 摘要支持 |
| `ecdh` | SM2DH（§6.A 29），通用 `DeriveSharedSecret` KEX 适配点（§6.B B4） | SM2 派生参数 |

`0.6.0` 的 OAEP-SM3 和 `SupportsRSASignatureDigest` 已存在，不重复开发；
签名可运行支持以固定版本原生验证为准，不能将 OAEP 支持等同于签名支持。

### 2.4 `0.10.0` — PQC

| 领域 | 内容 | 前置（§3） |
|------|------|-------------|
| `asym` 签名 | ML-DSA-44 / 65 / 87、SLH-DSA 12 变体 | PQC 密钥生成、签验与序列化路径 |
| `asym` KEM | 原生 `Encapsulate` / `Decapsulate` | `EVP_PKEY_encapsulate` / `EVP_PKEY_decapsulate` |

本版独立验收密钥生命周期、编码往返、算法/参数不匹配和能力探测；8.4 构建不能
引用不存在的符号，不可用能力明确报错，不引入第三方算法替代实现。

### 2.5 `0.11.0` — CMS 与时间戳

| 领域 | 内容 | 对应缺口 | 前置（§3） |
|------|------|----------|-------------|
| `pkcs/pkcs7` | CMS 族（`cms` 命令），复用 `0.8.0` 容器基础设施 | §6.A 5 | CMS |
| 新顶级包 `ts` | RFC 3161：ASN.1 请求/响应与 HTTP 传输 | §6.A 53 | CMS / TS |

`ts` 与 `x509` 平级，实施时同步包索引与依赖图；当前仍为 16 个公开包。
数据库化、文件系统绑定的 CA 工作流不属于本版，继续按 §4 暂缓。

### 2.6 `0.12.0` — TLS 能力完善

| 能力 | 对应缺口 | 前置（§3） |
|------|----------|-------------|
| 服务端 SNI 多证书：`GetCertificate` / `GetConfigForClient` | §6.B A1 | TLS 深度 |
| ALPN：`Config.NextProtos` 与协商协议读取 | §6.B A2 | TLS 深度 |
| 会话复用与票据：缓存、会话状态、票据密钥管理 | §6.B A3 / A4 | TLS 深度 |
| 客户端证书认证：`ClientAuth` / `ClientCAs` | §6.B A8 | TLS 深度 |
| 自定义证书校验回调：`VerifyPeerCertificate` / `VerifyConnection` | §6.B A5 | TLS 深度 |
| `Options` / `Modes`、完整 `ConnectionState`、`VerifyHostname` / `UnderlyingConn`、错误码常量 | §6.B A6 / A10 | 配置与状态绑定 |
| DH 参数加载、ECDHE 曲线配置 | §6.B B3 / A7 | TLS 参数绑定；不新增独立 DH 密钥交换算法 |
| `HostnameOptions`：邮箱与主机名校验 flags | §6.B B5 | 主机名校验 flags |
| `ListenAndServeTLS` / `ServeTLS`、OCSP stapling、keylog、HTTP 集成 | §6.A 9 / 43 | TLS 深度与标准库集成 |

复用已有 `NewListener`，不重复实现；TLS / NTLS 回环、互操作与关闭/并发测试先于
`1.0.0` 完成，避免稳定版同时承接大量首次实现的传输功能。

### 2.7 `1.0.0` — 公开 API 收敛与稳定

- **E2 原语公开面**：统一按名分发的 Options，集中处理公开签名收敛。
- **E3 应用级组合**：复用已有内存签发流程，补应用级组合与 CRL 配置式签发入口
  （§6.A 6 / §6.B B9）；不承接文件系统 CA 数据库。
- 给出迁移对照、双语 CHANGELOG 的 `BREAKING` 与兼容性承诺，完成全量回归；
  不以新增大批算法/协议作为本版交付前提。

---

## 3. 实施前置：需新增或扩展的 cgo 绑定

以下均为未来实施前置，不表示已绑定；纯 Go 限额与现有句柄 Close 复用不新增 cgo。

| 家族 | 需要的 C 接口或扩展 | 服务对象 | 目标版本 |
|------|--------------------|----------|----------|
| 完整序列号 | ASN.1 INTEGER / BIGNUM 无损转换、`X509_REVOKED_set_serialNumber`，复用已有证书序列号读取 | `x509` CRL 读写 | `0.7.0` |
| DER 扩展 | `OBJ_txt2obj`、`X509_EXTENSION_create_by_OBJ` 与对应释放；复用已有扩展提交路径 | `x509` | `0.7.0` |
| 信任路径 | `X509_STORE_set_default_paths` / `X509_STORE_load_locations` | `x509.Store` | `0.7.0` |
| SM2 压缩点 | `EC_POINT_oct2point`、`EC_POINT_is_on_curve` / `EC_POINT_is_at_infinity`、仿射坐标读取 | `asym` 经 `core` 校验与展开 | `0.7.0` |
| PKCS#12 改密 | `PKCS12_unpack_authsafes` / `unpack_p7data` / `unpack_p7encdata`、safe/bag 重加密与打包、MAC 校验及重建 | `pkcs/pkcs12` | `0.7.0` |
| PKCS#7 签名/加密族 | `PKCS7_sign` / `PKCS7_verify` / `PKCS7_encrypt` / `PKCS7_decrypt`，按需补分离内容与选项绑定 | `pkcs/pkcs7` | `0.8.0` |
| 上下文签名 | `EVP_DigestSignInit_ex` 的 `instance` / `context-string` 参数及验签对应路径 | `asym` | `0.9.0` |
| SM2DH | `EVP_PKEY_derive*` 的 SM2 派生参数（已绑定基础调用，需泛化） | `ecdh` | `0.9.0` |
| PQC / KEM | 原生 PQC 密钥、签验、序列化路径；`EVP_PKEY_encapsulate` / `EVP_PKEY_decapsulate` | `asym` | `0.10.0` |
| CMS / TS | `CMS_*` / `TS_*` | `pkcs/pkcs7`、`ts` | `0.11.0` |
| TLS 深度 | ALPN、`SSL_SESSION_*`、SNI/验证回调、客户端 CA、票据、stapling/keylog、配置与状态绑定 | `tls` | `0.12.0` |
| 主机名校验 flags | `X509_check_host` 的 flags 扩展 / `X509_check_email` 等 | `tls.HostnameOptions` | `0.12.0` |

**已落地的相关绑定**（列此便于对照，避免重复规划）：

- `0.6.0`：扩展摘要与 XOF；`EVP_CIPHER_fetch` 复用覆盖 AES 扩展模式与 ZUC；
  `EVP_CIPHER_CTX_set_flags`（WRAP）、空载荷 update 修正；EC 参数 PEM 编解码、
  `EVP_PKEY_check` / `EVP_PKEY_public_check`；PKCS#8 PBE/PRF 与 PKCS#1 公钥编解码；
  OCSP nonce 与请求 CertID 匹配；X509 AUX 信任属性；PKCS#12 PBE/iter shim。
- `0.3.0`：`OpenSSLVersionWithIndex`（`meta` 版本/构建信息）、`X509_REVOKED_*` /
  `X509_CRL_add0_revoked` / `X509_CRL_sort`（`x509.CRLBuilder`）、`X509_check_host` /
  `X509_check_ip_asc`（`Certificate.VerifyHostname`）、`X509_STORE_set_verify_time`（`Store.SetTime`）；
- `0.5.0`：`EVP_MAC_*` 全家族（`mac`）、`EVP_aes_192_*` / `EVP_sm4_ccm` / `EVP_sm4_xts` /
  `EVP_chacha20*`（`sym`）、泛化 `EVP_KDF_fetch` + `EVP_KDF_derive`（`kdf` 10 种）、
  `EVP_*_do_all_provided` 与 `OSSL_PROVIDER_*` / `OPENSSL_info(SEED_SOURCE)` /
  `SSL_CTX_get0_implemented_groups`（`meta` 枚举，注：TLS 组枚举需 OpenSSL 3.2+）。

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
| 1 | `engine` | 不做 | 已被 provider 机制取代 |
| 2 | 数据库化、文件系统绑定的 CA 工作流 | **暂缓，不承诺版本** | 本质是持久化状态机；继续复用既有内存签发流程，不以 `OpenCA` / index.txt 工作流作为协议版本交付条件 |
| 3 | DSA / 独立 DH 密钥交换算法 | 不做 | 非国密目标场景；TLS 的 DH 参数加载仍归 `0.12.0` |
| 4 | EC-ElGamal / Paillier | 不做 | 非国密目标场景 |
| 5 | 需重编铜锁方可验证的六项 | 不做（标注保留） | 白盒 SM4、Bulletproofs、SM2 门限、SDF、SMTC、Delegated Credential；见 CLI 对比 §6.D |
| 6 | 提升 `internal/core` 原生句柄为公开类型 | 不做 | 跨包取句柄须走现有桥接，公开签名不得出现 internal 类型 |
| 7 | 公开 BIO、原生 HMAC_CTX、NID 常量表 | 不做 | 维持 Go 惯例封装；见官方 SDK 对比 §9 |
| 8 | `crypto/*` deprecated 转发包 | 不做 | `0.3.0` 已完成迁移，不重新扩大公开面 |
| 9 | ECIES / 私有混合加密容器 | **暂缓，不承诺版本** | 下游尚无指定互通格式；不自行定义容器。出现明确互通对象或 HPKE/JWE 等标准协议需求后重新立项；原生 HPKE 可用不等于本库已封装 |
| 10 | 库内自动加载 legacy provider | 不做 | 保持默认原生能力边界；单 DES 已在 `0.6.0` 以 `K‖K‖K` 驱动 DES-EDE3 等价实现，仅用于存量数据兼容 |
| 11 | EC/SM2 自定义 XML 格式 | 不做 | `xml/rsa` 只处理 .NET RSAKeyValue；不另创 ECKeyValue 格式（I-13） |

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
| 下游 22 项需求复核与处置 | [downstream-requirements.md](downstream-requirements.md) |
| 与铜锁 CLI 的能力对比（缺口编号来源） | [cli-comparison.md](cli-comparison.md) |
| 待实现 API 逐条清单 | [cli-comparison-todo.md](cli-comparison-todo.md) |
| 与官方 SDK 的能力对比 | [official-sdk-comparison.md](official-sdk-comparison.md) |
| 开发规范 / 测试规范 | [development-guide.md](development-guide.md) · [testing-guide.md](testing-guide.md) |
| 变更记录 | [CHANGELOG.md](../CHANGELOG.md) · [CHANGELOG.zh.md](../CHANGELOG.zh.md) |
