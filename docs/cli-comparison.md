# 铜锁 CLI 与 tongsuo-go 能力对比

> 复核日期：2026-11-18 ｜ 本库基线：`0.13.0` 待发布。
> CLI 基线：本机 `/opt/tongsuo-8.4.0/bin/openssl` 与 `/opt/tongsuo-8.5.0/bin/openssl`。
> 本次核对公开源码并重新执行版本、命令及算法枚举；未重新执行全部密码学操作或互通测试。
> 已交付能力的验收证据见 [测试规范](testing-guide.md)，不把本次静态核对写成测试通过。

## 1. 对比口径

本库提供调用铜锁的 Go SDK。下表按开发者任务对比，列出公开入口与实际剩余边界，
不要求复刻命令行参数、配置文件语言或文本输出。当前符号以 [API 清单](api-reference.md)
及对应源码为准；未来版本仅由 [roadmap.md](roadmap.md) 分配，候选需求见
[requirements.md](requirements.md)。

- **已覆盖**：存在公开入口覆盖表中描述的任务，不表示支持该命令全部选项。
- **部分覆盖**：已有核心流程，仍有明确功能边界。
- **未封装**：没有对应公开入口；与原生是否支持分开判断。
- **不纳入**：部署工具、历史协议或已明确拒绝的公开面，不计作产品待办。

算法枚举、CLI 帮助及命令存在只能证明发现结果；provider 初始化、参数接受和协议互通
仍须实际验证。8.5 的结果不能外推至 8.4，也不能外推至其他编译选项。

## 2. 算法与密钥

| CLI / 任务 | 本库公开入口与源码 | 状态及边界 |
|---|---|---|
| `dgst`：摘要与 XOF | [digest](../digest/) 的 `New` / `Sum` / `SumSource` / `SumTo` | 已覆盖 SM3、MD5、SHA-1/SHA-2/SHA-3、SHAKE 与扩展摘要；不是旧文档的“五种摘要” |
| `mac`、`dgst -hmac` | [mac](../mac/mac.go) 的 `Names` / `New` / `Sum`，以及 HMAC 便利入口 | 已覆盖 HMAC、CMAC、GMAC、KMAC、SipHash、Poly1305、EIA3；参数和输出长度按算法约束 |
| `enc`：对称加解密 | [sym](../sym/) 的按名入口、模式入口、`cipher.Block` / `cipher.AEAD` 与形态入口 | 已覆盖 AES-128/192/256、SM4、多种扩展模式、ChaCha20、ZUC；DES/2-key/3-key 3DES 仅作存量兼容；单 DES 通过 K‖K‖K 等价实现 |
| AEAD / SIV / GCM-SIV | [sym/extended.go](../sym/extended.go) 与相关实现、测试 | 已有 SDK 入口；不假定 CLI `enc` 支持 AEAD。GCM-SIV 与 SIV 空消息有版本边界，见 API/测试规范 |
| `kdf` | [kdf/kdf.go](../kdf/kdf.go)、[algorithms.go](../kdf/algorithms.go) 的 `Derive` 与类型化入口 | 部分覆盖：HKDF、PBKDF2、scrypt、SSKDF、TLS PRF、TLS13-KDF、X9.42/X9.63、KBKDF、HMAC-DRBG；另有条件可用的 Argon2ID。尚缺 SSHKDF、PKCS12KDF、KRB5KDF |
| `genpkey` / `genrsa` / `pkey` / `rsa` | [asym](../asym/) 的算法专用 `GenerateRSA` / `GenerateEC` 等入口、PEM/DER、PKCS#1/8、`Check` / `PublicCheck` | 部分覆盖：主流密钥生成、编码和校验已实现；统一按名密钥生成仍待 1.0.0 收敛；自定义 RSA 指数、多素数及任意原生参数透传未提供 |
| `pkeyutl` / `dgst`：签验与公钥加解密 | [asym/rsa.go](../asym/rsa.go)、SM2/ECDSA/EdDSA 实现 | 已有 RSA v1.5/PSS/OAEP、SM2、ECDSA、Ed25519/Ed448 及上下文/ph 变体；RSA-SM3 与 EdDSA 变体依运行库能力 |
| `pkeyutl -derive` | [ecdh/derive.go](../ecdh/derive.go)、[ecdh.go](../ecdh/ecdh.go) | 已有六条 ECDH 曲线、`DeriveSharedSecret`、显式参数 SM2DH；SM2DH 不提供密钥确认，不等于任意原生 DH 参数均被公开支持 |
| `ecparam` / `pkeyparam` | [ecdh/parameters.go](../ecdh/parameters.go) 的参数读写、生成与 `Curve.Check` | 部分覆盖：已有命名/显式 EC 参数 PEM 和文件入口，范围受 `CurveByName` 限制；`Curves` 列 SDK 支持集，非铜锁所有曲线；不再规划重复的 `key.Parameters` 类型 |
| `ec -conv_form` / 公钥压缩编码 | 现有公钥 PEM/DER 与 SM2 密文格式转换 | 部分覆盖：SM2 压缩 C1 输入已有支持，但不能代替公钥输出点形式控制；见 I-35 |
| PQC 签名、KEM 与 TLS 混合组 | `asym` 支持 PQC 密钥、签验和 ML-KEM，`tls.Config.CurvePreferences` 可配置 TLS 组 | 已覆盖：铜锁 8.5.0 实测七组 TLS 1.3 握手，并支持 ML-DSA 证书认证 |

## 3. 证书、容器与输入输出

| CLI / 任务 | 本库公开入口与源码 | 状态及边界 |
|---|---|---|
| `req` / `x509` | [x509/x509.go](../x509/x509.go)、[csr.go](../x509/csr.go)、[issue.go](../x509/issue.go) | 已有自签、CSR、分步签发、由 CSR 签发及证书转 CSR；完整序列号、文本/DER 扩展与信任属性已交付 |
| `verify` | [x509/store.go](../x509/store.go)、[reliability.go](../x509/reliability.go) | 已有显式根、中间链、默认路径/CA 文件目录、验证时间、链结果与结构化错误；默认路径属于铜锁配置 |
| `crl` / `ca -gencrl` | [x509/crl.go](../x509/crl.go) 的 `CRLBuilder`、解析、验签、吊销匹配 | 部分覆盖：已可按证书或完整序列号构建 CRL；配置式一次调用入口归 1.0.0；不承接 `index.txt` 状态管理 |
| `ca` 数据库工作流 | 内存证书/CSR/CRL 原语 | 部分覆盖：SDK 签发原语已有；文件锁、serial/index.txt、审计与续期数据库暂缓，见 I-41 |
| `ocsp` | [x509/ocsp.go](../x509/ocsp.go)、[ocsp_http.go](../x509/ocsp_http.go) | 部分覆盖：请求/响应、验证、HTTP 获取与 nonce 已有；不提供完整 OCSP responder 服务，TLS staple 另见 I-29 |
| `pkcs7` / `crl2pkcs7` | [pkcs/pkcs7](../pkcs/pkcs7/) 的 `Build` / `Extract` / `FromCRL` / `ExtractCRLs` / `Sign` / `Verify` / `Encrypt` / `Decrypt` | 已有证书/CRL 容器与基础签验、信封；现有 `FromCRL` 不是“CRL + 任意证书”的通用 Bundle 构建器；按原生支持限制签名/接收者算法 |
| `cms` | PKCS#7 基础流程不能替代 CMS 实现 | 未封装：CMS 签验、信封、DigestedData 归 0.14.0，见 I-37；PKCS#7 与 CMS 不作为同一格式选项 |
| `pkcs8` | [asym/pkcs8.go](../asym/pkcs8.go) 的 `MarshalPKCS8` / `LoadPKCS8` / `PKCS8Options` | 已有 PEM/DER、PBE/PRF 参数，不再列作缺失的 `-topk8` 能力 |
| `pkcs12` | [pkcs/pkcs12](../pkcs/pkcs12/) 的 Pack/Parse/改密及 Options | 已有 PBE、迭代、口令选项；复杂 safe/bag 无损改密已交付；不承诺 Pack/Parse 覆盖所有复杂容器结构 |
| `ts` | 尚无公开 `ts` 包 | 未封装：RFC 3161 请求/响应、验证与 HTTP 归 0.14.0，见 I-39 |
| `storeutl` | [keystore/load.go](../keystore/load.go)、[x509/load.go](../x509/load.go) | 部分覆盖：本地 PEM/DER/PKCS#12 与证书/CRL 多对象加载已有；非文件 provider/硬件 URI 不支持，见 I-42 |
| `asn1parse` | [asn1](../asn1/) 的 `Parse` / `ParseWithLimits` / `Dump` | 部分覆盖：纯 Go DER viewer 与限额；不实现 `-genstr` / `-genconf` 配置语言，见 I-45 |
| `version` / `info` / `errstr` / `list` | [meta](../meta/) 的版本、`ReadBuildInfo`、错误码与算法枚举 | 已覆盖查询任务；枚举结果不保证每种算法可实际操作 |
| `rand` / base64 / hex / PEM / 文件与管道 | [rand](../rand/)、[meta](../meta/) 的 Source/Sink/Encoding/Format/Passphrase/PEM 工具 | 已有 SDK 入口；无需再逐命令复制 `File` / `Reader` / `Hex` 组合 API |

## 4. TLS / NTLS

| CLI 能力 | `0.10.0` 本库现状 | 剩余边界与处置 |
|---|---|---|
| `s_client` / `s_server`，TLS/NTLS 双证书 | `Dial` / `DialContext` / `Client` / `Server.Accept` / `NewListener` | 已交付；底层只接受 `*net.TCPConn`，不是任意 `net.Conn`，见 I-40 |
| SNI、多证书、ALPN、客户端认证、证书链 | `GetCertificate` / `GetConfigForClient`、`NextProtos`、`ClientAuth` 等 | 已交付；ALPN 可协商 `h2` 不等于提供 HTTP/2/gRPC 集成 |
| CA/名称、验证回调、组/签名/DH 参数、Options/Modes | Config 与 ConnectionState | 已交付 Go 形态配置，不透传任意原生整数控制项 |
| RFC 8998 | `Config.RFC8998`，两套 SM4 TLS 1.3 套件 | 已有严格配置与互通记录；不把 SM2 证书或套件枚举当作完整 RFC 8998 支持 |
| `-msg` / `-state` / `-trace` / `-keylogfile` | `Config.Diagnostics`，有界事件、trace/keylog Writer | 已交付；keylog 必须显式开启，输出错误会终止连接 |
| SCT / 安全重协商状态 | `CaptureSCT`、`SignedCertificateTimestamps`、`SecureRenegotiation` | 已交付；仅捕获 SCT，不实施 CT 信任策略；状态查询不是主动重协商 |
| `sess_id` / 会话缓存 / 票据 | 0.11.0 已实现 | 缓存、原生 DER/PEM、过期/实际复用、票据轮换与 SDK/CLI 双向恢复；[会话规则](tls-sessions.md)，I-31 |
| `-www` / `-HTTP` / OCSP stapling | 0.12.0 已实现 HTTP/1.1 和 OCSP stapling | [接入与验证规则](tls-http-ocsp.md)，I-29 |
| STARTTLS、外部 PSK、0-RTT、主动重协商 | 未提供对应公开流程 | 暂缓，I-43；不作为普通会话恢复的隐含交付 |

## 5. 值得做的缺口与决策

以下编号来自 [需求台账](requirements.md)，与旧版 §6.A / §6.B / D 编号不再混用。

| 需求 | 价值与决策 | 目标 |
|---|---|---|
| I-31 / I-29 | 会话恢复降低握手成本，HTTP/OCSP 完成典型客户端与服务端集成 | 已在 0.11.0 / 0.12.0 实现 |
| I-37 / I-39 | CMS 与 RFC 3161 有标准格式和现成 CLI 互通对象；CMS 补摘要封装/验证 | 0.14.0 |
| I-34 | SSHKDF / PKCS12KDF 填补已存在原生接口的协议派生缺口，可独立验向量 | 0.15.0 |
| I-35 | EC/SM2 压缩/未压缩公钥导出用于标准密钥交换与存储互通 | 0.15.0 |
| I-36 | 配置式 CRL 签发与现有多步原语组合，随 API 稳定集中设计 | 1.0.0 |
| I-05 / I-40–I-48 | 标准混合加密、通用流传输、CA 状态管理、硬件/provider、特殊协议或参数 | 暂缓；价值、限制与重开条件见需求台账 |

## 6. 不纳入与特殊构建能力

- `engine`、公开 BIO/HMAC_CTX/NID、任意原生参数透传不属于 SDK 对齐目标。
- `fipsinstall`、`rehash`、`help`、交互 shell 是部署/命令工具；`speed` / `s_time` 的
  SDK 性能目标用 Go Benchmark 表达，不新增同名产品入口。
- `rsautl`、Netscape `nseq` / `spkac`、DSA、独立 DH、SRP/CMP、口令数据库工具、
  Paillier/EC-ElGamal 及库内自动加载 legacy 继续按路线图不纳入。
- S/MIME 邮件封装与 CMS 密码学流程分开，邮件场景待 I-47 确认。
- 白盒 SM4、Bulletproofs、SM2 门限、SDF、SMTC、Delegated Credential 继续不纳入。
  本次两版 `list -disabled` 仅列 SCTP，8.5 的命令表出现 `bulletproofs`、`sm2_threshold`、
  `delecred`；因此撤销旧文档“全部缺失、必需重编”的固定判断。未逐项执行这些操作，
  不对原生可用性、构建依赖或硬件访问作成功承诺。
- SM9 在本次对比中未发现可用公开路径，不新增虚构 API 或版本承诺。

## 7. 复核与维护

本次重新执行：

```bash
/opt/tongsuo-8.4.0/bin/openssl version
/opt/tongsuo-8.5.0/bin/openssl version
# 分别在两版执行；输出依赖构建选项，不固定行数/别名数量为能力数量。
/opt/tongsuo-8.5.0/bin/openssl list -commands -1
/opt/tongsuo-8.5.0/bin/openssl list -disabled
/opt/tongsuo-8.5.0/bin/openssl list -kdf-algorithms
/opt/tongsuo-8.5.0/bin/openssl list -signature-algorithms
/opt/tongsuo-8.5.0/bin/openssl list -kem-algorithms
/opt/tongsuo-8.5.0/bin/openssl list -tls-groups
```

8.4.0 不接受 `list -tls-groups`，本次命令明确报 unknown option；这不等于该版本没有
TLS 组或不能通过其他原生入口查询。8.5.0 枚举可见 ML-KEM、ML-DSA、SLH-DSA 与混合组，
0.13.0 的 SDK 操作与握手验收范围见上表及 API 清单。

更新实现后同步本表状态与 API 清单，删除已完成需求；历史验收保留于测试规范与
CHANGELOG。新发现的候选只进需求台账，决定交付后再进入路线图，避免维护另一套 Phase 排期。
