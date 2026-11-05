# 版本路线图（`0.7.0` 至 `1.0.0`）

> **用途**：本文件是本仓库**唯一的版本归属来源**。未来能力的目标版本以 §2 为准；
> 逐符号目标形态见 [api-reference.md](api-reference.md) 的 🧭 行，实施前置见 §3。
>
> **基线**：`0.7.0` 已实现、待发布，以铜锁 8.4.0 验证；§2.1 保留本版范围与验收结果，
> `0.9.0` 已在开发分支实现、待集成/发布，其余后续版本仍为规划。当前实现及迁移见 [公开 API 清单](api-reference.md) 与
> [CHANGELOG](../CHANGELOG.md#070---2026-11-04)；发布状态以版本标签为准。
>
> **相关文档**：功能需求的复核与验收边界见
> [功能需求复核记录](requirements.md)；CLI 与官方 SDK 的缺口编号分别见
> [cli-comparison.md](cli-comparison.md)、[official-sdk-comparison.md](official-sdk-comparison.md)。

---

## 1. 里程碑总览

| 版本 | 主题 | 关键内容 | 破坏性 |
|------|------|----------|--------|
| `0.7.0` | **可靠性、数据完整性与 PKCS 容器** | 显式释放、解析限额、完整序列号、DER 扩展、信任路径、SM2 压缩输入、复杂 PKCS#12 无损改密、PKCS#7 签验与加解密 | **是**：ECDH Public 签名调整、序列号校验收紧与改密行为变化 |
| `0.8.0` | **铜锁 8.5 兼容与经典算法扩展** | 8.4/8.5 矩阵、RSA-SM3 签名、GCM-SIV、EdDSA 上下文/预哈希、SM2DH、通用 KEX | 否 |
| `0.9.0` | **TLS / NTLS 握手与认证** | 连接可靠性、参数配置、证书链、混合端口、SNI、ALPN、客户端认证、验证策略、连接状态与示例 | **是**：新增字段影响非键名字面量，首次 I/O 自动握手与独立 deadline |
| `0.10.0` | **RFC 8998 与完整握手诊断** | 国密 TLS 1.3 严格配置、两个 SM4 套件、结构化事件、详细 trace、keylog | 否 |
| `0.11.0` | **会话复用与票据** | 客户端/服务端缓存、会话导入导出、票据控制、密钥轮换、握手后票据处理与身份隔离 | 否 |
| `0.12.0` | **HTTP/1.1 集成与 OCSP stapling** | 客户端/服务端集成、便捷服务入口、staple 配置与读取、状态验证示例 | 否 |
| `0.13.0` | **PQC** | ML-DSA、SLH-DSA、原生 KEM，密钥生命周期与序列化、能力探测 | 否 |
| `0.14.0` | **CMS 与时间戳** | CMS 扩展、独立顶级包 `ts` 的 RFC 3161 能力 | 否 |
| `1.0.0` | **公开 API 收敛与稳定** | 统一 Options、应用级组合入口、CRL 配置式签发、迁移指南与兼容性承诺 | **是** |

**节奏原则**：在 `0.7.0` 可靠性与容器基础上，先完成 `0.8.0` 原生兼容与经典算法，
再按四版交付传输能力，随后扩展 PQC 与 CMS；各版本按验收条件交付，不承诺日历日期。
`0.x` 优先增补 API，`1.0.0` 集中收敛公开面。
安全或一致性修复若改变既有行为，必须在实际交付版本的双语 CHANGELOG 中写明
`BREAKING` 与迁移方式；纯排期调整不新增 CHANGELOG 条目。

**版本调整**：PKCS#7 基础流程已合入 `0.7.0`；`0.8.0` 兼容与经典算法范围保持不变。
原集中在 `0.11.0` 的 TLS 计划前移并拆为 `0.9.0` 至 `0.12.0`，纳入 RFC 8998 与
完整握手诊断；PQC 延后至 `0.13.0`，CMS/时间戳延后至 `0.14.0`，`1.0.0` 范围保持不变。

**兼容原则**：`0.7.0` 保持铜锁 **8.4.0** 发布基线。`0.8.0` 增加固定
8.5 版本构建与运行验证，保留 8.4 构建兼容；新能力须通过编译保护与运行时探测报告
支持情况，不以 master、替代密码实现或自动加载 legacy provider 兜底。

---

## 2. 分版本范围

### 2.1 `0.7.0` — 可靠性、数据完整性与 PKCS 容器（已实现，待发布）

| 领域 | 交付内容与边界 | 需求编号 | 前置（§3） |
|------|----------------|----------|-------------|
| 生命周期 | ECDH 公私钥与 CSR 公开幂等 `Close()`；ECDH `PrivateKey.Public()` 改为返回独立副本与 error，公私钥及原 `asym` 密钥独立释放，关闭后可失败操作返回错误 | I-09 / I-15 | 复用 core 句柄关闭与 `EVP_PKEY_dup` |
| `asn1` | `ParseWithLimits` 与可识别的深度/节点数超限错误；保留 `Parse` 的固定 128 层保护和既有行为 | I-16 | 无（纯 Go） |
| `x509` 序列号与 CRL | 新增 `Certificate.SerialBigInt` / `SetSerialBigInt`、`IssueOptions.SerialBigInt`、`CRLBuilder.RevokeSerial(*big.Int, …)`、`RevokedEntry.SerialBigInt`，保留规划的 `SerialHex` / `RevokeSerialHex` 适配。旧 int64 入口保留为受限兼容接口；证书设置、CSR 签发、`Revoke(cert)`、CRL 读写、`IsRevoked` / `RevocationCheck` 均贯通完整值，覆盖 RFC 5280 的 20 octets 边界 | I-18 / I-20、I-23 / I-24 | 完整 ASN.1 INTEGER 读写与比较 |
| `x509` 扩展 | 公开按 OID 写入 DER 的入口，支持已知和自定义 OID；`Data` 保留原始扩展值，不还原任意配置串，不放开签名后修改 | I-19 | 按 OID 构造 DER 扩展 |
| `x509` 信任路径 | `Store.SetDefaultPaths`、`LoadLocations`；默认路径属于铜锁配置，不等同于各平台原生信任库，不隐式信任输入链的自签根 | I-17 | 默认路径与 CA 文件/目录加载 |
| `asym` SM2 | 经 native → core → API 解码、校验压缩 C1，支持转换与解密；保持既有输出形式，不新增压缩输出选项 | I-10 | EC 点解码与校验 |
| `pkcs/pkcs12` | 两个改密入口均在 safe/bag 层重加密，支持多私钥、多 safe 与嵌套 safeContentsBag，保留内容、顺序及属性；覆盖 PBES2/AES 与可用 3DES，不用解析后重打包兜底 | I-22 | PKCS#12 safe/bag 重加密 |
| 文档与互通 | 说明 RSA 签名为模数长度字节串并补双向互验；补带扩展的分步签发示例，保留签名后不可变约束 | I-08 / I-21 | 无 |

RSA 的签名格式符合 [RFC 8017 §8](https://www.rfc-editor.org/rfc/rfc8017.html#section-8)，
不改成 SM2/ECDSA 的 `SEQUENCE { r, s }`。`0.6.0` 的 PKCS#12
`ChangePasswordWithOptions` 是解析后重打包，不代表已经完成 I-22 的无损改密。
0.7.0 已替换两个改密入口，保留复杂内容与属性；不支持的算法/保护方式明确失败。

**CRL 与序列号需求的取舍**：直接按序列号吊销与完整
大整数接口均属 SDK 的基础数据封装，接受并合入现有序列号工作项，作为同版验收条件。
不能只新增 int64 的 `RevokeSerial` 后把完整匹配推迟；序列号归属、授权与持久化仍由
调用方负责，数据库化 CA 工作流继续按 §4 暂缓。新旧写入口统一校验正整数及长度，读取外部
值不得静默截断；兼容策略、错误路径与可变 `big.Int` 的复制语义见
[需求台账 §3](requirements.md#3-crl-与完整序列号职责判断与排期)。

#### PKCS#7 签名与加密

| 领域 | 内容 | 对应缺口 | 前置（§3） |
|------|------|----------|-------------|
| `pkcs/pkcs7` | `Sign` / `Verify`：带 signerInfo 的 SignedData，附带与分离签名，明确区分签名有效与证书受信任 | I-11、§6.A 32 / §6.B B12 | PKCS#7 签名族 |
| `pkcs/pkcs7` | `Encrypt` / `Decrypt`：EnvelopedData，覆盖错误密钥与篡改检测，不宣称非认证加密可检测所有篡改 | I-11、§6.A 32 | PKCS#7 加密族 |

复用现有证书袋与 CRL 容器能力；CMS 扩展留给 `0.14.0`，不以一个模糊的
“CMS/PKCS#7”格式参数混同两阶段的交付。算法支持以铜锁原生能力和互通验收为准。

#### 兼容策略与确定的默认行为

- **生命周期**：`PrivateKey.Public() (*PublicKey, error)` 使用独立句柄；复制失败返回
  error，不返回借用别名。ECDH/CSR 的 Close 对 nil、零值和已关闭对象幂等；关闭后
  可失败操作报错，查询类操作返回约定零值。同步所有调用点与释放示例，不承诺 Close
  与密码学操作并发安全；调用方须先结束使用再释放。
- **解析限额**：`ParseWithLimits` 两个限额必须为正数；深度沿用现有构造类型层数，
  节点数包含根与叶。用 `ErrDepthLimit` / `ErrNodeLimit` 区分超限，可经 `errors.Is`
  识别。原 Parse 保留 128 层保护、既有接受范围及错误文本；遍历不得因调高限额而
  触发递归栈溢出。
- **序列号**：旧 SetSerial 等 int64 写入口保留签名，但统一拒绝零和负数；完整值写入
  以 DER INTEGER 内容不超过 20 octets 为界，包含必要的符号补零。读取外部值不截断。
  Public 签名变化、校验收紧及公开结构体新增字段须提供 BREAKING 与迁移说明。
- **复杂 P12**：两入口均先验证 MAC，再按 safe/bag 遍历重加密，保留多私钥、证书链、
  CRL、其他可保留 bag、嵌套层级、内部顺序及全部属性。普通 ChangePassword 保留原
  算法、派生参数与 MAC 策略，更新口令并重新生成必要的盐/IV；WithOptions 应用现有
  PBE、迭代及读写口令参数，仍保留全部内容。空 FriendlyName 保留名称；非空仅在
  单密钥身份明确时修改关联密钥/证书名称，多密钥时拒绝歧义。必须覆盖 AES-128/192/256
  的 PBES2 与可用 3DES；无 MAC、不同 MAC/加密口令、签名保护或其他无法完整处理的
  算法/结构明确失败。失败无输出并释放资源，不加载 legacy、不降级为 Bundle 重打包。
- **P7 默认值**：Sign 默认 SHA-256、附带内容、DER 输出；Encrypt 默认 AES-256-CBC，
  支持多个 RSA 接收者。Verify/Decrypt 接受 DER 或 PKCS7 PEM，内容按二进制处理，
  不转换换行。Verify 默认要求显式信任存储，校验全部签名者；仅显式 SignatureOnly
  才跳过证书链验证，结果标记 TrustVerified=false。未完成要求的验证不返回内容。
- **P7 原生边界**：8.4.0 本地 CLI 探测确认 RSA/ECDSA 签名、RSA 接收者加密可用；
  SM2 签名/加密和 EC 接收者加密明确报不支持。其余组合不默认承诺，不借 CMS 或
  第三方算法冒充 PKCS#7 支持；CMS 仍归 0.14.0。CLI 互验使用 smime 的签验/加解密
  子流程，不使用不存在的 pkcs7 -sign/-encrypt 选项。

#### 开发批次与完成条件

| 批次 | 内容与依赖 | 本批完成条件 |
|---|---|---|
| 1 | ECDH/CSR 生命周期、ASN.1 限额 | 独立释放、关闭后使用、限额边界、深/宽树与迁移示例通过 |
| 2 | 完整序列号与 CRL 全链路 | 读写/签发/吊销/匹配无 int64 中转，边界与 CLI 互通通过 |
| 3 | DER 扩展、信任路径、SM2 压缩输入 | 扩展原值、显式信任与两种密文顺序验收通过 |
| 4 | 复杂 PKCS#12 无损改密 | 两入口、多密钥、嵌套与属性结构保留，错误路径及互通通过 |
| 5 | PKCS#7 签名与验签 | 附带/分离、全部签名者、信任/仅验签及资源释放通过 |
| 6 | PKCS#7 加解密、示例及全量回归 | 多接收者、CLI 双向互通、build/vet/test/race 与 Linux static 通过 |

六批能力已实现，双语 GoDoc、API/架构/测试文档与示例已同步；双语 CHANGELOG 维护
`0.7.0 - 2026-11-04`。8.4.0 的 build/vet、默认/CLI/race 全量测试与 Linux static 标签构建
通过；六个独立示例模块已检查。复杂 P12 原生成功/失败路径通过 ASan/LSan 检查。

### 2.2 `0.8.0` — 铜锁 8.5 兼容与经典算法扩展

| 领域 | 内容 | 前置（§3） |
|------|------|-------------|
| 兼容性 | 固定 8.4.0 / 8.5 版本分别构建、运行单元测试与 CLI 对拍；头文件、链接库与 CLI 必须对应，master 仅作前瞻验证 | 独立安装与 CI 矩阵 |
| `sym` | AES-GCM-SIV；评估新 provider 的 AES-SIV 空消息边界，旧基线仍明确拒绝 | 新版 provider、能力探测与标准向量 |
| `asym` | ED25519ph / ED25519ctx / ED448ph；RSA-PKCS#1 v1.5 / PSS 的 SM3 签名可运行支持（I-06） | 上下文签名、RSA provider 摘要支持 |
| `ecdh` | SM2DH（§6.A 29），通用 `DeriveSharedSecret` KEX 适配点（§6.B B4） | SM2 派生参数 |

`0.6.0` 的 OAEP-SM3 和 `SupportsRSASignatureDigest` 已存在，不重复开发；
签名可运行支持以固定版本原生验证为准，不能将 OAEP 支持等同于签名支持。

### 2.3 `0.9.0` — TLS / NTLS 握手与认证（已实现，待集成/发布）

| 能力 | 交付内容与边界 | 前置（§3） |
|------|----------------|-------------|
| 连接可靠性与入口 | 修复读写互相阻塞、独立读写 deadline、取消/关闭竞争及错误归因；新增包装已连接 TCP socket 的客户端入口，保留 `Server.Accept` 惰性握手与 `NewListener` 自动握手语义 | TLS 配置与认证 |
| 协议与凭证 | 显式 TLS、NTLS、服务端同端口混合模式；完整 TLS 证书链及 NTLS 签名/加密双证书链；客户端显式选择协议，不自动失败重试另一协议 | TLS 配置与认证 |
| SNI / ALPN | `GetCertificate` / `GetConfigForClient`、`NextProtos` 与协商协议读取；NTLS 按完整双证书身份切换；SNI 发送名称与验证名称分别配置（§6.B A1 / A2） | TLS 配置与认证 |
| 认证与验证策略 | `ClientAuth` / `ClientCAs`、`VerifyPeerCertificate` / `VerifyConnection`；新增不验证、验证并记录失败后继续、验证失败终止三种显式策略（§6.B A5 / A8） | TLS 配置与认证 |
| 参数与状态 | 版本、套件、组/曲线、签名算法、DH 参数、`Options` / `Modes`；严格配置方式拒绝无效/不支持参数；`ConnectionState`、`VerifyHostname` / `UnderlyingConn`、错误码常量（§6.B A6 / A7 / A10 / B3） | TLS 配置与认证 |
| 名称校验 | `HostnameOptions`、邮箱与主机名校验 flags、IP 校验（§6.B B5） | 主机名校验 flags |

**下游交付**：SDK API + 可运行客户端/服务端示例，下游可构建类似铜锁
`s_client` / `s_server` 的握手测试；不新增正式 CLI 产品。保留 SDK 旧入口实际行为，
统一其文档口径；示例默认验证并记录失败后继续，另提供严格验证和完全不验证选项。
握手完成、验证通过分别表达，验证状态区分未验证/通过/失败；自定义验证回调返回
错误始终终止连接，不能以诊断模式吞掉。NTLS 套件自身的客户端凭证要求仍须满足。

**完成条件**：TLS 1.2 / 1.3、NTLS ECC / ECDHE 分别通过回环和 CLI 双向互通，
断言协商结果与双向数据；覆盖混合端口、SNI/ALPN、缺凭证/中间链、错误信任/名称、
三种验证策略及 NTLS 两套身份的失败路径。并发读写、独立 deadline、取消/关闭和
FD/句柄释放通过回归；同一 SSL 对象的原生调用受控，等待 socket 就绪时不阻塞另一方向。

**实现边界**：新增 `tls.Client` 与 `examples/handshake`；保留 `Server.Accept` 惰性构造，首次 I/O 自动握手。
`StrictConfig` 精确限制套件集合，参数不支持时失败；`Options` / `Modes` 仅接受公开命名常量。
基础配置限制组时，SNI 所选配置必须显式给出 `CurvePreferences`，不能隐式继承残留限制；
配置和源凭证的并发/生命周期约定见 API 清单。原生写入开始后出错须关闭连接。
8.4.0 的 TLS/NTLS 回环、CLI 双向认证和全仓库检查结果见测试规范；详细事件流仍归下一版。

### 2.4 `0.10.0` — RFC 8998 与完整握手诊断（规划）

| 能力 | 交付内容与边界 | 前置（§3） |
|------|----------------|-------------|
| RFC 8998 | TLS 1.3 单套签名凭证、严格配置入口、`TLS_SM4_GCM_SM3` / `TLS_SM4_CCM_SM3`，约束冲突明确失败 | RFC 8998 / 诊断 |
| 结构化诊断 | 每连接有序交付握手开始/完成、状态、收发消息/Alert、证书验证事件及可保留的数据副本；失败握手仍可读取已发生的信息（§6.A 43 / 44） | RFC 8998 / 诊断 |
| trace / keylog | 可选详细 trace 与 keylog，默认关闭；复用铜锁原生解码，未知内容保留类型与原始字节，不承诺 CLI 文本逐字符一致；显式启用不可用能力时返回不支持错误 | RFC 8998 / 诊断 |

RFC 8998 是国密 **TLS 1.3 单证书**配置，与 NTLS/TLCP **签名+加密双证书**分别配置、
分别验收。协议处理复用铜锁 TLS 状态机，不依赖 SDK 自行编排 SM2DH。
依据 [RFC 8998 §2–3](https://www.rfc-editor.org/rfc/rfc8998.html#section-3)，验收
TLS 1.3、两个 SM4 套件、`curveSM2` 的 supported_groups/key_share、`sm2sig_sm3` 的
签名协商/CertificateVerify、证书的 SM2 公钥/SM2-SM3 签名/签名用途及客户端认证约束；
握手签名使用 `TLSv1.3+GM+Cipher+Suite`，证书验证按 RFC 8998 §3.2.1 核对 SM2 ID
`1234567812345678` 与 CA 实际签发约定。仅枚举或协商出 SM4 套件不算完整验收。

**完成条件**：两个套件分别完成客户端/服务端、单向/双向认证和 CLI 双向互通；错误
版本、组、签名与证书配置明确失败。TLS / NTLS / RFC 8998 的消息、状态、Alert、
验证事件、trace 与 keylog 分别验收。原生消息回调可能经过解密/重组，不作为原始
网络抓包；诊断不无限积累日志，写入失败明确反馈，不把验证失败覆盖为通过。

### 2.5 `0.11.0` — 会话复用与票据（规划）

| 能力 | 交付内容与边界 | 前置（§3） |
|------|----------------|-------------|
| 会话缓存与状态 | 跨连接客户端缓存、服务端缓存、`Conn.SessionState()`、导入导出、过期及实际复用结果（§6.B A3） | TLS 会话与票据 |
| 票据 | 开关、数量控制、密钥管理与轮换、TLS 1.3 握手后票据处理（§6.B A4） | TLS 会话与票据 |
| 身份隔离 | 按协议、服务身份、客户端身份和验证配置隔离缓存，复用后仍执行约定的验证回调 | TLS 会话与票据 |

**完成条件**：在前两版协议矩阵上验证首次/恢复握手、拒绝复用、过期、密钥轮换与
跨身份隔离；不以“握手成功”代替“实际复用”。TLS 1.3 测试与示例必须处理握手后
到达的票据，再进行恢复连接，不能握手后立即断开并假定已有可用会话。

### 2.6 `0.12.0` — HTTP/1.1 集成与 OCSP stapling（规划）

| 能力 | 交付内容与边界 | 前置（§3） |
|------|----------------|-------------|
| HTTP/1.1 | 客户端/服务端集成、`ListenAndServeTLS` / `ServeTLS`、握手/回显/HTTP 响应示例，复用已有 `NewListener`（§6.A 9 / 43 / 44） | TLS stapling / HTTP 集成 |
| OCSP stapling | 配置、请求、读取 staple 与状态验证示例，分别表达“取得响应”和“验证响应有效” | TLS stapling / HTTP 集成 |

**完成条件**：在已有 TLS / NTLS / RFC 8998 协议矩阵上验证 HTTP/1.1 与适用的
stapling 路径；受控本地测试覆盖缺失、过期、吊销及错误签名/身份的响应。不支持的
协议/原生组合明确报告能力边界；ALPN 能协商 `h2` 不等于已交付 HTTP/2 集成。

### 2.7 `0.13.0` — PQC

| 领域 | 内容 | 前置（§3） |
|------|------|-------------|
| `asym` 签名 | ML-DSA-44 / 65 / 87、SLH-DSA 12 变体 | PQC 密钥生成、签验与序列化路径 |
| `asym` KEM | 原生 `Encapsulate` / `Decapsulate` | `EVP_PKEY_encapsulate` / `EVP_PKEY_decapsulate` |

本版独立验收密钥生命周期、编码往返、算法/参数不匹配和能力探测；8.4 构建不能
引用不存在的符号，不可用能力明确报错，不引入第三方算法替代实现。

### 2.8 `0.14.0` — CMS 与时间戳

| 领域 | 内容 | 对应缺口 | 前置（§3） |
|------|------|----------|-------------|
| `pkcs/pkcs7` | CMS 族（`cms` 命令），复用 `0.7.0` 容器基础设施 | §6.A 5 | CMS |
| 新顶级包 `ts` | RFC 3161：ASN.1 请求/响应与 HTTP 传输 | §6.A 53 | CMS / TS |

`ts` 与 `x509` 平级，实施时同步包索引与依赖图；当前仍为 16 个公开包。
数据库化、文件系统绑定的 CA 工作流不属于本版，继续按 §4 暂缓。

### 2.9 `1.0.0` — 公开 API 收敛与稳定

- **E2 原语公开面**：统一按名分发的 Options，集中处理公开签名收敛。
- **E3 应用级组合**：复用已有内存签发流程，补应用级组合与 CRL 配置式签发入口
  （§6.A 6 / §6.B B9）；不承接文件系统 CA 数据库。
- 给出迁移对照、双语 CHANGELOG 的 `BREAKING` 与兼容性承诺，完成全量回归；
  不以新增大批算法/协议作为本版交付前提。

---

## 3. 绑定实现与后续实施前置

下表 `0.7.0` 和 `0.9.0` 行已实现；`0.8.0` 及其余后续版本仍为实施前置，不表示已绑定。
纯 Go 限额与现有句柄 Close 复用不新增 cgo。

| 家族 | 需要的 C 接口或扩展 | 服务对象 | 目标版本 |
|------|--------------------|----------|----------|
| 完整序列号 | ASN.1 INTEGER / BIGNUM 无损转换、`X509_set_serialNumber` / `X509_REVOKED_set_serialNumber` 的完整值路径及无损比较；复用已有证书 hex 读取，不经 C long/int64 中转 | `x509` 证书/CSR 签发、CRL 读写与吊销匹配 | `0.7.0` |
| DER 扩展 | `OBJ_txt2obj`、`X509_EXTENSION_create_by_OBJ` 与对应释放；复用已有扩展提交路径 | `x509` | `0.7.0` |
| 信任路径 | `X509_STORE_set_default_paths` / `X509_STORE_load_locations` | `x509.Store` | `0.7.0` |
| SM2 压缩点 | `EC_POINT_oct2point`、`EC_POINT_is_on_curve` / `EC_POINT_is_at_infinity`、仿射坐标读取 | `asym` 经 `core` 校验与展开 | `0.7.0` |
| PKCS#12 改密 | `PKCS12_unpack_authsafes` / `unpack_p7data` / `unpack_p7encdata`、多密钥与嵌套 safe/bag 重加密与打包、完整属性保留、MAC 校验及重建 | `pkcs/pkcs12` | `0.7.0` |
| PKCS#7 签名/加密族 | `PKCS7_sign` / `sign_add_signer` / `final` / `verify` / `get0_signers` / `encrypt` / `decrypt`，补分离内容与选项绑定 | `pkcs/pkcs7` | `0.7.0` |
| 上下文签名 | `EVP_DigestSignInit_ex` 的 `instance` / `context-string` 参数及验签对应路径 | `asym` | `0.8.0` |
| SM2DH | `EVP_PKEY_derive*` 的 SM2 派生参数（已绑定基础调用，需泛化） | `ecdh` | `0.8.0` |
| TLS 配置与认证 | NTLS 混合模式、证书链、ALPN、SNI/验证回调、客户端 CA、组/签名算法/DH 参数、配置与状态绑定；完善 I/O、deadline 与原生错误采集 | `tls` | `0.9.0` |
| 主机名校验 flags | `X509_check_host` 的 flags 扩展 / `X509_check_email` 等 | `tls.HostnameOptions` | `0.9.0` |
| RFC 8998 / 诊断 | `SSL_CTX_enable_sm_tls13_strict`、SM4 套件/curveSM2/sm2sig_sm3 配置与状态、消息/状态/验证回调、`SSL_trace`、keylog | `tls` | `0.10.0` |
| TLS 会话与票据 | `SSL_SESSION_*`、会话新建/缓存回调、复用状态、票据数量与密钥轮换绑定 | `tls` | `0.11.0` |
| TLS stapling / HTTP 集成 | `SSL_CTX_set_tlsext_status*` / `SSL_get_tlsext_status_ocsp_resp` 等；HTTP 入口复用已有 Listener 与标准库 | `tls` | `0.12.0` |
| PQC / KEM | 原生 PQC 密钥、签验、序列化路径；`EVP_PKEY_encapsulate` / `EVP_PKEY_decapsulate` | `asym` | `0.13.0` |
| CMS / TS | `CMS_*` / `TS_*` | `pkcs/pkcs7`、`ts` | `0.14.0` |

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
| 3 | DSA / 独立 DH 密钥交换算法 | 不做 | 非国密目标场景；TLS 的 DH 参数加载归 `0.9.0` |
| 4 | EC-ElGamal / Paillier | 不做 | 非国密目标场景 |
| 5 | 需重编铜锁方可验证的六项 | 不做（标注保留） | 白盒 SM4、Bulletproofs、SM2 门限、SDF、SMTC、Delegated Credential；见 CLI 对比 §6.D |
| 6 | 提升 `internal/core` 原生句柄为公开类型 | 不做 | 跨包取句柄须走现有桥接，公开签名不得出现 internal 类型 |
| 7 | 公开 BIO、原生 HMAC_CTX、NID 常量表 | 不做 | 维持 Go 惯例封装；见官方 SDK 对比 §9 |
| 8 | `crypto/*` deprecated 转发包 | 不做 | `0.3.0` 已完成迁移，不重新扩大公开面 |
| 9 | ECIES / 私有混合加密容器 | **暂缓，不承诺版本** | 尚无明确的互通格式与对象；不自行定义容器。出现明确互通对象或 HPKE/JWE 等标准协议需求后重新立项；原生 HPKE 可用不等于本库已封装 |
| 10 | 库内自动加载 legacy provider | 不做 | 保持默认原生能力边界；单 DES 已在 `0.6.0` 以 `K‖K‖K` 驱动 DES-EDE3 等价实现，仅用于存量数据兼容 |
| 11 | EC/SM2 自定义 XML 格式 | 不做 | `xml/rsa` 只处理 .NET RSAKeyValue；不另创 ECKeyValue 格式（I-13） |
| 12 | STARTTLS、外部 PSK、0-RTT、主动重协商 | **暂缓，不承诺版本** | 不作为四版 TLS 系列或 1.0 稳定版的交付前提；RFC 8998 已单独归入 `0.10.0` |

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
| 功能需求复核与处置 | [requirements.md](requirements.md) |
| 与铜锁 CLI 的能力对比（缺口编号来源） | [cli-comparison.md](cli-comparison.md) |
| 待实现 API 逐条清单 | [cli-comparison-todo.md](cli-comparison-todo.md) |
| 与官方 SDK 的能力对比 | [official-sdk-comparison.md](official-sdk-comparison.md) |
| 开发规范 / 测试规范 | [development-guide.md](development-guide.md) · [testing-guide.md](testing-guide.md) |
| 变更记录 | [CHANGELOG.md](../CHANGELOG.md) · [CHANGELOG.zh.md](../CHANGELOG.zh.md) |
