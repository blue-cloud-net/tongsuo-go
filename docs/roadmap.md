# 版本路线图（`0.15.0` 至 `1.0.0`）

> **用途**：本文件是本仓库**唯一的版本归属来源**。未来能力的目标版本以 §2 为准；
> 逐符号目标形态见 [api-reference.md](api-reference.md) 的 🧭 行，实施前置见 §3。
>
> **基线**：`0.14.0`（2026-11-20 定版）。固定验证铜锁 8.4.0/8.5.0。
> 0.14.0 的交付范围见 [CHANGELOG](../CHANGELOG.zh.md)。以下列出 0.15.0 起的计划。
>
> **相关文档**：功能需求的复核与验收边界见
> [功能需求复核记录](requirements.md)；CLI 与官方 SDK 的能力证据分别见
> [cli-comparison.md](cli-comparison.md)、[official-sdk-comparison.md](official-sdk-comparison.md)。

---

## 1. 里程碑总览

| 版本 | 主题 | 关键内容 | 破坏性 |
|------|------|----------|--------|
| `0.15.0` | **CMS 与时间戳** | CMS 签验/信封、DigestedData、独立顶级包 `ts` 的 RFC 3161 能力 | 否 |
| `0.16.0` | **标准派生与公钥编码互通** | SSHKDF / PKCS12KDF、EC/SM2 公钥压缩与未压缩编码 | 否 |
| `1.0.0` | **公开 API 收敛与稳定** | 统一 Options、应用级组合入口、CRL 配置式签发、迁移指南与兼容性承诺 | **是** |

**节奏原则**：以 `0.14.0` 为基线，下一步扩展 CMS 与标准派生/公钥编码互通；各版本按验收条件交付，不承诺日历日期。
`0.x` 优先增补 API，`1.0.0` 集中收敛公开面。
安全或一致性修复若改变既有行为，必须在实际交付版本的双语 CHANGELOG 中写明
`BREAKING` 与迁移方式；纯排期调整不新增 CHANGELOG 条目。

**兼容原则**：保持铜锁 **8.4.0** 发布基线，固定验证 **8.5.0**，保留 8.4 构建兼容；新能力须通过编译保护与运行时探测报告
支持情况，不以 master、替代密码实现或自动加载 legacy provider 兜底。

`0.11.0` 至 `0.12.0` 的破坏性列为「轻微」：只向 `ConnectionState` / `Config` 追加导出
字段，未改变既有字段与默认行为；影响范围限于无字段名的复合字面量，迁移方式随交付
写入双语 CHANGELOG。

---

## 2. 分版本范围

### 铜锁上游待支持的 PQC 能力

铜锁 8.5.0 的 TLS 签名方案包含 ML-DSA，不包含 SLH-DSA。
SLH-DSA TLS 认证待铜锁提供可协商的签名方案后再验收，本版仍交付 SLH-DSA 签验和 X.509。
`X448MLKEM1024` 可见于 EVP KEM 枚举，但 8.5.0 的 TLS 组配置拒绝该名称，
待铜锁支持其 TLS 协商后再纳入 TLS 矩阵。两项均无预定版本。

### 2.2 `0.15.0` — CMS 与时间戳

| 领域 | 内容 | 对应缺口 | 前置（§3） |
|------|------|----------|-------------|
| `pkcs/pkcs7` | CMS 签验、信封与 DigestedData 生成/验证，复用既有容器基础设施 | I-37 | CMS |
| 新顶级包 `ts` | RFC 3161：请求/响应、验证与 HTTP 传输 | I-39 | CMS / TS |

`ts` 与 `x509` 平级，实施时同步包索引与依赖图；当前仍为 16 个公开包。
数据库化、文件系统绑定的 CA 工作流不属于本版，继续按 §4 暂缓。

**完成条件**：CMS 与 CLI 双向互通，附带/分离内容、信任与多签名者、篡改和错误密钥均验收；
DigestedData 仅验证摘要完整性，不代表签名认证。时间戳覆盖 imprint/nonce/policy、
TSA 签名、证书用途、链与时间校验，区分解析成功和验证通过；HTTP 失败与资源释放可回归。

### 2.3 `0.16.0` — 标准派生与公钥编码互通

| 领域 | 范围与价值 | 需求 | 前置（§3） |
|------|------------|------|-------------|
| `kdf` | SSHKDF / PKCS12KDF 的类型化与按名入口，补标准派生参数而不引入 SSH 协议栈 | I-34 | EVP_KDF 参数映射 |
| `asym` | EC/SM2 公钥 SPKI PEM/DER 的压缩/未压缩输出选择，旧默认保持不变；不扩成 SM2 密文压缩输出 | I-35 | 原生公钥点形式与编码 |

**完成条件**：两版铜锁独立标准向量及适用 CLI 对拍；SSHKDF 覆盖类型字节与 session ID，
PKCS12KDF 明确 Unicode 编码、diversifier 与空/缺失口令语义，非法参数不能静默默认。
公钥编码覆盖 EC 与 SM2 的往返、压缩点合法性和源对象不变；不支持的密钥或原生组合明确失败。
KRB5KDF、hybrid 点形式和额外曲线扩容不隐含纳入，后两项仅在有互通需求时重新评估。

### 2.4 `1.0.0` — 公开 API 收敛与稳定（I-36）

- **E2 原语公开面**：统一按名分发的 Options，补非对称按名密钥生成入口（当前只有算法专用 Generate 函数），集中处理公开签名收敛。
- **E3 应用级组合**：复用已有内存签发流程，补应用级组合与 CRL 配置式签发入口
  （I-36）；不承接文件系统 CA 数据库。
- 给出迁移对照、双语 CHANGELOG 的 `BREAKING` 与兼容性承诺，完成全量回归；
  不以新增大批算法/协议作为本版交付前提。

---

## 3. 绑定实现与后续实施前置

0.14.0 及之前的绑定已实现。下表仅列后续实施前置，不表示已绑定；已实现绑定见 [内部 API 清单](api-reference-internal.md)。

| 家族 | 需要的 C 接口或扩展 | 服务对象 | 目标版本 |
|------|--------------------|----------|----------|
| CMS / TS | `CMS_*`（含摘要封装/验证）/ `TS_*`、验证与 HTTP 编排 | `pkcs/pkcs7`、`ts` | `0.15.0` |
| SSHKDF / PKCS12KDF | `EVP_KDF_fetch` / derive 参数类型、编码及所有权，复用现有泛化绑定并补缺失参数 | `kdf` | `0.16.0` |
| EC/SM2 公钥点形式 | 原生公钥 point-format 设置、SPKI 编码与独立句柄复制，避免修改源密钥 | `asym` | `0.16.0` |

---

## 4. 明确不做 / 暂缓

| # | 项 | 处置 | 理由 |
|---|----|------|------|
| 1 | `engine` | 不做 | 已被 provider 机制取代 |
| 2 | 数据库化、文件系统绑定的 CA 工作流 | **暂缓，不承诺版本** | 本质是持久化状态机；继续复用既有内存签发流程，不以 `OpenCA` / index.txt 工作流作为协议版本交付条件 |
| 3 | DSA / 独立 DH 密钥交换算法 | 不做 | 非国密目标场景；TLS 的 DH 参数加载归 `0.9.0` |
| 4 | EC-ElGamal / Paillier | 不做 | 非国密目标场景 |
| 5 | 特殊扩展与设备能力 | 不做（按构建记录） | 白盒 SM4、Bulletproofs、SM2 门限、SDF、SMTC、Delegated Credential；是否可用依具体构建与实测，不能从命令存在或缺失推断；见 [CLI 对比 §6](cli-comparison.md#6-不纳入与特殊构建能力) |
| 6 | 提升 `internal/core` 原生句柄为公开类型 | 不做 | 跨包取句柄须走现有桥接，公开签名不得出现 internal 类型 |
| 7 | 公开 BIO、原生 HMAC_CTX、NID 常量表 | 不做 | 维持 Go 惯例封装；见 [官方 SDK 对比 §4](official-sdk-comparison.md#4-设计差异与不对齐项) |
| 8 | `crypto/*` deprecated 转发包 | 不做 | `0.3.0` 已完成迁移，不重新扩大公开面 |
| 9 | ECIES / 私有混合加密容器 | **暂缓，不承诺版本** | 尚无明确的互通格式与对象；不自行定义容器。出现明确互通对象或 HPKE/JWE 等标准协议需求后重新立项；原生 HPKE 可用不等于本库已封装 |
| 10 | 库内自动加载 legacy provider | 不做 | 保持默认原生能力边界；单 DES 已在 `0.6.0` 以 `K‖K‖K` 驱动 DES-EDE3 等价实现，仅用于存量数据兼容 |
| 11 | EC/SM2 自定义 XML 格式 | 不做 | `xml/rsa` 只处理 .NET RSAKeyValue；不另创 ECKeyValue 格式（I-13） |
| 12 | STARTTLS、外部 PSK、0-RTT、主动重协商 | **暂缓，不承诺版本** | 不作为四版 TLS 系列或 1.0 稳定版的交付前提；RFC 8998 已单独归入 `0.10.0` |
| 13 | 报文级裸握手 / 心跳发包（`RawHandshake` / `SendRecord`） | 不做 | 需绕过铜锁状态机自行拼装 TLS 记录层，等于在本库内自研协议栈；Heartbleed / ROBOT / CCS-Injection / POODLE / Ticketbleed 一类主动探测属渗透与漏洞扫描工具职责，不作为 SDK 能力（I-33） |
| 14 | TLS 压缩与 heartbeat 状态查询 | 不做 | 本库构建未启用 ZLIB / BROTLI / ZSTD，压缩恒不可协商，字段恒为 false 无诊断价值；heartbeat 无公开原生状态接口；配置侧已由 `OptionNoCompression` 表达（I-32） |
| 15 | SM2DH 密钥确认 | **暂缓，不承诺版本** | 固定 8.5.0 provider 仅输出派生密钥，未暴露确认值；确认值生成、对端校验及失败后禁用密钥待原生能力可用后实施，派生成功不等于对端认证或密钥确认；见 [需求复核 §3](requirements.md#3-sm2dh-密钥确认的原生限制) |

其他候选（通用流传输、provider/硬件 URI、标准混合加密、KRB5KDF 等）的限制与重开条件
统一见 [需求台账 §2](requirements.md#2-暂缓需求与重开条件)，未分配版本。

---

## 附录 A. 相关文档

| 用途 | 文档 |
|------|------|
| 公开 API 逐符号清单（含 🧭 规划中形态） | [api-reference.md](api-reference.md) |
| 内部 API 清单（`internal/*`） | [api-reference-internal.md](api-reference-internal.md) |
| 分层、目录、依赖方向、桥接设计 | [architecture.md](architecture.md) |
| 功能需求复核与处置 | [requirements.md](requirements.md) |
| 与铜锁 CLI 的能力对比（能力证据） | [cli-comparison.md](cli-comparison.md) |
| 对比缺口处置索引 | [cli-comparison-todo.md](cli-comparison-todo.md) |
| 与官方 SDK 的能力对比 | [official-sdk-comparison.md](official-sdk-comparison.md) |
| 开发规范 / 测试规范 | [development-guide.md](development-guide.md) · [testing-guide.md](testing-guide.md) |
| 变更记录 | [CHANGELOG.md](../CHANGELOG.md) · [CHANGELOG.zh.md](../CHANGELOG.zh.md) |
