# 版本路线图（`0.11.0` 至 `1.0.0`）

> **用途**：本文件是本仓库**唯一的版本归属来源**。未来能力的目标版本以 §2 为准；
> 逐符号目标形态见 [api-reference.md](api-reference.md) 的 🧭 行，实施前置见 §3。
>
> **基线**：`0.10.0` 已于 2026-11-12 发布；固定验证铜锁 8.4.0/8.5.0。
> 本文件仅保留 `0.11.0` 及以后的规划与未完成事项；`0.10.0` 及之前的交付范围已完成，
> 历史交付与验收记录见双语 CHANGELOG 和 [测试规范](testing-guide.md)。
> 当前公开面见 [公开 API 清单](api-reference.md) 与 [CHANGELOG](../CHANGELOG.md#0100---2026-11-12)；
> 发布状态以版本标签为准。
>
> **相关文档**：功能需求的复核与验收边界见
> [功能需求复核记录](requirements.md)；CLI 与官方 SDK 的能力证据分别见
> [cli-comparison.md](cli-comparison.md)、[official-sdk-comparison.md](official-sdk-comparison.md)。

---

## 1. 里程碑总览

| 版本 | 主题 | 关键内容 | 破坏性 |
|------|------|----------|--------|
| `0.11.0` | **会话复用与票据** | 客户端/服务端缓存、会话导入导出、票据控制、密钥轮换、握手后票据处理、身份隔离与复用标志 | 轻微：导出结构体扩容 |
| `0.12.0` | **HTTP/1.1 集成与 OCSP stapling** | 客户端/服务端集成、便捷服务入口、staple 配置、读取与状态快照、状态验证示例 | 轻微：导出结构体扩容 |
| `0.13.0` | **PQC** | ML-DSA、SLH-DSA、原生 KEM，密钥生命周期与序列化、能力探测 | 否 |
| `0.14.0` | **CMS 与时间戳** | CMS 签验/信封、DigestedData、独立顶级包 `ts` 的 RFC 3161 能力 | 否 |
| `0.15.0` | **标准派生与公钥编码互通** | SSHKDF / PKCS12KDF、EC/SM2 公钥压缩与未压缩编码 | 否 |
| `1.0.0` | **公开 API 收敛与稳定** | 统一 Options、应用级组合入口、CRL 配置式签发、迁移指南与兼容性承诺 | **是** |

**节奏原则**：以已发布 `0.10.0` 为基线，先完成会话复用与 HTTP/1.1 集成，
随后扩展 PQC、CMS 与标准派生/公钥编码互通；各版本按验收条件交付，不承诺日历日期。
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

### 2.1 `0.11.0` — 会话复用与票据（规划）

| 能力 | 交付内容与边界 | 前置（§3） |
|------|----------------|-------------|
| 会话缓存与状态 | 跨连接客户端缓存、服务端缓存、`Conn.SessionState()`、`ConnectionState.SessionReused`、DER/PEM 导入导出、只读会话元数据、过期及实际复用结果（I-31） | TLS 会话与票据 |
| 票据 | 开关、数量控制、密钥管理与轮换、TLS 1.3 握手后票据处理（I-31） | TLS 会话与票据 |
| 身份隔离 | 按协议、服务身份、客户端身份和验证配置隔离缓存，复用后仍执行约定的验证回调 | TLS 会话与票据 |

**完成条件**：在已交付的 TLS / NTLS / RFC 8998 协议矩阵上验证首次/恢复握手、拒绝复用、过期、密钥轮换与
跨身份隔离；不以“握手成功”代替“实际复用”。TLS 1.3 测试与示例必须处理握手后
到达的票据，再进行恢复连接，不能握手后立即断开并假定已有可用会话。

### 2.2 `0.12.0` — HTTP/1.1 集成与 OCSP stapling（规划）

| 能力 | 交付内容与边界 | 前置（§3） |
|------|----------------|-------------|
| HTTP/1.1 | 客户端/服务端集成、`ListenAndServeTLS` / `ServeTLS`、握手/回显/HTTP 响应示例，复用已有 `NewListener`（I-29） | TLS stapling / HTTP 集成 |
| OCSP stapling | 配置、请求、读取 staple 与状态验证示例，分别表达“取得响应”和“验证响应有效”；`ConnectionState.OCSPStapled` / `OCSPResponse` 提供连接级快照，DER 可直接交 `x509.ParseOCSPResponse`（I-29） | TLS stapling / HTTP 集成 |

**完成条件**：在已有 TLS / NTLS / RFC 8998 协议矩阵上验证 HTTP/1.1 与适用的
stapling 路径；受控本地测试覆盖缺失、过期、吊销及错误签名/身份的响应。不支持的
协议/原生组合明确报告能力边界；ALPN 能协商 `h2` 不等于已交付 HTTP/2 集成。

### 2.3 `0.13.0` — PQC（I-38）

| 领域 | 内容 | 前置（§3） |
|------|------|-------------|
| `asym` 签名 | ML-DSA-44 / 65 / 87、SLH-DSA 12 变体 | PQC 密钥生成、签验与序列化路径 |
| `asym` KEM | ML-KEM-512/768/1024 与原生 `Encapsulate` / `Decapsulate`，明确算法/模式支持范围 | `EVP_PKEY_encapsulate` / `EVP_PKEY_decapsulate` |
| `tls` PQC / 混合组 | 对原生可用的 ML-KEM 与经典/PQC 混合组明确支持矩阵并实际握手；至少验证 X25519MLKEM768 与原生可用的 curveSM2MLKEM768，不能以 Groups 字符串配置替代验收 | 原生组配置与协商状态 |

本版独立验收密钥生命周期、编码往返、算法/参数不匹配和能力探测；8.4 构建不能
引用不存在的符号，不可用能力明确报错，不引入第三方算法替代实现。

### 2.4 `0.14.0` — CMS 与时间戳

| 领域 | 内容 | 对应缺口 | 前置（§3） |
|------|------|----------|-------------|
| `pkcs/pkcs7` | CMS 签验、信封与 DigestedData 生成/验证，复用既有容器基础设施 | I-37 | CMS |
| 新顶级包 `ts` | RFC 3161：请求/响应、验证与 HTTP 传输 | I-39 | CMS / TS |

`ts` 与 `x509` 平级，实施时同步包索引与依赖图；当前仍为 16 个公开包。
数据库化、文件系统绑定的 CA 工作流不属于本版，继续按 §4 暂缓。

**完成条件**：CMS 与 CLI 双向互通，附带/分离内容、信任与多签名者、篡改和错误密钥均验收；
DigestedData 仅验证摘要完整性，不代表签名认证。时间戳覆盖 imprint/nonce/policy、
TSA 签名、证书用途、链与时间校验，区分解析成功和验证通过；HTTP 失败与资源释放可回归。

### 2.5 `0.15.0` — 标准派生与公钥编码互通

| 领域 | 范围与价值 | 需求 | 前置（§3） |
|------|------------|------|-------------|
| `kdf` | SSHKDF / PKCS12KDF 的类型化与按名入口，补标准派生参数而不引入 SSH 协议栈 | I-34 | EVP_KDF 参数映射 |
| `asym` | EC/SM2 公钥 SPKI PEM/DER 的压缩/未压缩输出选择，旧默认保持不变；不扩成 SM2 密文压缩输出 | I-35 | 原生公钥点形式与编码 |

**完成条件**：两版铜锁独立标准向量及适用 CLI 对拍；SSHKDF 覆盖类型字节与 session ID，
PKCS12KDF 明确 Unicode 编码、diversifier 与空/缺失口令语义，非法参数不能静默默认。
公钥编码覆盖 EC 与 SM2 的往返、压缩点合法性和源对象不变；不支持的密钥或原生组合明确失败。
KRB5KDF、hybrid 点形式和额外曲线扩容不隐含纳入，后两项仅在有互通需求时重新评估。

### 2.6 `1.0.0` — 公开 API 收敛与稳定（I-36）

- **E2 原语公开面**：统一按名分发的 Options，补非对称按名密钥生成入口（当前只有算法专用 Generate 函数），集中处理公开签名收敛。
- **E3 应用级组合**：复用已有内存签发流程，补应用级组合与 CRL 配置式签发入口
  （I-36）；不承接文件系统 CA 数据库。
- 给出迁移对照、双语 CHANGELOG 的 `BREAKING` 与兼容性承诺，完成全量回归；
  不以新增大批算法/协议作为本版交付前提。

---

## 3. 绑定实现与后续实施前置

下表仅列后续实施前置，不表示已绑定；已实现绑定见 [内部 API 清单](api-reference-internal.md)。

| 家族 | 需要的 C 接口或扩展 | 服务对象 | 目标版本 |
|------|--------------------|----------|----------|
| TLS 会话与票据 | `SSL_session_reused`、`SSL_SESSION_*`、会话新建/缓存回调、复用状态、票据数量与密钥轮换绑定 | `tls` | `0.11.0` |
| TLS stapling / HTTP 集成 | `SSL_CTX_set_tlsext_status*` / `SSL_get_tlsext_status_ocsp_resp` 等；HTTP 入口复用已有 Listener 与标准库 | `tls` | `0.12.0` |
| PQC / KEM | 原生 PQC 密钥、签验、序列化路径；`EVP_PKEY_encapsulate` / `EVP_PKEY_decapsulate`，TLS 组配置与实际协商状态 | `asym`、`tls` | `0.13.0` |
| CMS / TS | `CMS_*`（含摘要封装/验证）/ `TS_*`、验证与 HTTP 编排 | `pkcs/pkcs7`、`ts` | `0.14.0` |
| SSHKDF / PKCS12KDF | `EVP_KDF_fetch` / derive 参数类型、编码及所有权，复用现有泛化绑定并补缺失参数 | `kdf` | `0.15.0` |
| EC/SM2 公钥点形式 | 原生公钥 point-format 设置、SPKI 编码与独立句柄复制，避免修改源密钥 | `asym` | `0.15.0` |

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
