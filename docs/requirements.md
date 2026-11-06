# 功能需求复核与交付边界

> 状态：0.8.0 已实现、待标签发布，0.9.0 已实现、待发布，0.10.0 起仍为规划 ｜ 实现基线：`0.9.0`
> ｜ 最后复核：2026-11-06
>
> 按 `0.6.0` 复核原始缺口，并以 `0.7.0` 验收更新交付状态；需求编号仅用于本文与路线图之间的交叉引用。

本文记录功能需求的复核结论及验收边界；版本归属以 [roadmap.md](roadmap.md) §2 为准，
当前 API 见 [api-reference.md](api-reference.md)。0.7.0 已实现的范围以代码与验收为准；
后续版本归属继续由路线图维护。

## 1. 功能需求逐条处置

| 编号 | 需求 | 0.6.0 复核结论 | 版本/处置 |
|---|---|---|---|
| I-01 | AES-OFB/CFB | `0.6.0` 已有类型化与按名入口，覆盖 128/192/256 位 | 已实现，随实际升级关闭 |
| I-02 | DES/3DES | `0.6.0` 已有 DES / DES-EDE / DES-EDE3 的 ECB/CBC；单 DES 用 K‖K‖K 等价实现，不加载 legacy | 已实现，仅限存量数据兼容 |
| I-03 | 填充支持矩阵 | `Supports` / `Paddings` 已在 `0.6.0` 实现 | 已实现，随实际升级关闭 |
| I-04 | AES 静默忽略 Padding | `0.6.0` 已统一应用 Padding，非法组合返回 `ErrUnsupportedPadding` | 已修复，随实际升级关闭 |
| I-05 | ECIES | 暂无指定互通对象，不自行定义容器；HPKE/JWE 也尚未封装 | 暂缓；有具体互通格式或标准协议需求再立项 |
| I-06 | RSA-SM3 | OAEP-SM3 与签名摘要能力探测已在 `0.6.0` 实现；8.4 RSA provider 不支持 SM3 签名 | `0.8.0` 已验证 8.5.0 的 PKCS#1 v1.5/PSS 与 CLI 双向互验；8.4.0 明确不支持 |
| I-07 | 签名 DER/raw 互转 | `SignatureParts` / `SignatureDER` / `FormatSignature` 已实现，转换明确给出分量宽度，仅适用 SM2/ECDSA | `0.6.0` 已实现 |
| I-08 | RSA 签名应改成 DER | 需求依据错误；RSA-PSS/PKCS#1 v1.5 的签名是模数长度字节串，不是 r/s DER | 不改变格式；`0.7.0` 已补说明与双向互验 |
| I-09 | ECDH 无公开 Close | 原生副本已有独立生命周期，仍缺公开释放入口 | `0.7.0` 已实现：公私钥幂等 Close，Public 改为独立副本与 error，关闭后使用检查 |
| I-10 | SM2 压缩点密文 | 裸格式互转保留原 C1，当前压缩点转 DER 明确报错，未发现所述“重建时丢失 C1”路径 | `0.7.0` 已实现：经铜锁解码和校验，支持压缩输入转换/解密；不增压缩输出 |
| I-11 | PKCS#7 签名/加密 | `0.6.0` 已有证书/CRL 容器，仍缺 signerInfo 与 EnvelopedData 流程 | `0.7.0` 已实现：Sign / Verify / Encrypt / Decrypt；默认验证信任，按 8.4 原生算法范围交付 |
| I-12 | OKP/oct JWK | `0.6.0` 已实现 Ed25519/Ed448/X25519/X448 OKP 与 oct 导入导出 | 已实现，随实际升级关闭 |
| I-13 | XML 仅 RSA | 包文档已明确 .NET RSAKeyValue，范围符合设计 | 维持仅 RSA，不另创 EC/SM2 XML |
| I-14 | RSA PKCS#1 公钥 | `0.6.0` 已有显式导出/加载入口，不要求通用 SPKI 加载器接受所有标签 | 已实现，按显式入口迁移 |
| I-15 | CSR 无公开 Close | core 已有 Close，API 层仍缺入口 | `0.7.0` 已实现：公开幂等 Close 与关闭后错误检查 |
| I-16 | ASN.1 限额 | 当前 Parse 已有固定 128 层保护；缺可配置深度、节点数限额及可识别超限错误 | `0.7.0` 已实现：ParseWithLimits，保持现有 Parse 行为 |
| I-17 | 默认信任库 | 缺默认路径与 CA 文件/目录加载；默认路径属于铜锁配置，不能承诺平台原生系统信任库 | `0.7.0` 已实现：SetDefaultPaths / LoadLocations，不隐式信任输入根 |
| I-18 | CRL 序列号截断 | `RevokedEntry.Serial` 经 int64 读取，无法无损承载长序列号 | `0.7.0` 已实现：新增 SerialHex，保留受限兼容视图 |
| I-19 | DER 扩展写入 | core 已有 DER 扩展基础，公开 API 仍以配置串为主；Data 与 Value 含义不同 | `0.7.0` 已实现：公开按已知/自定义 OID 写入 DER，不反解任意配置串 |
| I-20 | 只能按证书吊销 | 缺按完整序列号入口，且现有 Revoke(cert) 也经 int64 中转 | `0.7.0` 已实现：RevokeSerialHex；现有 Revoke 同步修复截断 |
| I-21 | 便捷签发无法再加扩展 | 立即签名、之后不可变是既有设计；NewCertificate + Set/Add + Sign 已可满足需求 | `0.7.0` 已实现：补推荐示例与入口说明，不放开签名后修改 |
| I-22 | 外部 P12 改密 | 原生诊断中默认导出容器改密失败，显式 3DES/SHA-1 组合成功；“所有外部容器一律失败”不成立。WithOptions 重打包不是无损修复 | `0.7.0` 已实现：两个改密入口均保留复杂 safe/bag 内容，覆盖多私钥与嵌套，不依赖升级 8.5 解决 |
| I-29 | OCSP 装订状态 | `ConnectionState` 只报版本/套件/ALPN/组/签名算法/证书，缺装订标志与响应体；原生 `SSL_get_tlsext_status_ocsp_resp` 可用 | `0.12.0`：新增 `ConnectionState.OCSPStapled` / `OCSPResponse`，DER 可直接交 `x509.ParseOCSPResponse(der, cert, issuer)`；与 stapling 配置同版交付 |
| I-30 | TLS 扩展 SCT 列表 | 原生无 SCT 只读 getter（`s->ext.scts` 为内部字段），只能经 `SSL_CTX_set_ct_validation_callback` 采集 | `0.10.0`：`Config.CaptureSCT` 显式开启，`ConnectionState.SignedCertificateTimestamps` 逐项保留 SCT DER；默认关闭，回调恒允许，本库只记录不执行 CT 策略校验 |
| I-31 | 会话复用标志 | 无 `SessionReused`，无法区分首次与恢复握手；原生 `SSL_session_reused` 可用 | `0.11.0`：`ConnectionState.SessionReused` 与 `Conn.SessionState()` 同版交付，启用缓存不等于实际复用 |
| I-32 | 安全重协商 / 压缩 / heartbeat 状态 | 仅安全重协商有原生查询接口（`SSL_get_secure_renegotiation_support`） | `0.10.0` 只做 `ConnectionState.SecureRenegotiation`；压缩与 heartbeat 见路线图 §4 第 14 条不做 |
| I-33 | 报文级裸握手 / 心跳发包 | 需绕过铜锁状态机自行拼装 TLS 记录层，与「复用原生状态机、不自研协议栈」冲突 | 不做，登记路线图 §4 第 13 条；属渗透与漏洞扫描工具职责 |

### 1.1 编号说明

本仓库 `I-01` 至 `I-33` 为独立序列，`I-23` / `I-24` 在本仓库**指 CRL 按序列号吊销
与完整大整数序列号**（见 §3）。下游使用方台账里同号条目（TLS OCSP 装订、SCT 列表）
含义不同，自本次复核起按其能力重新登记为 `I-29` 至 `I-33`，不复用 `I-23` / `I-24`。
引用外部台账时须注明来源与版本，避免与本文编号混用。

## 2. 实现与验收边界

- **正确性优先**：I-18/I-20 同时贯通完整序列号的读写与证书吊销路径，不能只增加
  一个显示字段；I-23/I-24 进一步补齐证书设置、CSR 签发与吊销匹配，详见 §3。
  I-19 保留原始扩展 DER 和 critical/OID，仍禁止签名后编辑。
- **原生能力**：SM2 点展开与 P12 重加密均通过 native → core → API；不手写替代
  密码算法，不引入第三方依赖，不自动加载 legacy provider。
- **无损改密**：ChangePassword 与 ChangePasswordWithOptions 均保留多私钥、证书链、
  CRL、其他可保留 bag、嵌套层级、safe/bag 顺序及全部属性，不经单 key/cert Bundle
  重打包。普通入口保留算法/派生/MAC 策略；WithOptions 应用编码参数。空 FriendlyName
  保留名称，非空仅在单密钥身份明确时改名，多密钥时拒绝歧义。先验证 MAC，无法处理
  的算法/保护方式或结构明确失败；详细默认值见路线图 §2.1。
- **互通验收**：随机签名、加密容器以双向验证/解密及结构语义比较为准，不能要求随机
  产物逐字节相等；确定性转换与原始 DER 迁移使用逐字节断言。
- **格式纠偏**：RSA 签名输出格式见 [RFC 8017 §8](https://www.rfc-editor.org/rfc/rfc8017.html#section-8)；
  默认信任路径见 [OpenSSL X509_STORE 文档](https://docs.openssl.org/3.0/man3/X509_STORE_add_cert/)。
- **连接状态扩容**：`ConnectionState`（以及必要的 `Config`）只追加字段，不改变既有
  字段语义；导出结构体扩容会影响无字段名复合字面量，须在双语 CHANGELOG 与迁移说明
  中标注。SCT 采集默认关闭，开启后 CT 校验回调恒返回允许，因此本库不承担 CT 策略
  校验责任；`OPENSSL_NO_CT` 构建下明确返回不支持，不静默返回空列表。

### 2.1 0.7.0 兼容取舍与容器边界（已发布）

- **I-09/I-15**：ECDH Public() 改为 (*PublicKey, error)，公私钥与源 asym 密钥独立
  释放；Close 对 nil、零值和重复调用幂等，可失败操作在关闭后报错。此签名变化需迁移。
- **I-16**：ParseWithLimits 的限额均为正数，节点数包含根，深度沿用构造类型层数；
  ErrDepthLimit/ErrNodeLimit 可经 errors.Is 识别，原 Parse 的 128 层行为与错误文本保留。
- **I-11**：原 0.8 范围合入 0.7；Sign 默认 SHA-256 与附带内容，Encrypt 默认
  AES-256-CBC、多 RSA 接收者；输出 DER，Verify/Decrypt 接受 DER/PKCS7 PEM，二进制
  内容不转换换行。Verify 默认要求显式信任存储并验证全部签名者，仅显式 SignatureOnly
  跳过链验证，结果明确 TrustVerified=false，失败不返回内容。8.4.0 验收 RSA/ECDSA
  签名与 RSA 接收者加密；SM2 及其他不支持组合明确失败。CMS 留给调整后的 0.14.0。
- **I-22**：多私钥、多 safe 和嵌套 safeContentsBag 为必须成功项；无 MAC、不同
  MAC/加密口令、签名保护及其他未支持算法/结构明确拒绝。比较改密前后的内容与属性
  结构，不要求随机盐/IV 或加密后的整个 DER 相同。

## 3. CRL 与完整序列号：职责判断与排期

| 编号 | 优先级 | 需求与当前限制 | 是否应做 / 处置 |
|---|---|---|---|
| I-23 | 高 | 直接按序列号追加 CRL 吊销记录；目前入口必须取得完整证书，无法仅凭已知序列号生成条目 | **已实现，扩充 I-20，归 `0.7.0`**。CRL 条目的协议数据是序列号、吊销时间及扩展，不要求携带完整证书；SDK 应提供内存构建原语 |
| I-24 | 中 | 大整数序列号贯通证书设置、CRL 写入、读取与匹配；当前 int64 接口无法表达完整的协议取值范围 | **已实现，扩充 I-18/I-20，归 `0.7.0`**。完整序列号属于数据正确性，作为 I-23 的共同交付条件，不拆到后续版本 |

**0.6.0 原状与修复范围**：原有 `Certificate.SetSerial`、
`IssueOptions.Serial`、`CRLBuilder.Revoke`、`RevokedEntry.Serial`、`CRL.IsRevoked`
与 core `RevocationCheck` 均经过 `int64`；底层读取使用 `ASN1_INTEGER_get`，超范围
不能视为完整值，可能让不同长序列号得到相同受限结果。已有 `Certificate.SerialHex`
只解决证书显示，原 `0.7.0` 规划的 `RevokedEntry.SerialHex` / `RevokeSerialHex`
当时未完整覆盖证书设置与匹配；0.7.0 已贯通这些路径。I-23/I-24 扩充既有工作项的验收范围，不另计两套独立实现。

**职责判断**：按 [RFC 5280 §5.1.2.6](https://www.rfc-editor.org/rfc/rfc5280.html#section-5.1.2.6)，
CRL 以序列号列出吊销对象；因此直接按序列号构建条目属于 SDK 的封装职责。
但序列号仅在签发者范围内有意义：调用方仍负责确认其归属、吊销授权和记录真实性。
SDK 不负责恢复遗失证书、签发数据库、全局序列号分配、持久化或审计工作流；
路线图中数据库化 CA 工作流继续暂缓，不能把本次原语增补推迟到 `1.0.0` 的组合入口。

**接口取向**：新增以标准库 `*big.Int` 为参数/结果的入口，保持无第三方依赖；
[Go `crypto/x509`](https://pkg.go.dev/crypto/x509#RevocationListEntry) 也以
`*big.Int` 表达证书与 CRL 条目序列号。目标形态见 API 清单：
`Certificate.SerialBigInt` / `SetSerialBigInt`、`CRLBuilder.RevokeSerial`、
`RevokedEntry.SerialBigInt` 与 `IssueOptions.SerialBigInt`。
保留已有 `SerialHex` 和已规划的 hex 适配入口，复用同一无损转换路径；不为每个
便捷签发函数新增一组 BigInt/Hex/Bytes 变体。大序列号签发可走
`NewCertificate` → `SetSerialBigInt` → Set/Add → `Sign`，CSR 签发走增补后的选项。

**共同验收条件（0.7.0 已实现并通过）**：

1. 无需被吊销证书对象，仅用序列号、时间、原因即可构建并签名 CRL；原因码、构建器
   关闭/已签名状态的校验与现有 `Revoke` 一致。`Revoke(cert)` 复用完整值路径。
2. 大整数设置、PEM/DER 往返、CRL 两种吊销入口、条目读回、`IsRevoked` 与
   `RevocationCheck` 全程不经过 `int64`。两条超范围但不同的序列号不得误匹配；
   同一序列号的不同 hex 大小写或前导零表示按整数值匹配。
3. 新写入入口拒绝 nil、零、负数及超出签发长度边界的值；旧 int64 写入口也统一拒绝
   零和负数。hex 入口拒绝空串及非法字符。按 [RFC 5280 §4.1.2.2](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.2)
   的正整数与 20 octets 边界验收；DER INTEGER 内容长度包含必要的符号补零。
   读取外部非合规序列号时保留完整整数或明确报错，不截断、不取绝对值，不用 0/-1 冒充成功结果。
4. 输入 `*big.Int` 在调用时复制，返回值为独立对象；修改输入/返回值不得改变已写入
   的证书或 CRL。`IssueOptions.SerialBigInt != nil` 且旧 `Serial != 0` 时拒绝歧义，
   nil 则保留旧选项路径；设置证书序列号仍遵守签名后不可变。
5. 旧 `int64` 签名与字段保留，明确受限且不用于内部身份比较。`IsRevoked` 继续只查
   条目；`RevocationCheck` 保留 issuer 匹配与 CRL 信任前提，不把本次修改扩成完整
   CRL 校验。实施时说明导出结构体新增字段对无字段名字面量的迁移影响。
6. 铜锁 **8.4.0** 上通过单元测试及 CLI 双向互通，至少覆盖超 `int64` 的正整数、
   20 octets 边界、不同高位但相同低 64 位、不同长整数的溢出折叠与错误路径。
   交付时才更新双语 CHANGELOG；排期确认不代表功能已经可用。

## 4. SM2DH 密钥确认的原生限制

`0.8.0` 已交付显式参数的 SM2DH 派生（静态/临时密钥、双方 ID、角色、长度，SM3）。
GB/T 32918.3 的确认消息生成、对端校验及失败后禁用密钥为独立需求：固定铜锁 8.5.0
provider 的 derive 接口仅输出派生密钥，未暴露确认值，因此延期至原生支持，不承诺版本。
调用方仍须认证静态公钥，不能把双方各自完成派生当作身份认证或密钥确认。

## 5. 维护约定

1. 本库实际交付后，按 API 及运行时铜锁版本逐条复核并更新状态；“已排期”不能算
   “已修复”。本文只记录本库的功能缺口、技术判断、排期与验收边界，不记录需求来源、
   使用方身份、外部代码路径或业务侧限制。
2. 未来功能仅在路线图/API 的规划段登记，实际交付时更新双语 CHANGELOG；
   纯文档调整不新增条目，未发布版本既有条目中的排期引用应保持一致。
3. 新增需求使用库内编号及不含外部项目身份的最小复现；历史 `docs/issues/` 报告保持原样。
