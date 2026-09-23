# 铜锁 CLI 缺失子命令 → 待生成 API 清单（TODO）

> **用途**：把 `docs/cli-comparison.md` §6.A 中判定为 **❌ 缺失**、且**不在**该文 §9「明确不实现清单」内的子命令，逐条展开为**待实现的 API**。每条 API 前带复选框 `[ ]`，**勾选即表示打算做**。
>
> **口径**：
> 1. 只产出**应用级函数**（一个调用完成一件事，明确输入源与输出形态），**不产出底层函数、不暴露底层 cgo 函数**；
> 2. API **放进现有包**；确实无现成归属的，标注「建议新增包」并在附录 A 汇总；
> 3. 判定与优先级沿用 `docs/cli-comparison.md` §6.A 的编号、优先级与理由；
> 4. **包名已按重构后形态归一**——重构前的 `tongsuo` / `crypto/mac` / `crypto/ecdh` / `key` 等写法已替换；目标包结构见 [refactor-roadmap.md](refactor-roadmap.md) §2，逐符号签名见 [api-reference.md](api-reference.md)。
>
> **范围**：**14 个子命令 / 100 条 API**。不含 ⚠️ 部分对齐项、不含 §9「明确不实现」项、不含无对应子命令的扩展算法（PQC 等）——三者见附录 B。

---

## 0. 范围总览

| 次序 | 子命令 | §6.A 编号 | 优先级 | 归属包 | API 数 | 需新增 native 绑定 |
|---|---|---|---|---|---|---|
| 1 | `version` | 55 | P1 | `meta`（本版新增） | 4 | 否（`internal/core` 已有实现） |
| 2 | `mac` | 26 | P1 | `mac`（本版新增） | 13 | 是（`EVP_MAC_*`；本版仅 HMAC，其余见 `0.4.0`） |
| 3 | `ca` | 2 | P1 | `x509`（现有） | 12 | 否 |
| 4 | `cms` | 5 | P2 | `pkcs/pkcs7`（现有） | 8 | 是（`CMS_*`） |
| 5 | `crl2pkcs7` | 7 | P2 | `pkcs/pkcs7`（现有） | 2 | 否 |
| 6 | `ec_elgamal` | 13 | P2 | ❌ 不做（见备注） | 10 | 是（`EC_ELGAMAL_*`） |
| 7 | `ecparam` | 14 | P2 | `ecdh`（现有） | 7 | 否 |
| 8 | `errstr` | 17 | P2 | `meta`（本版新增） | 3 | 否 |
| 9 | `info` | 23 | P2 | `meta`（本版新增） | 5 | 是（`OPENSSL_info`） |
| 10 | `paillier` | 29 | P2 | ❌ 不做（见备注） | 9 | 是（`Paillier_*`） |
| 11 | `pkeyparam` | 35 | P2 | `asym`（现有） | 5 | 否 |
| 12 | `sess_id` | 46 | P2 | `tls`（现有） | 8 | 是（`SSL_SESSION_*`） |
| 13 | `storeutl` | 52 | P2 | `asym` + `x509`（现有） | 6 | 否 |
| 14 | `ts` | 53 | P2 | 建议新增顶层包 `ts` | 8 | 是（`TS_*`） |

> **备注**：`ec_elgamal` 与 `paillier` 在 [refactor-roadmap.md](refactor-roadmap.md) §11
> 「明确不做」中已列为**不做**（非国密目标场景）；本表保留行仅为与
> `docs/cli-comparison.md` §6.A 编号对应。若后续确要做，包名建议 `asym/elgamal`
> 与 `asym/paillier`，而非顶层 `crypto/*`。

**复用型横切项**（不单独设包，随下列 API 落地）：hex / base64 编码助手、文件与 `io.Reader` 输入、`*Format`（PEM/DER）维度、口令来源抽象——见 `docs/cli-comparison.md` §6.C C1–C5、C8。

---

## 1. `version` — 版本 / 构建版本信息

- **§6.A**：55 ｜ **优先级**：P1 ｜ **归属包**：`meta`（本版新增）｜ **API 数**：4
- **现状**：`internal/core` 已有 `VersionText` / `VersionNum` / `TongsuoVersionNum`，但**未导出**，外部无法调用。
- **对齐 CLI**：`tongsuo version`

- [x] `meta.Version() string` — 返回铜锁版本 banner；输入：无 → 输出：如 `"Tongsuo 8.5.0-pre2 22 Sep 2026"`
- [ ] `meta.VersionString() string` — 纯版本号（无产品名前缀与构建日期），如 `"3.5.4"`
- [ ] `meta.VersionNum() uint64` — OpenSSL 兼容版本号（转发 `OpenSSL_version_num`）
- [ ] `meta.TongsuoVersionNum() uint64` — 铜锁自有版本号（转发 `Tongsuo_version_num`）

---

## 2. `mac` — 按算法名计算消息认证码

- **§6.A**：26 ｜ **优先级**：P1 ｜ **归属包**：`mac`（本版新增）｜ **API 数**：13
- **现状**：只有 `crypto/hmac`（HMAC × 6 种摘要）；缺 CMAC / GMAC / KMAC-128 / KMAC-256 / SipHash / Poly1305 / EIA3。
- **对齐 CLI**：`tongsuo mac -macopt cipher:SM4 -macopt hexkey:... GMAC`
- **前置**：`internal/native` 需新增 `EVP_MAC_*` 绑定（`EVP_MAC_fetch` / `new` / `init` / `update` / `final`）。

- [ ] `mac.Names() []string` — 列出可用 MAC 算法名（等价 `list -mac-algorithms`）
- [ ] `mac.New(name string, key []byte, opts *Options) (hash.Hash, error)` — 按算法名构造流式 MAC
- [ ] `mac.Sum(name string, key, data []byte, opts *Options) ([]byte, error)` — 一次性计算；输入：算法名 + 密钥 + 数据 → 输出：MAC 字节
- [ ] `mac.SumFile(name string, key []byte, path string, opts *Options) ([]byte, error)` — 文件输入
- [ ] `mac.SumReader(name string, key []byte, r io.Reader, opts *Options) ([]byte, error)` — 流式输入
- [ ] `type Options struct { Cipher string; IV, AAD []byte; Custom []byte; OutputLen int }` — 覆盖 `-macopt cipher: / hexkey: / hexiv: / custom: / size:`
- [ ] `mac.CMAC(cipherName string, key, data []byte) ([]byte, error)` — 便捷入口
- [ ] `mac.GMAC(cipherName string, key, iv, aad, data []byte) ([]byte, error)` — 便捷入口
- [ ] `mac.KMAC128(key, data, custom []byte, outLen int) ([]byte, error)` — 便捷入口
- [ ] `mac.KMAC256(key, data, custom []byte, outLen int) ([]byte, error)` — 便捷入口
- [ ] `mac.SipHash(key, data []byte) ([]byte, error)` — 便捷入口
- [ ] `mac.Poly1305(key, data []byte) ([]byte, error)` — 便捷入口
- [ ] `mac.EIA3(key, count, data []byte) ([]byte, error)` — 便捷入口（铜锁独有）

> 说明：`EIA3` 为铜锁独有 MAC；`CMAC`/`GMAC` 需 `cipher` 参数（SM4 / AES-128/192/256）。

---

## 3. `ca` — CA 数据库化签发 / 吊销 / 续期

- **§6.A**：2 ｜ **优先级**：P1 ｜ **归属包**：`x509`（现有）｜ **API 数**：12
- **现状**：有 `x509.CreateCertificate` + `CRL` + `Store`（纯内存对象），但**无状态化工作流**（index.txt / serial / crlnumber）。
- **对齐 CLI**：`tongsuo ca -batch -config x.cnf`、`-gencrl`、`-revoke`、`-renew`
- **前置决策**：本库为内存对象模型，`ca` 本质是「文件系统 + 策略」，**需先定形态**（内存 CA 结构体 vs 目录绑定）。

- [ ] `x509.OpenCA(dir string, opts *CAOptions) (*CA, error)` — 打开或初始化 CA 目录；输入：目录路径 → 输出：`*CA`
- [ ] `x509.NewCA(opts *CAOptions) (*CA, error)` — 纯内存 CA（不落盘）
- [ ] `type CAOptions struct { CertFile, KeyFile, IndexFile, SerialFile, CRLNumberFile, NewCertsDir string; Digest string; DefaultDays int; Policy *CAPolicy }`
- [ ] `type CAEntry struct { Serial, Status, Subject, FileName string; Expiry, RevokedAt time.Time; RevokeReason int }`
- [ ] `(*CA).IssueCSR(csrPEM []byte, days int, exts []Extension) (certPEM []byte, err error)` — 签发 + 落库（index.txt / serial）
- [ ] `(*CA).IssueSelfSigned(subject *Name, pub PublicKey, days int, exts []Extension) ([]byte, error)` — 自签（免 CSR）
- [ ] `(*CA).Revoke(certPEM []byte, reason int) error` — 吊销 + 落库（含 reason 常量）
- [ ] `(*CA).Renew(certPEM []byte, days int) ([]byte, error)` — 续期（等价 `-renew`）
- [ ] `(*CA).GenerateCRL(days int) (crlPEM []byte, err error)` — 生成 CRL + 递增 crlnumber（等价 `-gencrl`）
- [ ] `(*CA).Entries() ([]CAEntry, error)` — 读取 index.txt
- [ ] `(*CA).NextSerial() (string, error)` — 读取并递增 serial
- [ ] `(*CA).Close() error` — 幂等释放

---

## 4. `cms` — CMS 签名 / 验签 / 加密 / 解密

- **§6.A**：5 ｜ **优先级**：P2 ｜ **归属包**：`pkcs/pkcs7`（现有，CMS 与 PKCS#7 同源 RFC 5652）｜ **API 数**：8
- **现状**：`pkcs/pkcs7` 只有证书袋 `Build`/`Extract`/`MarshalPEM`。
- **对齐 CLI**：`cms -sign` / `-verify` / `-encrypt` / `-decrypt` / `-digest_create` / `-digest_verify`
- **前置**：`internal/native` 需新增 `CMS_*` 绑定。

- [ ] `pkcs7.Sign(data []byte, opts *SignOptions) ([]byte, error)` — 生成签名/封装数据；输入：明文 + 签名证书与私钥 → 输出：CMS/PKCS#7 DER
- [ ] `pkcs7.Verify(data []byte, opts *VerifyOptions) (*SignedData, error)` — 验签并返回签名者信息
- [ ] `pkcs7.Encrypt(data []byte, opts *EncryptOptions) ([]byte, error)` — 信封加密（多接收者）
- [ ] `pkcs7.Decrypt(data []byte, opts *DecryptOptions) ([]byte, error)` — 信封解密
- [ ] `type SignOptions struct { SignerCert, SignerKey []byte; ExtraCerts [][]byte; Detached bool; Digest string; SignTime time.Time }`
- [ ] `type VerifyOptions struct { Roots []*x509.Certificate; RequireSignerCert bool; Detached []byte }`
- [ ] `type SignedData struct { Signers []SignerInfo; Certificates []*x509.Certificate; Raw []byte }`
- [ ] `pkcs7.DigestCreate(data []byte, alg string) ([]byte, error)` / `pkcs7.DigestVerify(data []byte, opts *VerifyOptions) error`

---

## 5. `crl2pkcs7` — CRL（+证书）打包为 PKCS#7

- **§6.A**：7 ｜ **优先级**：P2 ｜ **归属包**：`pkcs/pkcs7`（现有）｜ **API 数**：2
- **现状**：`pkcs/pkcs7` 只支持证书集合，不支持 CRL。
- **对齐 CLI**：`tongsuo crl2pkcs7 -nocrl -certfile c.pem -out o.p7b`

- [ ] `pkcs7.FromCRL(crlPEM []byte, certPEMs ...[]byte) ([]byte, error)` — 输入：CRL（可空）+ 证书 → 输出：PKCS#7（`nocrl` 语义即 crlPEM 为 nil）
- [ ] `pkcs7.ExtractCRLs(data []byte) ([][]byte, error)` — 从 PKCS#7 取出 CRL 列表

---

## 6. `ec_elgamal` — EC-ElGamal 同态运算

- **§6.A**：13 ｜ **优先级**：P2 ｜ **归属包**：❌ 不做（见 §0 备注）｜ **API 数**：10
- **现状**：无任何对应实现。
- **对齐 CLI**：`tongsuo ec_elgamal -encrypt` / `-decrypt` / `-add` / `-add_plain` / `-sub` / `-mul`
- **前置**：`internal/native` 需新增 `EC_ELGAMAL_*` 绑定；密文形态需与 CLI 的 hex 表示对齐。

- [ ] `ecelgamal.GenerateKey(curve string) (*PrivateKey, error)` — 生成密钥对（默认 `secp256k1`）
- [ ] `ecelgamal.Encrypt(pub *PublicKey, data []byte) ([]byte, error)` — 同态加密
- [ ] `ecelgamal.Decrypt(priv *PrivateKey, ct []byte) ([]byte, error)` — 解密
- [ ] `ecelgamal.AddCiphertext(pub *PublicKey, ct1, ct2 []byte) ([]byte, error)` — 密文 + 密文
- [ ] `ecelgamal.AddPlain(pub *PublicKey, ct, plain []byte) ([]byte, error)` — 密文 + 明文
- [ ] `ecelgamal.SubCiphertext(pub *PublicKey, ct1, ct2 []byte) ([]byte, error)` — 密文 − 密文
- [ ] `ecelgamal.SubPlain(pub *PublicKey, ct, plain []byte) ([]byte, error)` — 密文 − 明文
- [ ] `ecelgamal.MulPlain(pub *PublicKey, ct, scalar []byte) ([]byte, error)` — 密文 × 明文标量
- [ ] `ecelgamal.LoadPrivateKeyPEM` / `MarshalPEM` / `LoadPublicKeyPEM` / `MarshalPEM` — 密钥 PEM 往返
- [ ] `ecelgamal.EncryptHex` / `ecelgamal.DecryptHex` — 与 CLI 一致的十六进制密文形态（依赖 §6.C C5 的 hex 助手）

---

## 7. `ecparam` — EC 曲线参数文件与曲线枚举

- **§6.A**：14 ｜ **优先级**：P2 ｜ **归属包**：`ecdh`（现有）｜ **API 数**：7
- **现状**：只能按曲线名生成密钥，**无参数文件读写、无曲线枚举、无点形式控制**。
- **对齐 CLI**：`ecparam -list_curves` / `-genkey` / `-param_enc` / `-conv_form` / `-check`

- [ ] `ecdh.ListCurves() []string` — 命名曲线枚举（含 `SM2`、`secp256k1`、brainpool 族）
- [ ] `ecdh.MarshalParametersPEM(c *Curve, explicit bool) ([]byte, error)` — 输出参数文件（`explicit` 对应 `-param_enc explicit`）
- [ ] `ecdh.LoadParametersPEM(paramPEM []byte) (*Curve, error)` — 读取参数文件
- [ ] `ecdh.LoadParametersFile(path string) (*Curve, error)` — 文件入口
- [ ] `ecdh.GenerateKeyFromParameters(paramPEM []byte) (*PrivateKey, error)` — 由参数文件生成密钥
- [ ] `(*Curve).Check() error` — 参数合法性校验（等价 `-check`）
- [ ] `ecdh.PointForm` 常量 + `ecdh.MarshalPublicPEMForm(c *Curve, pub *PublicKey, form PointForm) ([]byte, error)` — 点形式控制（`compressed` / `uncompressed` / `hybrid`）

---

## 8. `errstr` — 错误码 → 文本

- **§6.A**：17 ｜ **优先级**：P2 ｜ **归属包**：`meta`（本版新增；与 §1/§9 同包）｜ **API 数**：3
- **现状**：`*core.OpError` 携带 `ERR_get_error` 码，但**无按 code 反查文本**的公开入口。
- **对齐 CLI**：`tongsuo errstr 0x12345678`

- [ ] `meta.ErrorString(code uint64) string` — 错误码 → 文本（`ERR_error_string`）
- [ ] `meta.ErrorCode(err error) (uint64, bool)` — 从任意 `error` 提取铜锁错误码（识别 `*core.OpError`）
- [ ] `meta.ParseErrorCode(s string) (uint64, error)` — 解析十六进制/十进制错误码字符串

---

## 9. `info` — 构建与运行环境信息

- **§6.A**：23 ｜ **优先级**：P2 ｜ **归属包**：`meta`（本版新增；与 §1/§8 同包）｜ **API 数**：5
- **现状**：无任何构建信息 API。
- **对齐 CLI**：`tongsuo info -c`
- **前置**：`internal/native` 需新增 `OPENSSL_info` 绑定（`MODULES_DIR` / `ENGINES_DIR` / `CPU_INFO` 等）。

- [ ] `meta.ReadBuildInfo() *BuildInfo` — 一次性获取构建与运行环境信息（**备注**：不能取名 `BuildInfo()`，会与同名类型冲突，见 [api-reference.md](api-reference.md) §1）
- [ ] `type BuildInfo struct { Platform, Compiler, BuildDate, OpenSSLDir, EnginesDir, ModulesDir, SeedingSource, CPUInfo string; Options []string }`
- [ ] `(BuildInfo) String() string` — 文本视图（等价 `tongsuo version -a` 输出）
- [ ] `meta.Providers() []ProviderInfo` — 活跃 provider 名称/版本/状态（`0.4.0`，需 `OSSL_PROVIDER_*`）
- [ ] `type ProviderInfo struct { Name, Version, Status string }`

---

## 10. `paillier` — Paillier 同态运算

- **§6.A**：29 ｜ **优先级**：P2 ｜ **归属包**：❌ 不做（见 §0 备注）｜ **API 数**：9
- **现状**：无任何对应实现。
- **对齐 CLI**：`tongsuo paillier -keygen` / `-pubgen` / `-encrypt` / `-decrypt` / `-add` / `-add_plain` / `-sub` / `-mul`
- **前置**：`internal/native` 需新增 `Paillier_*` 绑定。

- [ ] `paillier.GenerateKey(bits int) (*PrivateKey, error)` — 生成密钥对（等价 `-keygen <bits>`）
- [ ] `paillier.PublicKeyFromPrivate(priv *PrivateKey) *PublicKey` — 由私钥导出公钥（等价 `-pubgen`）
- [ ] `paillier.LoadPrivateKeyPEM` / `MarshalPEM` / `LoadPublicKeyPEM` / `MarshalPEM` — 密钥 PEM 往返
- [ ] `paillier.Encrypt(pub *PublicKey, data []byte) ([]byte, error)` — 同态加密
- [ ] `paillier.Decrypt(priv *PrivateKey, ct []byte) ([]byte, error)` — 解密
- [ ] `paillier.AddCiphertext(pub *PublicKey, ct1, ct2 []byte) ([]byte, error)` — 密文 + 密文
- [ ] `paillier.AddPlain(pub *PublicKey, ct, plain []byte) ([]byte, error)` — 密文 + 明文
- [ ] `paillier.SubCiphertext` / `SubPlain` — 密文 − 密文、密文 − 明文
- [ ] `paillier.MulPlain(pub *PublicKey, ct, scalar []byte) ([]byte, error)` — 密文 × 明文标量

---

## 11. `pkeyparam` — 密钥参数文件读写

- **§6.A**：35 ｜ **优先级**：P2 ｜ **归属包**：`asym`（现有）｜ **API 数**：5
- **现状**：无参数文件读写能力（与 §7 `ecparam` 联动）。
- **对齐 CLI**：`pkeyparam -in param.pem -text -noout` / `-check`

- [ ] `key.LoadParametersPEM(pemBytes []byte) (*Parameters, error)` — 解析参数文件
- [ ] `key.LoadParametersFile(path string) (*Parameters, error)` — 文件入口
- [ ] `(*Parameters).MarshalPEM(explicit bool) ([]byte, error)` — 导出参数文件
- [ ] `type Parameters struct { Alg Algorithm; Curve string }` + `(*Parameters).Algorithm() Algorithm` — 参数对象（`Algorithm` 复用现有常量）
- [ ] `(*Parameters).GenerateKey() (AsymmetricPrivateKey, error)` — 由参数生成密钥

---

## 12. `sess_id` — SSL 会话读写与转换

- **§6.A**：46 ｜ **优先级**：P2 ｜ **归属包**：`tls`（现有）｜ **API 数**：8
- **现状**：`SSL_SESSION_*` 未绑定，无会话对象；这也是「会话复用」缺失的连带缺口。
- **对齐 CLI**：`sess_id -in s.pem -outform DER -text`
- **前置**：`internal/native` 需新增 `SSL_SESSION_*`、`i2d_SSL_SESSION` / `d2i_SSL_SESSION` 绑定。

- [ ] `tls.ParseSession(der []byte) (*Session, error)` — 由 DER 解析会话
- [ ] `tls.LoadSessionPEM(pemBytes []byte) (*Session, error)` — PEM 入口
- [ ] `tls.LoadSessionFile(path string) (*Session, error)` — 文件入口
- [ ] `(*Session).MarshalDER() ([]byte, error)` — DER 输出（等价 `-outform DER`）
- [ ] `(*Session).MarshalPEM() ([]byte, error)` — PEM 输出
- [ ] `(*Session).Text() string` — 文本视图（等价 `-text`）
- [ ] `(*Session).ID() []byte` / `Version() string` / `CipherName() string` / `PeerCertificate() (*x509.Certificate, error)` / `Expiry() time.Time` — 会话字段读取
- [ ] `(c *Conn).Session() (*Session, error)` + `tls.DialWithSession(network, addr string, cfg *Config, sess *Session) (*Conn, error)` — 会话获取与复用拨号

---

## 13. `storeutl` — 从 URI 统一加载密钥 / 证书 / CRL

- **§6.A**：52 ｜ **优先级**：P2 ｜ **归属包**：`asym` + `x509`（现有）｜ **API 数**：6
- **现状**：各类型各自 `Load*`，**无统一加载器**、无按内容自动识别、无多对象遍历。
- **对齐 CLI**：`storeutl -certs -crls file:c.pem`、`storeutl file:k.p12`
- **URI 语法**：`file:path`、`file:path#<n>`（等价 `-r <n>`），裸路径视同 `file:`。

- [ ] `key.Load(uri string) (Key, error)` — 统一加载单个密钥；自动识别 PKCS#8 / PKCS#1 / SEC1 / SPKI / PKCS#12
- [ ] `key.LoadAll(uri string) ([]Key, error)` — 多对象（多 PEM 块、PKCS#12 bundle）
- [ ] `key.LoadFromReader(r io.Reader) (Key, error)` — 流式入口（stdin 场景）
- [ ] `key.LoadWithPassphrase(uri string, pass Passphrase) (Key, error)` — 口令来源抽象（依赖 §6.C C8）
- [ ] `x509.LoadFromURI(uri string) (certs []*Certificate, crls []*CRL, err error)` — 证书与 CRL 统一加载
- [ ] `x509.LoadFromReader(r io.Reader) ([]*Certificate, []*CRL, error)` — 流式入口

---

## 14. `ts` — 时间戳协议（RFC 3161）

- **§6.A**：53 ｜ **优先级**：P2 ｜ **归属包**：建议新增顶层包 `ts` ｜ **API 数**：8
- **现状**：无任何对应实现。
- **对齐 CLI**：`ts -query` / `-reply` / `-verify`，以及 `tsget` 式的 HTTP 请求
- **前置**：`internal/native` 需新增 `TS_*` 绑定。

- [ ] `ts.Digest(data []byte, alg string) ([]byte, error)` — 计算待签时间戳的消息摘要
- [ ] `ts.CreateRequest(alg string, digest []byte, policy string, certReq bool) ([]byte, error)` — 构造时间戳请求（等价 `-query`）
- [ ] `ts.ParseRequest(der []byte) (*Request, error)` — 解析请求
- [ ] `ts.ParseResponse(der []byte) (*Response, error)` — 解析响应（等价 `-reply`）
- [ ] `ts.Verify(resp, reqDER []byte, roots []*x509.Certificate) (*Timestamp, error)` — 校验时间戳令牌（等价 `-verify`）
- [ ] `ts.Request(ctx context.Context, url string, reqDER []byte, opts *RequestOptions) ([]byte, error)` — HTTP 传输（含重试/超时）
- [ ] `type Timestamp struct { GenTime time.Time; Serial string; Policy string; Accuracy time.Duration; Ordering bool; TSA *x509.Certificate }`
- [ ] `type Response struct { Status int; StatusText string; Timestamp *Timestamp; Raw []byte }`

---

## 附录 A — 需新增的包

> 与 [refactor-roadmap.md](refactor-roadmap.md) §2（目标 16 包）对齐后，
> 「需新增的包」只剩 **2 个外部包**；其余均已归入重构后的既有包。

| 包 | 承载 | 理由 |
|---|---|---|
| `meta`（本版新增） | `version` / `info` / `errstr` | 属运行环境与元信息，重构后的既有包均无归属；仅暴露查询函数，不涉密码学操作 |
| `ts`（顶层，`0.7.0`） | `ts` | RFC 3161 协议栈，含 ASN.1 结构与 HTTP 传输，体量与 `x509` 相当 |

**归入重构后既有包的 7 项**：`mac`（本版新增，承载 `EVP_MAC_*` 系算法）；`ca` → `x509`；
`ecparam` → `ecdh`；`pkeyparam`、`storeutl` → `asym`（`storeutl` 另有 `x509` 部分）；
`sess_id` → `tls`；`cms`、`crl2pkcs7` → `pkcs/pkcs7`。

**明确不做 2 项**：`ec_elgamal`、`paillier`（见 [refactor-roadmap.md](refactor-roadmap.md) §11）。

> 不再需要「新增 `crypto/mac`」：重构后算法原语包本就扁平在顶层，`mac` 已是 16 包之一；
> 同理「新增 `crypto/ecdh`」也无需讨论，`ecdh` 已存在。

---

## 附录 B — 本次不含的项（口径说明）

1. **24 项 ⚠️ 部分对齐**（本次口径为「仅 ❌ 缺失项」）：`asn1parse`(1)、`ciphers`(3)、`crl`(6)、`dgst`(8)、`ec`(12)、`enc`(15)、`genpkey`(20)、`genrsa`(21)、`kdf`(24)、`list`(25)、`ocsp`(28)、`pkcs12`(31)、`pkcs7`(32)、`pkcs8`(33)、`pkey`(34)、`pkeyutl`(36)、`rand`(38)、`req`(40)、`rsa`(41)、`s_client`(43)、`s_server`(44)、`skeyutl`(47)、`verify`(54)、`x509`(56)。
   > 其中 `dgst`(8) / `enc`(15) / `req`(40) 为 **P0**，`pkcs7 -sign`、`pkcs8 -topk8`、`pkeyutl -derive` 等为高频缺口；若后续要做，需另开一份同格式的 TODO。
2. **18 项 §9「明确不实现」**：`engine`、`fipsinstall`、`rsautl`、`s_time`、`speed`、`rehash`、`nseq`、`spkac`、`passwd`、`prime`、`dsaparam`、`gendsa`、`dsa`、`dhparam`、`srp`、`cmp`、`smime`、`help`。
3. **无对应子命令的扩展算法**（本次以子命令为维度，故不含）：ML-KEM（含 5 个混合组）、ML-DSA-44/65/87、SLH-DSA 12 变体（§6.D D1–D4）。
4. **横切项**（不单独设 API，随上述各项落地）：默认 stdin/stdout（§6.C C1/C2）、文件读写（C3）、统一 `Format` 维度（C4）、hex/base64/hexdump 助手（C5/C6）、口令来源抽象（C8）。
