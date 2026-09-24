# 内部 API 清单（`internal/*`）

> **用途**：列出本仓库 `internal/` 下五个包的导出 API（签名 + 一句话说明），供本仓库内部开发（绑定层、核心层、测试）速查。
>
> **口径**：
> 1. 只列 `internal/` 的包；对外公开面见 `docs/api-reference.md`；
> 2. `internal/` 受 Go 机制保护，**模块外无法 `import`**；下列符号只在本仓库内可见；
> 3. 每项格式为「完整签名 — 中文一句话」；未导出（小写）符号不列；
> 4. 某些 `internal/core` 类型会**出现在公开 API 签名中**（如 `*core.PKey`），下文用 ⚠️ 标出。
>
> **范围**：**5 个包**。生成基线：`0.3.0 - TBD`。

---

## 0. 包索引与层间关系

| # | 包 | 角色 |
|---|---|---|
| 1 | `internal/core` | 核心层：句柄包装、生命周期、错误、协议编排 |
| 2 | `internal/native` | 绑定层：cgo + 内嵌 C shim，直接映射铜锁 C 函数 |
| 3 | `internal/digest` | 纯 Go 共享实现：把 `*core.Digest` 适配为 `hash.Hash` |
| 4 | `internal/keyaccess` | 公开密钥对象 → `*core.PKey` 的内部反查（结构化接口断言，无注册表） |
| 5 | `internal/testutil` | 测试共享：铜锁 CLI 包装与跳过判定 |

```
API 层（meta / digest / mac / sym / asym / ecdh / kdf / rand / keystore / x509 / tls / asn1 / jwk / pkcs/* / xml-rsa）
    ↓                                              ↑
internal/core     ← 句柄/上下文包装、生命周期、错误、协议编排
internal/keyaccess → 公开密钥对象到 *core.PKey 的反查（叶子包，只依赖 internal/core）
    ↓
internal/native   ← cgo + shim.c（X_ 前缀），1:1 映射铜锁 C 函数

internal/digest   ← 被 digest 包用于构造 hash.Hash
internal/testutil ← 仅被 *_test.go 使用
```

> **分层硬约束**：API 层任何包**不得** import `internal/native`（跨层调用，见
> `AGENTS.md` §3.3）。需要绑定层能力时，先在 `internal/core` 加包装再调用——
> `meta`（版本 / 构建信息 / errstr）与 `tls`（套件探测 / 错误分类）就是这两条路径的
> 样板；仓库当前 **API 层对 `internal/native` 的直连为 0**。

---

## 1. `internal/core` — 核心层

### 1.1 句柄与错误

- `type Handle struct { …（内部字段） }` — 所有句柄包装的基类：持有原生指针、`owned` 所有权标记与释放函数
- `func NewHandle(ptr unsafe.Pointer, owned bool, closeFunc func(unsafe.Pointer)) *Handle` — 构造句柄（`owned` 决定 Close 是否调用 `closeFunc`）
- `func (h *Handle) Ptr() unsafe.Pointer` — 返回底层原生指针
- `func (h *Handle) IsClosed() bool` — 是否已释放
- `func (h *Handle) Close() error` — 释放句柄（幂等；`owned` 为 false 时不释放）
- `type OpError struct { Op string; Code uint64; Msg string; Err error }` — 统一错误类型（携带铜锁错误码）
- `func NewOpError(op string, code uint64) *OpError` — 由操作名与错误码构造（`Msg` 取自 `ERR_error_string_n`）
- `func ErrorString(code uint64) string` — 错误码 → 文本（包装 `ERR_error_string_n`，等价 `tongsuo errstr`；与只认 `X509_V_ERR_*` 的 `VerifyErrorMessage` 不同）
- `func DrainErrors() uint64` — 弹出本线程错误队列全部错误码，返回最后一条（0 = 队列为空）
- `type SSLErrorClass int` + `SSLErrorClassOther` / `SSLErrorClassVersion` / `SSLErrorClassCipher` / `SSLErrorClassPeerVerify` / `SSLErrorClassNetwork` — TLS / 证书错误码的**无 OpenSSL 符号名**语义分类（供 `tls` 映射为 `HandshakeErrorKind`）
- `func ClassifySSLError(code uint64) SSLErrorClass` — 依据 lib / reason 判别版本 / 套件 / 验证 / 兵底四类（尽力而为的启发式）

### 1.2 摘要

- `type Digest struct { …（内部字段） }` — `EVP_MD` 描述符包装（铜锁自有常量对象）
- `func (d *Digest) Size() int` / `func (d *Digest) BlockSize() int` — 摘要长度 / 分组长度
- `func (d *Digest) OneShot(data []byte) ([]byte, error)` — 一次性计算摘要
- `func SM3() *Digest` / `MD5()` / `SHA1()` / `SHA224()` / `SHA256()` / `SHA384()` / `SHA512()` `*Digest` — 各算法描述符（⚠️ 通过公开签名泄漏，如 `rsa.EncryptOAEP`、`key.CoreKey`）
- `type DigestCtx struct { …（内部字段） }` — 流式摘要上下文
- `func NewDigestCtx(d *Digest) (*DigestCtx, error)` — 创建上下文
- `func (c *DigestCtx) Update(data []byte) error` — 追加数据
- `func (c *DigestCtx) Sum() ([]byte, error)` — 取摘要（不重置，可继续 Update）
- `func (c *DigestCtx) Final() ([]byte, error)` — 取摘要并结束
- `func (c *DigestCtx) Reset() error` — 重置
- `func (c *DigestCtx) Close() error` — 释放（幂等）

### 1.3 对称密码

- `type Cipher struct { …（内部字段） }` — `EVP_CIPHER` 描述符包装
- `func (c *Cipher) BlockSize() int` / `KeySize() int` / `IVSize() int` — 元数据
- `func SM4ECB()` / `SM4CBC()` / `SM4CTR()` / `SM4OFB()` / `SM4CFB()` / `SM4GCM()` `*Cipher` — SM4 各模式描述符
- `func AES128ECB()` / `AES128CBC()` / `AES128CTR()` / `AES128GCM()` `*Cipher`、`func AES256ECB()` / `AES256CBC()` / `AES256CTR()` / `AES256GCM()` `*Cipher` — AES 各模式描述符
- `type CipherCtx struct { …（内部字段） }` — 加解密上下文
- `func NewCipherCtx(c *Cipher, key, iv []byte, enc bool) (*CipherCtx, error)` — 创建上下文
- `func NewGcmCtx(c *Cipher, key, nonce []byte, enc bool) (*CipherCtx, error)` — 创建 GCM 模式上下文
- `func (c *CipherCtx) SetPadding(pad bool) error` — 开关填充
- `func (c *CipherCtx) Update(in []byte) ([]byte, error)` — 流式加解密
- `func (c *CipherCtx) Final() ([]byte, error)` — 收尾
- `func (c *CipherCtx) EncryptAll(in []byte) ([]byte, error)` / `DecryptAll(in []byte) ([]byte, error)` — 一次性加解密
- `func (c *CipherCtx) Clone() (*CipherCtx, error)` — 复制上下文（并发安全用的模板副本）
- `func (c *CipherCtx) SetIVLength(n int) error` — 设置 GCM IV 长度
- `func (c *CipherCtx) SetAad(aad []byte) error` — 设置 GCM AAD
- `func (c *CipherCtx) GetTag(tag []byte) error` / `SetTag(tag []byte) error` — 读写 GCM tag
- `func (c *CipherCtx) Close() error` — 释放（幂等）

### 1.4 MAC 与 KDF

- `type HmacCtx struct { …（内部字段） }` — `HMAC_CTX` 包装
- `func NewHmacCtx(d *Digest, key []byte) (*HmacCtx, error)` — 创建
- `func (c *HmacCtx) Update(data []byte) error` / `Final() ([]byte, error)` / `Sum() ([]byte, error)` / `Reset() error` / `Close() error` — 流式、取值、重置、释放
- `func HKDF(mdName string, secret, salt, info []byte, length int) ([]byte, error)` — 一次性 HKDF
- `func PBKDF2(mdName string, password, salt []byte, iter, keyLen int) ([]byte, error)` — 一次性 PBKDF2
- `func Argon2IDAvailable() bool` — 探测 Argon2ID 是否可用（本机构建不可用时返回 false）

### 1.5 非对称密钥

- `type PKey struct { …（内部字段） }` — `EVP_PKEY` 句柄包装（⚠️ 公开签名中大量出现，如 `jwk.Marshal`、`pkcs12.Bundle.PrivateKey`、各算法 `Key()`）
- `var DefaultSM2ID = []byte("1234567812345678")` — SM2 默认 userId
- `func (k *PKey) BaseID() int` / `TypeID() int` — 基础类型 ID（如 `EVP_PKEY_RSA`）/ 精确类型 ID
- `func (k *PKey) Algorithm() string` — 算法名（`"RSA"` / `"EC"` / `"SM2"` / `"ED25519"` / …）
- `func GenerateSM2Key() (*PKey, error)` — 生成 SM2 密钥
- `func GenerateRSAKey(bits int) (*PKey, error)` — 生成 RSA 密钥
- `func GenerateECKey(curve string) (*PKey, error)` — 按曲线名生成 EC 密钥
- `func GenerateED25519Key() (*PKey, error)` / `GenerateED448Key() (*PKey, error)` — 生成 EdDSA 密钥
- `func GenerateX25519Key() (*PKey, error)` / `GenerateX448Key() (*PKey, error)` — 生成 OKP 密钥
- `func LoadPrivateKeyPEM(pem []byte) (*PKey, error)` — 加载私钥 PEM（PKCS#8 / 传统）
- `func LoadPrivateKeyPEMEncrypted(pemBytes []byte, pass string) (*PKey, error)` — 加载加密私钥 PEM
- `func LoadPrivateKeyPKCS1PEM(pemBytes []byte) (*PKey, error)` — 加载 RSA 传统 PKCS#1 PEM
- `func LoadPublicKeyPEM(pem []byte) (*PKey, error)` — 加载 SPKI 公钥 PEM
- `func (k *PKey) MarshalPrivateKeyPEM() ([]byte, error)` / `MarshalPublicKeyPEM() ([]byte, error)` — 导出 PEM
- `func (k *PKey) MarshalPrivateKeyPKCS1PEM() ([]byte, error)` — 导出 PKCS#1 PEM
- `func (k *PKey) MarshalEncryptedPEM(pass string) ([]byte, error)` — 导出加密 PKCS#8 PEM
- `func (k *PKey) MarshalEncryptedPEMWithCipher(cipher, pass string) ([]byte, error)` — 指定对称算法导出加密 PEM
- `func ChangePrivateKeyPassword(pemBytes []byte, oldPass, newPass string) ([]byte, error)` — 更换口令
- `func ChangePrivateKeyPasswordWithCipher(pemBytes []byte, newCipher, oldPass, newPass string) ([]byte, error)` — 指定对称算法更换口令
- `func (k *PKey) Encrypt(data []byte) ([]byte, error)` / `Decrypt(data []byte) ([]byte, error)` — SM2 加解密
- `func (k *PKey) EncryptPKCS1v15(data []byte) ([]byte, error)` / `DecryptPKCS1v15(data []byte) ([]byte, error)` — RSA PKCS#1 v1.5
- `func (k *PKey) EncryptOAEP(data []byte, md *Digest) ([]byte, error)` / `DecryptOAEP(data []byte, md *Digest) ([]byte, error)` — RSA OAEP
- `func (k *PKey) Sign(data, id []byte) ([]byte, error)` / `Verify(data, sig, id []byte) error` — SM2 签名验签（带 userId）
- `func (k *PKey) SignMessage(msg []byte) ([]byte, error)` / `VerifyMessage(msg, sig []byte) error` — 裸消息签名验签（内部按算法选择摘要）
- `func (k *PKey) SignDigest(data []byte, md *Digest) ([]byte, error)` / `VerifyDigest(data, sig []byte, md *Digest) error` — 指定摘要签名验签
- `func (k *PKey) SignDigestPSS(data []byte, md *Digest, saltLen int) ([]byte, error)` / `VerifyDigestPSS(data, sig []byte, md *Digest, saltLen int) error` — RSA-PSS 版
- `func (k *PKey) Derive(peer *PKey) ([]byte, error)` — 通用密钥协商（`EVP_PKEY_derive`）
- `func (k *PKey) RawPrivateKey() ([]byte, error)` / `RawPublicKey() ([]byte, error)` — 导出原始密钥字节（OKP）
- `func (k *PKey) RawPrivate() ([]byte, bool)` / `RawPublic() ([]byte, bool)` — 取原始字节（不报错形式）
- `func NewRawPrivateKey(typeID int, raw []byte) (*PKey, error)` / `NewRawPublicKey(typeID int, raw []byte) (*PKey, error)` — 由原始字节构造
- `func NewOKPPrivate(typeID int, raw []byte) (*PKey, error)` / `NewOKPPublic(typeID int, raw []byte) (*PKey, error)` — 由原始字节构造 OKP 密钥
- `func (k *PKey) Equal(other *PKey) bool` / `PublicEqual(other *PKey) bool` — 私钥 / 公钥相等判定
- `func (k *PKey) Params() *KeyParams` — 提取密钥参数
- `func (k *PKey) Close() error` — 释放（幂等）
- `type KeyParams struct { Type string; N *big.Int; E *big.Int; D *big.Int; P *big.Int; Q *big.Int; Dmp1 *big.Int; Dmq1 *big.Int; Iqmp *big.Int; Curve string; X *big.Int; Y *big.Int }` — RSA（含 CRT 系数）/ EC / SM2 参数（⚠️ 通过 `crypto/{rsa,ecdsa}.Params()` 泄漏）

### 1.6 X.509

- `type Name struct { …（内部字段） }` / `type NameEntry struct { …（内部字段） }` — `X509_NAME` 与其条目
- `func NewName() (*Name, error)` — 创建空名字
- `func (n *Name) AddEntry(field, value string) error` — 追加 RDN
- `func (n *Name) Text(nid int) string` / `Get(field string) string` / `Nid(field string) int` / `Len() int` / `Entries() []NameEntry` / `String() string` — 读取
- `func (n *Name) Close() error` — 释放
- `type Certificate struct { …（内部字段） }` — `X509` 句柄包装（⚠️ 通过 `Certificate.Core()` 泄漏）
- `func NewCertificate() (*Certificate, error)` — 创建空证书
- `func LoadCertificatePEM(pem []byte) (*Certificate, error)` / `LoadCertificateDER(der []byte) (*Certificate, error)` — 加载
- `func (c *Certificate) MarshalPEM() ([]byte, error)` / `MarshalDER() ([]byte, error)` — 导出
- `func (c *Certificate) SetVersion(version int) error` / `SetSerial(serial int64) error` / `SetIssuer(n *Name) error` / `SetSubject(n *Name) error` / `SetPublicKey(k *PKey) error` / `SetValidity(notBefore, notAfter time.Time) error` — 构建
- `func (c *Certificate) AddBasicConstraints(isCA bool) error` / `AddExtension(nid int, value string) error` / `AddSubjectAltName(value string) error` / `AddKeyUsage(value string) error` / `AddExtendedKeyUsage(value string) error` / `AddSubjectKeyID() error` / `AddAuthorityKeyID(issuer *Certificate) error` — 扩展
- `func (c *Certificate) Sign(signer *PKey, md *Digest) error` / `Verify(pub *PKey) error` — 签名与验签（EdDSA 走 `X509_sign_ctx` 路径）
- `func (c *Certificate) Subject() string` / `Issuer() string` / `Serial() int64` / `Version() int` / `NotBefore() time.Time` / `NotAfter() time.Time` — 基本信息
- `func (c *Certificate) SubjectName() *Name` / `IssuerName() *Name` / `SubjectEntries() []NameEntry` / `IssuerEntries() []NameEntry` / `SubjectText() string` / `IssuerText() string` — 名字
- `func (c *Certificate) SAN() []string` / `KeyUsageBits() int` / `ExtendedKeyUsage() []string` / `IsCA() bool` / `PathLen() int64` / `SubjectKeyID() []byte` / `AuthorityKeyID() []byte` / `CertificateType() string` — 扩展读取
- `func (c *Certificate) Extensions() []Extension` — 全部扩展
- `func (c *Certificate) Fingerprint(md *Digest) (string, error)` — 指纹
- `func (c *Certificate) PublicKey() (*PKey, error)` — 提取公钥
- `func (c *Certificate) VerifyHostname(host string) error` — 主机名 / IP 校验（`X509_check_host` / `X509_check_ip_asc`，等价 `verify -verify_hostname`）
- `func (c *Certificate) Signature() []byte` / `SignatureAlgorithm() string` / `SignatureAlgorithmOID() string` — 签名信息
- `func (c *Certificate) MarshalDER() ([]byte, error)` / `Close() error` — 导出与释放
- `type Extension struct { …（内部字段） }` — 单个扩展
- `type CertificateRequest struct { …（内部字段） }` — PKCS#10 请求
- `func NewCertificateRequest() (*CertificateRequest, error)` — 创建空白请求
- `func LoadCertificateRequestPEM(pem []byte) (*CertificateRequest, error)` / `LoadCertificateRequestDER(der []byte) (*CertificateRequest, error)` — 加载
- `func (r *CertificateRequest) MarshalPEM() ([]byte, error)` / `MarshalDER() ([]byte, error)` — 导出
- `func (r *CertificateRequest) SetSubject(n *Name) error` / `SetPublicKey(k *PKey) error` / `Sign(priv *PKey, md *Digest) error` / `Verify() error` — 构建与校验
- `func (r *CertificateRequest) SubjectName() *Name` / `SubjectEntries() []NameEntry` / `SubjectText() string` — subject 读取
- `func (r *CertificateRequest) SetChallengePassword(pwd string) error` / `ChallengePassword() string` — challengePassword
- `func (r *CertificateRequest) AddExtensions(exts ...Extension) error` / `AddExtension(nid int, value string) error` / `AddSubjectAltName(value string) error` / `Extensions() []Extension` — 扩展
- `func (r *CertificateRequest) PublicKey() (*PKey, error)` — 提取公钥
- `func (r *CertificateRequest) Signature() []byte` / `SignatureAlgorithm() string` / `SignatureAlgorithmOID() string` — 签名信息
- `func (r *CertificateRequest) Close() error` — 释放
- `type RevokedEntry struct { …（内部字段） }` / `type CRL struct { …（内部字段） }` — 吊销记录与 CRL
- `func NewCRL(issuer *Name, priv *PKey, thisUpdate, nextUpdate time.Time) (*CRL, error)` — **一次签发 CRL**（= `NewCRLForIssuer` + 设时间窗/Number 1 + `Sign`）
- `func NewCRLForIssuer(issuer *Name) (*CRL, error)` — 新建空 v2 CRL 并设 issuer（供公开 `x509.CRLBuilder` 分步组装；不写时间/Number、不签名）
- `func (c *CRL) SetThisUpdate(t time.Time) error` / `SetNextUpdate(t time.Time) error` / `SetNumber(n int64) error` — 构建器元数据
- `func (c *CRL) AddRevokedEntry(serial int64, at time.Time, reason int) error` — 追加吊销条目（`reason < 0` 则不写 crlReasons；成功即把 `X509_REVOKED` 所有权转交 CRL）
- `func (c *CRL) SortRevokedEntries() error` — 按序列号排序（CRL 构建器未暴露此步）
- `func (c *CRL) Sign(priv *PKey) error` — 分步签名（SM2/RSA/ECDSA/Ed25519/Ed448）
- `func LoadCRLPEM(pem []byte) (*CRL, error)` / `LoadCRLDER(der []byte) (*CRL, error)` — 加载
- `func (c *CRL) MarshalPEM() ([]byte, error)` / `MarshalDER() ([]byte, error)` — 导出
- `func (c *CRL) AddAuthorityKeyID(issuer *Certificate) error` — 附加 AKID
- `func (c *CRL) Issuer() *Name` / `Version() int` / `LastUpdate() time.Time` / `NextUpdate() time.Time` / `RevokedEntries() []RevokedEntry` / `Number() int64` / `Extensions() []Extension` — 读取
- `func (c *CRL) Signature() []byte` / `SignatureAlgorithm() string` / `SignatureAlgorithmOID() string` / `AuthorityKeyID() []byte` — 签名信息
- `func (c *CRL) Verify(pub *PKey) error` / `Close() error` — 验签与释放
- `func RevocationCheck(cert *Certificate, crls []*CRL) error` — 吊销检查
- `type VerifyError struct { …（内部字段） }` — `X509_verify_cert` 失败信息（⚠️ 通过 `x509` 包同名类型转出）
- `func VerifyErrorMessage(code int) string` — 错误码 → 文本
- `type Store struct { …（内部字段） }` — `X509_STORE` 包装（⚠️ 通过 `x509.Store` 持有；公开层无 `Close`，见 `docs/issues/2026-09-24/P1010`）
- `func NewStore() (*Store, error)` — 创建
- `func (s *Store) AddCert(c *Certificate) error` / `AddCRL(c *CRL) error` / `SetFlags(flags uint64) error` / `SetTime(t time.Time) error` / `Close() error` — 操作与释放（`SetTime` 写 `X509_VERIFY_PARAM_set_time`，对该 Store 后续每次 `ChainVerify` 生效）
- `func ChainVerify(cert *Certificate, store *Store, intermediates []*Certificate) ([]*Certificate, error)` — 链验证并返回完整链

### 1.7 容器（PKCS#7 / PKCS#12）

- `type MemBIO struct { …（内部字段） }` — 内存 BIO 包装（`BIO_s_mem`）
- `func NewMemBIO() (*MemBIO, error)` — 创建
- `func (m *MemBIO) Write(data []byte) error` / `Bytes() ([]byte, error)` / `Close()` — 写入、取内容、释放
- `type PKCS12 struct { …（内部字段） }` — `PKCS12` 包装
- `func CreatePKCS12(pass, name string, key *PKey, cert *Certificate, ca []*Certificate) (*PKCS12, error)` — 打包
- `func LoadPKCS12DER(der []byte) (*PKCS12, error)` — 加载
- `func (p *PKCS12) Parse(pass string) (*PKey, *Certificate, []*Certificate, error)` — 用口令解析出私钥、证书与 CA 链
- `func (p *PKCS12) MarshalDER() ([]byte, error)` — 导出 DER
- `func (p *PKCS12) ChangePassword(oldPass, newPass string) error` — 改密
- `func (p *PKCS12) SetMAC(pass string) error` — 重算 MAC
- `func (p *PKCS12) Close() error` — 释放
- `type PKCS7 struct { … (内部字段) }` — `PKCS7` 包装（**当前仅实现 certificates-only**）
- `func NewPKCS7SignedData() (*PKCS7, error)` — 创建 `signedData` 类型容器
- `func LoadPKCS7DER(der []byte) (*PKCS7, error)` — 加载
- `func (p *PKCS7) AddCertificate(c *Certificate) error` / `Certificates() ([]*Certificate, error)` — 加证书 / 取证书
- `func (p *PKCS7) MarshalDER() ([]byte, error)` / `Close() error` — 导出与释放

### 1.8 OCSP

- `type OCSPRequest struct { …（内部字段） }` — OCSP 请求
- `func CreateOCSPRequest(cert, issuer *Certificate, hash string) (*OCSPRequest, error)` — 构造请求
- `func (r *OCSPRequest) MarshalDER() ([]byte, error)` / `Close() error` — 导出与释放
- `type OCSPResponse struct { …（内部字段） }` — OCSP 响应
- `func LoadOCSPResponseDER(der []byte) (*OCSPResponse, error)` — 加载响应
- `func (r *OCSPResponse) Status() int` / `StatusText() string` / `ProducedAt() time.Time` / `ResponderCerts() ([]*Certificate, error)` — 响应级信息
- `func (r *OCSPResponse) Check(cert, issuer *Certificate) (*CertStatus, error)` — 查找目标证书状态（自适应 CertID 摘要）
- `func (r *OCSPResponse) Verify(roots *Store, certs []*Certificate) error` — 校验响应签名
- `func (r *OCSPResponse) Close() error` — 释放
- `type CertStatus struct { …（内部字段） }` — 单证书状态

### 1.9 TLS / NTLS

- `type TLSContext struct { …（内部字段） }` — `SSL_CTX` 包装
- `func NewClientTLSContext() (*TLSContext, error)` / `NewServerTLSContext() (*TLSContext, error)` / `NewNTLSContext() (*TLSContext, error)` — 创建客户端 / 服务端 / NTLS 上下文
- `func (c *TLSContext) UseCertificate(cert *Certificate, key *PKey) error` — 装入证书与私钥
- `func (c *TLSContext) UseSignCertificate(cert *Certificate, key *PKey) error` / `UseEncryptCertificate(cert *Certificate, key *PKey) error` — NTLS 签名 / 加密证书
- `func (c *TLSContext) SetCipherList(list string) error` / `SetCipherSuites(list string) error` — 经典 / TLS 1.3 套件列表
- `func (c *TLSContext) CipherList() []CipherInfo` — 读取 ctx 支持的套件
- `func (c *TLSContext) SetMinProtoVersion(v uint16) error` / `SetMaxProtoVersion(v uint16) error` — 协议版本范围
- `func (c *TLSContext) SetVerifyMode(mode int) error` / `SetVerifyDepth(depth int) error` — 验证模式与深度
- `func (c *TLSContext) AddVerifyRoots(certs []*Certificate) error` — 注入受信根
- `func (c *TLSContext) SetDefaultVerifyPaths() error` — 使用系统默认信任路径
- `func (c *TLSContext) IsNTLS() bool` — 是否 NTLS 上下文
- `func (c *TLSContext) Close() error` — 释放（幂等）
- `type SSLConn struct { …（内部字段） }` — `SSL` 包装
- `func NewSSLConn(ctx *TLSContext, fd int) (*SSLConn, error)` — 由 ctx 与 fd 创建
- `func (s *SSLConn) Connect() error` / `Accept() error` — 客户端 / 服务端握手
- `func (s *SSLConn) Read(buf []byte) (int, error)` / `Write(buf []byte) (int, error)` — 读写
- `func (s *SSLConn) SetDeadline(t time.Time) error` — 设置截止时间
- `func (s *SSLConn) SetHostname(host string) error` — 设置校验主机名（`SSL_set1_host`）
- `func (s *SSLConn) SetServerName(host string) error` — 设置 SNI
- `func (s *SSLConn) Version() string` / `CipherName() string` — 协商结果
- `func (s *SSLConn) VerifyResult() int` — 对端验证结果码（关闭后返回 `VerifyResultClosed`）
- `func (s *SSLConn) PeerCertificate() (*Certificate, error)` / `PeerCertificates() ([]*Certificate, error)` — 对端证书与链
- `func (s *SSLConn) Close() error` — 释放（幂等）
- `type CipherInfo struct { …（内部字段） }` — 套件元数据
- `const NTLSVersion uint16` — NTLS（TLCP）协议版本常量（与 `native.NTLSVersion` 同值；公开层 `tls.NTLSVersion` 来自此处）
- `func ProbeCipherSuites(version uint16) []CipherInfo` — 枚举**指定协议版本**下可用的全部套件（自建临时 ctx、min=max=version；NTLS 走 `NTLS_method`）；供 `tls.CipherSuites` 使用
- `func CipherVersionToUint16(version uint16) uint16` — 校验并回传协议版本常量（未知返回 0）
- `func VersionNameToUint16(name string) uint16` — 版本名（如 `"TLSv1.2"`）→ 版本常量
- `const VerifyResultClosed = -2` — `VerifyResult` 在连接已关闭时的返回值

### 1.10 随机数与工具

- `func RandomBytes(b []byte) error` — 填充随机字节（`RAND_bytes`）
- `func ZeroBytes(b []byte)` — 清零内存（`OPENSSL_cleanse`）

### 1.11 版本

- `func VersionText() string` — 铜锁版本字符串（如 `"Tongsuo 8.5.0-pre2 …"`）
- `func VersionString() string` — 纯版本号（`OpenSSL_version(OPENSSL_VERSION_STRING)`，如 `"3.5.4"`）
- `func VersionNum() uint64` — OpenSSL 兼容版本号
- `func TongsuoVersionNum() uint64` — 铜锁自有版本号
- `type BuildEnv struct { …（公开字段） }` — 编译期 / 运行期环境快照（banner / 版本号 / CFLAGS / BUILT_ON / PLATFORM / 库·引擎·模块目录 / CPU_INFO）
- `func ReadBuildEnv() BuildEnv` — 一次性读取上述快照（不返回 error，缺项退化为空串）

---

## 2. `internal/native` — 绑定层

### 2.1 约定

- **函数名与铜锁 C 函数名一致**（如 `EVP_DigestInit_ex`）；需要 shim 才能暴露的（宏、可变参、回调、`SIZE_MAX` 等）加 **`X_` 前缀**，实现位于 `shim.c` / `shim.h`。
- **族缩写写法**：2.2–2.14 中形如 `` `X509_NAME_new` `free` `` 的写法表示同一前缀下的 `X509_NAME_new` 与 `X509_NAME_free`（省略了与上一个名字相同的公共前缀）；同理 `` `SSL_CIPHER_sk_{num,value}` `` 表示 `SSL_CIPHER_sk_num` 与 `SSL_CIPHER_sk_value`。
- **签名风格**：
  - 入参/出参的原生指针统一为 `unsafe.Pointer`；`[]byte` 表示「Go 切片直通」；
  - 布尔返回 `bool`（C 的 `int`/`1` 语义）；
  - 「取值 + 是否成功」用 `(T, bool)`；
  - C 的 `int` 返回值直接返回 `int`（如 `SSL_get_error`）。
- `func init()` — 注册铜锁线程锁回调，进程内自动执行。

### 2.2 `binding_digest.go` — 摘要与签名

`EVP_sm3` `EVP_md5` `EVP_sha1` `EVP_sha224` `EVP_sha256` `EVP_sha384` `EVP_sha512`、`EVP_MD_get_size` `EVP_MD_get_block_size`、`EVP_MD_CTX_new` `EVP_MD_CTX_free` `EVP_MD_CTX_copy_ex`、`EVP_DigestInit_ex` `EVP_DigestUpdate` `EVP_DigestFinal_ex`、`EVP_DigestSign` `EVP_DigestVerify`、`X_EVP_Digest`

### 2.3 `binding_cipher.go` — 对称密码

`EVP_sm4_{ecb,cbc,ctr,ofb,cfb128,gcm}`、`EVP_aes_{128,256}_{ecb,cbc,ctr,gcm}`、`EVP_CIPHER_get_{block_size,key_length,iv_length}`、`EVP_CIPHER_CTX_new` `free` `copy` `ctrl` `set_padding`、`EVP_CipherInit_ex`、`EVP_EncryptUpdate` `EVP_DecryptUpdate` `EVP_EncryptFinal_ex` `EVP_DecryptFinal_ex`、`EVP_UpdateAAD`

### 2.4 `binding_pkey.go` — 非对称密钥

`X_EVP_PKEY_Q_keygen_{sm2,rsa,ec,ed25519,ed448,x25519,x448}`、`EVP_PKEY_free` `dup` `eq` `size`、`EVP_PKEY_get_{base_id,id,bn_param,utf8_string_param,octet_string_param}`、`EVP_PKEY_CTX_new_from_pkey` `free` `set1_id` `set_rsa_padding` `set_rsa_pss_saltlen` `set_rsa_mgf1_md` `set_rsa_oaep_md`、`EVP_PKEY_encrypt_init` `encrypt` `decrypt_init` `decrypt`、`EVP_PKEY_derive_init` `derive_set_peer` `derive`、`EVP_DigestSignInit` `DigestSignUpdate` `DigestSignFinal`、`EVP_DigestVerifyInit` `DigestVerifyUpdate` `DigestVerifyFinal`、`EVP_PKEY_new_raw_{private,public}_key` `EVP_PKEY_get_raw_{private,public}_key`、`I2d_PUBKEY` `I2d_PrivateKey` `D2i_PrivateKey`、`RSA_free`、`X_PEM_read_bio_PrivateKey` `_pass`、`X_PEM_write_bio_PrivateKey` `_enc` `_enc_cipher`、`X_PEM_read_bio_PUBKEY` `X_PEM_write_bio_PUBKEY`、`X_PEM_read_bio_RSAPrivateKey` `X_PEM_write_bio_RSAPrivateKey`

### 2.5 `binding_hmac.go` — HMAC

`HMAC_CTX_new` `HMAC_CTX_free` `HMAC_CTX_copy`、`HMAC_Init_ex` `HMAC_Update` `HMAC_Final`

### 2.6 `binding_kdf.go` — KDF

`EVP_KDF_HKDF`、`EVP_KDF_PBKDF2`、`EVP_KDF_Available`

### 2.7 `binding_rand.go` — 随机数

`RAND_bytes`

### 2.8 `binding_bio.go` — BIO

`BIO_s_mem` `BIO_new` `BIO_new_mem_buf` `BIO_free` `BIO_read` `BIO_write`

### 2.9 `binding_error.go` — 错误与清零

`PopError`（`ERR_get_error` 家族）、`ErrorString`（`ERR_error_string_n`）、`Cleanse`（`OPENSSL_cleanse`）、`ErrGetLib`、`ErrGetReason`

### 2.10 `binding_version.go` — 版本

`OpenSSLVersionText`、`OpenSSLVersionNum`、`TongsuoVersionNum`

### 2.11 `binding_x509.go` — 证书 / CSR / CRL / Store（最大绑定面）

- **对象与名字**：`OBJ_nid2sn` `OBJ_obj2nid` `OBJ_txt2nid` `OBJ_obj2txt` `OBJ_to_string`；`X509_NAME_new` `free` `add_entry_by_txt` `get_entry_count` `get_entry` `get_text_by_txt` `get_text_by_NID` `oneline` `cmp`；`X509_NAME_ENTRY_nid` `_value`
- **证书主体**：`X509_new` `free` `dup`、`X509_set_version` `set_serial_int` `get_serial_int`、`X509_set_issuer_name` `set_subject_name` `get_issuer_name` `get_subject_name`、`X509_set_pubkey` `get_pubkey`、`X509_set_not_before` `set_not_after` `get_not_before` `get_not_after`、`X509_get_version`
- **签名与编码**：`X509_sign` `X509_verify` `X509_sign_ctx`、`X509_digest`、`I2d_X509` `D2i_X509`、`X_PEM_read_bio_X509` `X_PEM_write_bio_X509`、`X509_get_signature_info`
- **扩展**：`X509V3_EXT_conf_nid` `_ctx` `_crl` `_ctx_crl`、`X509_add_ext`、`X509_EXTENSION_free/get_object/get_critical/get_data`、`X509_get_ext_count` `X509_get_ext`、`X509_sk_X509_EXTENSION_*`、`ASN1_STRING_data_bytes`、`ASN1_INTEGER_free` `ASN1_INTEGER_get`
- **扩展语义读取**：`X509_get_san` `X509_get_key_usage` `X509_get_eku` `X509_get_basic_constraints`、`X509_get0_subject_key_id` `X509_get0_authority_key_id`、`X509_GENERAL_NAMES_{free,num,value}` `X509_GENERAL_NAME_{type,to_string}`、`X509_EXTENDED_KEY_USAGE_{free,num,value}`、`X509_BASIC_CONSTRAINTS_{free,ca,pathlen}`、`X509_ASN1_BIT_STRING_free` `ASN1_BIT_STRING_get_bit`
- **CSR**：`X509_REQ_new` `free` `set_pubkey` `get_pubkey` `set_subject_name` `get_subject_name` `sign` `sign_ctx` `verify`、`X509_REQ_add_extensions` `get_extensions`、`X509_REQ_set/get_challenge_password`、`I2d_X509_REQ` `D2i_X509_REQ` `I2d_X509_REQ_INFO`、`X509_REQ_get0_signature` `_get_signature_info`、`X_PEM_read_bio_X509_REQ` `X_PEM_write_bio_X509_REQ`
- **Store 与链验证**：`X509_STORE_new` `free` `add_cert` `add_crl` `set_flags` `get0_param`、`X509_VERIFY_PARAM_set_time`、`X509_STORE_CTX_new` `free` `init` `set0_untrusted` `get_error` `get_error_depth` `get_current_cert` `get0_chain`、`X509_verify_cert` `X509_verify_cert_error_string`、`X509_sk_X509_*`
- **主机名校验**：`X509_check_host` `X509_check_ip_asc`
- **CRL**：`X509_CRL_new` `free` `verify` `sign` `sign_ctx` `sort` `add0_revoked`、`X509_CRL_set_version` `set_issuer_name` `set1_lastUpdate` `set1_nextUpdate` `set_crl_number`、`X509_CRL_get_version` `get0_lastUpdate` `get0_nextUpdate` `get_issuer` `get_REVOKED` `get_ext_count` `get_ext` `get0_authority_key_id` `get_crl_number` `get_signature_info`、`X509_sk_X509_REVOKED_{num,value}`、`X509_REVOKED_new` `free` `set_serial_int` `set_revocation_date` `set_reason`、`X509_REVOKED_get0_serialNumber` `_get0_revocationDate` `_crl_reason`、`I2d_X509_CRL` `D2i_X509_CRL`、`X_PEM_read_bio_X509_CRL` `X_PEM_write_bio_X509_CRL`

> ⚠️ **所有权实测（铜锁 8.5）**：`X509_REVOKED_set_serialNumber` /
> `X509_REVOKED_set_revocationDate` 会**复制**入参（而非接管指针），因此
> `X509_REVOKED_set_serial_int` / `set_revocation_date` 自行创建并释放临时
> `ASN1_INTEGER` / `ASN1_TIME`（与 `X509_set_serial_int` 同形）；而
> `X509_CRL_add0_revoked` 是**接管** `X509_REVOKED` 指针（add0 语义），成功即
> 不得再 `X509_REVOKED_free`。

### 2.12 `binding_pkcs.go` — PKCS#12 / PKCS#7

`X_PKCS12_create`、`X_PKCS12_parse`、`PKCS12_free`、`I2d_PKCS12` `D2i_PKCS12`、`PKCS12_newpass` `PKCS12_set_mac`；`PKCS7_new` `free` `set_type` `content_new` `add_certificate` `get0_certificates`、`I2d_PKCS7` `D2i_PKCS7`

### 2.13 `binding_ocsp.go` — OCSP

`OCSP_cert_to_id`、`OCSP_CERTID_free`、`OCSP_REQUEST_new` `free`、`OCSP_request_add0_id`、`I2d_OCSP_REQUEST`、`D2i_OCSP_RESPONSE`、`OCSP_RESPONSE_free`、`OCSP_response_status` `_status_str` `_get1_basic`、`OCSP_BASICRESP_free`、`OCSP_resp_get0_produced_at` `_get0_certs` `_find_status`、`OCSP_basic_verify`、`OCSP_cert_status_str`、`OCSP_crl_reason_str`

### 2.14 `binding_ssl.go` — TLS / NTLS

`TLS_client_method` `TLS_server_method` `NTLS_method`、`SSL_CTX_new` `free` `enable_ntls` `get_cert_store`、`SSL_CTX_use_certificate` `use_PrivateKey` `use_sign_certificate` `use_enc_certificate` `use_sign_PrivateKey` `use_enc_PrivateKey`、`SSL_CTX_check_private_key`、`SSL_CTX_set_cipher_list` `set_ciphersuites` `set_min_proto_version` `set_max_proto_version` `set_verify` `set_verify_depth` `set_default_verify_paths` `get_ciphers`、`SSL_new` `free` `set_fd` `connect` `accept` `shutdown` `read` `write` `get_error`、`SSL_get_version` `get_current_cipher_name` `get_verify_result` `get_peer_certificate` `get_peer_cert_chain`、`SSL_set1_host` `SSL_set_tlsext_host_name`、`SSL_CIPHER_get_{name,id,protocol_id,version}` `SSL_CIPHER_sk_{num,value}`

### 2.15 未绑定 / 未暴露家族

`SSL_SESSION_*`、`SSL_CTX_set_alpn*`、`SSL_CTX_set_tlsext_ticket_key_cb`、`SSL_CTX_set_tlsext_status*`（OCSP stapling）、`SSL_CTX_set_client_CA_list`、`CMS_*`、`OSSL_STORE_*`、`TS_*`、`EVP_MAC_*`、`EVP_PKEY_encapsulate/decapsulate`、`EVP_*_xts/ccm/ocb/wrap`、除 HKDF/PBKDF2 外的 `EVP_KDF` 算法、`EVP_aes_192_*`、`EVP_aes_*_ofb/cfb`、`EVP_chacha20*`、`EVP_sm4_ccm/xts`、`ZUC`、SM9、Paillier / EC-ElGamal、ML-KEM / ML-DSA / SLH-DSA、白盒 SM4。

---

## 3. `internal/digest` — 纯 Go `hash.Hash` 共享实现

被 `crypto/{md5,sha1,sha256,sha512,sm3}` 用于把 `*core.Digest` 适配为标准库接口。

- `func NewHash(d *core.Digest, size, block int) hash.Hash` — 由核心摘要描述符构造 `hash.Hash`
- `type Hash struct { …（内部字段） }` — `hash.Hash` 实现
- `func (h *Hash) Write(p []byte) (n int, err error)` — 追加数据
- `func (h *Hash) Sum(in []byte) []byte` — 按 `hash.Hash` 语义取摘要（不改变内部状态）
- `func (h *Hash) Reset()` — 重置
- `func (h *Hash) Size() int` / `func (h *Hash) BlockSize() int` — 摘要长度 / 分组长度

---

## 4. `internal/testutil` — 测试共享工具

**不含断言逻辑**，仅提供铜锁 CLI 的定位与执行；CLI 对拍测试（`//go:build tongsuocli`）统一用它。

- `func OpenSSLBin() string` — 返回铜锁命令行路径（`TONGSUO_OPENSSL_BIN`，默认 `/opt/tongsuo/bin/openssl`）
- `func RunOpenSSL(args []string, stdin []byte) ([]byte, error)` — 执行铜锁 CLI 并捕获 stdout
- `func OpenSSLAvailable() bool` — 铜锁 CLI 是否可用
- `func SkipIfNoOpenSSL(t *testing.T) string` — CLI 不可用时跳过用例，否则返回其路径

---

## 5. `internal/keyaccess` — 公开密钥对象 → 原生句柄的内部反查

把 `asym` 的**非导出**密钥类型所隐含的 `CorePKey() *core.PKey` 契约，暴露为本模块内部可用的类型断言入口。外部模块因 `internal/` 路径规则无法 `import`。

**关键性质：无注册表** —— 本包只声明接口形状，靠 Go 的**结构化接口满足**在运行时识别 `asym` 的非导出类型，因此没有 `init()` 顺序依赖、没有全局可变状态、没有并发写入。`asym` **不需要** `import` 本包。

**类型与函数**

- `type corePKeyer interface { CorePKey() *core.PKey }`（非导出）— 形状契约；由 `asym` 的非导出密钥类型隐式满足
- `func PKey(v any) (*core.PKey, bool)` — 反查 `v` 背后的原生句柄；`v` 为 nil / 非本库密钥类型 / 未实现契约时返回 `(nil, false)`

**消费方**：`ecdh`、`x509`、`tls`、`jwk`、`pkcs/pkcs12`

**契约要求（`asym` 侧）**

1. 密钥的**具体类型必须非导出**（`*privateKey` / `*publicKey` …），对外只返回 `PrivateKey` / `PublicKey` 接口；
2. 具体类型上实现导出方法 `CorePKey() *core.PKey`；
3. 该方法**不得**出现在任何导出接口中（`asym.Key` / `PrivateKey` / `PublicKey` 均不含它）—— 否则即成为公开 API；
4. `sym` 的对称密钥不实现该契约（无原生句柄）；`PKey` 对其返回 `(nil, false)` 是预期行为。

**验收**

- `go doc -all ./asym` 输出中**不得**出现 `CorePKey`
- `grep -rn "keyaccess" --include=*.go` 只应命中 `internal/keyaccess/` 与上述 5 个消费方
