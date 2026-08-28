# 路线图

本文档描述 `tongsuo-go` 的版本与开发阶段规划。当前所有规划功能均属于 **v0.1.0**，
内部按开发阶段拆分实施。架构说明见 [architecture.md](architecture.md)，开发规范见
[development-guide.md](development-guide.md)，测试规范见 [testing-guide.md](testing-guide.md)。

**优先级原则**：核心国密（SM3 / SM4 / SM2）优先，后续阶段再补齐 AES、X.509、TLS/NTLS。

---

## v0.1.0

### Phase 1 — 基础框架与核心国密（已完成）

**框架基础**
- [x] 三层目录结构搭建（`internal/native` / `internal/core` / `crypto/*`）
- [x] `go.mod`（module `github.com/blue-cloud-net/tongsuo-go`）
- [x] 绑定层框架：`shim.h` / `shim.c` 骨架、`binding_version.go`、`#cgo` 与 `static` 标签
- [x] `handle` 句柄基类（`owned` 所有权 + `Close()` + `SetFinalizer`）
- [x] `OpError` 错误类型（携带 `ERR_get_error()` 错误码）
- [x] 铜锁版本查询（`OpenSSL_version` / `Tongsuo_version_num`）
- [x] OpenSSL 线程锁初始化
- [x] 四份设计文档（architecture / development-guide / roadmap / testing-guide）

**SM3 哈希算法**
- [x] 绑定层：`EVM_MD` / `EVM_MD_CTX` / `EVM_Digest*` 系列
- [x] 核心层：`Digest` / `DigestCtx`
- [x] API 层：`crypto/sm3`（`hash.Hash` 实现 + `Sum`）
- [x] 测试：GB/T 32905 标准向量、边界条件、交叉验证

**SM4 对称加密（ECB / CBC）**
- [x] 绑定层：`EVM_CIPHER` / `EVM_CIPHER_CTX` 系列
- [x] 核心层：`Cipher` / `CipherCtx`
- [x] API 层：`crypto/sm4`（`cipher.Block` + 便捷函数，支持 PKCS7 填充）
- [x] 测试：GB/T 32907 标准向量、openssl CLI 对比

---

### Phase 2 — 对称加密完善与通用工具

**SM4 流密码模式**
- [x] SM4-CTR / OFB / CFB 高层 API（`EncryptCTR` / `EncryptOFB` / `EncryptCFB` 等）
- [x] 测试：流模式往返、长度不变性、非法 IV

**SM4-GCM（AEAD 认证加密）**
- [x] 绑定层：`EVP_CIPHER_CTX_ctrl`（GCM tag 获取/设置、IV 长度）、`EVP_EncryptUpdateAAD`
- [x] 核心层：`CipherCtx` 扩展 GCM 专用方法（`NewGcmCtx` 两步初始化 / `SetAad` / `GetTag` / `SetTag` / `SetIVLength`）
- [x] API 层：`crypto/sm4` 的 `EncryptGCM` / `DecryptGCM` + `NewGCM`（实现 `crypto/cipher.AEAD`）
- [x] 测试：AAD 一致/不一致、篡改检测（密文与 tag）、非法参数、往返、AEAD 接口

**随机数生成（RNG）**
- [x] 绑定层：`RAND_bytes`
- [x] API 层：`crypto/rand`（`Read` / `Bytes`）
- [x] 测试：长度正确性、随机性、多次调用独立性

**编码工具**
- [x] **决策：由 Go 标准库覆盖**。`encoding/hex` 与 `encoding/base64` 已提供完整且经广泛验证的
  编解码能力，本项目不再自研冗余包装，直接使用标准库（见
  [development-guide.md](development-guide.md) §7 代码风格——避免无意义的间接层）

---

### Phase 3 — SM2 非对称算法（已完成）

**SM2 密钥管理**
- [x] SM2 密钥对生成（`crypto/sm2.GenerateKey`，基于 `EVP_PKEY_Q_keygen`）
- [x] SM2 密钥序列化（PEM：私钥 PKCS#8、公钥 SubjectPublicKeyInfo）

**SM2 加密 / 解密**
- [x] SM2 加密 / 解密（`Encrypt` / `Decrypt`）
- [x] **格式说明**：Tongsuo 8.x（OpenSSL 3.x）SM2 加密输出为 **ASN.1 DER** 编码
  （内含 C1C3C2），与 `openssl pkeyutl` 输出一致；与 C# 参考项目的裸 C1C3C2 不同，
  如需裸格式可在后续增加转换层

**SM2 数字签名**
- [x] SM2 签名（SM2withSM3，`Sign`，ASN.1 DER）
- [x] SM2 验签（`Verify`）
- [x] SM2 自定义 userId 支持（`SignWithID` / `VerifyWithID`；默认使用铜锁默认用户标识）

**SM2 测试**
- [x] 单元测试：密钥生成、PEM 往返、加解密往返、签名验签、篡改检测、空数据、非法 PEM
- [x] openssl CLI 双向交叉验证（本库签名↔openssl 验签、本库加密↔openssl 解密 等）

---

### Phase 4 — HMAC、更多哈希与 AES（已完成）

**HMAC 消息认证码**
- [x] 绑定层：`HMAC_CTX` 系列（`HMAC_CTX_new/free/copy`、`HMAC_Init_ex/Update/Final`）
- [x] 核心层：`HmacCtx`（含非破坏性 `Sum`，基于 `HMAC_CTX_copy`）
- [x] API 层：`crypto/hmac`（`NewSM3` / `NewSHA256` 等实现 `hash.Hash`，`SumSM3` / `SumSHA256` 便捷函数）
- [x] 测试：标准库 `crypto/hmac` 交叉验证、流式/Reset、CLI 对比（`openssl dgst -hmac`）

**更多哈希算法**
- [x] `crypto/md5`、`crypto/sha1`、`crypto/sha256`、`crypto/sha512` 子包（`hash.Hash` + `Sum`）
- [x] 核心层补充 SHA-224 / SHA-384 描述符（可用于 HMAC，未建独立子包——与 Go 标准库一致）
- [x] 测试：标准向量 + Go 标准库交叉验证

**AES 高层 API**
- [x] `crypto/aes`：`NewCipher`（`cipher.Block`，128/256）、`Encrypt/Decrypt`（ECB/CBC/CTR/GCM）、`NewGCM`（`cipher.AEAD`）
- [x] 测试：NIST FIPS 197 标准向量、各模式往返、AEAD 接口、openssl CLI 对比

---

### Phase 5 — X.509 证书管理（已完成）

**证书解析**
- [x] PEM 加载/导出（`LoadCertificatePEM` / `MarshalPEM`）
- [x] 读取 Subject / Issuer / 有效期 / 序列号 / 公钥

**证书创建与签名**
- [x] 证书创建（`CreateCertificate` 一次性 + `NewCertificate` 构建器）
- [x] 自签名与 CA 签发（SM2 + SM3）
- [x] BasicConstraints 扩展（`AddBasicConstraints`，CA:TRUE/FALSE）
- [x] 验证（`Verify`，本库与 `openssl verify -CAfile` 双向互通）

**CSR（证书签名请求）**
- [x] 生成与签名（`NewCertificateRequest`）
- [x] PEM 加载/导出、公钥读取、签名验证
- [x] 说明：Tongsuo 8.5-pre1 的 `X509_REQ_verify` 对 SM2 有缺陷，已改为手动重建
  CertificationRequestInfo 并走 SM2 验签路径（结果与 `openssl req -verify` 一致）

**CRL（证书吊销列表）**
- [ ] 已移至 Phase 9 统一规划（CRL 解析 + 吊销检查）

**测试**
- [x] 自签/CA 链/CSR 单元测试 + openssl CLI 交叉验证（verify / x509 / req -verify）

---

### Phase 6 — TLS / NTLS 传输层

- [x] TLS 客户端 / 服务端封装（`tls.Dial` / `tls.NewServer` / `tls.Accept` / `tls.Conn`）
- [x] NTLS（国密 TLS）双证书支持（加密证书 + 签名证书，`Config.SignCert/EncCert`）
- [x] 测试：回环握手 / 多轮读写 / 协议版本与密码套件
- [x] 互操作测试：与官方 `openssl s_server` / `s_client`（`-ntls -enable_ntls` 双证书）互通

---

### Phase 7 — 加密层补全（P0，已完成）

**SM2 密文顺序转换（C1C2C3 ↔ C1C3C2 ↔ DER）**
- [x] `crypto/sm2` 新增 `Format(ct, from, to)`：DER / C1C2C3 / C1C3C2 三种密文格式互转
  （纯 Go 解析 ASN.1 中的 C1 点坐标、C3 哈希、C2 密文并重排，无需新绑定）
- [x] 便捷函数 `EncryptWithOrder` / `DecryptWithOrder`（默认 C1C3C2，兼容裸格式互操作）
- [x] 测试：三格式往返一致性、与铜锁 openssl pkeyutl 输出对比

**SM4 Zero 填充（ECB / CBC）**
- [x] `crypto/sm4` 新增 `EncryptECBZero` / `DecryptECBZero` / `EncryptCBCZero` / `DecryptCBCZero`
  （底层复用 `SetPadding(false)` + 手动补零）
- [x] 测试：Zero 填充往返、非法 IV

**HMAC-SHA384**
- [x] `crypto/hmac` 新增 `NewSHA384` / `SumSHA384`（复用核心层已具备的 SHA-384 描述符）
- [x] 测试：Go 标准库 `crypto/hmac` 交叉验证

---

### Phase 8 — 证书结构化解析与交换（对应需求 2.2 P0/P1 主干，已完成）

**证书结构化解析**
- [x] 绑定层：`X509_NAME_get_entry_count/get_entry`、`X509_NAME_ENTRY_get_object/data`、
  `ASN1_STRING_to_UTF8` + 更多 NID（O / OU / L / ST / C / E / serialNumber）——完整 RDN
- [x] 绑定层：`X509_get_ext_d2i`（SAN / KeyUsage / EKU / BasicConstraints / SKID / AKID）、
  `X509_get0_subject_key_id` / `X509_get0_authority_key_id`
- [x] 核心层：`Name` 扩展条目枚举（`Entries()` / `Get(field)` / 完整 `String()`）
- [x] API 层：`crypto/x509` 的 `SubjectName()` / `IssuerName()`（完整 RDN）、`SAN()` /
  `KeyUsage()` / `ExtendedKeyUsage()` / `IsCA()` / `PathLen()` / `Version()` / `CertificateType()`
- [x] 测试：解析真实证书断言各字段（完整 RDN / SAN / KeyUsage / EKU / SKID / AKID / 扩展列表）

**证书指纹（P0）**
- [x] 绑定层：`X509_digest`（EVP_sha1 / EVP_sha256 / SM3 等）
- [x] API 层：`Fingerprint(alg)` 返回十六进制指纹（sha1 / sha256 / sm3 / md5 / sha384 / sha512）
- [x] 测试：与 `openssl x509 -fingerprint -sha256` 一致

**证书 DER 交换（PEM ↔ DER）**
- [x] 绑定层：`i2d_X509` / `d2i_X509`、`i2d_X509_REQ` / `d2i_X509_REQ`
- [x] API 层：`MarshalDER()` / `LoadCertificateDER` / CSR 对应 DER 加载导出
- [x] 测试：PEM ↔ DER 往返、与 `openssl x509 -outform DER` 互通（字节一致）

**证书构建扩展补充**
- [x] 绑定层：`X509V3_EXT_conf_nid`（带 `X509V3_CTX`）扩展至 SAN / KeyUsage / EKU / SKID / AKID
- [x] API 层：`NewCertificate` 构建器支持 `AddSubjectAltName` / `AddKeyUsage` /
  `AddExtendedKeyUsage` / `AddSubjectKeyID` / `AddAuthorityKeyID`
- [x] 测试：生成的证书含扩展、`openssl x509 -text` 对比（SKID/AKID 链关系断言）

**CSR 高级**
- [x] 绑定层：`X509_REQ_add_extensions` / `X509_REQ_get_extensions`、
  `X509_REQ_set/get_challenge_password`
- [x] API 层：`NewEmptyCertificateRequest` 构建器（`SetSubject` / `SetPublicKey` /
  `SetChallengePassword` / `AddExtensions` / `Sign`），支持 SAN / 扩展 / 挑战密码 / 多字段 Subject
- [x] 测试：CSR 扩展读取、挑战密码校验、`openssl req -text` 对比

---

### Phase 9 — 证书链验证与吊销（对应需求 2.2，P1，已完成）

**证书链验证（X509_STORE）**
- [x] 绑定层：`X509_STORE_new/free/add_cert/add_crl/set_flags`、`X509_STORE_CTX_new/free/init/set0_untrusted`
- [x] 绑定层：`X509_verify_cert`、`X509_STORE_CTX_get_error/error_depth/current_cert`、
  `get0_chain`（链补全）、`X509_verify_cert_error_string`
- [x] 核心层：`Store`（封装 X509_STORE：AddCert / AddCRL / SetFlags）
- [x] API 层：`ChainVerify(cert, roots, intermediates)` 返回完整链，失败映射 `*VerifyError`
  （Code / Depth / Message）
- [x] 测试：自签链通过、伪造 CA 拒绝、过期证书拒绝（code 10）、Root→Intermediate→Leaf
  三层链补全、`openssl verify -CAfile` 互通

**CRL（证书吊销列表）**
- [x] 绑定层：`d2i_X509_CRL` / `i2d_X509_CRL`、`X509_CRL_get_issuer/version/lastUpdate/nextUpdate`、
  `X509_CRL_get_REVOKED`、`X509_REVOKED_get0_serialNumber/revocationDate/get_ext_d2i`（吊销原因）
- [x] 核心层：`CRL` 类型（Load PEM/DER / Issuer / 时间窗 / RevokedEntries 含原因 / MarshalPEM/DER）
- [x] API 层：`crypto/x509` 的 `ParseCRL` / `LoadCRLPEM` / `LoadCRLDER` / `CRL` / `RevokedEntry`
- [x] 测试：解析 openssl 生成的 CRL 断言吊销条目与原因、`openssl crl -text` 对比

**吊销检查**
- [x] 绑定层：`X509_V_FLAG_CRL_CHECK` / `X509_V_FLAG_CRL_CHECK_ALL`（`Store.SetCRLCheck(All)`）
- [x] API 层：`RevocationCheck(cert, crls)`（序列号比对 + issuer 匹配）
- [x] 测试：撤销证书拒绝（ChainVerify 报 code 23）、未撤销通过、`openssl verify -crl_check` 互通

---

### Phase 10 — 密钥体系扩展（RSA / EC，对应需求 2.3，P1，已完成）

**RSA / EC 密钥类型支持**
- [x] 绑定层：通用 keygen（shim `X_EVP_PKEY_Q_keygen_rsa(bits)` / `X_EVP_PKEY_Q_keygen_ec(curve)`）
- [x] 绑定层：`EVP_PKEY_get_base_id` / `EVP_PKEY_get_id`（密钥类型识别，Phase 8 已完成）
- [x] 绑定层：参数提取 `EVP_PKEY_get_bn_param`（RSA n/e/d/rsa-factor1/rsa-factor2；EC priv）、
  `EVP_PKEY_get_utf8_string_param`（curve/group）、`EVP_PKEY_get_octet_string_param`（EC pub 点）
- [x] 核心层：`PKey` 泛化（RSA Sign/Verify PKCS1v15/PSS、RSA Encrypt/Decrypt PKCS1v15/OAEP、
  ECDSA Sign/Verify DER、`Params`）
- [x] API 层：`crypto/rsa`（`GenerateKey` / `Load` / `Marshal`（PKCS#8 / PKCS#1 / 加密）/ `Sign` /
  `Verify` / `Encrypt` / `Decrypt` / `Params`）
- [x] API 层：`crypto/ecdsa`（`GenerateKey` / `Load` / `Marshal` / `Sign` / `Verify` / `Params`）
- [x] `CreateCertificate` 泛化 key 接口（`PublicKey` / `PrivateKey` 接口，SM2 / RSA / ECDSA 均可签发；
  签名摘要按密钥类型自动选择）
- [x] 测试：与 openssl 交叉验证（keygen / PEM / 签名验签 / 加解密）

**密钥格式转换**
- [x] 绑定层：`i2d/d2i_PrivateKey`（传统 DER，RSA 为 PKCS#1）
- [x] API 层：`MarshalPKCS1PEM` / `LoadPrivateKeyPEM`（自动识别 PKCS#8 / PKCS#1）
- [x] 测试：各格式往返、`openssl rsa -traditional` 对比

**私钥 ops**
- [x] 绑定层：shim 口令回调桥接（`pem_password_cb`，经 void* 上下文传递口令）
- [x] API 层：`MarshalEncryptedPEM` / `ChangePassword` / `LoadEncryptedPEM` / `Public()`
- [x] 测试：加密 PEM 往返、改密、提公钥、`openssl pkey -aes256` 互通

**密钥匹配**
- [x] 绑定层：`EVP_PKEY_eq`；`EVP_PKEY_public_eq` 铜锁不存在 → 用 `i2d_PUBKEY`（SPKI DER）比较
- [x] API 层：`Match`（私钥 ↔ 公钥 / 证书公钥）
- [x] 测试：匹配 / 不匹配场景

---

### Phase 11 — 容器格式（对应需求 2.4，P2，依赖 Phase 10，已完成）

**PKCS#12（PFX）**
- [x] 绑定层：补 `BIO_write`；核心层新增 `MemBIO` 封装
- [x] 绑定层：`PKCS12_create`（shim 桥接 CA 栈）/ `d2i_PKCS12` / `i2d_PKCS12` / `PKCS12_parse` /
  `PKCS12_newpass` / `PKCS12_set_mac`
- [x] API 层：`crypto/pkcs12` 的 `Pack`（证书 + 私钥 + CA 链 + 口令）/ `Parse`（Bundle）/ `ChangePassword`
- [x] 测试：打包 / 拆分 / 改密往返、`openssl pkcs12` 双向互通

**PKCS#7（P7B）**
- [x] 绑定层：`PKCS7_new` / `set_type` / `content_new` / `add_certificate` / `d2i_PKCS7` / `i2d_PKCS7`；
  证书提取经公开结构体 `p7->d.sign->cert`（铜锁无 `PKCS7_get_certificates`）
- [x] API 层：`crypto/pkcs7` 的 `Build`（证书集合）/ `Extract`（DER 或 PEM）/ `MarshalPEM`
- [x] 测试：`openssl crl2pkcs7` / `openssl pkcs7 -print_certs` 互通

---

### Phase 12 — 在线与格式工具（对应需求 2.5/2.6，P2；OCSP 依赖 Phase 9，JWK/XML 依赖 Phase 10，已完成）

**OCSP（在线证书状态协议）**
- [x] 绑定层：`OCSP_cert_to_id` / `OCSP_REQUEST_new` / `OCSP_request_add0_id` / `i2d_OCSP_REQUEST`、
  `d2i_OCSP_RESPONSE` / `OCSP_response_get1_basic` / `OCSP_resp_find_status` / `OCSP_basic_verify`
  （shim 桥接证书栈）、`OCSP_resp_get0_produced_at/certs`
- [x] API 层：`crypto/ocsp` 的 `CreateRequest` / `ParseResponse` / `Verify`（响应验证经 `OCSP_basic_verify`
  配合 Phase 9 的 `Store` 信任锚）
- [x] 测试：本地 `openssl ocsp` 离线 responder 互通（good / revoked 含原因与时间）

**ASN.1 树 / DER dump**
- [x] API 层：`crypto/asn1`（纯 Go）DER → 可读树（tag / len / value）+ hex dump
- [x] 测试：对证书 DER 断言结构、与 `openssl asn1parse` 直接子节点数一致

**JWK / XML**
- [x] API 层：`crypto/jwk`（JWK ↔ PEM，RSA n/e/d/p/q、EC crv/x/y/d，base64url）
- [x] API 层：`crypto/rsaxml`（RSA PEM ↔ XML，.NET RSAKeyValue 格式，含 DP/DQ/InverseQ）
- [x] 测试：JWK 与 `openssl pkey` / `genpkey` 互通、XML 往返

---

### 发布

- [ ] 发布 tag（v0.1.0）：打 tag 供消费方 `go get @v0.x.y` 固定版本
- [ ] CI/CD 流水线（GitHub Actions：编译、测试、lint、覆盖率、静态链接验证）
- [ ] 完整 GoDoc API 文档
- [ ] 示例程序完善（`examples/`）
- [ ] 覆盖率达标检查（核心算法包 ≥ 80%）

---

## 说明

- ✅ **Phase 6（TLS / NTLS 传输层）已完成**：`internal/core/ssl`（TLSContext / SSLConn）+
  顶层 `tls` 包（`Dial` / `Server` / `Conn` / `Config`）；回环测试协商
  TLSv1.3（TLS_AES_256_GCM_SHA384）与 NTLSv1.1（ECC-SM2-SM4-GCM-SM3）；
  已通过 `tongsuocli` 互操作测试与官方 `openssl s_server` / `s_client`
  （`-ntls -enable_ntls` 国密双证书）双向互通。
- ⚠️ Tongsuo CLI 注意：`openssl s_server/s_client` 使用 NTLS 时**必须同时加
  `-enable_ntls`**（仅 `-ntls` 会因状态机未路由到 NTLS 而报
  `state_machine:internal error`）。
- Phase 1–5 已完成（基础框架 + SM3/SM4 核心国密 + SM2 + SM4-GCM + RNG + HMAC + 哈希 + AES + X.509 证书/CSR）
- ✅ **Phase 7（加密层补全，P0）已完成**：`crypto/sm2` 新增 `Format` / `EncryptWithOrder` /
  `DecryptWithOrder`（DER ↔ C1C3C2 ↔ C1C2C3 密文互转）；`crypto/sm4` 新增 `*Zero` 填充便捷函数
  （ECB / CBC）；`crypto/hmac` 新增 `NewSHA384` / `SumSHA384`。已通过单元测试与
  铜锁 openssl CLI 交叉验证
- ✅ **Phase 8（证书结构化解析与交换，P0/P1）已完成**：完整 RDN 解析（`SubjectName()` /
  `IssuerName()` + `Entries()` / `Get()` / `String()`）、证书指纹（`Fingerprint(alg)`，
  sha1/sha256/sm3/md5/sha384/sha512）、DER 交换（`MarshalDER` / `Load*DER`，证书与 CSR）、
  构建扩展（SAN / KeyUsage / EKU / SKID / AKID）、CSR 高级（SAN / 扩展 / 挑战密码 /
  多字段 Subject，`NewEmptyCertificateRequest` 构建器）。已通过单元测试与铜锁 openssl
  CLI 交叉验证（fingerprint / DER / x509 -text / req -text）
- ✅ **Phase 9（证书链验证与吊销，P1）已完成**：`Store`（信任锚：AddCert / AddCRL /
  SetFlags）+ `ChainVerify(cert, roots, intermediates)`（返回完整链，失败映射 `*VerifyError`
  含 Code/Depth/Message）；CRL 解析（`ParseCRL` / `LoadCRLPEM` / `LoadCRLDER`，吊销条目含
  序列号/时间/原因）；`RevocationCheck(cert, crls)`（序列号 + issuer 匹配）。已通过单元测试
  与铜锁 openssl CLI 交叉验证（verify -CAfile / crl -text / verify -crl_check，撤销报 code 23）
- ✅ **Phase 10（密钥体系扩展 RSA/EC，P1）已完成**：新增 `crypto/rsa`（GenerateKey /
  Load / Marshal（PKCS#8 / PKCS#1 / 加密 PEM）/ Sign（PKCS1v15 / PSS）/ Verify /
  Encrypt/Decrypt（PKCS1v15 / OAEP）/ Params / ChangePassword / Match）与 `crypto/ecdsa`
  （GenerateKey / Load / Marshal / Sign / Verify / Params）；`CreateCertificate` / CSR 泛化
  为 `PublicKey` / `PrivateKey` 接口（SM2 / RSA / ECDSA 均可签发，摘要按密钥类型自动选择）；
  私钥加密 PEM / 改密 / 提公钥；密钥匹配（`EVP_PKEY_eq` + SPKI DER 比较）。已通过单元测试
  与铜锁 openssl CLI 交叉验证（pkey / genpkey / dgst -sha256 / pkeyutl OAEP / rsa -traditional /
  pkey -aes256）
- ✅ **Phase 11（容器格式 PKCS#12 / PKCS#7，P2）已完成**：新增 `crypto/pkcs12`
  （`Pack` / `Parse` / `ChangePassword`，支持证书 + 私钥 + CA 链 + 口令）与 `crypto/pkcs7`
  （`Build` / `Extract` / `MarshalPEM`，证书集合 DER / PEM 交换）；核心层新增 `MemBIO`、
  PKCS12 / PKCS7 类型；PKCS7 证书提取经公开结构体访问（铜锁无 `PKCS7_get_certificates`）。
  已通过单元测试与铜锁 openssl CLI 双向互通（pkcs12 -export / pkcs12 -nokeys / crl2pkcs7 /
  pkcs7 -print_certs）
- ✅ **Phase 12（在线与格式工具，P2）已完成**：`crypto/ocsp`（`CreateRequest` / `ParseResponse` /
  `Verify`，与 `openssl ocsp` 离线 responder 互通，含 good/revoked 状态与原因）；
  `crypto/asn1`（纯 Go DER 树 + hex dump，与 `openssl asn1parse` 结构一致）；
  `crypto/jwk`（JWK ↔ PEM，RSA/EC，与 `openssl pkey`/`genpkey` 互通）；
  `crypto/rsaxml`（RSA PEM ↔ XML，.NET RSAKeyValue）
- 至此 Phase 1–12 全部完成（v0.1.0 功能规划落地）；后续为发布收尾（CI/CD、示例、GoDoc、覆盖率、
  发布 tag）
- 说明：Phase 5 中延后的 CRL 解析与吊销检查已并入 Phase 9 统一规划；
  `CreateCertificate` / CSR 已泛化支持 SM2 / RSA / ECDSA（Phase 10 落地）
- 核心国密优先：Phase 1–3 是重点；Phase 4–12 顺序可根据实际需求调整
- 如需提出新功能需求，请提交 Issue
