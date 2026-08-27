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
- [ ] 规划中：CRL 解析与吊销查询（后续补充）

**测试**
- [x] 自签/CA 链/CSR 单元测试 + openssl CLI 交叉验证（verify / x509 / req -verify）

---

### Phase 6 — TLS / NTLS 传输层

- [x] TLS 客户端 / 服务端封装（`tls.Dial` / `tls.NewServer` / `tls.Accept` / `tls.Conn`）
- [x] NTLS（国密 TLS）双证书支持（加密证书 + 签名证书，`Config.SignCert/EncCert`）
- [x] 测试：回环握手 / 多轮读写 / 协议版本与密码套件
- [x] 互操作测试：与官方 `openssl s_server` / `s_client`（`-ntls -enable_ntls` 双证书）互通
- [ ] `net/http` 集成（可选，延后）
- [ ] 会话复用（session resumption，可选，延后）

---

### 发布

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
- 说明：Phase 5 中 CRL 解析延后至后续补充；证书签名当前支持 SM2（RSA/EC 证书待对应密钥类型支持）
- 核心国密优先：Phase 1–3 是重点；Phase 4–6 顺序可根据实际需求调整
- 如需提出新功能需求，请提交 Issue
