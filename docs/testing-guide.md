# 测试规范

本文档规定 `tongsuo-go` 的测试组织、命名以及各类算法**必须覆盖**的用例。
整体开发规范见 [development-guide.md](development-guide.md)，架构说明见
[architecture.md](architecture.md)，重构后的包清单见 [api-reference.md](api-reference.md)，
后续版本规划见 [roadmap.md](roadmap.md)。

> 包名约定：本文档统一使用**重构后的 16 包名**（`digest` / `mac` / `kdf` / `rand` /
> `sym` / `asym` / `ecdh` / `keystore` / `x509` / `tls` / `meta` / `asn1` /
> `jwk` / `pkcs/pkcs7` / `pkcs/pkcs12` / `xml/rsa`）。`crypto/` 与 `key/` 已取消。

---

## 1. 测试文件命名与组织

- **测试与源码同包**：测试文件位于被测包目录内，命名 `{file}_test.go`
  （如 `digest/digest_test.go`），测试目录**镜像源码目录**（Go 惯例）
- 每个算法模块提供**两类测试**：

| 测试类型 | 说明 | 运行方式 |
|---------|------|---------|
| 单元测试 | 标准向量、往返、边界、错误路径、交叉验证 | 默认 `go test` 运行 |
| CLI 对比测试 | 调用铜锁 openssl 命令行逐字节比对 | `//go:build tongsuocli` 标签隔离，默认**不**运行 |

- CLI 对比测试在文件头用 `//go:build tongsuocli` 标注（等价 C# 的
  `[Category("TongsuoCli")]`）
- 共享工具放 `internal/testutil`（openssl CLI 封装；**不含断言逻辑**）；
  缺铜锁时统一用 `SkipIfNoOpenSSL` 跳过，**禁止**各测试文件自行复制
  `runOpenSSL`
- 标准向量与证书数据放 `testdata/`

---

## 2. 测试运行方式

```bash
# 默认：仅单元测试
TONGSUO_HOME=/opt/tongsuo LD_LIBRARY_PATH=${TONGSUO_HOME}/lib \
CGO_CFLAGS="-I${TONGSUO_HOME}/include" CGO_LDFLAGS="-L${TONGSUO_HOME}/lib" \
go test ./...

# 包含 CLI 对比测试
go test -tags tongsuocli ./...

# 覆盖率
go test -cover ./...

# 基准
go test -bench .

# 模糊测试
go test -fuzz FuzzRoundTrip ./sym
```

- CLI 测试依赖铜锁 openssl 命令行，路径通过环境变量 `TONGSUO_OPENSSL_BIN` 指定
  （默认 `/opt/tongsuo/bin/openssl`）或由 `TONGSUO_HOME` 推导
- 覆盖目标：核心算法包（`digest` / `mac` / `sym` / `asym` / `ecdh` / `kdf` / `x509`）
  行覆盖 **≥ 80%**（参考值，**不**由 CI 强制；本地可通过
  `./scripts/check-coverage.sh` 手动检查）

---

## 3. 摘要与 MAC 测试（`digest` / `mac`）

### 3.1 `digest`

合并后的 `digest` 同时服务 SM3 / MD5 / SHA1 / SHA224 / SHA256 / SHA384 / SHA512，
下列用例需**逐算法**覆盖：

| 测试用例 | 描述 |
|---------|------|
| 输出位宽 | `SM3Size` / `SHA256Size` 等常量等于算法定义长度 |
| 空字节数组 | 与国标 / RFC 附录的空输入向量比对 |
| 标准向量 × N | 每个 GB/T 附录向量独立一个用例，命名含来源（如 `GBT32905_Vector_Abc`） |
| 幂等性 | 两次计算相同输入结果一致 |
| 唯一性 | 不同输入结果不同 |
| 一次性 vs 流式 | `SumSM3(data)` 与 `hash.Hash`（多次 `Write` + `Sum`）结果一致 |
| 按名 vs 定长 | `Sum("SM3", data)` 与 `SumSM3(data)` 结果一致；未知算法名返回 `ErrUnknownAlgorithm` |
| Reset 重置 | `Reset()` 后重新计算与首次一致 |
| nil / 空输入 | 行为明确（不崩溃，返回预期错误或向量值） |
| 交叉验证 | 与 Go 标准库同算法（如 `crypto/sha256`）对随机数据逐字节比对 |

**CLI 对比测试**：调用 `openssl dgst -sm3` / `-sha224` / `-sha384` 等对随机数据与
标准向量分别与库实现比对。

### 3.2 `mac`

| 测试用例 | 描述 |
|---------|------|
| 标准向量 | RFC 2104 附录 / RFC 2202 测试向量的 HMAC-MD5 / SHA1 行；SM3 用 GB/T 32905 拼合向量 |
| 一次性 vs 流式 | `SumHMACSM3(k, d)` 与 `NewHMACSM3(k)` + `Write` + `Sum` 一致 |
| 密钥长度边界 | 空密钥、超分组长度密钥（> 64 / 128 字节）不崩溃且与 CLI 一致 |
| 按名分发 | `Sum("HMAC-SM3", k, d)` 与定长入口一致；非 `HMAC-*` 名返回 `ErrUnknownAlgorithm` |
| 篡改检测 | 修改消息或密钥任一字节，摘要不同 |

**CLI 对比测试**：`openssl mac -macopt hexkey:… HMAC-SM3` 逐字节比对；`0.5.0` 起本库也走 provider `EVP_MAC_*` 路径，因此**所有算法都要求逐字节一致**（
不再只是长度断言）。

**`0.5.0` 新增的 MAC 家族（`mac/families_test.go` / `mac/families_tongsuocli_test.go`）**

| 测试用例 | 描述 |
|---------|------|
| CMAC 标准向量 | NIST SP 800-38B 的 AES-128/192/256 与 GB/T 32907 的 SM4 向量；`cipherName` 不写模式时内部补 `-CBC` |
| GMAC 标准向量 | NIST GCM 附件 B 的 tag 向量；IV / AAD 一致性 |
| KMAC-128/256 | SP 800-185 向量；输出长度参与域分隔（取错长度会得到不同结果） |
| SipHash / Poly1305 / EIA3 | 各自标准向量；SipHash 断言长度（16 字节）与 CLI 逐字节一致 |
| 按名 vs 类型化 | `Sum("CMAC", k, d, &Options{Cipher: "AES-128"})` 与 `CMAC("AES-128", k, d)` 一致 |
| 必需参数缺失 | CMAC 缺 `Cipher`、GMAC 缺 `IV` 等返回 `ErrInvalidOptions` |

---

## 4. 对称加密测试（`sym`）

合并后的 `sym` 同时服务 AES（128 / 256）与 SM4，每种模式
（ECB / CBC / CTR / OFB / CFB / GCM）须有独立的**加密 + 解密 + 往返**用例：

| 测试用例 | 描述 |
|---------|------|
| 标准向量加密 | 使用 GB/T 32907 附录的密钥 + 明文，断言密文与预期一致（NoPadding） |
| 标准向量解密 | 上述密文解密后还原为原始明文 |
| 往返（随机密钥） | `Encrypt → Decrypt` 还原原始明文，各模式独立 |
| 填充模式 PKCS7 | 非块对齐数据加密后长度正确，解密后还原 |
| 错误密钥解密 | 使用不同密钥解密，结果不等于原始明文 |
| 空数据 | NoPadding 下空输入不崩溃（或返回预期错误） |
| 非法密钥 / IV 长度 | 返回明确错误（如 AES 15 字节密钥、SM4 非 16 字节密钥） |
| 多块数据 | 至少 3 个完整块的数据正确加解密 |
| 按名 vs 定长 | `EncryptSM4CBC(k, iv, d)` 与 `Encrypt("SM4-CBC", k, iv, d, nil)` 结果一致；未知名返回 `ErrUnknownAlgorithm` |

**AEAD（SM4-GCM / AES-GCM）额外用例：**

| 测试用例 | 描述 |
|---------|------|
| 加密 + tag | 加密输出密文，获取 128-bit tag |
| 解密 + 校验 | 提供正确 tag 解密成功 |
| AAD 一致 / 不一致 | AAD 相同解密成功，不同则失败 |
| 篡改检测 | 密文或 tag 任一字节被改 → 解密失败 |
| nonce 长度 | 非法 nonce 长度（非 12 字节）返回错误 |
| `cipher.AEAD` 接口 | `NewSM4GCM(k)` / `NewAESGCM(k)` 返回的 `cipher.AEAD` 可直接用 `Seal` / `Open` |

**CLI 对比测试**：调用 `openssl enc -sm4-cbc/-sm4-ecb/-sm4-ctr/-sm4-gcm`、
`-aes-128-cbc/-aes-256-gcm` 对随机密钥 / IV / 明文逐字节比对，每种模式独立用例。

**`0.5.0` 新增算法（`sym/newalgos_test.go` / `sym/newalgos_tongsuocli_test.go`）**

| 测试用例 | 描述 |
|---------|------|
| AES-192 全模式 | ECB / CBC / CTR / GCM 往返 + 与 CLI `-aes-192-*` 逐字节一致；`NewAESKey` / `GenerateSymmetricKey` 接受 24 字节 |
| SM4-CCM | 12 字节 nonce、16 字节 tag；标准向量与 tag 篡改检测；明文长度需在 `NewCCMCtx` 之前给定 |
| SM4-XTS | 32 字节双子密钥；允许 CTS（数据 ≥ 16 字节），15 字节拒绝；与 CLI `-sm4-xts` 对拍 |
| ChaCha20 / Poly1305 | RFC 8439 §2.4.2 向量 + 往返；AEAD 的 AAD / tag 用例同 GCM |
| 流式 vs 一次性 | `EncryptSource` / `DecryptSource` 与 `Encrypt` / `Decrypt` 逐字节一致（含跨 64 KiB 分块、空输入） |
| 流式拒绝 AEAD | `EncryptSource("SM4-GCM", …)` 等返回 `ErrUnsupported` |
| 流式坏填充 | 破坏最后一密文块→ `DecryptSource` 必须返回错误（不放宽校验） |

---

## 5. 非对称与协商测试（`asym` / `ecdh`）

### 5.1 `asym`

合并后的 `asym` 服务 SM2 / RSA / ECDSA / Ed25519 / Ed448 / X25519 / X448，
下列用例需**逐算法**覆盖（不适用的行可标注原因跳过）：

| 区域 | 测试用例 |
|------|---------|
| **密钥生成** | 每次生成结果不同；密钥位宽正确；`GenerateKey(alg, opts)` 与类型化入口产物可互换使用 |
| **PEM/DER 导入导出** | 私钥 PEM 往返、公钥 PEM 往返、私钥 DER 往返、公钥 DER 往返；`LoadPrivateKeyPEM` 回退路径（PKCS#8 / RSA PKCS#1 / EC SEC1）逐条覆盖 |
| **签名 / 验签** | 同密钥签名验签成功；篡改数据 / 签名均失败；自定义 userId；空数据签名 |
| **加密 / 解密** | 同密钥加密 + 解密；不同密钥解密失败；每次密文不同（SM2 随机点） |
| **标准向量** | GB/T 32918 系列标准向量（加密 / 签名） |
| **交叉验证** | 库签名 → openssl 验签；openssl 签名 → 库验签 |
| **参数提取**（仅 RSA） | `Params()` 私钥侧 `N / E / D / P / Q / Dmp1 / Dmq1 / Iqmp` 均非 nil；`Dmp1 < P`、`Dmq1 < Q`、`Iqmp * Q ≡ 1 (mod P)`；公钥侧 CRT 字段全部 nil；openssl genpkey 生成的密钥经本库加载后同样满足 |
| **接口契约** | `PrivateKey` / `PublicKey` 的 `Algorithm()` / `Equal()` / `Match()` 语义；`Seed()` / `Bytes()` 仅对 Ed / X 系有效，其余返回 `ErrUnsupported` |

**CLI 对比测试**：生成密钥，导出 PEM，调用 `openssl pkeyutl` / `openssl dgst -sm3 -sign`
进行加解密或签名验签，与库结果比对。

### 5.2 `ecdh`

| 测试用例 | 描述 |
|---------|------|
| 共享密钥对称性 | A 私钥 + B 公钥 与 B 私钥 + A 公钥 得到同一共享密钥 |
| 曲线覆盖 | P-256 / P-384 / P-521 / X25519 / X448 / secp256k1 逐条 |
| RFC 向量 | RFC 7748 §5.2 / §6.1 标准向量逐字节比对 |
| 标准库对拍 | NIST 曲线与 Go 标准库 `crypto/ecdh` 对随机数据结果一致 |
| 密钥对象构造 | `LoadPrivateKey(asym.PrivateKey)` / `LoadPublicKey(asym.PublicKey)` 可用；非对称算法密钥（如 RSA）返回 `ErrUnsupportedKey` |
| 句柄生命周期 | 构造后对 `asym` 侧密钥调 `Close()`，`ecdh` 侧仍可协商（验证 `EVP_PKEY_dup` 生效） |
| 低阶点 / 非曲线点 | X25519 低阶点与非法公钥返回错误（不得返回全零共享密钥） |

**CLI 对比测试**：`openssl pkeyutl -derive` 双向对拍。

---

## 6. 传输层测试（`tls`）

| 区域 | 测试用例 |
|------|---------|
| **TLS 回环** | 客户端 ↔ 服务端握手（TLSv1.3）、多轮读写、`Close` 关闭 |
| **NTLS 回环** | 客户端 ↔ 服务端国密双证书握手（NTLSv1.1 / ECC-SM2-SM4-GCM-SM3） |
| **协议 / 套件** | `Version()` / `CipherName()` 协商结果断言 |
| **互操作（CLI）** | ① 本库 NTLS 客户端 → `openssl s_server -ntls -enable_ntls`（双证书）→ HTTP 响应；② `openssl s_client -ntls -enable_ntls` → 本库 NTLS 服务端 |

> ⚠️ **NTLS CLI 关键**：`openssl s_server` / `s_client` 必须同时传 `-enable_ntls`
> （`-ntls` 只切换 method，未设置 `SSL_CTX_enable_ntls` 会导致状态机
> `state_machine:internal error`，报错于 `ssl/statem/statem.c` 版本检查处）。

**`tls.Listener`（`0.5.0`，`tls/listener_test.go`）**

| 测试用例 | 描述 |
|---------|------|
| Accept 即握手 | 客户端 `Dial`（开 RootCAs + ServerName）→ 服务端 `Accept` 返回的连接**不调 `Handshake`** 即可读写 |
| NTLS 回环 | 双证书配置下 `Listener` 同样完成握手，`Version()` 非空 |
| 握手失败关闭连接 | 裸 TCP 发垃圾字节 → `Accept` 返回错误且**不返回连接** |
| Close 幂等 | 4 个 goroutine 并发 `Close` 均返回 nil；之后 `Accept` 返回错误；`Addr` 仍可用 |
| 凭证校验 | `nil` 监听器、空 `Config`、NTLS 缺加密证书均在构造时报错，且**不关闭** `ln` |
| 并发安全 | 涉及并发生命周期，改 `tls` 时必须加跑 `go test -race ./tls/` |

---

## 7. 密钥派生与随机数测试（`kdf` / `rand`）

| 包 | 测试用例 |
|----|---------|
| `kdf` | HKDF 用 RFC 5869 附录 A 向量逐条；PBKDF2 用 RFC 6070 向量；Argon2ID 用 RFC 9106 §5 向量（铜锁未编译 argon2 时用 `ErrUnsupported` 分支）；`Derive("HKDF", …)` 与 `HKDF(…)` 结果一致；未知名 `ErrUnknownAlgorithm`；迭代次数 / 密钥长度边界（0、1、超长） |
| `rand` | 长度断言（`Bytes(n)` 返回 n 字节）；两次输出不同；全零概率极低（100 次采样）；`Reader()` 与 `io.ReadFull` / `io.Copy` 组合可用 |

> `rand` **不做** CLI 逐字节对拍（随机性无法比对）；`kdf` 的 CLI 对拍见下。

**CLI 对比测试**：`openssl kdf -kdfopt digest:SM3 -kdfopt hexkey:… HKDF`、
`-kdfopt pass:… -kdfopt salt:… PBKDF2`。

**`0.5.0` 新增的 8 种 KDF（`kdf/algorithms_test.go` / `kdf/kdf_tongsuocli_test.go`）**

| 算法 | 标准向量来源（铜锁 `test/recipes/30-test_evp_data/`） |
|------|------|
| SCRYPT | `evpkdf_scrypt.txt`（draft-josefsson-id-scrypt-kdf-03） |
| SSKDF | `evpkdf_ss.txt` |
| TLS1-PRF | `evpkdf_tls11_prf.txt`（master secret 向量） |
| TLS13-KDF | `evpkdf_tls13_kdf.txt`（EXTRACT_ONLY + EXPAND_ONLY 两步串联） |
| X963KDF | `evpkdf_x963.txt` |
| X942KDF | `evpkdf_x942.txt`（RFC 2631 示例） |
| KBKDF | `evpkdf_kbkdf_counter.txt`（HMAC 计数器模式 COUNT=0） |
| HMAC-DRBG-KDF | `evpkdf_hmac_drbg.txt` |

另需覆盖：参数校验（缺 `Digest` / `Secret` / `CEKAlg` / `MAC` / `Entropy` /
`Mode` 各自报错）、确定性（同输入两次结果相同）、类型化入口与 `Derive` 等价。

> ⚠️ **provider 默认值与 CLI 差异**（已写入用例注释，勿当 bug 改）：
> KBKDF 的 `use-l` / `use-separator` 在 provider 侧默认为 1，本库 `false` 显式传 0，
> 对拍时须显式传 `-kdfopt use-l:0 -kdfopt use-separator:0`；X942KDF 反之，
> `use-keybits` 默认即为 1，本库 `false` 表示**不下传**。

> ⚠️ **HKDF known bug**：Tongsuo 8.4 的 HKDF 与 CLI 输出存在不一致（见
> `kdf_tongsuocli_test.go` 现有降级断言与说明）；迁移后沿用该策略，**不得**
> 为对齐而放宽其它算法的断言。

---

## 8. CLI 对比工具（`internal/testutil`）

封装铜锁 openssl 命令行调用（对应 C# 的 `OpenSslCommandRunner`）：

- 统一入口 `RunOpenSSL(args, stdin)`，内部通过 `os/exec` 调用
- `OpenSSLAvailable()` 探测 + `SkipIfNoOpenSSL(t)` 统一跳过；
  **禁止**各测试文件自行复制 `runOpenSSL`
- 方法命名遵循 `{Operation}{Alg}{Mode}()`（如 `HashSm3`、`EncryptSm4Cbc`、`SignSm2`）
- 参数顺序：`key → iv（可选）→ data`
- **不包含任何断言逻辑**，只负责执行与返回结果

---

## 9. 基准与模糊测试

- 关键路径提供 benchmark（如 `BenchmarkSM3`、`BenchmarkSM4CBC`、`BenchmarkSignSM2`），
  便于回归性能
- 提供 fuzz 用例：`FuzzRoundTrip`（加密 → 解密往返，放 `sym`），确保不崩溃、往返一致
- fuzz 与 benchmark 同样遵循"标准向量 + 往返"的覆盖思路

---

## 10. 向量来源

| 算法 | 标准 |
|------|------|
| SM3 | GB/T 32905-2016 附录 A |
| SM4 | GB/T 32907-2016 附录 A |
| SM2 | GB/T 32918 系列 |
| AES | NIST FIPS 197 附录 B/C |
| Ed25519 / Ed448 | RFC 8032 §7.1 / §7.2 |
| X25519 / X448 | RFC 7748 §5.2 / §6.1 |
| ECDH（P-256 / P-384 / P-521） | NIST SP 800-56A（对拍 Go 标准库 `crypto/ecdh`） |
| secp256k1 | SEC 2（对拍铜锁 `openssl` CLI） |
| HMAC-MD5 / HMAC-SHA1 | RFC 2104 附录、RFC 2202 |
| HKDF | RFC 5869 附录 A |
| PBKDF2 | RFC 6070 |
| Argon2ID | RFC 9106 §5 |
| SHA-224 / SHA-256 / SHA-384 / SHA-512 | FIPS 180-4 示例向量 |

---

## 11. X.509 扩展测试（`x509`）

扩展创建横跨证书、CSR 与 CRL 三条路径，**每条路径都必须独立覆盖**——
它们在底层走的是不同的 `X509V3_CTX` 装配路径，一处遗漏就会在该路径上单独失效。

| 路径 | 测试用例 | 断言要点 |
|------|---------|---------|
| **证书** | `certificatePolicies`（OID `2.5.29.32` / NID `89`） | 逐字节断言 DER（`1.2.3.4` → `3007300506032a0304`）；`critical,` 前缀置 critical 位；`ia5org,` 多策略；anyPolicy（`2.5.29.32.0`） |
| **证书** | `ReplaceExtension` 覆盖 `certificatePolicies` | 替换成功、DER 更新、扩展在证书中的**位置不变** |
| **证书** | `subjectAltName` = `email:copy` | subject 含 `emailAddress` 时成功，且 SAN 中出现该邮箱（验证 `ctx->subject_cert` 已接入） |
| **CSR** | `certificatePolicies` | 创建成功、`Extensions()` 可读、DER 往返后仍在 |
| **CSR** | `subjectAltName` = `email:copy` | 同上，验证 `ctx->subject_req` 已接入 |
| **CRL** | `issuingDistributionPoint` / `freshestCRL` | 按名与按 NID 两条路径均成功；`Extensions()` 可见且 `OID` 字段已填充；签名后 `Verify` 通过 |
| **通用** | 扩展往返 | 证书签名 → PEM 往返 → 扩展仍在、验签仍通过 |
| **证书 / CSR / CRL** | `AddCertificatePolicies`（类型化策略入口） | 逐字节断言扩展 DER 与黄金向量一致；CPS 限定符为 IA5String；`organization` / `explicitText` 为 UTF8String；`critical` 位正确；多条策略各成一条 `PolicyInformation`；读回（`CertificatePolicies()`）与写入一致 |
| **证书 / CSR / CRL** | `AddCertificatePolicies` 错误路径 | 空列表、非法 OID、重复 OID、非 IA5 的 CPS URL、只有通知编号而无机构名均报错；已存在该扩展时重复添加报 `x509: extension already present (nid 89)`；`Sign` 之后添加报 `x509: certificate already signed` |
| **证书 / CSR / CRL** | 编码器单测（纯 Go，脱离 cgo） | 黄金向量逐字节比对（单策略无限定符 / 单策略带 CPS 与 userNotice）；OID 编解码往返；整数补码往返；DER 长度长式编码；畸形 DER（截断 / 尾随字节 / 空序列 / tag 错误）一律报错；未知限定符 OID 被跳过而非报错 |
| **证书 / CSR / CRL** | 读回 openssl 产物 | 解析 `openssl` 用 `[polsect]` 段生成的证书（DisplayText 为 VisibleString）→ 策略、机构名、通知编号与文本全部一致 |

> ⚠️ **DisplayText 编码差异**：铜锁 openssl 的配置文件路径用 **VisibleString** 承载
> `organization` / `explicitText`，对非 ASCII 内容会产出**不合规**的 DER（VisibleString
> 的字符集是 7-bit ISO 646）；本库统一用 **UTF8String**（RFC 5280 的 DisplayText
> CHOICE 允许），产出合规 DER 且 openssl 能正常读回。因此**逐字节**对拍只对
> 「无 userNotice」或「纯 ASCII userNotice 且库侧也用 VisibleString」的样例成立；
> 含非 ASCII 文本时对拍断言**语义**（`openssl x509 -ext certificatePolicies` 的
> 文本输出）而非字节。读侧必须同时接受四种 DisplayText 分支，否则读不回
> openssl 生成的证书。

**CLI 对比测试**：`openssl x509 -text` / `-ext certificatePolicies` 断言
"Certificate Policies" 与策略 OID；`openssl crl -text` 断言
"Issuing Distribution Point"。
`certificatePolicies` 另需双向对拍：① 用 `openssl req -x509` 的 `[polsect]` 段
生成证书后由本库读回（校验 VisibleString 兼容）；② 本库生成的证书交
`openssl x509 -ext certificatePolicies` 展示（校验 UTF8String 可被铜锁读回，
含非 ASCII 文本时逐字断言）。

> ⚠️ **回归重点**：OpenSSL 的 `r2i` 类扩展（`certificatePolicies` 等）要求扩展
> 上下文中**存在配置库**，否则报 `X509V3_R_NO_CONFIG_DATABASE`（`0x11000088`）；
> 而 `ctx->subject_cert` / `subject_req` / `issuer_cert` 会被扩展解析器
> **直接解引用**（如 `email:copy`），缺失即 `SIGSEGV`。因此上述用例必须断言
> **成功 + 正确的 DER / 语义**，不得以"错误信息不含某个串"代替——那是把问题
> 藏起来而不是修好它。

**CLI 对比测试**：`openssl x509 -text` / `-ext certificatePolicies` 断言
"Certificate Policies" 与策略 OID；`openssl crl -text` 断言
"Issuing Distribution Point"。
`certificatePolicies` 另需双向对拍：① 用 `openssl req -x509` 的 `[polsect]` 段
生成证书后由本库读回（校验 VisibleString 兼容）；② 本库生成的证书交
`openssl x509 -ext certificatePolicies` 展示（校验 UTF8String 可被铜锁读回，
含非 ASCII 文本时逐字断言）。

---

## 12. X.509 名字与非 ASCII 内容（`x509`）

`X509_NAME` 写入走 `X509_NAME_add_entry_by_txt`，字符串类型**必须是
`MBSTRING_UTF8`**：`MBSTRING_ASC` 会把 Go 的 UTF-8 字节按 Latin-1 逐字节重编码，
`CN=海峰` 由 6 字节变成 12 字节 mojibake（`CN=æµ·å³°`）。同理，读取不得使用
固定长度的栈缓冲（`X509_NAME_get_text_by_NID` 最多写 255 字节，会把多字节字符
截断）。

| 层次 | 用例 | 断言要点 |
|------|------|---------|
| 名字层 | `name_test.go` `TestNameNonASCII` | CJK 单值、ASCII/CJK 混合、非 BMP（emoji）、超长值（`L` 100 汉字 = 300 字节）、上限边界（`O` 64 字符）均 `Entries()` / `Get()` 逐字符相等 |
| 名字层 | `TestNameInvalidUTF8`、`TestNameRejectNonASCIIForRestrictedTypes` | 非法 UTF-8（`\xff\xfe`、孤立代理、截断序列）与 `C=中国`、`emailAddress=海峰@…`、空值一律报错，且 `Len()` 保持 0（不留半成品） |
| DER 编码 | `cert_test.go` `TestCertificateNonASCIISubjectRoundTrip` | DER 直接含 `0C 06 E6 B5 B7 E5 B3 B0`；**不含**双重编码串 `C3 A6 C2 B5 C2 B7…`；`asn1.Parse` 复核 CN 为 `UTF8String` 且全树无 `BMPString`；PEM 往返后条目与顺序不变 |
| 签发 | `chain_test.go` `TestChainVerifyNonASCIINames`、`issue_test.go` `TestIssueFromCSRNonASCII` | CJK CA / leaf 链 `ChainVerify` 通过；leaf 的 issuer 与 CA 的 subject 逐条相等；CSR 签发后 subject 逐条相等 |
| CSR | `csr_test.go` `TestCSRNonASCII`、`TestCSRChallengePasswordInvalidUTF8` | subject、challengePassword、`nsComment` 的中英值经 PEM 往返全保真且 `Verify()` 通过；非法 UTF-8 口令报错 |
| 扩展 | `extension_test.go` `TestExtensionNonASCII` | `nsComment` 的 `Data` 含原始 UTF-8 字节；`certificatePolicies` 的 `organization` / `explicitText` 读回一致 |
| CRL | `crl_test.go` `TestCRLNonASCIIIssuer` | CJK 颁发者在 DER 往返后逐条保真，`Verify(ca)` 通过 |
| 名字顺序 | `name_test.go` `TestNameAddOrder` | `.Add("C").Add("O").Add("OU").Add("CN")` → `Entries()` 顺序与调用一致（追加语义，`0.5.0` 前是前插）；`String()` 按 DER 前向输出，等于书写顺序 |
| 传输层 | `tls` `TestLoopbackNonASCIISubject`、`TestNTLSLoopbackNonASCII` | CJK subject 经 TLS / NTLS 握手到达对端后 `PeerCertificates()` / `PeerEncCertificates()` 仍逐条保真（goroutine 内不得 `t.Fatal*`，见 P1004） |
| CLI 对拍 | `name_tongsuocli_test.go` | `TestCLISubjectDERParity`：同一书写顺序下本库与 `openssl req -x509 -subj` 的 subject DER **逐字节相同**（RDN 顺序 + 编码类型的强断言）；本库证书 → `openssl x509 -subject -nameopt utf8` 与 `asn1parse`；`openssl req -utf8` 产物 → 本库读回；`openssl verify` / `req -verify` / `crl -issuer`；另含对照用例：不带 `-utf8` 的 CLI 产物读回就是 12 字节 mojibake |

> ⚠️ **不要把 CLI 默认行为当基准**：`openssl req -subj` 不带 `-utf8` 时用
> `MBSTRING_ASC`，与本库修复后的行为**不同**。ASCII 值的 DER 两者一致（既有
> 逐字节对拍仍成立），含非 ASCII 时必须加 `-utf8` 对拍，或断言语义而非字节。

---

## 13. 形态入口测试（`meta` / 各原语包，`0.5.0`）

「形态入口」指各原语包里 `*Source` / `*Sink` 形态的入口（`SumSource` /
`EncryptSource` / `DeriveTo` / `Marshal*To` / `Load*Source` / `MarshalFormat`）。
它们不是新算法，**测试重点是「与既有一次性入口等价」+「形态语义正确」**。

### 13.1 `meta` 自身

| 文件 | 覆盖点 |
|------|--------|
| `meta/list_test.go` | 七个算法族非空且必含规范名、去重、字典序、稳定性 |
| `meta/list_tongsuocli_test.go` | **包含关系断言**：本库报告的名字必须出现在 `openssl list` 输出中（大小写不敏感），并校验必含清单；不做逐条相等（CLI 会列出别名与历史名） |
| `meta/encoding_test.go` | raw / hex / base64 往返；hex 忽略空白、base64 忽略 CRLF；`Dump` 的 `xxd` 排版 |
| `meta/source_test.go` | bytes / reader / file / stdin 形态；一次性源二次 `Open` 返回 `ErrSourceConsumed`；`NewBytesSource` 构造时复制 |
| `meta/sink_test.go` | 编码只能在首次写入前设置；hex 分块写出与一次性等价（base64 走 `base64.NewEncoder`，天然流式）；`Close` 幂等 |
| `meta/passphrase_test.go` | `pass:` / `env:` / `file:` / `fd:` / `stdin:` 五种来源；file / fd / stdin 剥行尾换行；`String()` 必须脱敏（**不得**出现明文口令） |
| `meta/format_test.go` | `ParseFormat` 大小写不敏感、未知名报错、`String()` 往返 |

### 13.2 各原语包的形态入口

| 包 / 文件 | 覆盖点 |
|-----------|--------|
| `digest/forms_test.go` | 三种 `Source` 与 `Sum` 结果一致；`SumTo` 的 raw / hex 编码；`SumReaderTo` 等价；未知名报错 |
| `mac/forms_test.go` | `SumSource` / `SumFile` 与 `Sum` 一致；`SumTo` 编码；CMAC 缺 `Cipher` 返回 `ErrInvalidOptions` |
| `sym/forms_test.go` | **流式与一次性逐字节对拍**（8 种模式 × 跨 64 KiB 分块）；空输入走 PKCS#7；AEAD / XTS 返回 `ErrUnsupported`；密钥长度错误 `ErrInvalidKeyLength`；破坏密文末块后解密必须报错 |
| `kdf/forms_test.go` | `DeriveTo` 的 raw / hex 编码；参数校验错误透传 |
| `asym/forms_test.go` | `LoadPrivateKeySource` 明文 / 加密两条路径；**无口令加载加密 PEM 必须报错**；`MarshalPrivateKeyTo` 明文 / 加密写出均可读回；`nil` 入参报错 |
| `x509/forms_test.go` | `MarshalFormat` 与 `MarshalPEM` / `MarshalDER` 一致；`LoadCertificateSource` 自动识别 PEM / DER（含前导空白）；`MarshalCertificateTo` hex 编码；`MarshalCSRTo` 双向 |

### 13.3 两个必须守住的语义

1. **`Sink` 不自动 `Close`**：入口函数只 `Write`，收尾（尤其是 file sink 的 flush
   与 base64 encoder 的尾巴）由调用方负责。测试里每个用例都显式 `sink.Close()`
   之后再读 `sink.Bytes()`，这本身就是该契约的回归用例。
2. **库内不得向终端索要口令**：`X_PEM_read_bio_PrivateKey` 传入的回调永远返回 0，
   因此 `LoadPrivateKeySource(encrypted, nil)` 立即失败。**不要**为了让某个用例
   「跑通」而恢复 `NULL` 回调——那会让任何无终端进程（CI、systemd 服务）在
   `LoadPrivateKeyPEM` 上永久阻塞。

### 13.4 CLI 对拍

形态入口本身不做 CLI 对拍（它们不含算法逻辑），对拍落在底层算法测试里：

- `digest/*_tongsuocli_test.go`：`openssl dgst -sm3 -hex`
- `mac/*_tongsuocli_test.go`：`openssl mac -macopt …`
- `sym/*_tongsuocli_test.go`：`openssl enc -<alg>`
- `kdf/kdf_tongsuocli_test.go`：`openssl kdf -kdfopt … <ALG>`
