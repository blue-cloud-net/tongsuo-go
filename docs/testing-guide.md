# 测试规范

本文档规定 `tongsuo-go` 的测试组织、命名以及各类算法**必须覆盖**的用例。
整体开发规范见 [development-guide.md](development-guide.md)，架构说明见
[architecture.md](architecture.md)，重构后的包清单见 [api-reference.md](api-reference.md)，
包结构迁移路径见 [refactor-roadmap.md](refactor-roadmap.md)。

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

**CLI 对比测试**：`openssl mac -macopt hexkey:… HMAC-SM3`（CLI 侧走 provider，本库
本版走 legacy `HMAC_CTX_*`）逐字节比对，用于确认两条路径一致。

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

---

## 7. 密钥派生与随机数测试（`kdf` / `rand`）

| 包 | 测试用例 |
|----|---------|
| `kdf` | HKDF 用 RFC 5869 附录 A 向量逐条；PBKDF2 用 RFC 6070 向量；Argon2ID 用 RFC 9106 §5 向量（铜锁未编译 argon2 时用 `ErrUnsupported` 分支）；`Derive("HKDF", …)` 与 `HKDF(…)` 结果一致；未知名 `ErrUnknownAlgorithm`；迭代次数 / 密钥长度边界（0、1、超长） |
| `rand` | 长度断言（`Bytes(n)` 返回 n 字节）；两次输出不同；全零概率极低（100 次采样）；`Reader()` 与 `io.ReadFull` / `io.Copy` 组合可用 |

> `rand` **不做** CLI 逐字节对拍（随机性无法比对）；`kdf` 的 CLI 对拍见下。

**CLI 对比测试**：`openssl kdf -kdfopt digest:SM3 -kdfopt hexkey:… HKDF`、
`-kdfopt pass:… -kdfopt salt:… PBKDF2`。

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
