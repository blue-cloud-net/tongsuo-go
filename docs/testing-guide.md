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

**`0.6.0` 扩展摘要（`digest/extended_test.go` / `digest/digest_tongsuocli_test.go`）**

| 测试用例 | 描述 |
|---------|------|
| 标准向量 | SHA-512/224 / SHA-512/256（FIPS 180-4）、SHA3-224/256/384/512（FIPS 202）、KECCAK-256（原始 Keccak 空串向量），按名与类型化两条路径均逐字节比对 |
| SHAKE 显式长度 | `Sum("SHAKE128", …)` / `New("SHAKE128")` 必须返回 `ErrXOFNeedsLength`；`SumSHAKE128` 需 0 长度报错 |
| XOF 前缀性质 | 同一输入的 64 字节输出必须以 16 字节输出为前缀 |
| 长度与分组 | `Size` / `BlockSize` 与导出的 `*Size` / `*BlockSize` 常量一致 |
| 运行时探测 | `Available` 对 8.4 缺失的 KECCAK-* / SHA-256/192 返回 false，相应测试 `t.Skip` |
| CLI 对拍 | 14 种定长算法与 `openssl dgst -<name>` 逐字节一致；SHAKE 用 `-xoflen N` 对拍 |

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

**`0.6.0` 新增模式与填充矩阵（`sym/des_test.go` / `sym/padding_test.go` / `sym/newmodes_tongsuocli_test.go`）**

| 测试用例 | 描述 |
|---------|------|
| AES-OFB / CFB | 128 / 192 / 256 三种密钥长度各自往返；密文长度等于明文长度（流模式）；`DecryptAESOFB` 与 `EncryptAESOFB` 结果相同；IV 非 `BlockSize` 返回错误；与 CLI `-aes-{128,256}-{ofb,cfb}` 逐字节一致 |
| DES 家族往返 | `DES-ECB/CBC`、`DES-EDE-ECB/CBC`、`DES-EDE3-ECB/CBC` 六个名字的往返、空明文与分组对齐明文 |
| **单 DES 等价性** | `DES-*` 的输出必须与 `DES-EDE3-*` 在 `K‖K‖K` 密钥下**逐字节相同**（实现依赖的数学事实，必须钉住） |
| 单 DES 基准真相 | `-tags tongsuocli` 下用 `openssl enc -des-cbc -provider legacy -provider default` 作基准，与 `DES-CBC` 输出逐字节比对；无法加载 legacy 时 `t.Skip`（**库运行时不加载 legacy，仅测试用**） |
| DES 长度错误 | 密钥长度不符 → `ErrInvalidKeyLength`；IV 非 8 字节 → `invalid iv size`；`NewDESCipher` 的 `BlockSize() == 8` |
| 3DES / 2-key 3DES 对拍 | `-des-ede3-{ecb,cbc}` 与 `-des-ede-{ecb,cbc}` 逐字节一致 |
| 填充矩阵静态查询 | `Paddings` / `Supports`：分组模式返回 `pkcs7/zero/none`，流模式与 XTS 返回 `none`，AEAD 返回空；未知名返回 `ErrUnknownAlgorithm`，未知填充名返回 `(false, nil)` |
| 非法组合不发数据即拒 | `Encrypt("AES-128-CTR", …, nil, &Options{Padding: pkcs7})` 等在**空数据**上即返回 `ErrUnsupportedPadding` |
| AES-CBC 真正消费填充 | `PaddingNone` 下密文长度等于明文（已对齐），且与 pkcs7 密文前缀一致；未对齐时报错 |
| zero 填充语义 | 加密补零到分组整数倍、解密**不剥离**（长度仍为分组倍数） |
| Zero 入口一致性 | `EncryptSM4CBCZero` 与 `Encrypt("SM4-CBC", …, &Options{Padding: "zero"})` 逐字节相同 |

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

### 5.3 签名表示转换与 RSA-SM3（`0.6.0`）

| 测试用例 | 描述 |
|---------|------|
| DER → (r,s) → DER | SM2 与 ECDSA 各取真实签名，拆分后重组必须逐字节等于原 DER |
| der → raw → der | `FormatSignature` 宽度 32（SM2 / P-256）；raw 长度必须为 64 |
| 前导零补齐 | `r` / `s` 最高位为 0 时 DER 更短，raw 必须左补回定长（最易错处，必须有专门用例） |
| 宽度缺失 / 不符 | `der → raw` 不给 width 报错；width 过小报错；raw 长度与 width 不一致报错 |
| 结构严格性 | 空 SEQUENCE、垃圾字节、**尾随字节**、空 / 零分量均返回错误 |
| RSA + SM3（PKCS#1 v1.5 / PSS / OAEP） | 三种填充下签名、验签、加解密往返；篡改消息必失败；摘要不匹配必失败 |
| RSA-SM3 与 CLI 互验 | 本库签名 → `openssl dgst -sm3 -verify`；`openssl dgst -sm3 -sign` → 本库验签；PSS 带 `-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest` |

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

## `0.6.0` 增量验收（铜锁 8.4.0）

- `sym/extended_test.go`：RFC 3394 WRAP、RFC 5297 SIV、RFC 7253 OCB 空消息、
  ZUC 零向量、NIST CAVS 11.0 AES-128/256-XTS（含密文窃取）、OpenSSL 官方 AES-256-CCM 16 字节 tag 向量；全部新模式 × 密钥长度 × 输入长度往返；认证 tag/AAD/nonce/密文
  篡改；WRAP 完整性；8.4 SIV 空消息拒绝（0.8.0 在 8.5 支持并认证）；CCM 空载荷必须生成并校验 tag。
  模糊种子为 `FuzzAESWrapPadRoundTrip`，基准为 `BenchmarkAESOCB`。
- `ecdh/parameters*_test.go`：P-256/384/521/secp256k1 命名/显式参数逐字节 CLI 对拍，
  文件入口、参数驱动生成、坏输入与不支持曲线。
- `asym/pkcs8*_test.go`：PBE v1/v2、PRF、迭代、空/错误口令、PEM/DER；RSA PKCS#1
  公钥与 `Check`/`PublicCheck`；PKCS#8 双向 CLI 转换后私钥 DER 一致。
  RSA-SM3 签名不在 8.4.0 可用集：原生能力为 false 时必须断言 `ErrUnsupported`，
  CLI 同时必须失败；不能以 t.Skip 掩盖不一致。OAEP-SM3 必须往返通过。
- `pkcs/pkcs12/options*_test.go`：全部 PBE 选择、独立读/写口令、改密；CLI 输出
  必须包含指定 PBE、迭代次数与 friendlyName，避免参数静默失效。
- `keystore/load_test.go`、`x509/extended_test.go`：PEM 多对象/DER/PKCS#12 自动识别，
  本地 file URI，未知块与部分结果清理；trusted PEM 往返不改变签名 DER，加载保持签名终态。
- `x509/extended_tongsuocli_test.go`：离线 OCSP responder 只读取 `-reqin`，不附加
  `-cert` 重新生成请求；HTTP 成功、nonce 一致/缺失/不匹配、响应签名与信任属性对拍。
  默认测试覆盖 HTTP 状态、Content-Type、限长、超时与错误 DER。
- AES-CCM/OCB/SIV/XTS 不由 `openssl enc` 提供；其标准向量与错误路径由单元测试覆盖，
  CLI 对拍覆盖 `enc` 可用的 WRAP/WRAP-PAD/CBC-CTS/ZUC。既有 8.4 缺失算法与 HKDF
  差异保持原能力探测/降级策略，不修改期望向量。

显式设置 `TONGSUO_HOME=/opt/tongsuo-8.4.0`、对应 `CGO_CFLAGS` / `CGO_LDFLAGS` /
`LD_LIBRARY_PATH` 与 `TONGSUO_OPENSSL_BIN`，不要跟随可能指向 master 的 `/opt/tongsuo`。
完成 `go build ./...`、`go vet ./...`、`go test -count=1 ./...`、
`go test -tags tongsuocli -count=1 ./...`，涉及句柄生命周期的本版还需 `go test -race ./...`。


## 0.7.0 验收与后续版本要求

0.7.0 已实现并增加以下测试；0.8.0 及以后的条目仍为未来门槛，版本归属见
[roadmap.md](roadmap.md) §2。

### `0.7.0` — 可靠性、数据完整性与 PKCS 容器

| 能力 | 必测场景 |
|---|---|
| ECDH / CSR Close | nil/重复关闭；关闭后导出/协商/验签返回错误；ECDH 副本关闭不影响原 asym 密钥，反向关闭也不影响副本 |
| ASN.1 限额 | 深度及节点数恰好达限/超限、宽树/深树、非法限额、可识别的超限错误；现有 Parse 的 128 层保护和合法输入结果保持 |
| 证书 / CRL 完整序列号（I-18/I-20、I-23/I-24） | 证书大整数设置、CSR 签发及 PEM/DER 往返；无需被吊销证书的 RevokeSerial、hex 适配与 Revoke(cert) 均无损；条目读回、IsRevoked / RevocationCheck 不经 int64 比较，与铜锁 8.4.0 CLI 双向互通 |
| 序列号边界与兼容 | 超 int64、20 octets 与 DER 符号补零边界；不同高位但相同低 64 位、不同长整数溢出结果不得误匹配；hex 大小写/前导零按整数值等价；新写入拒绝 nil/零/负数/超长值与非法 hex，外部非合规值无损读取或明确报错，旧 int64 限制明确 |
| 大整数所有权与错误路径 | 修改输入或返回的 big.Int 不改变证书/CRL；IssueOptions 新旧序列号同时设置报错；已关闭/签名状态、非法原因码与原错误约束回归；保持 issuer 匹配及 CRL 信任前提 |
| DER 扩展 | 读取已有扩展后迁移 DER、已知/自定义 OID、critical 保留、错误 OID/DER；签名前添加、签名后拒绝修改；最终证书验签成功 |
| 信任路径 | 显式 CA 文件/目录与临时默认信任源、受信/不受信链、关闭后调用；不得隐式信任输入根，不依赖公网或宿主机根证书偶然状态 |
| SM2 压缩输入 | 两种 C2/C3 顺序、压缩点 → DER → 解密、既有未压缩输出；无效前缀、截断、非曲线点/无穷远点、篡改认证失败；经铜锁原生验证 |
| PKCS#12 改密 | 两个入口均覆盖多私钥、多 safe、嵌套 safeContentsBag、CRL 与可保留 bag；PBES2/AES-128/192/256 和可用 3DES，旧口令失败/新口令成功；空/错误口令、损坏 MAC、截断；内容、层级、顺序和全部属性保持 |
| RSA 签名格式 | SHA-256 的 PKCS#1 v1.5 / PSS 与 CLI 双向互验；签名长度等于模数字节数；统一 PSS 摘要/MGF1/salt 参数；不把首字节不是 0x30 当成失败 |
| 分步签发示例 | NewCertificate → Set/Add → Sign，SAN/KU/SKID/AKID 等扩展可读回，签名可验证；不通过放开签名终态解决 |

P12 先验证 MAC；无 MAC、不同 MAC/加密口令、签名保护及其他不支持的算法/结构明确失败。
WithOptions 应用 PBE/迭代后仍保留内容与属性；空 FriendlyName 不清空原名称，多密钥
非空改名须报歧义。普通改密保留原算法/派生/MAC 策略，并更新必要的随机盐/IV；
不能自动加载 legacy 或退回有损重打包。
随机签名/密文不做跨独立运行的逐字节相等断言；比较结构、内容、属性并双向验签/解密。
涉及句柄生命周期与原生内存的改动须跑 race、正常/错误路径与 CLI 互操作。

#### 同版兼容与边界补充

- ECDH Public 返回 (*PublicKey, error)，覆盖公钥先关、私钥先关、源 asym 先关，
  其余独立对象均仍可使用；nil/零值/重复关闭幂等，关闭后操作失败，迁移示例可编译。
- ParseWithLimits 的正数参数、根节点计数、构造层数、等于限额/超限均有断言；
  ErrDepthLimit/ErrNodeLimit 经 errors.Is 识别，原 Parse 128 层与错误文本回归，
  深/宽输入不会因递归耗尽栈。
- SetSerial 等旧 int64 写入口与新入口统一拒绝零/负数；20 octets 包含 DER 符号补零，
  覆盖 159 位边界与需要第 21 字节的正数拒绝路径。

#### 同版 PKCS#7 容器验收

- 附带/分离签名均与铜锁 CLI 双向互验，分离内容缺失或不匹配、损坏容器、错误密钥
  和签名篡改必须失败；证书袋/CRL 现有行为回归。
- EnvelopedData 双向加解密，覆盖错误接收者密钥和畸形输入；不能把非认证加密的
  偶然解密成功当成完整性认证，按所选算法验证能够保证的错误条件。
- Verify 默认要求显式 Roots 并验证全部签名者；缺信任存储、不受信任、任一签名损坏
  均失败且不返回内容。显式 SignatureOnly 仍验签，成功结果 TrustVerified=false。
  附带/分离均覆盖空内容与二进制换行；验证结果证书归 SignedData.Close 幂等释放。
- 必须覆盖 RSA/ECDSA 签名、默认 SHA-256、默认 AES-256-CBC 和多 RSA 接收者；
  SM2 签验/加解密及其他不支持组合明确报错，不以 Skip 掩盖。CLI 使用 smime 进行
  双向互通，证书袋/CRL 提取仍使用 pkcs7。
- 保持铜锁 8.4.0 发布基线，完成 build/vet/单元测试/CLI 对拍及生命周期 race 检查。

#### 0.7.0 实际验证与夹具

8.4.0 环境中已通过默认单元测试、tongsuocli 全量互操作、race、build/vet 及 Linux
static 标签构建。新增测试集中于 limits/lifecycle/reliability、SM2 压缩输入、RSA
签名字节串和 PKCS operations/complex/lossless 测试文件；FuzzPKCS7EnvelopeRoundTrip
验证随机二进制内容的信封往返，FuzzParseWithLimits 验证 DER 限额；随机产物验证内容与结构，
不修改标准向量或放宽断言。

复杂 P12 单元测试使用 `pkcs/pkcs12/testdata/complex.c`，在临时目录编译/生成多密钥、
嵌套、CRL、secretBag、自定义属性夹具，解密后比较每项内容及属性的摘要/名称/顺序。
编译器沿用 cgo 所需的 `cc`，头文件和库取 `TONGSUO_HOME`；不依赖 openssl CLI。
CLI 测试额外检查外部 PBES2/AES 与 3DES 的算法、迭代及 MAC 参数保留。原生 P12
改密成功/错误路径另经临时 ASan/LSan 驱动检查，无原生内存错误或泄漏。

#### `0.9.0` 实现测试映射

- `tls/handshake_test.go`：ALPN 优先级/冲突、独立 SNI/验证名称、TLS/NTLS 完整身份选择与 SNI 精确套件/组切换、混合端口并发、客户端认证、三种信任策略、自定义验证拒绝、状态副本与 Close 后快照。
- `tls/pki_test.go`：真实三级链、TLS 1.2/1.3、DNS/IP/邮箱与 hostname flags、SNI 更换版本/签名/密钥类型/标准 ffdhe2048 参数，覆盖缺中间链、过期、错误名称/邮箱。标准库只生成测试交叉夹具，生产路径均使用铜锁。
- NTLS ECC/ECDHE × GCM/CBC：独立签名/加密私钥及 CA 签发证书、双向认证和实际套件断言；错误信任在 Report 中保存两套身份的失败记录。签名/加密使用不同中间 CA 时，ECC/ECDHE 均严格双向验证两链，缺失加密侧中间链明确失败。
- `tls/handshake_tongsuocli_test.go`（tongsuocli）：TLS 1.2、TLS 1.3、NTLS ECC、NTLS ECDHE；CLI client → SDK server 与 SDK client → CLI server 均验证 mTLS、ALPN 和实际收发数据，CLI/头文件/库取同一安装前缀。
- `internal/core/ssl_lifecycle_test.go`：构造失败接管 fd、显式 Close 与 Handle/finalizer 共用析构路径均释放 fd；上下文先关闭仍可安全释放 SSL，断开 socket 的真实 errno 可跨 goroutine 解包。
- I/O 回归：读取挂起时写入可推进、独立 deadline、写超时后禁止不同缓冲重试、错误凭证配对/关闭句柄、并发状态/Close；已有取消/FD 生命周期用例继续运行。
- `tls/handshake_example_test.go` 提供 Client 的 GoDoc 探测用法；`BenchmarkHandshake` 测量 TLS 1.2/1.3、NTLS ECC/ECDHE 完整握手和释放开销；真实验证失败逐项断言公开验证码、SSLCode 与原生错误队列。
- `examples/handshake` 为独立 Go module，构建并使用本地 CA/证书运行握手+回显；示例 Report 默认值与严格/不验证选项分开验证。详细消息事件/trace/keylog 不属于本版验收。

#### `0.9.0` 本地验证结果（Linux amd64，2026-11-05）

铜锁 8.4.0：全仓库 build/vet、默认测试、tongsuocli 对拍、race 与 static 标签构建通过；
全仓库 race + GOEXPERIMENT=cgocheck2 联合检查通过。七个独立示例模块均
build/vet 通过；四种握手 Benchmark 完成。混合端口示例实测 TLS 1.2、NTLS ECC/ECDHE
严格双向认证、ALPN、数据回显，另验证 Report 默认继续、VerifyNone 和严格失败后的状态/错误码。

合并 0.8.0 后，铜锁 8.4.0 / 8.5.0 的全仓库默认测试和 tongsuocli 对拍均通过，
build/vet 与 TLS/core race 检查通过。独立开发时在 `941ae5b` 基线上复现的 NTLS
旧证书用途及 AES-WRAP CLI 差异，已由 0.8.0 的证书用途适配及独立 EVP 驱动解决。
本次合并验证环境为 Linux amd64，未在本次运行中验证 macOS / arm64。

### `0.8.0` 至 `1.0.0`

- `0.8.0`（已实现）：8.4.0/8.5.0 独立构建与 CLI 同源验证；50 组 RFC 8452
  向量和独立 EVP 对拍，覆盖 AES-192 原生扩展、空消息和 tag/AAD/nonce/密钥篡改；
  SIV 空消息在 8.4 拒绝、8.5 认证。8 组 RFC 8032 上下文/ph 向量与 CLI 双向互验，
  覆盖 context 0/255/256 字节、错配与变体隔离；RSA-SM3 分 PKCS#1 v1.5/PSS/OAEP
  验收，并独立探测 PSS/MGF1/盐长。通用 KEX 六曲线与既有路径一致；SM2DH 校验
  GB/T 32918.5-2017 附录 B.2、双方角色/ID/输出长度与句柄释放，不把派生称为确认。
  NTLS 正确用途握手及互换用途拒绝均覆盖；8.5 enc 的 WRAP 拒绝经明确断言，
  使用独立 EVP 保持逐字节双向比较。测试驱动仅在临时目录编译，不下载铜锁。
- `0.9.0`：TLS 1.2/1.3、NTLS ECC/ECDHE 分别回环与 CLI 双向互通，断言协议/套件与
  双向数据；覆盖混合端口并发、SNI/ALPN、完整证书链、客户端认证和严格参数配置。
  三种显式验证策略对同一错误证书分别断言连接结果和验证事实；覆盖错误 CA、过期、
  名称/IP、缺中间链/客户端凭证及 NTLS 两套身份。独立读写 deadline、双向并发 I/O、
  取消/关闭、原生错误归因和 FD/句柄释放通过回归；保留 SDK 旧入口行为与既有 Listener。
- `0.10.0`：RFC 8998 的 `TLS_SM4_GCM_SM3` / `TLS_SM4_CCM_SM3` 分别完成单向/双向
  认证和 CLI 双向互通，按路线图 §2.4 核对 TLS 1.3、curveSM2 的组/key_share、
  sm2sig_sm3 的协商/CertificateVerify、证书约束及握手签名/证书验证的 SM2 ID；
  错误版本/组/签名/证书明确失败，不能仅凭套件名判定符合 RFC 8998。
  TLS/NTLS/RFC 8998 分别验证结构化状态、消息、Alert、验证事件、trace 和 keylog，
  覆盖失败握手、回调数据生命周期、输出失败及缺少原生能力；不依赖整段日志文本断言。
  SCT 采集验证开启/关闭两态、逐项 TLS wire 编码与构造值一致，`OPENSSL_NO_CT` 构建明确不支持；
  `SecureRenegotiation` 在 TLS 1.2 与 NTLS 下分别断言取值。
- `0.11.0`：在累积协议矩阵上验证实际会话复用、缓存/导入导出、过期、拒绝复用、
  票据开关与密钥轮换、协议/服务身份/客户端身份/验证策略隔离；TLS 1.3 先处理握手后
  票据，再恢复连接。启用配置不等于实际复用，复用后的验证回调也须验收；同一缓存
  连续两次握手断言 `SessionReused` 由 false 变 true。
- `0.12.0`：已有协议矩阵上的 HTTP/1.1 客户端/服务端、便捷入口及 OCSP stapling；
  使用受控本地服务，覆盖缺失/过期/吊销、错误签名/身份的 staple。取得响应不等于
  有效响应，不支持组合明确报告；不把 ALPN h2 协商当作 HTTP/2 集成通过。
  `OCSPStapled` 覆盖缺失/存在两态，`OCSPResponse` 须能被 `x509.ParseOCSPResponse` 解析。
- `0.13.0`：PQC/KEM 原生能力探测、密钥编码往返、标准向量/互操作、参数不匹配、
  生命周期与失败清理；8.4 编译不引用不存在的符号。
- `0.14.0`：CMS 互操作、RFC 3161 请求/响应匹配与时间戳验证；HTTP 用受控本地服务，
  验证失败不能降级成“成功解析即有效”。
- `1.0.0`：迁移示例可编译，公开签名/Options 对照与全量回归通过，再给出兼容性承诺。

以上均为未来交付门槛，不表示已完成；传输各版沿用固定铜锁 8.4.0/8.5 验证矩阵，
分别执行 build、vet、默认/CLI/race 测试、Linux static 与示例构建。SDK 交付 API 与
可运行示例；示例默认记录验证失败后继续，严格验证与完全不验证另行显式选择。
STARTTLS、外部 PSK、0-RTT、主动重协商不作为本轮交付门槛。

### `0.10.0` 实施验收矩阵（待实现）

下表是 [路线图 §2.4](roadmap.md#24-0100--rfc-8998-与完整握手诊断规划) 的新增用例要求，
不表示用例已经存在或已通过。基础单元/回环不依赖外部服务，CLI 用例继续用
`tongsuocli` 标签及 `internal/testutil`，只在确实缺铜锁 CLI 时按统一工具说明跳过。

| 用例组 | 必须断言 | 拟落点 |
|--------|----------|--------|
| RFC 8998 配置 | 零值归一；版本/NTLS/混合/双证书/套件/组/签名冲突在连接前失败；客户端无证书仅在单向认证允许；SNI 不能取消基础严格限制 | `tls/rfc8998_test.go` |
| RFC 8998 互通 | 两套件 × SDK 客户端/服务端 × 单向/双向认证；双向数据、TLS 1.3、wire 套件 ID、curveSM2/key_share、sm2sig_sm3/CertificateVerify、证书用途与 SM2 ID；错误根/名称/密钥/签名明确失败 | `tls/rfc8998_test.go` / `rfc8998_tongsuocli_test.go` |
| 事件语义 | 每连接序号严格递增、开始/结束各一次、方向与类型、Alert 原始码、验证深度/码与 DER；VerifyReport 的失败仍为失败，VerifyNone 不虚构成功；未知类型保留原文，重试不重复生命周期事件 | `tls/diagnostics_test.go` |
| 生命周期 | 回调载荷可保留且不受后续调用/Close 改写；失败握手已派发信息可用；快照深拷贝，Dial 失败无 FD/句柄泄漏，SNI 切换与多连接事件不串线 | API 与 `internal/core` 回归 |
| 派发与错误 | 顺序/字节限额边界、单项超限、累积超限、短写、回调/Writer 首错可 `errors.Is` 匹配；与协议失败并存时不丢失原始原因；并发读写、取消/Close、WANT 重试与握手后 I/O 无死锁/竞态 | API/core，追加 race |
| trace / keylog | TLS 1.2/1.3、NTLS ECC/ECDHE、RFC 8998 分别验证；默认零输出；trace 检查稳定结构，不逐字符对拍；keylog 检查格式/标识与连接归属，不把密钥输出到测试日志 | `tls/diagnostics_test.go` / CLI 对拍 |
| SCT | 关闭不采集；开启无 SCT/多 SCT、重复项和原生顺序、`i2o_SCT` 字节一致及解析往返；验证策略不因 CT 捕获而改变；分别记录各协议实际支持的来源 | `tls/state_test.go` / core/native |
| 条件编译 | 无 CT/trace 构建能编译，显式启用返回不支持错误，关闭仍正常；构建证据单列，不能用跳过代替 | 两版原生能力探路与构建验证 |
| 安全重协商 | TLS 1.2 与 NTLS 分别对比原生标志；TLS 1.3 不将该值解释为支持主动重协商 | `tls/state_test.go` |

全量矩阵、静态链接及 ASan/LSan 门禁见路线图 §2.4.4；实际执行后补录版本、
构建选项、平台和结果。原生不触发的事件/协议组合应给出实测边界，不能填充假事件。

## NTLS 线程错误队列回归

NTLS 握手后读取必须隔离 OS 线程上前次原生调用留下的错误。
`internal/core/ssl_error_queue_test.go` 在同一线程注入旧错误并验证读取超时，
不得改成只检查错误非空。回环另覆盖服务端先等待、客户端延迟发送的时序；
Linux amd64 的 race 阶段重复该回环 50 次。调查与 act 漏检原因见
[铜锁 8.5.0 NTLS 调查](ntls-8.5-race-investigation.md)。
