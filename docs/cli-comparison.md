# 铜锁 CLI 与本库能力对比

> 本文件回答：**与铜锁自带的命令行（`tongsuo`，即铜锁发行版中的 `openssl` 程序）相比，本仓库还有哪些能力没有覆盖？**
>
> 口径：本库的目标形态是**「CLI 级应用函数」**——调用方只需给出输入与参数即可拿到输出，不必像裸 `EVP_*` 那样自行组装多步流程；本库**暂不提供底层函数**，也**不暴露底层 cgo 函数**。因此本报告既对比「CLI 有的功能本库有没有」，也对比「本库现有公开面是否偏离该目标形态」。
>
> 报告**不写代码改动、不给新 API 签名**；所有「本库现状」结论均可在源码中校验。
>
> **包名口径**：本文件的「本库现状」列使用**重构前**包名（`crypto/*` / `key` / `ocsp`）——那是采集时的真实状态。重构后的 16 包名与逐符号签名见 [api-reference.md](api-reference.md)，包级迁移对照见 [refactor-roadmap.md](refactor-roadmap.md) §2 / §4。
> 公开面收敛（§6.E 的 12 项内部类型泄露）已在 [refactor-roadmap.md](refactor-roadmap.md) §5 全部落实。

---

## 1. 摘要与结论

| 维度 | 结论 |
|---|---|
| **命令面** | 铜锁 CLI 提供 **56 个普通子命令** + **44 个伪命令**（摘要 15 + 密码 29）。本库**没有也不计划提供 CLI 程序**，因此逐命令对齐应理解为「该命令**所承载的能力**在本库有没有对应的应用级函数」。 |
| **对称算法面** | 铜锁 provider 侧共 **177 条 cipher 条目**；本库覆盖 AES-128/256 的 4 种模式与 SM4 的 6 种模式，**差距明显**：缺 AES-192、AES 的 OFB/CFB/CCM/XTS/OCB/SIV/GCM-SIV/WRAP/CTS、SM4-CCM/XTS、ChaCha20(-Poly1305)、ZUC-128-EEA3、DES/3DES/RC4/DESX。 |
| **摘要算法面** | 铜锁提供 16 个摘要（含 SHA-224/384、SHA-512/224、SHA-512/256、SHA3 四档、SHAKE128/256、KECCAK 四档、SHA-256/192）；本库只有 **MD5 / SHA-1 / SHA-256 / SHA-512 / SM3** 五个独立包，缺 SHA-224、SHA-384、SHA3、SHAKE、KECCAK。 |
| **MAC 与 KDF 面** | 铜锁有 **8 个 MAC** 与 **13 个 KDF**；本库只有 HMAC（6 种摘要）与 HKDF/PBKDF2——`crypto/kdf` 甚至**没有 `Argon2ID` 派生函数**（只有可用性探测），真正派生在 `key.Argon2ID`。 |
| **非对称面** | 铜锁有 RSA / DSA / DH / EC / SM2 / Ed25519(ph/ctx) / Ed448(ph) / X25519 / X448 / ML-DSA / SLH-DSA / Paillier / EC-ElGamal 等；本库覆盖 RSA / ECDSA / SM2 / Ed25519 / Ed448 / X25519 / X448 / ECDH，**缺 DSA、DH、SM2 密钥交换（`SM2DH`）、KEM（`-encap/-decap`）**。 |
| **PQC 面** | 铜锁本机构建**已启用** ML-KEM-512/768/1024（含 5 个混合组）、ML-DSA-44/65/87、SLH-DSA 12 变体；本库**零覆盖**。 |
| **格式容器面** | PKCS#7 本库**只有证书袋**（`Build`/`Extract`），无签名/加密；PKCS#8 缺 `-topk8`/`-v1`/`-v2`/`-v2prf`；PKCS#12 缺 PBE 算法与迭代次数选项；**CMS / CRL→PKCS#7 / NSEQ / SPKAC / storeutl / ts / smime / cmp 全部缺失**。 |
| **CA 工作流面** | 本库有 `x509.CreateCertificate` + `CRL` + `Store.ChainVerify` 等**内存对象级**能力，但**没有** `ca` 那样的数据库化签发/吊销工作流（index.txt / serial / crlnumber / 续期）。 |
| **TLS / NTLS 面** | 本库已覆盖 Dial/Server、NTLS 双证书、版本与套件枚举、`HandshakeContext`、`*HandshakeError`；**缺** ALPN、会话复用与票据、客户端证书认证、服务端 SNI 多证书、`net.Listener` 包装、OCSP stapling、keylog/-msg/-state 调试输出。 |
| **输入输出形态** | **最大的形态落差**：CLI 是「默认 stdin/stdout + `-in/-out` + `-inform/-outform` + `-hex/-binary/-base64` + `-passin/-passout`（`pass:/env:/file:/fd:/stdin`）」，本库是**纯内存 `[]byte` / `(T, error)`**——无文件、无流、无编码助手、无口令来源抽象。 |
| **公开面形态** | 本库**已将 cgo 与原生句柄封在 `internal/`**，但 `internal/core` 的类型仍**通过公开签名泄漏**（`*core.PKey` / `*core.Digest` / `*core.KeyParams` / `*core.Certificate` 等 20+ 处，含公开导出接口 `key.CoreKey`），且大量 API 是**多步组装式**（`NewCertificate()` + 10 个 `Set*` + `Sign()`），与本库「CLI 级应用函数」的目标形态**方向相反**。 |
| **优先级** | Phase 1 采集型小件 → Phase 2 输入输出形态 → Phase 3 算法覆盖 → Phase 4 容器与协议 → Phase 5 传输深度 / PQC / 扩展算法 / 公开面收敛（详见 §8）。 |

一句话：**算法原语侧本库「窄但深」（国密线完整、Go 惯例化），CLI 侧「宽但浅」（56 命令 + 177 cipher + 16 摘要）**；真正的差距不在单个算法，而在**覆盖面**、**输入输出形态**，以及**公开面尚未收敛到目标形态**。

---

## 2. 对比方法与基线

| 项 | 值 |
|---|---|
| **对比基线（CLI）** | `/opt/tongsuo/bin/tongsuo`<br>`Tongsuo: Tongsuo 8.5.0-pre2 (Library: Tongsuo 8.5.0-pre2)`<br>`OpenSSL 3.5.4 3 Aug 2026 (Library: OpenSSL 3.5.4 3 Aug 2026)`<br>`platform: linux-x86_64`，`OPENSSLDIR: "/opt/tongsuo/ssl"` |
| **铜锁源码基线** | `/workspace/opensources/nginx/tongsuo`（`configdata.pm`：`linux-x86_64`，`--prefix=/opt/tongsuo`） |
| **本库基线** | `github.com/blue-cloud-net/tongsuo-go`，CHANGELOG `0.3.0`（2026-09-30 发布） |
| **CLI 侧检索方式** | 实机采集：`tongsuo version -a`、`tongsuo help`、`tongsuo list -commands -1`、`tongsuo list -<family> -1`（14 个族）、`tongsuo list -options <cmd>`（逐命令）、`tongsuo ciphers -v`；并与 `apps/progs.h`、`apps/progs.pl`、`configdata.pm` 交叉校验 |
| **本库侧检索方式** | 全仓库检索导出符号 + `internal/native/binding_*.go`（已绑定的 C 函数）+ 逐符号复核（文件:行） |
| **环境声明** | 本机**已安装铜锁 8.5.0-pre2**，故「CLI 能力」列全部为实机输出；本库侧为**静态检索**，未运行 `go build` / `go vet` / `go test`。 |
| **活跃 provider** | 仅 `default`（`OpenSSL Default Provider 3.5.4`） |
| **本机构建禁用项** | `tongsuo list -disabled` 输出：`RC5`、`SCTP`、`SSL3`、`ZLIB`、`BROTLI`、`ZSTD` |
| **未编译进本机构建的 app** | `bulletproofs`、`mod`(SMTC)、`sdf`、`sm2_threshold`、`delecred`——这五个命令**不在** `tongsuo help` 列表中，需以 `./config enable-*` 重编铜锁后才可验证 |

---

## 3. 定位对比：CLI 命令 vs 本库 API

| 维度 | 铜锁 CLI（`tongsuo`） | 本库（`tongsuo-go`） |
|---|---|---|
| **使用形态** | 命令行子命令 + 选项；一个命令完成一个任务 | Go 函数；**目前多为「多步组装」**，尚未收敛到「一次调用完成一个任务」 |
| **输入** | `-in`（默认 stdin）、`-inform PEM/DER/P12`、`-passin` | `[]byte` 参数、`io.Reader`（仅 TLS）、口令为 `string`/`[]byte` |
| **输出** | `-out`（默认 stdout）、`-outform`、`-hex/-binary/-base64`、`-text/-noout` | 返回值 `[]byte` / 结构体；无编码与落地助手 |
| **错误形态** | 退出码 + stderr 文本 | `(T, error)` + 结构化 `*core.OpError` / `*x509.VerifyError` / `*tls.HandshakeError` |
| **多步流程** | 由选项一次表达（如 `req -x509 -newkey ec -pkeyopt ec_paramgen_curve:SM2 -days 365 -subj ...`） | 需调用方自行串联（`GenerateECKey` → `NewCertificate` → `Set*` → `Sign` → `MarshalPEM`） |
| **状态管理** | 文件系统（index.txt、serial、PEM 文件） | 内存对象 + `Close()` 幂等 + finalizer 兜底 |
| **算法覆盖** | 宽（177 cipher + 16 摘要 + 8 MAC + 13 KDF + PQC + 同态） | 窄而深（国密线完整 + Go 惯例接口） |
| **目标形态** | —— | **CLI 级应用函数**：不提供底层函数、不暴露底层 cgo 函数（见 §6.E 收敛清单） |

---

## 4. CLI 能力清单

### 4.1 普通子命令（56 个）

实机 `tongsuo list -commands -1` 输出 56 项，与 `tongsuo help` 的 Standard commands 段一致：

| 类别 | 子命令 |
|---|---|
| 摘要 / MAC / KDF | `dgst` `mac` `kdf` `speed` |
| 对称编解码 | `enc` |
| 非对称 | `genpkey` `pkey` `pkeyparam` `pkeyutl` `genrsa` `rsa` `rsautl` `gendsa` `dsa` `dsaparam` `dhparam` `ec` `ecparam` `prime` `rand` |
| 铜锁独有 / 扩展 | `ec_elgamal` `paillier` |
| 格式与容器 | `asn1parse` `pkcs7` `crl2pkcs7` `pkcs8` `pkcs12` `nseq` `smime` `spkac` `storeutl` `cms` |
| 证书与 CA | `req` `ca` `x509` `crl` `verify` `ocsp` `cmp` `ts` `rehash` |
| TLS / 网络 | `s_client` `s_server` `s_time` `sess_id` `ciphers` |
| 对称密钥管理 | `skeyutl` |
| 枚举与元信息 | `list` `info` `version` `passwd` `engine` `errstr` `fipsinstall` `help` |

> 铜锁相较上游 OpenSSL 的差异：`rsa` / `genrsa` / `dhparam` / `dsa*` / `gendsa` / `ec` / `ecparam` **未被标记为 deprecated**（`apps/progs.pl` 的 `%cmd_deprecated` 被注释），仅 `rsautl` 仍标 deprecated；新增 `ec_elgamal` 与 `paillier`；`s_client` / `s_server` 增加 NTLS 与国密选项。
>
> **不存在** `openssl sm2` / `openssl sm3` / `openssl sm4` / `openssl sm9` / `openssl ntls` 这类子命令：SM2 以「密钥算法名」暴露，SM4 以 cipher 伪命令暴露，NTLS 是 `s_client` / `s_server` 的开关选项。**铜锁本版本也没有 SM9**（无 `crypto/sm9`、无 `include/openssl/sm9.h`、无 `list` 条目）。

### 4.2 摘要伪命令（15 个，走 `dgst`）

`md5` `sha1` `sha224` `sha256` `sha384` `sha512` `sha512-224` `sha512-256` `sha3-224` `sha3-256` `sha3-384` `sha3-512` `shake128` `shake256` `sm3`

### 4.3 密码伪命令（29 个，走 `enc`）

`aes-128-cbc` `aes-128-ecb` `aes-192-cbc` `aes-192-ecb` `aes-256-cbc` `aes-256-ecb` `base64` `des` `des-cbc` `des-cfb` `des-ecb` `des-ede` `des-ede-cbc` `des-ede-cfb` `des-ede-ofb` `des-ede3` `des-ede3-cbc` `des-ede3-cfb` `des-ede3-ofb` `des-ofb` `des3` `desx` `rc4` `rc4-40` `sm4-cbc` `sm4-cfb` `sm4-ctr` `sm4-ecb` `sm4-ofb`

### 4.4 `list` 的枚举维度（`tongsuo list -options list`）

`commands` / `standard-commands` / `all-algorithms` / `digest-commands` / `digest-algorithms` / `kdf-algorithms` / `random-instances` / `random-generators` / `mac-algorithms` / `cipher-commands` / `cipher-algorithms` / `encoders` / `decoders` / `key-managers` / `skey-managers` / `key-exchange-algorithms` / `kem-algorithms` / `signature-algorithms` / `tls-signature-algorithms` / `asymcipher-algorithms` / `public-key-algorithms` / `public-key-methods` / `store-loaders` / `tls-groups` / `tls1_2` / `tls1_3` / `providers` / `engines` / `disabled` / `objects` / `options <cmd>`

修饰符：`-1`（单列）、`-verbose`、`-select <name>`、`-provider` / `-provider-path` / `-propquery`。

### 4.5 实机算法族清单（摘要）

| 族 | 实机规模 | 关键内容 |
|---|---|---|
| `cipher-algorithms` | 177 行（含 Legacy 段） | AES-128/192/256 × CBC/ECB/OFB/CFB/CFB1/CFB8/CTR/OCB/CCM/GCM/XTS/WRAP/WRAP-PAD/CBC-CTS/SIV/GCM-SIV/CBC-HMAC-SHA1/CBC-HMAC-SHA256；`ChaCha20`、`ChaCha20-Poly1305`；`SM4-CBC/ECB/OFB/CFB/CTR/GCM/CCM/XTS`；`ZUC-128-EEA3`；DES/DES-EDE/DES-EDE3/DESX/RC4/RC4-40 |
| `digest-algorithms` | 71 行（含 Legacy 段） | MD5、MD5-SHA1、SHA1、SHA224、SHA256、SHA384、SHA512、SHA512-224、SHA512-256、SHA3-224/256/384/512、SHAKE128/256、SM3、KECCAK-224/256/384/512、KECCAK-KMAC-128/256、SHA-256/192、NULL，以及 `RSA-SM3` 等 RSA 别名 |
| `mac-algorithms` | 8 | CMAC、GMAC、HMAC、KMAC-128、KMAC-256、SIPHASH、POLY1305、EIA3 |
| `kdf-algorithms` | 13 | HKDF、TLS13-KDF、SSKDF、PBKDF2、PKCS12KDF、SSHKDF、X942KDF-CONCAT/X963KDF、TLS1-PRF、KBKDF、X942KDF/X942KDF-ASN1、SCRYPT、KRB5KDF、HMAC-DRBG-KDF |
| `signature-algorithms` | 59 行 | RSA 族（含 RSA-SHA3-\*、RSA-SM3）、DSA 族（含 SHA2-\*/SHA3-\*）、ED25519/ED25519ph/ED25519ctx/ED448/ED448ph、SM2、ECDSA 族（含 SHA3-\*）、ML-DSA-44/65/87、SLH-DSA 12 变体，以及把 MAC 当作签名算法暴露的 HMAC/SIPHASH/POLY1305/EIA3/CMAC |
| `key-exchange-algorithms` | 8 | DH、X25519、X448、ECDH、**SM2DH**、TLS1-PRF、HKDF、SCRYPT |
| `kem-algorithms` | 12 | RSA、EC、X25519、X448、ML-KEM-512/768/1024、X25519MLKEM768、X448MLKEM1024、SecP256r1MLKEM768、SecP384r1MLKEM1024、curveSM2MLKEM768 |
| `asymcipher-algorithms` | 2 | RSA、SM2 |
| `key-managers` | 126 行 | EC/SM2、ECX（X25519/X448/Ed25519/Ed448）、RSA/DH/DSA、ML-KEM/ML-DSA/SLH-DSA、template |
| `public-key-algorithms` | 179 行 | 上述公私钥算法的 OID ↔ 名称映射 |
| `tls-groups` | 25 组 | secp256r1/384r1/521r1、x25519、x448、brainpoolP256r1tls13/384/512、**curveSM2**、ffdhe2048–8192、MLKEM512/768/1024、SecP256r1MLKEM768、X25519MLKEM768、SecP384r1MLKEM1024、**curveSM2MLKEM768** |
| `ciphers -v` | 70 行 | 含 TLS 1.3 国密套件 `TLS_SM4_GCM_SM3`、`TLS_SM4_CCM_SM3`，与 NTLSv1.1 套件 `ECC-SM2-SM4-GCM-SM3`、`ECDHE-SM2-SM4-GCM-SM3`、`ECC-SM2-SM4-CBC-SM3`、`ECDHE-SM2-SM4-CBC-SM3`、`RSA-SM4-GCM-SHA256`、`RSA-SM4-GCM-SM3`、`RSA-SM4-CBC-SHA256`、`RSA-SM4-CBC-SM3` |

### 4.6 铜锁特有的 CLI 选项（实机核验）

| 命令 | 选项 | 说明 |
|---|---|---|
| `s_client` | `-ntls` `-enable_ntls` `-enable_sm_tls13_strict` `-sign_cert` `-enc_cert` `-alpn` `-no_ticket` `-keylogfile` `-msg` `-state` | NTLS 双证书与国密严格模式 |
| `s_server` | `-ntls` `-enable_ntls` `-enable_force_ntls` `-enable_sm_tls13_strict` `-sign_cert` `-sign_cert2` `-enc_cert` `-enc_cert2` `-sign_certform` `-enc_certform` `-alpn` `-num_tickets` `-stateless` `-www` `-HTTP` | 含 SNI 第二套双证书与 HTTP 演示服务 |
| `ec_elgamal` | `-encrypt` `-decrypt` `-add` `-add_plain` `-sub` `-mul` `-key_in` `-text` | EC-ElGamal 同态运算 |
| `paillier` | `-keygen` `-pubgen` `-key` `-pub` `-encrypt` `-decrypt` `-add` `-add_plain` `-sub` `-mul` `-key_in` | Paillier 同态运算 |
| `genrsa` | `-traditional` `-f4` `-F4` `-3` `-primes` | 传统 PKCS#1 输出与指数/素因子数控制 |
| `pkeyutl` | `-sign` `-verify` `-encrypt` `-decrypt` `-derive` `-decap` `-encap` | 含 KEM 封装/解封装与通用派生 |
| `kdf` | `-kdfopt` `-cipher` `-digest` `-mac` `-keylen` `-binary` | 按算法名选 KDF |
| `mac` | `-macopt` `-cipher` `-digest` `-binary` | 按算法名选 MAC |
| `skeyutl` | `-skeyopt` `-skeymgmt` `-genkey` `-cipher` | 对称密钥对象管理 |
| `cms` | `-encrypt` `-decrypt` `-sign` `-verify` `-resign` `-sign_receipt` `-digest_create` `-digest_verify` | CMS 完整操作族 |
| `enc` | `-d` `-e` `-p` `-P` `-k` `-kfile` `-pass` `-ciphers` `-list` | 对称加解密与口令派生入口 |

---

## 5. 本库能力现状清单

### 5.1 算法原语（`crypto/`）

| 包 | 导出能力 | 缺口要点 |
|---|---|---|
| `crypto/sm3` | `New() hash.Hash`、`Sum(data) [32]byte` | —— |
| `crypto/md5` | `New()`、`Sum(data) [16]byte` | —— |
| `crypto/sha1` | `New()`、`Sum(data) [20]byte` | —— |
| `crypto/sha256` | `New()`、`Sum(data) [32]byte` | 无 SHA-224、无 SHA-384 独立包 |
| `crypto/sha512` | `New()`、`Sum(data) [64]byte` | 无 SHA-512/224、SHA-512/256 |
| `crypto/aes` | `BlockSize`/`NonceSize`/`TagSize`、`NewCipher(key)`（ECB 无填充，实现 `cipher.Block`）、`EncryptECB`/`DecryptECB`、`EncryptCBC`/`DecryptCBC`、`EncryptCTR`/`DecryptCTR`、`EncryptGCM`/`DecryptGCM`、`NewGCM(key)`（实现 `cipher.AEAD`） | **仅 ECB/CBC/CTR/GCM**；**密钥仅 16/32 字节（无 AES-192）**；无 OFB/CFB/CCM/XTS/OCB/SIV/WRAP/CTS |
| `crypto/sm4` | `BlockSize`/`KeySize`/`NonceSize`/`TagSize`、`NewCipher(key)`、`NewGCM(key)`（实现 `cipher.AEAD`）、ECB/CBC（各含 PKCS#7 与 Zero 两套）、`EncryptCTR`/`DecryptCTR`、`EncryptOFB`/`DecryptOFB`、`EncryptCFB`/`DecryptCFB`、`EncryptGCM`/`DecryptGCM` | 无 **CCM**、无 **XTS** |
| `crypto/hmac` | `NewSM3`/`NewMD5`/`NewSHA1`/`NewSHA256`/`NewSHA384`/`NewSHA512`、`SumSM3`/`SumSHA256`/`SumSHA384` | 无 SHA-224；无 CMAC/GMAC/KMAC/SipHash/Poly1305/EIA3 |
| `crypto/kdf` | `HKDF(md, secret, salt, info, length)`、`PBKDF2(md, password, salt, iter, keyLen)`、`Argon2IDAvailable()` | **无 `Argon2ID()` 派生函数**；无 scrypt/SSKDF/TLS1-PRF/X9.42/KBKDF/KRB5KDF/PKCS12KDF |
| `crypto/rand` | `Read(b)`、`Bytes(n)` | 无 base64/hex 输出形态 |
| `crypto/sm2` | `DefaultID`、`GenerateKey`、`LoadPrivateKeyPEM`/`LoadPublicKeyPEM`、`PublicKeyFromPKey`、`Encrypt`/`Decrypt`、`Sign`/`Verify`、`SignWithID`/`VerifyWithID`、`Format`（`der`/`c1c3c2`/`c1c2c3`）、`EncryptWithOrder`/`DecryptWithOrder` | 无加密 PEM 导出、无 PKCS#1、无公钥 DER 导出；**无密钥交换（`SM2DH`）** |
| `crypto/rsa` | `GenerateKey(bits≥1024)`、`LoadPrivateKeyPEM`/`LoadPublicKeyPEM`/`LoadEncryptedPEM`、`ChangePassword`、`MarshalPEM`(PKCS#8)/`MarshalPKCS1PEM`/`MarshalEncryptedPEM(_WithCipher)`、`SignPKCS1v15`/`SignPSS`、`VerifyPKCS1v15`/`VerifyPSS`、`EncryptPKCS1v15`/`DecryptPKCS1v15`、`EncryptOAEP`/`DecryptOAEP`、`Params()`、`Match()` | 无 raw RSA；**OAEP 签名含 `*core.Digest` 参数**（内部类型泄漏）、无 OAEP label/MGF1 选择；无 `-check`/`-pubcheck` 等价；无 PKCS#1 公钥（`RSAPublicKey_in/out`） |
| `crypto/ecdsa` | `GenerateKey(curve)`、`Sign`/`Verify`、PEM 全套、`Params()`、`Match()` | 无 deterministic ECDSA；无曲线参数文件读写 |
| `crypto/ed25519` / `crypto/ed448` | `GenerateKey`、`PrivateKeyFromSeed`、`PublicKeyFromBytes`、`Sign`/`Verify`、PEM 全套、`Seed`/`Bytes`/`Match` | 无 `ph`/`ctx` 变体（CLI 有 `ED25519ph`/`ED25519ctx`/`ED448ph`） |
| `crypto/x25519` / `crypto/x448` | `GenerateKey`、`PrivateKeyFromBytes`/`PublicKeyFromBytes`、`SharedSecret`、PEM 全套、`Match` | —— |
| `crypto/ecdh` | 曲线构造 `P256()`/`P384()`/`P521()`/`Secp256k1()`/`X25519()`/`X448()`、`GenerateKey`、`(*PrivateKey).ECDH`、PEM 全套（**含 SEC1 加载**） | 曲线不含 SM2（SM2 走 `crypto/sm2` 且无 KE） |

### 5.2 密钥统合（`key/`）

| 项 | 现状 |
|---|---|
| 算法常量 | `AlgRSA` `AlgSM2` `AlgECDSA` `AlgED25519` `AlgED448` `AlgX25519` `AlgX448` `AlgAES128` `AlgAES256` `AlgSM4`（**无 AES-192、无 DSA/DH、无 PQC**） |
| 接口 | `Key`、`SymmetricKey`、`AsymmetricKey`、`AsymmetricPrivateKey`、`AsymmetricPublicKey`、**`CoreKey`（公开导出，`Key() *core.PKey`）** |
| 生成 | `GenerateSymmetricKey`、`NewAESKey`(16/32)、`NewSM4Key`(16)、`GenerateRSAKey`、`GenerateSM2Key`、`GenerateECKey`、`GenerateEd25519Key`、`GenerateEd448Key`、`GenerateX25519Key`、`GenerateX448Key` |
| PEM 解析 | `LoadPrivateKeyPEM`（PKCS#8 → 回退 RSA PKCS#1）、`LoadPrivateKeyPEMEncrypted`、`LoadPublicKeyPEM`（SPKI）、`ParsePEM`（仅切块）——**不回退 EC SEC1** |
| 导出 | `Marshal()`(PKCS#8)、`MarshalEncrypted(pass)`（AES-256-CBC + PBKDF2）、`MarshalPKCS1()`、公钥 `Marshal()`(SPKI) |
| KDF | `HashMD5`/`SHA1`/`SHA224`/`SHA256`/`SHA384`/`SHA512`/`SM3`、`HKDF`、`PBKDF2`、`Argon2ID` |
| 生命周期 | `Close(k)`、`NewHandle(id, key)`、`Handle.MarshalJSON`/`UnmarshalJSON`（JSON 内嵌 PEM，对称密钥明文、私钥未加密） |
| 存储 | `Store` 接口 + `NewMemoryStore()`：`Get`/`Put`/`Delete`/`List`/`Rotate`/`History` |

### 5.3 证书（`x509/`）

| 项 | 现状 |
|---|---|
| 加载/导出 | `LoadCertificatePEM`/`LoadCertificateDER`/`WrapCertificate`/`MarshalPEM`/`MarshalDER`/`Core()`（**泄漏 `*core.Certificate`**） |
| 读取 | `Subject`/`Issuer`/`NotBefore`/`NotAfter`/`Serial(int64)`/`Version`、`SubjectName`/`IssuerName`/`SubjectEntries`/`IssuerEntries`/`SubjectText`/`IssuerText` |
| 扩展读取 | `SAN`/`KeyUsage`/`ExtendedKeyUsage`/`IsCA`/`PathLen`/`SubjectKeyID`/`AuthorityKeyID`/`CertificateType()`/`Extensions()`/`Fingerprint(alg)` |
| 构建 | `NewCertificate()` + `SetVersion`/`SetSerial`/`SetIssuer`/`SetSubject`/`SetValidity`/`SetPublicKey`/`AddBasicConstraints`/`AddSubjectAltName`/`AddKeyUsage`/`AddExtendedKeyUsage`/`AddSubjectKeyID`/`AddAuthorityKeyID` + `Sign`；便捷函数 `CreateCertificate(...)` |
| 验签 | `Verify(signerPub)`、`SelfSigned()`、`PublicKey()`(SM2 包装)、`PublicKeyPKey()`(任意算法，**泄漏 `*core.PKey`**)、`Signature()`/`SignatureAlgorithm()`/`SignatureAlgorithmOID()` |
| CSR | `NewCertificateRequest`/`NewEmptyCertificateRequest`/`SetSubject`/`SetPublicKey`/`Sign`/`Verify`/`LoadCertificateRequestPEM`/`LoadCertificateRequestDER`/`MarshalPEM`/`MarshalDER`/`SetChallengePassword`/`AddExtensions`/`AddSubjectAltName`/`Extensions` |
| CRL | `ParseCRL`/`LoadCRLPEM`/`LoadCRLDER`/`MarshalPEM`/`MarshalDER`/`RevokedEntries`/`IsRevoked`/`Verify`/`Extensions`，顶层 `RevocationCheck(cert, crls)` |
| 链验证 | `NewStore`/`AddCert`/`AddCRL`/`SetCRLCheck`/`SetCRLCheckAll`/`SetFlags`/`Core()`、`ChainVerify(cert, roots, intermediates)`、`VerifyError` |
| **缺失** | 主机名/邮箱/IP 校验（`CheckHost`/`CheckIP`/`VerifyHostname`）、任意扩展按 NID+文本添加、`-x509toreq` 等价、`-addtrust`/`-setalias`/`-subject_hash`、`ca` 式数据库工作流、`-attime`/`-crl_download` |

### 5.4 传输（`tls/`）

| 项 | 现状 |
|---|---|
| 配置 | `Config{Cert, Key, NTLS, SignCert, SignKey, EncCert, EncKey, MinVersion, MaxVersion, CipherSuites, RootCAs, InsecureSkipVerify, ServerName}` |
| 客户端 | `Dial`、`DialContext(ctx, ...)` |
| 服务端 | `NewServer(config)`、`(*Server).Accept(raw net.Conn)`（惰性握手）、`Close` |
| 连接 | `Conn` 实现 `net.Conn`：`Read`/`Write`/`Close`（幂等）、`Handshake`/`HandshakeContext`、`LocalAddr`/`RemoteAddr`、`SetDeadline` 系列、`Version()`、`CipherName()`、`PeerCertificates()`、`PeerEncCertificates()` |
| 枚举 | `CipherSuites(version) []CipherSuiteInfo{Name, ID, MinVersion, MaxVersion}`（含 `NTLSVersion = 0x0101`） |
| 错误 | `*HandshakeError{Op, Kind, Err}`、`classifyOpenSSLError`、`ErrClosed`/`ErrVersionNotSupported`/`ErrNoSharedCipher`/`ErrPeerVerification`/`ErrNetwork` |
| **缺失** | ALPN、会话复用（`SSL_SESSION`）、会话票据、客户端证书认证开关、服务端 SNI 多证书、`net.Listener` 包装、OCSP stapling、keylog、重协商控制、`-www`/`-HTTP` 演示服务 |

### 5.5 容器与格式

| 包 | 现状 |
|---|---|
| `pkcs/pkcs7` | `Build(certs)`、`MarshalPEM(der)`、`Extract(data)`——**仅证书袋**；native 已绑 `PKCS7_set_type`/`content_new`/`add_certificate`/`get0_certificates`，但**未暴露签名/加密流程** |
| `pkcs/pkcs12` | `Pack(cert, key, ca, password, name)`、`Parse(data, password)`、`ChangePassword(data, old, new)`、`Bundle{PrivateKey *core.PKey, Certificate, CACerts}`——**无 PBE 算法/迭代/友好名数组选项** |
| `ocsp` | `CreateRequest(cert, issuer, hash)`（`sha1`/`sha256`/`sm3`）、`ParseResponse(der, cert, issuer)`、`Response{Status, CertStatus, RevocationTime, RevocationReason, ThisUpdate, NextUpdate, ResponderCerts}`、`(*Response).Verify(roots, intermediates)`；CertID 自适应 sha1→sha256→sm3——**无 HTTP 传输、无 `-respin`/`-reqin` 文件流程、无 nonce** |
| `jwk` | `Key{Kty, Kid, Use, Alg, N, E, D, P, Q, DP, DQ, QI, Crv, X, Y}`、`Marshal`/`MarshalKey`/`Parse`/`FromPEM`/`MarshalJSON`/`IsPrivate`/`ToPEM`/`ToPublicPEM`——**仅 RSA/EC，无 OKP（Ed25519/X25519）、无对称 octet** |
| `asn1` | `Node{Offset, Tag, Class, Number, Constructed, Length, Value, Children}`、`Parse(der)`、`Dump(node)` + 常量——**纯解码/转储，无编码构造（`-genstr`/`-genconf` 无对应）、无 `-strparse` 子结构定位** |
| `xml/rsa` | `MarshalPrivate`/`MarshalPublic`/`UnmarshalPrivate`/`UnmarshalPublic`（.NET `RSAKeyValue`）；`xml/doc.go` 为命名空间占位 |

### 5.6 内部层已绑定面（`internal/native`）

| binding 文件 | 已绑定家族 |
|---|---|
| `binding_digest.go` | `EVP_sm3/md5/sha1/sha224/sha256/sha384/sha512`、`EVP_MD_get_size/block_size`、`EVP_MD_CTX_new/free/copy_ex`、`EVP_DigestInit_ex/Update/Final_ex`、`EVP_DigestSign`/`EVP_DigestVerify` |
| `binding_cipher.go` | `EVP_sm4_{ecb,cbc,ctr,ofb,cfb128,gcm}`、`EVP_aes_{128,256}_{ecb,cbc,ctr,gcm}`、`EVP_CIPHER_CTX_{new,free,copy,ctrl,set_padding}`、`EVP_CIPHER_get_{block_size,key_length,iv_length}`、`EVP_CipherInit_ex`、`EVP_EncryptUpdate`/`DecryptUpdate`/`EncryptFinal_ex`/`DecryptFinal_ex` |
| `binding_pkey.go` | `EVP_PKEY_*`（`free/dup/eq/size`、`get_*_param`）、`EVP_PKEY_CTX_*`（`new_from_pkey/free/set1_id/set_rsa_padding/set_rsa_pss_saltlen/set_rsa_mgf1_md/set_rsa_oaep_md`）、`EVP_PKEY_{encrypt,decrypt,derive}*`、`EVP_DigestSign*`/`EVP_DigestVerify*`、`EVP_PKEY_new_raw_*`/`get_raw_*`、`I2d_PUBKEY`/`I2d_PrivateKey`/`D2i_PrivateKey`、`X_PEM_read/write_bio_*`、`X_EVP_PKEY_Q_keygen_{sm2,rsa,ec,ed25519,ed448,x25519,x448}` |
| `binding_hmac.go` | `HMAC_CTX_new/free/copy`、`HMAC_Init_ex/Update/Final` |
| `binding_kdf.go` | shim `X_EVP_KDF_HKDF`、`X_EVP_KDF_PBKDF2`、`X_EVP_KDF_available`（内部走 `EVP_KDF_fetch`） |
| `binding_rand.go` | `RAND_bytes` |
| `binding_bio.go` | `BIO_s_mem`/`BIO_new`/`BIO_new_mem_buf`/`BIO_free`/`BIO_read`/`BIO_write` |
| `binding_error.go` | `ERR_get_error` 家族、`ERR_error_string`、`OPENSSL_cleanse` |
| `binding_version.go` | `OpenSSL_version`、`OpenSSL_version_num`、`Tongsuo_version_num` |
| `binding_x509.go` | `OBJ_*`、`X509_NAME_*`、`X509_*`（new/free/dup/set/get/sign/verify/sign_ctx）、`X509V3_EXT_conf_nid*`、`X509_add_ext`、`X509_EXTENSION_*`、`I2d_X509`/`D2i_X509`、`X509_digest`、`X509_get_san/key_usage/eku/basic_constraints`、`X509_REQ_*`、`X509_STORE_*`/`X509_STORE_CTX_*`/`X509_verify_cert`、`X509_CRL_*`、`X509_REVOKED_*`、sk 辅助族、`X_PEM_read/write_bio_X509(_REQ/_CRL)` |
| `binding_ssl.go` | `TLS_client_method`/`TLS_server_method`/`NTLS_method`、`SSL_CTX_new/free`、`SSL_CTX_enable_ntls`、`SSL_CTX_get_cert_store`、`SSL_CTX_set_cipher_list`/`set_ciphersuites`/`set_min_proto_version`/`set_max_proto_version`/`set_verify`/`set_verify_depth`/`set_default_verify_paths`/`get_ciphers`、`SSL_CTX_use_{certificate,PrivateKey,sign_certificate,enc_certificate,sign_PrivateKey,enc_PrivateKey}`、`SSL_CTX_check_private_key`、`SSL_new/free/set_fd/connect/accept/shutdown/read/write/get_error/get_version/get_current_cipher_name/get_verify_result/get_peer_certificate/get_peer_cert_chain`、`SSL_set1_host`、`SSL_set_tlsext_host_name`、`SSL_CIPHER_*` |
| `binding_pkcs.go` | `PKCS12_free`、`I2d_PKCS12`/`D2i_PKCS12`、`PKCS12_newpass`/`set_mac`、shim `X_PKCS12_create`/`X_PKCS12_parse`；`PKCS7_new/free/set_type/content_new/add_certificate/get0_certificates`、`I2d_PKCS7`/`D2i_PKCS7` |
| `binding_ocsp.go` | `OCSP_cert_to_id`、`OCSP_CERTID_free`、`OCSP_REQUEST_new/free/add0_id`、`I2d_OCSP_REQUEST`、`D2i_OCSP_RESPONSE`、`OCSP_RESPONSE_*`、`OCSP_basic_verify`、`OCSP_cert_status_str`、`OCSP_crl_reason_str` |

`internal/core` 的包装类型：`Handle`、`OpError`、`Digest`、`DigestCtx`、`Cipher`、`CipherCtx`、`HmacCtx`、`PKey`、`KeyParams`、`Name`、`Certificate`、`CertificateRequest`、`Extension`、`Store`、`VerifyError`、`RevokedEntry`、`CRL`、`MemBIO`、`PKCS12`、`PKCS7`、`OCSPRequest`、`OCSPResponse`、`CertStatus`、`TLSContext`、`SSLConn`、`CipherInfo`。

**未绑定/未暴露**：`SSL_SESSION_*`、`SSL_CTX_set_alpn*`、`SSL_CTX_set_tlsext_ticket_key_cb`、`SSL_CTX_set_tlsext_status*`（OCSP stapling）、`SSL_CTX_set_client_CA_list`、`CMS_*`、`OSSL_STORE_*`、`TS_*`、`EVP_MAC_*`、`EVP_PKEY_encapsulate/decapsulate`、`EVP_*_xts/ccm/ocb/wrap`、除 HKDF/PBKDF2 之外的 `EVP_KDF` 算法、`EVP_aes_192_*`、`EVP_aes_*_ofb/cfb`、`EVP_chacha20*`、`EVP_sm4_ccm/xts`、`ZUC`、SM9、Paillier/EC-ElGamal、ML-KEM/ML-DSA/SLH-DSA、白盒 SM4。

---

## 6. 缺口矩阵

判定三档：**✅ 已对齐**（能力等价且形态可用） / **⚠️ 部分对齐**（能力在但覆盖面或形态不足） / **❌ 缺失**。
优先级四档：**P0**（高频刚需，直接影响「像 CLI 一样直接用」）/ **P1**（典型用法必备）/ **P2**（边缘或被间接覆盖）/ **P3**（不做或明确后置）。

### 6.A 子命令总表（56 个普通子命令）

| # | 子命令 | CLI 核心能力（实机选项） | 本库现状 | 判定 | 优先级 | 做或不做的理由 |
|---|---|---|---|---|---|---|
| 1 | `asn1parse` | DER 结构解析、`-strparse` 子结构定位、`-genstr`/`-genconf` 构造 | `asn1.Parse` / `asn1.Dump`（纯 Go） | ⚠️ | P1 | 缺**生成**与**子解析**；「解读一段 DER」已具备 |
| 2 | `ca` | CA 数据库化签发/吊销/续期（index.txt、serial、crlnumber） | `x509.CreateCertificate` + `CRL` + `Store`（纯内存对象） | ❌ | P1 | 缺状态化工作流；本质是「文件系统 + 策略」，与内存模型冲突，须先定形态 |
| 3 | `ciphers` | TLS 套件枚举与名称转换（`-v`/`-V`/`-stdname`/`-convert`） | `tls.CipherSuites(version)`（含 NTLS） | ⚠️ | P2 | 枚举已覆盖，缺 name↔ID 双向转换 |
| 4 | `cmp` | CMP（RFC 4210）客户端/服务端 | 无 | ❌ | P3 | 协议栈重、无 Go 标准对应；不做 |
| 5 | `cms` | CMS 签名/加密/验签/解封装/回执 | 无 | ❌ | P2 | 与 PKCS#7 同源，应在 PKCS#7 之后 |
| 6 | `crl` | CRL 签发（config 驱动）、解析、`-hash_old`、`-nameopt` | `ParseCRL`/`Load*`/`Marshal*`/`RevokedEntries`/`IsRevoked`/`Verify`/`RevocationCheck` | ⚠️ | P1 | 缺「按配置签发 CRL」的应用级入口与 `-nameopt` 形式 |
| 7 | `crl2pkcs7` | CRL（+证书）打包为 PKCS#7 | 无 | ❌ | P2 | 依赖 PKCS#7 签名族 |
| 8 | `dgst` | 摘要 / HMAC / 签名 / 验签 / `-binary`/`-hex`/`-r`/`-C` / 文件输入 | 各摘要包 `Sum` + `hmac.*` + 各算法 `Sign`/`Verify` | ⚠️ | **P0** | 缺「按算法名 + 输入源 + 输出编码」的单一入口；CLI 最常用命令 |
| 9 | `dhparam` | DH 参数生成/校验 | 无 | ❌ | P3 | 经典 DH 非目标场景 |
| 10 | `dsa` | DSA 密钥查看/转换/`-text` | 无（native 有 `EvpPkeyDSA` 常量但无 API） | ❌ | P3 | 非国密目标场景 |
| 11 | `dsaparam` | DSA 参数生成 | 无 | ❌ | P3 | 同上 |
| 12 | `ec` | EC/SM2 密钥查看与转换（`-param_enc`/`-conv_form`/`-check`/`-param_out`） | `key.GenerateECKey` / `ecdsa` / `ecdh` 的 PEM 读写 | ⚠️ | P1 | 缺参数形式、点压缩控制与 `-check` |
| 13 | `ec_elgamal` | EC-ElGamal 同态（加解密/加/减/标量乘） | 无 | ❌ | P2 | 铜锁独有；Go 侧无惯例接口，须先定形态 |
| 14 | `ecparam` | 曲线参数文件生成与 `-list_curves` | 无（仅按曲线名生成密钥） | ❌ | P2 | 缺曲线枚举与参数文件读写 |
| 15 | `enc` | 按 cipher 伪命令加解密、口令派生（`-k`/`-kfile`/`-pass`）、base64/zlib | `crypto/aes` / `crypto/sm4` 各模式一次性函数 | ⚠️ | **P0** | 缺「算法名 + 模式」统一入口、口令派生、base64、`-nopad`/`-nosalt` |
| 16 | `engine` | ENGINE 加载与管理 | 无 | ❌ | P3 | 已被 provider 取代；不做 |
| 17 | `errstr` | 错误码 → 文本 | `*core.OpError`（含 code，但无按库/原因查询） | ❌ | P2 | 缺错误码解析入口 |
| 18 | `fipsinstall` | FIPS provider 安装自检 | 无 | ❌ | P3 | 本机构建 `fips` 未启用；不做 |
| 19 | `gendsa` | DSA 密钥生成 | 无 | ❌ | P3 | 非目标场景 |
| 20 | `genpkey` | 任意算法生成 + `-pkeyopt` + `-genparam` + 加密输出 | 各算法 `Generate*` + `MarshalEncrypted` | ⚠️ | P1 | 缺统一入口、参数集生成、`-pkeyopt` 透传、PQC 算法 |
| 21 | `genrsa` | RSA 生成（`-traditional`/`-f4`/`-3`/`-primes`） | `rsa.GenerateKey` / `key.GenerateRSAKey` + `MarshalPKCS1PEM` | ⚠️ | P2 | `-traditional` 可表达；缺指数与素因子数控制 |
| 22 | `help` | 命令帮助 / `list -options <cmd>` | 不适用 | — | — | 本库无 CLI |
| 23 | `info` | 构建信息（modulesdir/enginesdir/seeds/cpu） | 无（`internal/core.VersionText` 等**未导出**） | ❌ | P2 | 连版本查询都没有公开 API |
| 24 | `kdf` | 13 种 KDF，按算法名 + `-kdfopt` | `crypto/kdf`（HKDF/PBKDF2/`Argon2IDAvailable`）+ `key.KDF` | ⚠️ | P1 | 覆盖 2/13；缺 scrypt/SSKDF/TLS1-PRF/X9.42/KBKDF/KRB5KDF/PKCS12KDF 与按名分发 |
| 25 | `list` | 算法/provider 全量枚举（31 个维度） | 仅 `tls.CipherSuites` | ⚠️ | P1 | 缺对称/摘要/MAC/KDF/签名/密钥交换/KEM 的枚举 API |
| 26 | `mac` | 8 种 MAC，按算法名 + `-macopt` | 仅 HMAC（6 摘要） | ❌ | P1 | 缺 CMAC/GMAC/KMAC/SipHash/Poly1305/EIA3 |
| 27 | `nseq` | Netscape 证书序列读写 | 无 | ❌ | P3 | 历史格式；不做 |
| 28 | `ocsp` | 请求生成/响应解析/验签/**HTTP 传输**（`-url`/`-host`/`-port`/`-timeout`） | `CreateRequest` / `ParseResponse` / `Verify` | ⚠️ | P1 | 缺网络层与文件流程；「能发出去」是应用级刚需 |
| 29 | `paillier` | Paillier 同态（密钥生成/加解密/加/减/标量乘） | 无 | ❌ | P2 | 铜锁独有；须先定形态 |
| 30 | `passwd` | 口令 hash（crypt/bcrypt/PBKDF2 形态） | 无 | ❌ | P2 | 与密码学库职责边界需先明确 |
| 31 | `pkcs12` | 打包/解析/改密（`-legacy`/`-twopass`/`-noiter`） | `Pack` / `Parse` / `ChangePassword` | ⚠️ | P1 | 缺 PBE 算法与迭代次数控制、读写口令分离 |
| 32 | `pkcs7` | 签名/验签/加密/解密/`-print_certs` | `Build` / `Extract` / `MarshalPEM`（**仅证书袋**） | ⚠️ | P1 | 缺签名与加密族；native 已有 `PKCS7_set_type`/`signedData` 基础 |
| 33 | `pkcs8` | PKCS#8 加解密与 PKCS#1↔PKCS#8（`-topk8`/`-v1`/`-v2`/`-v2prf`） | PKCS#8 与加密 PKCS#8 读写（各算法 `MarshalEncryptedPEM`、`key.MarshalEncrypted`） | ⚠️ | P1 | 缺 `-topk8` 双向转换与版本/PRF 选择 |
| 34 | `pkey` | 任意算法密钥查看/转换/`-check`/`-pubcheck` | 各算法各自的 PEM 读写 | ⚠️ | P1 | 缺统一入口与 `-check`/`-pubcheck` 等价 |
| 35 | `pkeyparam` | 密钥参数文件读写 | 无 | ❌ | P2 | 依赖 `ecparam`/`dsaparam`，随其一起 |
| 36 | `pkeyutl` | 签名/验签/加解密/**derive**/**encap/decap** | 各算法 `Sign`/`Verify`/`Encrypt`/`Decrypt`；`ecdh` 有 ECDH、`x25519`/`x448` 有 `SharedSecret` | ⚠️ | P1 | 缺 **SM2DH**、**KEM（ML-KEM/RSA/EC）**、`-rawin`、`-verifyrecover` |
| 37 | `prime` | 大素数生成/判定 | 无 | ❌ | P3 | 工具型；不做 |
| 38 | `rand` | 随机数（`-hex`/`-base64`/`-out`） | `rand.Read` / `rand.Bytes` | ⚠️ | P2 | 能力已有，缺输出编码 |
| 39 | `rehash` | 证书目录 hash 索引（c_rehash） | 无 | ❌ | P3 | 文件系统工具；不做 |
| 40 | `req` | CSR 生成/查看/验签/**一行自签证书**（`-x509`）/config 驱动 | `NewCertificateRequest` + `Sign`/`Verify`/`Marshal*`；自签走 `CreateCertificate` | ⚠️ | **P0** | 缺「一行完成」入口与 config 驱动；`req -x509` 是最常用命令之一 |
| 41 | `rsa` | RSA 密钥查看/转换（`-text`/`-check`/`-RSAPublicKey_in`/`-RSAPublicKey_out`） | `LoadPrivateKeyPEM` / `MarshalPKCS1PEM` / `Params()` | ⚠️ | P1 | 缺 PKCS#1 公钥形态与 `-check` |
| 42 | `rsautl` | 旧式 RSA 工具（deprecated） | `rsa` 的 PKCS1v15 族已覆盖功能 | ❌ | P3 | 明确不做（已被 `pkeyutl`/`rsa` 取代） |
| 43 | `s_client` | TLS/NTLS 客户端（`-ntls`/`-sign_cert`/`-enc_cert`/`-alpn`/`-keylogfile`/`-msg`/`-state`） | `tls.Dial` / `tls.DialContext` + NTLS 双证书 | ⚠️ | P1 | 缺 ALPN、客户端证书、调试输出、会话复用 |
| 44 | `s_server` | TLS/NTLS 服务端（`-sign_cert2`/`-www`/`-HTTP`/`-stateless`/`-num_tickets`） | `tls.NewServer` / `(*Server).Accept` | ⚠️ | P1 | 缺 `net.Listener` 包装、SNI 多证书、客户端认证、HTTP 演示 |
| 45 | `s_time` | 握手计时/吞吐 | 无（可用 Go benchmark 代） | ❌ | P3 | 不做 |
| 46 | `sess_id` | SSL_SESSION 读写/转换 | 无（`SSL_SESSION_*` 未绑定） | ❌ | P2 | 会话复用缺失的连带缺口 |
| 47 | `skeyutl` | 对称密钥对象（`-genkey`/`-skeyopt`/`-cipher`） | `key.AESKey` / `key.SM4Key` / `key.Handle` | ⚠️ | P2 | 已有对称密钥抽象；缺参数化与导入导出形态 |
| 48 | `smime` | S/MIME 签名/加密/封装 | 无 | ❌ | P3 | 依赖 CMS；不做 |
| 49 | `speed` | 算法基准 | 各包 `Benchmark*` 测试 | ❌ | P3 | 用 Go benchmark 替代；不做 |
| 50 | `spkac` | SPKAC 证书请求 | 无 | ❌ | P3 | 历史格式；不做 |
| 51 | `srp` | SRP 口令认证 | 无 | ❌ | P3 | 不做 |
| 52 | `storeutl` | OSSL_STORE URI 读取（`file:` 等） | 无 | ❌ | P2 | 与「文件输入」形态同源，Phase 2 后重新评估 |
| 53 | `ts` | 时间戳协议（RFC 3161） | 无 | ❌ | P2 | 协议栈重，且需 TSA 服务端配合 |
| 54 | `verify` | 证书链验证（`-CAfile`/`-untrusted`/`-attime`/`-crl_download`/`-show_chain`） | `x509.ChainVerify` / `x509.Store` | ⚠️ | P1 | 缺 `-attime`（指定验证时刻）、`-crl_download`、链输出 |
| 55 | `version` | 版本/构建信息 | `internal/core.VersionText`（**未导出**） | ❌ | P1 | 一行代码的缺口，却是最基础的元信息 |
| 56 | `x509` | 证书查看/转换/签发/指纹/`-x509toreq`/`-addtrust`/`-subject_hash` | 解析/创建/签发/`Fingerprint`/扩展读写 | ⚠️ | P1 | 缺 `-x509toreq`、信任属性、`subject_hash`、`-ocspid` |

**按优先级统计**：**P0 3 项**（`dgst`、`enc`、`req`）；**P1 20 项**；**P2 16 项**；**P3 16 项**；不适用 1 项（`help`）。

### 6.B 用户任务场景矩阵（细粒度）

> 本表以「用户想完成的一件事」为行，对齐本库「CLI 级应用函数」的目标形态。CLI 命令是**同一个任务可以由多条命令/多组选项完成**，这里只取最典型的一条。

| # | 任务场景 | CLI 做法 | 本库做法 | 判定 | 优先级 |
|---|---|---|---|---|---|
| B1 | 按算法名对文件/字节求摘要，输出 hex 或 raw | `dgst -sm3 -hex file` | `sm3.Sum(data)`（调用方自行读文件与编码） | ⚠️ | **P0** |
| B2 | 用密钥文件对文件签名/验签（RSA/SM2/ECDSA/EdDSA），输出 DER 或 base64 | `dgst -sm3 -sign key.pem -out sig file` | 先 `LoadPrivateKeyPEM` 再 `Sign`，再自行编码 | ⚠️ | **P0** |
| B3 | 按「算法 + 模式 + IV/口令」加解密数据 | `enc -sm4-cbc -k pass -pbkdf2 -in f -out g` | `sm4.EncryptCBC(key, iv, data)`（IV/密钥由调用方推导） | ⚠️ | **P0** |
| B4 | 一行生成自签证书 | `req -x509 -newkey ec -pkeyopt ec_paramgen_curve:SM2 -days 365 -subj "..." -keyout k -out c` | `GenerateECKey` → `NewCertificate` → `Set*`（≈10 步）→ `Sign` → `MarshalPEM` | ❌ | **P0** |
| B5 | 由已有密钥生成 CSR | `req -new -key k.pem -subj "..." -out csr.pem` | `NewCertificateRequest(subject, pub, priv)` | ⚠️ | P1 |
| B6 | 用 CA 签发证书（含 serial/有效期/扩展） | `x509 -req -CA ca.pem -CAkey ca.key -CAcreateserial -days 365 -extfile x.cnf` | `CreateCertificate(...)` + 扩展 `Add*` | ⚠️ | P1 |
| B7 | 校验证书链（受信根 + 中间 + 叶子） | `verify -CAfile ca.pem -untrusted i.pem leaf.pem` | `x509.ChainVerify(cert, roots, intermediates)` | ⚠️ | P1 |
| B8 | 校验证书主机名/IP | `verify -verify_hostname h -CAfile ca.pem leaf.pem` | **无对应 API** | ❌ | P1 |
| B9 | 生成 CRL 并检查吊销 | `ca -gencrl -config x.cnf -out c.crl` / `crl -verify` | `x509.NewCRL` + `Add*` + `Sign`；`RevocationCheck(cert, crls)` | ⚠️ | P1 |
| B10 | PEM ↔ DER ↔ PKCS#1 ↔ PKCS#8 ↔ SPKI 格式互转 | `pkcs8 -topk8` / `pkey -outform DER` / `rsa -RSAPublicKey_out` | 各算法 `MarshalPEM`/`MarshalPKCS1PEM`/`MarshalPKCS8`；**无 `-topk8` 等价、无 PKCS#1 公钥** | ⚠️ | P1 |
| B11 | PKCS#12 打包/解包/改密 | `pkcs12 -export -in c -inkey k -certfile ca -passout pass:x` | `pkcs12.Pack` / `Parse` / `ChangePassword` | ⚠️ | P1 |
| B12 | PKCS#7 签名/验签/加解密 | `pkcs7 -sign -in f -signer c -inkey k -out s.p7` | **仅证书袋** `Build`/`Extract` | ❌ | P1 |
| B13 | OCSP 查证书状态（含网络请求） | `ocsp -issuer i.pem -cert c.pem -url http://... -respout r` | `CreateRequest` → **调用方自行发 HTTP** → `ParseResponse` → `Verify` | ⚠️ | P1 |
| B14 | 按算法名计算 MAC | `mac -macopt cipher:SM4 -macopt hexkey:... GMAC -in f` | 仅 HMAC（`hmac.NewSM3` 等） | ❌ | P1 |
| B15 | 按算法名做密钥派生 | `kdf -kdfopt digest:SM3 -kdfopt hexkey:... HKDF -out k 32` | `kdf.HKDF` / `kdf.PBKDF2`（无按名分发，无 scrypt/SSKDF/…） | ⚠️ | P1 |
| B16 | 枚举可用算法与 TLS 套件 | `list -cipher-algorithms` / `ciphers -v` | 仅 `tls.CipherSuites(version)` | ⚠️ | P1 |
| B17 | TLS/NTLS 连通性检查与协议信息 | `s_client -connect h:p -ntls -enable_ntls -sign_cert ... -tls1_3` | `tls.Dial*` + `Version()`/`CipherName()`/`PeerCertificates()` | ⚠️ | P1 |
| B18 | NTLS 双证书服务端与客户端互操作 | `s_server -ntls -enable_ntls -sign_cert ... -enc_cert ...` | `tls.Config{NTLS, SignCert, SignKey, EncCert, EncKey}` | ✅ | — |
| B19 | 打印证书/CSR/CRL 的可读结构 | `x509 -text` / `req -text` / `crl -text` | `SubjectText`/`IssuerText`/`Extensions`；私钥无等价 dump | ⚠️ | P1 |
| B20 | ASN.1 结构解读与定位子结构 | `asn1parse -i -dump file` / `-strparse` | `asn1.Parse` + `asn1.Dump`（**无 `-strparse`**，无 `-dump` 十六进制视图） | ⚠️ | P2 |
| B21 | 生成随机数并输出 hex/base64 | `rand -hex 32` / `rand -base64 32` | `rand.Bytes(32)`（调用方自行编码） | ⚠️ | P2 |
| B22 | base64 编解码 | `base64 -in f` / `enc -a` | **无对应 API** | ❌ | P2 |
| B23 | 错误码 → 文本 | `errstr <hex>` | `*core.OpError` 含 code，但无按 code 反查 | ❌ | P2 |
| B24 | 读取运行时/构建版本信息 | `version -a` / `info -c` | **无公开 API**（`internal/core` 内有实现但未导出） | ❌ | P1 |
| B25 | 从 URI/文件统一加载密钥或证书 | `storeutl file:k.pem` | 各自 `Load*` 函数，无统一加载器 | ❌ | P2 |

### 6.C 输入输出形态对照（「像 CLI 一样直接用」的核心落差）

| # | 维度 | CLI 行为（实机核验） | 本库现状 | 判定 | 优先级 |
|---|---|---|---|---|---|
| C1 | 默认输入流 | 多数命令 `-in` **默认 stdin** | 无；一律 `[]byte` 参数 | ❌ | **P0** |
| C2 | 默认输出流 | 多数命令 `-out` **默认 stdout** | 无；一律返回值 | ❌ | **P0** |
| C3 | 文件读写 | `-in`/`-out` 直接吃路径 | 无；`os.ReadFile`/`os.WriteFile` 由调用方自理 | ❌ | P1 |
| C4 | 编码格式 | 各命令独立 `-inform`/`-outform`（`PEM`/`DER`/`P12`/`ENGINE`） | 各类型有 `MarshalPEM`/`MarshalDER`，但**无统一 `Format` 维度**，且需自行 `pem.Decode`/`pem.Encode` | ⚠️ | P1 |
| C5 | 输出编码 | `dgst -binary`/`-hex`/`-r`/`-C`、`rand -hex`/`-base64`、`pkeyutl -hexdump`、`-text`/`-noout` | 仅 `asn1.Dump` 内部做十六进制；**无 hex/base64/hexdump 助手** | ❌ | P1 |
| C6 | Base64 | `base64` 伪命令、`enc -a`/`-A` | 无 | ❌ | P2 |
| C7 | 压缩 | `enc -z`（zlib）、`brotli`/`zstd` 伪命令 | 无（本机构建 `ZLIB`/`BROTLI`/`ZSTD` 均 disabled） | ❌ | P3 |
| C8 | 口令来源 | 统一 `-passin`/`-passout`，支持 `pass:`/`env:`/`file:`/`fd:`/`stdin` | 仅接受 `string`/`[]byte` 明文口令；无来源抽象、无读写口令分离 | ❌ | P1 |
| C9 | 口令用于 pkeyopt | `-pkeyopt_passin` | 无 | ❌ | P3 |
| C10 | 二进制/结构化输出选择 | `-text` 打印结构、`-noout` 抑制主体输出 | 部分类型有文本视图（`SubjectText` 等）；无统一开关 | ⚠️ | P2 |
| C11 | 流式管道 | 完全支持管道串联（如 `genpkey` 的输出直接管道给 `asn1parse`） | 仅 `tls.Conn` 与 `hash.Hash` 是流式；其余一次性 | ⚠️ | P2 |
| C12 | 交互模式 | 无参数进入交互 prompt（`help`/`list`/`quit`） | 不适用（库形态） | — | — |
| C13 | provider/属性查询 | 全体命令带 `-provider`/`-provider-path`/`-propquery` | 无（provider 固定为 default） | ❌ | P3 |

### 6.D 铜锁独有 / 扩展能力

| # | 能力 | 铜锁实机状态 | 本库现状 | 判定 | 优先级 |
|---|---|---|---|---|---|
| D1 | **ML-KEM**（ML-KEM-512/768/1024） | 已启用（`kem-algorithms`） | 无 | ❌ | P2 |
| D2 | **ML-KEM 混合组**（X25519MLKEM768、X448MLKEM1024、SecP256r1MLKEM768、SecP384r1MLKEM1024、curveSM2MLKEM768） | 已启用（`kem-algorithms` + `tls-groups`） | 无 | ❌ | P2 |
| D3 | **ML-DSA**（ML-DSA-44/65/87） | 已启用（`signature-algorithms`） | 无 | ❌ | P2 |
| D4 | **SLH-DSA**（SHA2/SHAKE × 128/192/256 × s/f，共 12 变体） | 已启用（`signature-algorithms`） | 无 | ❌ | P2 |
| D5 | **Paillier 同态** | 已启用（`paillier` 命令） | 无 | ❌ | P2 |
| D6 | **EC-ElGamal 同态** | 已启用（`ec_elgamal` 命令） | 无 | ❌ | P2 |
| D7 | **SM2DH 密钥交换** | 已启用（`key-exchange-algorithms`） | 无 API（`EVP_PKEY_derive*` 已绑定，但无 SM2 派生入口） | ❌ | P1 |
| D8 | **ZUC-128-EEA3** | 已启用（`cipher-algorithms`） | 无 | ❌ | P2 |
| D9 | **EIA3 MAC** | 已启用（`mac-algorithms`） | 无 | ❌ | P2 |
| D10 | **SM4-CCM / SM4-XTS** | 已启用（`cipher-algorithms`） | 无（仅 ECB/CBC/CTR/OFB/CFB/GCM） | ❌ | P1 |
| D11 | **curveSM2 TLS 组** | 已启用（`tls-groups`） | 间接（作为 `CipherSuites` 探测结果可见，无显式组配置） | ⚠️ | P2 |
| D12 | TLS 1.3 国密套件（`TLS_SM4_GCM_SM3`/`TLS_SM4_CCM_SM3`） | 已启用（`ciphers -v`） | 可枚举（`CipherSuites(TLS1_3)`），可用性取决于铜锁与配置 | ⚠️ | P2 |
| D13 | NTLSv1.1 套件（`ECC-SM2-SM4-*`、`ECDHE-SM2-SM4-*`、`RSA-SM4-*`） | 已启用（`ciphers -v`） | `CipherSuites(NTLSVersion)` 可枚举；`Config{NTLS}` 可协商 | ✅ | — |
| D14 | **白盒 SM4**（`wbsm4`/`wbsm4kdf`） | **未启用**（`cipher-algorithms` 无条目，`wbsm4-xiaolai/baiwu/wsise` 均 disabled） | 无 | ❌ | P3（需重编铜锁） |
| D15 | **Bulletproofs / R1CS** | **未编译**（`bulletproofs` 不在命令列表） | 无 | ❌ | P3（需重编铜锁） |
| D16 | **SM2 门限签名/解密** | **未编译**（`sm2_threshold` 不在命令列表） | 无 | ❌ | P3（需重编铜锁） |
| D17 | **SDF 密码设备接口** | **未编译**（`sdf` 不在命令列表） | 无 | ❌ | P3（需重编铜锁） |
| D18 | **SMTC 模块管理** | **未编译**（`mod` 不在命令列表） | 无 | ❌ | P3（需重编铜锁） |
| D19 | **Delegated Credential**（RFC 9345） | **未编译**（`delecred` 不在命令列表） | 无 | ❌ | P3（需重编铜锁） |
| D20 | **SM9** | **铜锁本版本无**（无 `crypto/sm9`、无 `sm9.h`、无 `list` 条目） | 无 | — | — |
| D21 | KECCAK-224/256/384/512、SHA-256/192 | 已启用（`digest-algorithms`） | 无 | ❌ | P2 |
| D22 | AES-OCB / SIV / GCM-SIV / WRAP / CBC-CTS | 已启用（`cipher-algorithms`） | 无 | ❌ | P2 |
| D23 | ChaCha20 / ChaCha20-Poly1305 | 已启用（`cipher-algorithms`） | 无 | ❌ | P2 |

### 6.E 现有底层 API 收敛清单

> 本库的目标形态是 **CLI 级应用函数**：不提供底层函数、不暴露底层 cgo 函数。下表列出**与目标形态偏离**的现有公开面。**均为破坏性变更**；表中不给替代签名（本报告不设计 API），只标「破坏性等级」与「迁移要点」。
>
> 破坏性等级：**高**（公开签名直接引用不可导入的内部类型，调用方无法自行构造）/ **中**（公开面存在但语义偏底层，可直接替换）/ **低**（形态调整，功能等价）。

#### E1 内部类型泄漏（`internal/core` 出现在公开签名中）

| # | 位置（公开符号） | 泄漏类型 | 破坏性 | 迁移要点 |
|---|---|---|---|---|
| E1-1 | `key.CoreKey`（**公开导出接口**）及其内嵌者 `key.AsymmetricKey` / `key.PrivateKey` / `key.PublicKey` | `Key() *core.PKey` | 高 | 该接口是 `pkcs12.PrivateKey`、`jwk.MarshalKey` 的参数类型；收敛需同时处理这三处调用方 |
| E1-2 | `crypto/rsa.EncryptOAEP(pub, data, md *core.Digest)` / `DecryptOAEP` | **函数参数**即内部类型 | 高 | 调用方必须持有 `*core.Digest`（本库根本未公开其构造函数），实际不可用；应改为算法名等公开取值 |
| E1-3 | `crypto/{ecdsa,rsa}` 的 `(*PrivateKey).Params()` / `(*PublicKey).Params()` → `*core.KeyParams` | 返回值 | 高 | 与 `key` 包的参数视图重复；应统一到公开类型 |
| E1-4 | `crypto/{ecdh,ecdsa,ed25519,ed448,rsa,sm2,x25519,x448}` 的 `(*PrivateKey).Key()` / `(*PublicKey).Key()` → `*core.PKey` | 返回值（8 个包 × 2 ≈ 16 处） | 中 | 若保留则等于「对外提供底层句柄」；应收进 `internal` 或仅以受控形态暴露 |
| E1-5 | `crypto/{ed25519,ed448,rsa,x25519,x448}` 的 `(*PrivateKey).Match(other *core.PKey) bool` | 参数 | 中 | 调用方无法构造参数；应改为与公开密钥类型比较 |
| E1-6 | `crypto/sm2.PublicKeyFromPKey(k *core.PKey)` | 参数 | 中 | 同上 |
| E1-7 | `jwk.Marshal(key *core.PKey)` | 参数 | 中 | 与 `jwk.MarshalKey(key.CoreKey)` 功能重叠，收敛后只保留一个 |
| E1-8 | `x509.Certificate.Core()` → `*core.Certificate` | 返回值 | 中 | 属于「交出原生句柄」的逃生口 |
| E1-9 | `x509.Certificate.PublicKeyPKey()` / `x509.CertificateRequest.PublicKeyPKey()` → `*core.PKey` | 返回值 | 中 | 与 `Certificate.PublicKey()` 并存，且后者**算法绑定 SM2**，两者语义都不通用 |
| E1-10 | `x509.Store.Core()` → `*core.Store` | 返回值 | 中 | —— |
| E1-11 | `x509.PublicKey` / `x509.PrivateKey` duck 接口（`Key() *core.PKey`） | 接口方法签名 | 中 | 该窄接口是 `CreateCertificate`/`NewCertificateRequest` 的签名密钥类型 |
| E1-12 | `pkcs/pkcs12.PrivateKey`（= `key.CoreKey` 别名）、`pkcs12.Bundle.PrivateKey *core.PKey` | 类型别名 + 结构体字段 | 高 | 别名方案把 `key` 包的接口问题扩散到 `pkcs12` |

#### E2 原语级公开面（Go 惯例但属「底层」）

| # | 位置 | 说明 | 破坏性 | 迁移要点 |
|---|---|---|---|---|
| E2-1 | `crypto/{md5,sha1,sha256,sha512,sm3}.New()` → `hash.Hash` | 流式摘要原语 | 中 | 与「按算法名做摘要」的应用函数并存会造成两套入口 |
| E2-2 | `crypto/aes.NewCipher` → `cipher.Block`、`crypto/aes.NewGCM` → `cipher.AEAD` | 分组密码与 AEAD 原语 | 中 | 目标形态应只暴露「算法+模式+密钥+数据→密文」 |
| E2-3 | `crypto/sm4.NewCipher` → `cipher.Block` | 同上 | 中 | 同上 |
| E2-4 | `crypto/hmac.New*` → `hash.Hash` | 流式 MAC 原语 | 中 | 同上 |
| E2-5 | `crypto/rand.Read` / `rand.Bytes` | 随机数原语 | 低 | 缺编码与长度校验的应用级封装 |
| E2-6 | `crypto/ecdh.Curve` / `PrivateKey` / `PublicKey`（含 `ECDH`） | 曲线抽象（对齐 Go 标准库语义） | 低 | 语义清晰，可保留但需与「CLI 级」入口会合 |
| E2-7 | `asn1.Node` / `asn1.Parse` / `asn1.Dump` | 纯 Go 只读解析器 | 低 | 可作为工具保留 |
| E2-8 | `internal/digest.NewHash`（internal，但被 5 个公开包用于构造 `hash.Hash`） | 共享实现 | 低 | 收敛 E2-1 时一并处理 |

#### E3 多步组装面（与「CLI 一次调用」形态相反）

| # | 现有流程 | 步数 | CLI 对应 | 破坏性 | 迁移要点 |
|---|---|---|---|---|---|
| E3-1 | `NewCertificate()` + `SetVersion`/`SetSerial`/`SetIssuer`/`SetSubject`/`SetValidity`/`SetPublicKey`/`Add*` + `Sign` | ≥ 9 步 | `req -x509` / `x509 -req` | 中 | 缺一个「参数对象 + 一次调用」的入口（对应 §6.B B4/B6） |
| E3-2 | `NewEmptyCertificateRequest()` + `SetSubject`/`SetPublicKey` + `AddExtensions` + `Sign` | ≥ 5 步 | `req -new` | 中 | 对应 §6.B B5 |
| E3-3 | `NewStore()` + `AddCert`/`AddCRL`/`SetFlags` + `ChainVerify` | ≥ 4 步 | `verify` | 中 | 对应 §6.B B7 |
| E3-4 | `Generate*Key()` + `MarshalEncrypted(pass)` | 2 步 | `genpkey -aes-256-cbc` | 低 | 可接受，但缺 `-inform/-outform` 维度（§6.C C4） |
| E3-5 | `CreateRequest` → 自行发 HTTP → `ParseResponse` → `Verify` | 4 步 + 自建网络 | `ocsp -url` | 高 | 网络层完全由调用方承担（§6.B B13） |
| E3-6 | `pkcs7.Build(certs)` 仅接受 `[]*x509.Certificate` | 1 步但能力窄 | `pkcs7 -sign`/`-encrypt` | 中 | 缺签名/加密流程（§6.B B12） |
| E3-7 | `ChangePassword(pem, old, new)`（单一签名覆盖读写） | 1 步 | `pkcs12 -twopass`/`-passin`/`-passout` | 低 | 缺读写口令分离与来源抽象（§6.C C8） |

---

## 7. 本库优势清单（CLI 无对应或明显更弱）

| # | 能力 | 本库现状 | CLI 情况 | 性质 |
|---|---|---|---|---|
| 1 | **结构化错误** | `*core.OpError`（携带 `ERR_get_error` 码）、`*x509.VerifyError{Code, Depth, Message}`、`*tls.HandshakeError{Op, Kind, Err}`（含 `Is`/`Unwrap`） | 退出码 + stderr 文本 | 能力优势 |
| 2 | **内存对象 API** | 全部操作基于 `[]byte`/结构体，无文件依赖 | 多数命令需落地文件或走管道 | 能力优势 |
| 3 | **JWK（RFC 7517）** | `jwk.Marshal`/`Parse`/`FromPEM`/`ToPEM`/`ToPublicPEM`，RSA/EC ↔ PEM/JSON，含 CRT 字段 `dp`/`dq`/`qi` | **无 JWK 命令** | 能力优势 |
| 4 | **XML `RSAKeyValue`** | `xml/rsa` 双向序列化（.NET 互操作） | **无** | 能力优势 |
| 5 | **纯 Go ASN.1 viewer** | `asn1.Parse`/`Dump`，cgo-free，`maxDERDepth` 防栈溢出 | `asn1parse` 需加载铜锁 | 能力优势 |
| 6 | **密钥存储与轮转** | `key.Store` + `MemoryStore`：`Put`/`Get`/`List`/`Rotate`/`History` | **无** | 能力优势 |
| 7 | **密钥元数据与序列化** | `key.Handle{ID, Algorithm, Key, PEM, CreatedAt}` + JSON | **无** | 能力优势 |
| 8 | **Argon2ID 派生** | `key.Argon2ID(password, salt, time, memory, threads, keyLen)` | 本机构建 `argon2` 未启用 | 能力优势 |
| 9 | **结构化套件枚举** | `tls.CipherSuites(version) []{Name, ID, MinVersion, MaxVersion}` | `ciphers -v` 为文本表格 | 形态优势 |
| 10 | **CRT 参数暴露** | `KeyParams.Dmp1`/`Dmq1`/`Iqmp`（0.3.0 发布） | `rsa -text` 需文本解析 | 形态优势 |
| 11 | **secp256k1 曲线** | `ecdh.Secp256k1()` | `ec -name secp256k1` 支持 | 对等 |
| 12 | **Ed448 独立包** | `crypto/ed448` 全 API | 仅算法名/签名算法 | 形态优势 |
| 13 | **统一算法抽象** | `key.AsymmetricKey.Algorithm()` 返回 `Algorithm` 常量 | 算法名字符串 | 形态优势 |
| 14 | **签名结构访问** | `SignatureAlgorithmOID()`/`Signature()`/`Extensions()` 等结构化读取 | `-text` 文本解析 | 形态优势 |
| 15 | **生命周期管理** | `handle` 基类：`owned` 所有权 + 幂等 `Close()` + finalizer 兜底 | 进程退出即释放 | 形态优势 |
| 16 | **并发安全** | SM4 `cipher.Block` 用 `EVP_CIPHER_CTX_copy` 模板副本；测试可加 `-race` | 命令行为单线程 | 能力优势 |
| 17 | **Go 惯例接口** | 实现 `hash.Hash` / `cipher.Block` / `cipher.AEAD`，可与 Go 生态组合 | —— | 形态优势 |
| 18 | **静态链接** | `go build -tags static`（Linux 已接线） | 依赖运行时 `.so` | 能力优势 |
| 19 | **CLI 逐字节对拍测试** | `//go:build tongsuocli` 与铜锁 `openssl` 对拍 | **无自测机制** | 能力优势 |
| 20 | **覆盖率门禁脚本** | `scripts/check-coverage.sh` | **无** | 能力优势 |
| 21 | **RSA-PSS / OAEP 类型化 API** | `SignPSS`/`VerifyPSS`/`EncryptOAEP` | 需 `pkeyutl -pkeyopt rsa_padding_mode:pss` | 形态优势 |
| 22 | **NTLS 双证书字段化配置** | `Config{NTLS, SignCert, SignKey, EncCert, EncKey}` | 需 4 个文件路径选项 | 形态优势 |

---

## 8. 全量对齐路线图（能力级）

> 本节按**能力**排期；按**包结构**排期的 Phase 划分见 [refactor-roadmap.md](refactor-roadmap.md) §7。两者合并后：`0.3.0` 只做结构重构与少量顺带补全，本节的「Phase 1 采集型小件」自 `0.4.0` 起。
>
> 排序原则：先补「让本库像 CLI 一样直接用」的地基（形态），再补算法覆盖，最后补协议与破坏性收敛。

### Phase 1 — 采集型小件（风险低、不动 cgo、不涉破坏性变更）

| 项 | 对应缺口 |
|---|---|
| 公开版本/构建信息 API | §6.A 23 / 55，§6.B B24 |
| 算法枚举 API（摘要 / 对称 / MAC / KDF / 签名 / 密钥交换 / KEM / provider） | §6.A 25，§6.B B16 |
| hex / base64 / hexdump 编码助手 | §6.C C5 / C6，§6.B B21 / B22 |
| 错误码 → 文本解析 | §6.A 17，§6.B B23 |
| PEM 口令来源抽象（`pass:` / `env:` / `file:` / `fd:` / `stdin`） | §6.C C8 |
| 统一 `Format` 维度（PEM / DER）与 inform/outform 语义 | §6.C C4 |
| `key.LoadPrivateKeyPEM` 回退 EC SEC1（`crypto/ecdh` 已支持，`key` 未回退） | §5.2 |

### Phase 2 — 输入输出形态对齐（「像 CLI 一样直接用」的地基）

| 项 | 对应缺口 |
|---|---|
| 文件 / stdin / stdout 入口与出口 | §6.C C1 / C2 / C3 |
| `io.Reader` / `io.Writer` 流式 | §6.C C11 |
| 任务入口：按「算法名 + 输入源 + 输出编码」一次调用完成 **摘要 / 加解密 / MAC / KDF** | §6.A 8 `dgst` / 15 `enc` / 26 `mac` / 24 `kdf`（四个 P0–P1 命令的核心） |
| 统一加载器（替代 `storeutl` 的使用场景） | §6.A 52 |
| 一行生成自签证书、一行由密钥生成 CSR | §6.A 40，§6.B B4 / B5 |
| x509 主机名 / IP 校验 | §6.B B8 |

### Phase 3 — 算法覆盖

| 分组 | 项 |
|---|---|
| 对称 | AES-192；AES OFB/CFB/CCM/XTS/OCB/SIV/GCM-SIV/WRAP/CBC-CTS；SM4-CCM/XTS；ChaCha20(-Poly1305)；ZUC-128-EEA3 |
| 摘要 | SHA-224、SHA-384、SHA-512/224、SHA-512/256、SHA3-224/256/384/512、SHAKE128/256、KECCAK-224/256/384/512、SHA-256/192 |
| MAC | CMAC、GMAC、KMAC-128/256、SipHash、Poly1305、EIA3 |
| KDF | scrypt、SSKDF、TLS1-PRF、TLS13-KDF、X9.42、KBKDF、KRB5KDF、PKCS12KDF、SSHKDF、HMAC-DRBG-KDF；`crypto/kdf` 补 `Argon2ID` 派生函数 |
| 非对称 | **SM2DH 密钥交换**、KEM（`-encap`/`-decap`）、ML-DSA-44/65/87、SLH-DSA 12 变体、ML-KEM-512/768/1024 与混合组 |
| 经典算法 | DSA / DH 见 §9（不主动做） |

### Phase 4 — 容器与协议

| 项 | 对应缺口 |
|---|---|
| PKCS#7 签名 / 验签 / 加密 / 解密 | §6.A 32，§6.B B12 |
| PKCS#8 `-topk8` 双向转换、版本与 PRF 选择 | §6.A 33，§6.B B10 |
| PKCS#12 PBE 算法与迭代次数、读写口令分离 | §6.A 31，§6.B B11 |
| PKCS#1 公钥（`-RSAPublicKey_in/out`）、`-check`/`-pubcheck` | §6.A 41 / 34 |
| x509：`-x509toreq`、信任属性、`subject_hash`、`-attime`、链输出 | §6.A 54 / 56 |
| CRL 应用级签发入口（配置驱动） | §6.A 6，§6.B B9 |
| OCSP HTTP 客户端与 nonce | §6.A 28，§6.B B13 |
| `ca` 工作流（需先定「内存 vs 文件系统」形态） | §6.A 2 |
| `crl2pkcs7`、CMS、`ts`、`storeutl` | §6.A 7 / 5 / 53 / 52 |

### Phase 5 — 传输深度、扩展算法与公开面收敛

| 分组 | 项 | 对应缺口 |
|---|---|---|
| TLS / NTLS | ALPN、会话复用（`SSL_SESSION`）、会话票据、客户端证书认证、服务端 SNI 多证书、`net.Listener` 包装、OCSP stapling、keylog、HTTP 集成 | §6.A 43 / 44 |
| 同态 | Paillier、EC-ElGamal | §6.D D5 / D6 |
| 需重编铜锁方可验证 | Bulletproofs、SM2 门限、SDF、SMTC、白盒 SM4、Delegated Credential | §6.D D14–D19 |
| **公开面收敛（破坏性）** | §6.E 的 E1（内部类型泄漏）→ E2（原语级公开面）→ E3（多步组装面）；需配迁移说明 | §6.E |

### 版本归属建议

| 版本 | 内容 |
|---|---|
| `0.4.0` | Phase 1 全部 + Phase 2 起步 |
| `0.5.0` | Phase 2 完整 + Phase 3 主体（摘要 / MAC / KDF / 对称 / AES-192） |
| `0.6.0` | Phase 3 剩余（SM2DH / PQC）+ Phase 4 的格式容器部分 |
| `0.7.0` | Phase 4 的协议部分（CMS / ts / OCSP HTTP / `ca`） |
| `1.0.0` | Phase 5 + §6.E 公开面收敛（破坏性，需迁移指南） |

---

## 9. 明确不实现清单

| # | 项 | 不做理由 |
|---|---|---|
| 1 | `engine`（§6.A 16） | 已被 provider 机制取代 |
| 2 | `fipsinstall`（§6.A 18） | 本机构建 `fips` 未启用，且属部署工具 |
| 3 | `rsautl`（§6.A 42） | 上游已 deprecated，功能被 `pkeyutl` / `rsa` 覆盖 |
| 4 | `s_time`（§6.A 45）、`speed`（§6.A 49） | 基准能力用 Go `Benchmark*` 表达更合适 |
| 5 | `rehash`（§6.A 39） | 证书目录 hash 索引属文件系统工具（`c_rehash`） |
| 6 | `nseq`（§6.A 27）、`spkac`（§6.A 50） | Netscape 历史格式，无现代使用场景 |
| 7 | `passwd`（§6.A 30） | 口令 hash 属应用层职责，与密码学库目标场景无关 |
| 8 | `prime`（§6.A 37）、`dsaparam`（§6.A 11）、`gendsa`（§6.A 19） | 工具型参数生成，非国密与目标场景 |
| 9 | `dsa`（§6.A 10）、`dhparam`（§6.A 9） | 经典 DSA/DH 不主动做；若未来引入 DH 密钥协商（如 TLS tmp-DH）再重估 |
| 10 | `srp`（§6.A 51）、`cmp`（§6.A 4） | 协议栈重且与目标场景距离较远 |
| 11 | `smime`（§6.A 48） | 依赖 CMS；若 Phase 4 落地 CMS 可重新评估 |
| 12 | `help`（§6.A 22）与交互模式（§6.C C12） | 本库为库形态，不提供 CLI |
| 13 | provider / 属性查询（§6.C C13） | provider 固定为 default，无多 provider 语义 |
| 14 | 压缩（§6.C C7） | 本机构建 `ZLIB`/`BROTLI`/`ZSTD` 均 disabled |
| 15 | SM9（§6.D D20） | **铜锁本版本不提供**，无对应 C API |

---

## 10. 验证与维护约定

### 10.1 本报告的采集命令（可复现）

| 命令 | 用途 |
|---|---|
| `tongsuo version -a` | 版本、平台、构建信息 |
| `tongsuo help` | Standard commands / Message Digest commands / Cipher commands 三段总表 |
| `tongsuo list -commands -1` | 普通子命令全集（本次 56 项） |
| `tongsuo list -standard-commands -1` | 与上表对照 |
| `tongsuo list -cipher-algorithms -1` | 对称算法（本次 177 行） |
| `tongsuo list -digest-algorithms -1` | 摘要算法（本次 71 行） |
| `tongsuo list -mac-algorithms -1` | MAC（本次 8） |
| `tongsuo list -kdf-algorithms -1` | KDF（本次 13） |
| `tongsuo list -signature-algorithms -1` | 签名算法（本次 59 行） |
| `tongsuo list -key-exchange-algorithms -1` | 密钥交换（本次 8） |
| `tongsuo list -kem-algorithms -1` | KEM（本次 12） |
| `tongsuo list -asymcipher-algorithms -1` | 非对称加密（本次 2） |
| `tongsuo list -key-managers -1` | 密钥管理（本次 126 行） |
| `tongsuo list -public-key-algorithms -1` | 公钥算法 OID 映射（本次 179 行） |
| `tongsuo list -tls-groups -1` | TLS 组（本次 25 组） |
| `tongsuo list -providers` | 活跃 provider |
| `tongsuo list -disabled` | 本机构建禁用项 |
| `tongsuo list -options <cmd>` | 逐命令选项面（本次覆盖全部 56 个命令） |
| `tongsuo ciphers -v` | TLS / NTLS 套件（本次 70 行） |

### 10.2 复核约定

1. **「本库现状」列必须可复现**：每条结论都要能在源码中定位到对应导出符号（包路径 + 符号名）。
2. **判定口径固定三档**（✅ / ⚠️ / ❌），不得在后续修订中混入第四种语义。
3. **未实测项必须标注**：本机构建未启用的能力（§6.D D14–D19）不得写成「铜锁支持但本库不支持」，而应标为「需重编铜锁方可验证」。
4. **本报告不含代码改动与 API 签名**；所有实现方案推迟到具体 PR 的实施阶段另行设计。
5. **触发重采的条件**：铜锁版本变更、`list -<family>` 条目变化、`list -disabled` 变化、`Config` 的 `enable-*` 组合变化。重采后需同步 §4.5、§6.D 与 §2 的基线信息。

---

## 11. 符号对照表

### 11.1 摘要算法

| CLI 名称 | 本库现状 | 判定 |
|---|---|---|
| `MD5` / `md5` | `crypto/md5.New` / `Sum` | ✅ |
| `SHA1` / `sha1` | `crypto/sha1.New` / `Sum` | ✅ |
| `SHA224` / `sha224` | 无（`internal/core.SHA224` 与 `key.HashSHA224` 存在，API 层无包） | ❌ |
| `SHA256` / `sha256` | `crypto/sha256.New` / `Sum` | ✅ |
| `SHA384` / `sha384` | 无独立包（`key.HashSHA384` 可用；`crypto/hmac` 有 `NewSHA384`/`SumSHA384`） | ⚠️ |
| `SHA512` / `sha512` | `crypto/sha512.New` / `Sum` | ✅ |
| `SHA512-224` / `SHA512-256` | 无 | ❌ |
| `SHA3-224/256/384/512` | 无 | ❌ |
| `SHAKE128` / `SHAKE256` | 无 | ❌ |
| `SM3` / `sm3` | `crypto/sm3.New` / `Sum` | ✅ |
| `KECCAK-224/256/384/512`、`SHA-256/192` | 无 | ❌ |

### 11.2 对称算法

| CLI 名称 | 本库现状 | 判定 |
|---|---|---|
| `SM4-CBC/ECB/CFB/OFB/CTR` | `crypto/sm4.EncryptCBC` / `EncryptECB`（含 Zero 变体）/ `EncryptCFB` / `EncryptOFB` / `EncryptCTR` | ✅ |
| `SM4-GCM` | `crypto/sm4.EncryptGCM` / `DecryptGCM` | ✅ |
| `SM4-CCM` / `SM4-XTS` | 无 | ❌ |
| `AES-128/256-CBC/ECB/CTR/GCM` | `crypto/aes.EncryptCBC` / `EncryptECB` / `EncryptCTR` / `EncryptGCM` | ✅ |
| `AES-192-*` | 无（密钥长度仅 16/32） | ❌ |
| `AES-*-OFB/CFB/CCM/XTS/OCB/SIV/GCM-SIV/WRAP/CBC-CTS` | 无 | ❌ |
| `ChaCha20` / `ChaCha20-Poly1305` | 无 | ❌ |
| `ZUC-128-EEA3` | 无 | ❌ |
| `DES` / `DES-EDE` / `DES-EDE3` / `DESX` / `RC4` / `RC4-40` | 无 | ❌ |
| `base64` | 无 | ❌ |
| `zlib` / `brotli` / `zstd` | 无（本机构建均 disabled） | ❌ |

### 11.3 MAC 与 KDF

| CLI 名称 | 本库现状 | 判定 |
|---|---|---|
| `HMAC` | `crypto/hmac.NewSM3`/`MD5`/`SHA1`/`SHA256`/`SHA384`/`SHA512` | ✅ |
| `CMAC` / `GMAC` / `KMAC-128` / `KMAC-256` / `SIPHASH` / `POLY1305` / `EIA3` | 无 | ❌ |
| `HKDF` | `crypto/kdf.HKDF` / `key.HKDF` | ✅ |
| `PBKDF2` | `crypto/kdf.PBKDF2` / `key.PBKDF2` | ✅ |
| `SCRYPT` / `SSKDF` / `TLS1-PRF` / `TLS13-KDF` / `X942KDF` / `KBKDF` / `KRB5KDF` / `PKCS12KDF` / `SSHKDF` / `HMAC-DRBG-KDF` | 无 | ❌ |
| （上游无 Argon2 条目） | `key.Argon2ID`（本机构建 `argon2` 未启用） | ⚠️ |

### 11.4 非对称算法与密钥交换

| CLI 名称 | 本库现状 | 判定 |
|---|---|---|
| `SM2`（签名/验签/加解密） | `crypto/sm2.Sign`/`Verify`/`SignWithID`/`VerifyWithID`/`Encrypt`/`Decrypt`/`Format` | ✅ |
| `SM2DH`（密钥交换） | 无 | ❌ |
| `RSA`（PKCS#1v1.5 / PSS / OAEP） | `crypto/rsa.SignPKCS1v15`/`SignPSS`/`EncryptPKCS1v15`/`EncryptOAEP` | ✅（OAEP 有内部类型泄漏） |
| `RSA-SM3` | `crypto/sm2` 无；可用 `rsa.SignPKCS1v15(data, "sm3")` 路径表达 | ⚠️ |
| `ECDSA` / `ECDSA-SHA*` | `crypto/ecdsa.Sign`/`Verify` + `key.GenerateECKey` | ✅ |
| `ED25519` / `ED448` | `crypto/ed25519` / `crypto/ed448` 全 API | ✅ |
| `ED25519ph` / `ED25519ctx` / `ED448ph` | 无 | ❌ |
| `X25519` / `X448` | `crypto/x25519` / `crypto/x448`（`GenerateKey`/`SharedSecret`） | ✅ |
| `ECDH` | `crypto/ecdh`（P256/P384/P521/secp256k1/X25519/X448） | ✅ |
| `DH` | 无 | ❌ |
| `DSA` / `DSA-SHA*` | 无 | ❌ |
| `ML-DSA-44/65/87` | 无 | ❌ |
| `SLH-DSA-*`（12 变体） | 无 | ❌ |
| `ML-KEM-512/768/1024` + 混合组 | 无 | ❌ |
| `Paillier` / `EC-ElGamal` | 无（无对应库 API） | ❌ |

### 11.5 TLS / NTLS

| CLI 名称 | 本库现状 | 判定 |
|---|---|---|
| `s_client`（TLS） | `tls.Dial` / `tls.DialContext` | ⚠️ |
| `s_server`（TLS） | `tls.NewServer` / `(*Server).Accept` | ⚠️ |
| `-ntls` + `-enable_ntls` + 双证书 | `tls.Config{NTLS, SignCert, SignKey, EncCert, EncKey}` | ✅ |
| `ciphers` / `-tls1_3` / `-tls1_2` | `tls.CipherSuites(version)` | ✅ |
| `-alpn` | 无 | ❌ |
| 会话复用 / `sess_id` | 无（`SSL_SESSION_*` 未绑定） | ❌ |
| `-keylogfile` / `-msg` / `-state` / `-trace` | 无 | ❌ |
| `-www` / `-HTTP` | 无 | ❌ |
| 服务端 SNI 多证书（`-sign_cert2`） | 无（仅客户端发 SNI） | ❌ |
| 客户端证书认证 | 无 `ClientAuth` 配置字段 | ❌ |

### 11.6 容器与格式

| CLI 名称 | 本库现状 | 判定 |
|---|---|---|
| `pkcs12`（打包/解析/改密） | `pkcs12.Pack` / `Parse` / `ChangePassword` | ⚠️ |
| `pkcs7`（证书袋） | `pkcs7.Build` / `Extract` / `MarshalPEM` | ⚠️ |
| `pkcs7 -sign` / `-encrypt` | 无 | ❌ |
| `pkcs8`（PKCS#8 读写/加密） | 各算法 `MarshalEncryptedPEM`、`key.MarshalEncrypted` | ⚠️ |
| `pkcs8 -topk8` | 无 | ❌ |
| `req`（CSR） | `x509.NewCertificateRequest` / `Sign` / `Verify` / `MarshalPEM` | ⚠️ |
| `req -x509`（一行自签） | 无（需 `NewCertificate` + `Set*` + `Sign` 多步） | ❌ |
| `x509`（解析/查看/指纹） | `x509.LoadCertificatePEM` / `LoadCertificateDER` / `MarshalPEM` / `MarshalDER` / `Fingerprint` / `Extensions` | ⚠️ |
| `x509 -x509toreq` | 无 | ❌ |
| `verify`（链验证） | `x509.ChainVerify` / `x509.Store` | ⚠️ |
| `crl`（CRL 解析/校验） | `x509.ParseCRL` / `RevokedEntries` / `IsRevoked` / `Verify` | ⚠️ |
| `ca -gencrl` | 无 | ❌ |
| `ocsp`（请求/响应/验签） | `ocsp.CreateRequest` / `ParseResponse` / `Verify` | ⚠️ |
| `ocsp -url`（HTTP） | 无 | ❌ |
| `asn1parse`（解析/转储） | `asn1.Parse` / `Dump` | ⚠️ |
| `asn1parse -genstr` / `-genconf` | 无 | ❌ |
| `cms` / `crl2pkcs7` / `ts` / `smime` / `nseq` / `spkac` / `storeutl` | 无 | ❌ |
| `rand`（随机数） | `crypto/rand.Read` / `Bytes` | ⚠️ |
| `version` / `info` | 无公开 API（`internal/core.VersionText` 未导出） | ❌ |
| `errstr` | 无 | ❌ |
| `list`（算法枚举） | 仅 `tls.CipherSuites` | ⚠️ |
