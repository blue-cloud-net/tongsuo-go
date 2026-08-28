# 测试规范

本文档规定 `tongsuo-go` 的测试组织、命名以及各类算法**必须覆盖**的用例。
整体开发规范见 [development-guide.md](development-guide.md)，架构说明见
[architecture.md](architecture.md)，实施计划见 [roadmap.md](roadmap.md)。

---

## 1. 测试文件命名与组织

- **测试与源码同包**：测试文件位于被测包目录内，命名 `{file}_test.go`
  （如 `crypto/sm3/sm3_test.go`），测试目录**镜像源码目录**（Go 惯例）
- 每个算法模块提供**两类测试**：

| 测试类型 | 说明 | 运行方式 |
|---------|------|---------|
| 单元测试 | 标准向量、往返、边界、错误路径、交叉验证 | 默认 `go test` 运行 |
| CLI 对比测试 | 调用铜锁 openssl 命令行逐字节比对 | `//go:build tongsuocli` 标签隔离，默认**不**运行 |

- CLI 对比测试在文件头用 `//go:build tongsuocli` 标注（等价 C# 的
  `[Category("TongsuoCli")]`）
- 共享工具放 `internal/testutil`（openssl CLI 封装、标准向量加载）
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
go test -fuzz FuzzRoundTrip ./crypto/sm4
```

- CLI 测试依赖铜锁 openssl 命令行，路径通过环境变量 `TONGSUO_OPENSSL_BIN` 指定
  （默认 `/opt/tongsuo/bin/openssl`）或由 `TONGSUO_HOME` 推导
- 覆盖目标：核心算法包行覆盖 **≥ 80%**（参考值，**不**由 CI 强制；本地可通过
  `./scripts/check-coverage.sh` 手动检查）

---

## 3. 哈希算法测试（如 `crypto/sm3`）

必须覆盖以下用例：

| 测试用例 | 描述 |
|---------|------|
| 输出位宽 | `Size()` 等于算法定义位数（SM3 = 32 字节 / 256 bit） |
| 空字节数组 | 与 GB/T 国标附录的空输入向量比对 |
| 标准向量 × N | 每个 GB/T 附录向量独立一个用例，命名含来源（如 `GBT32905_Vector_Abc`） |
| 幂等性 | 两次计算相同输入结果一致 |
| 唯一性 | 不同输入结果不同 |
| 一次性 vs 流式 | `Sum(data)` 与 `hash.Hash`（多次 `Write` + `Sum`）结果一致 |
| Reset 重置 | `Reset()` 后重新计算与首次一致 |
| nil / 空输入 | 行为明确（不崩溃，返回预期错误或向量值） |
| 交叉验证 | 与 Go 标准库同算法（如 `crypto/sha256`）对随机数据逐字节比对 |

**CLI 对比测试**（`_tongsuocli_test.go`）：调用 `openssl dgst -sm3` 对随机数据与
标准向量分别与库实现比对。

---

## 4. 对称加密测试（如 `crypto/sm4`）

每种模式（ECB / CBC / CTR / GCM）须有独立的**加密 + 解密 + 往返**用例：

| 测试用例 | 描述 |
|---------|------|
| 标准向量加密 | 使用 GB/T 32907 附录的密钥 + 明文，断言密文与预期一致（NoPadding） |
| 标准向量解密 | 上述密文解密后还原为原始明文 |
| 往返（随机密钥） | `Encrypt → Decrypt` 还原原始明文，各模式独立 |
| 填充模式 PKCS7 | 非块对齐数据加密后长度正确，解密后还原 |
| 错误密钥解密 | 使用不同密钥解密，结果不等于原始明文 |
| 空数据 | NoPadding 下空输入不崩溃（或返回预期错误） |
| 非法密钥 / IV 长度 | 返回明确错误 |
| 多块数据 | 至少 3 个完整块的数据正确加解密 |

**AEAD（SM4-GCM）额外用例：**

| 测试用例 | 描述 |
|---------|------|
| 加密 + tag | 加密输出密文，获取 128-bit tag |
| 解密 + 校验 | 提供正确 tag 解密成功 |
| AAD 一致 / 不一致 | AAD 相同解密成功，不同则失败 |
| 篡改检测 | 密文或 tag 任一字节被改 → 解密失败 |
| nonce 长度 | 非法 nonce 长度（非 12 字节）返回错误 |

**CLI 对比测试**：调用 `openssl enc -sm4-cbc/-sm4-ecb/-sm4-ctr/-sm4-gcm` 对随机
密钥 / IV / 明文逐字节比对，每种模式独立用例。

---

## 5. 非对称测试（如 `crypto/sm2`）

| 区域 | 测试用例 |
|------|---------|
| **密钥生成** | 每次生成结果不同；密钥位宽正确 |
| **PEM/DER 导入导出** | 私钥 PEM 往返、公钥 PEM 往返、私钥 DER 往返、公钥 DER 往返 |
| **签名 / 验签** | 同密钥签名验签成功；篡改数据 / 签名均失败；自定义 userId；空数据签名 |
| **加密 / 解密** | 同密钥加密 + 解密；不同密钥解密失败；每次密文不同（SM2 随机点） |
| **标准向量** | GB/T 32918 系列标准向量（加密 / 签名） |
| **交叉验证** | 库签名 → openssl 验签；openssl 签名 → 库验签 |

**CLI 对比测试**：生成密钥，导出 PEM，调用 `openssl pkeyutl` / `openssl dgst -sm3 -sign`
进行加解密或签名验签，与库结果比对。

---

## 5.1 传输层测试（`tls`）

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

## 6. CLI 对比工具（`internal/testutil`）

封装铜锁 openssl 命令行调用（对应 C# 的 `OpenSslCommandRunner`）：

- 统一入口 `RunOpenSSL(args, stdin)`，内部通过 `os/exec` 调用
- 方法命名遵循 `{Operation}{Alg}{Mode}()`（如 `HashSm3`、`EncryptSm4Cbc`、`SignSm2`）
- 参数顺序：`key → iv（可选）→ data`
- **不包含任何断言逻辑**，只负责执行与返回结果

---

## 7. 基准与模糊测试

- 关键路径提供 benchmark（如 `BenchmarkSM3`、`BenchmarkSM4CBC`），便于回归性能
- 提供 fuzz 用例：`FuzzRoundTrip`（加密 → 解密往返），确保不崩溃、往返一致
- fuzz 与 benchmark 同样遵循"标准向量 + 往返"的覆盖思路

---

## 8. 向量来源

| 算法 | 标准 |
|------|------|
| SM3 | GB/T 32905-2016 附录 A |
| SM4 | GB/T 32907-2016 附录 A |
| SM2 | GB/T 32918 系列 |
| AES | NIST FIPS 197 附录 B/C（Phase 4） |
