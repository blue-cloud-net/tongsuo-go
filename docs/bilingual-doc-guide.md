# 双语 GoDoc 注释规范

本仓库采用**中文段在前、英文段在后**的双语 GoDoc 注释。本文档定义统一规则，
供新增 / 修改注释时遵循。

- 双语基本动机与示例：见 [development-guide.md §1.4–§1.5](development-guide.md)

---

## 1. 段式（默认）

中文段在前，英文段在后，两段之间**必须显示成单独的 `//` 空行**，每段都以
符号名起头。段数必须**中英对称**，每对段语义对应。

```go
// Encrypt 使用 SM2 公钥加密 data。
// 输出为 Tongsuo 8.x（OpenSSL 3.x）的 ASN.1 DER 格式（内含 C1C3C2），与
// `openssl pkeyutl -encrypt` 一致。
// SM2 不支持空明文，data 必须非空。
//
// Encrypt encrypts data with the given SM2 public key and returns the
// ciphertext in ASN.1 DER (C1C3C2 internal order), matching the format
// emitted by `openssl pkeyutl -encrypt` under Tongsuo 8.x (OpenSSL 3.x).
// SM2 does not support an empty plaintext; data must be non-empty.
```

---

## 2. 单行式（仅适用于 `//export`）

`//export` 行紧贴函数体，单行式在中文一行 + 英文一行（**中间不空行**）即可，
两行各自以符号名起头：

```go
// Encrypt 使用 SM2 公钥加密 data。
// Encrypt encrypts data with the given SM2 public key.
//
//export Cgo_SM2_Encrypt
func Cgo_SM2_Encrypt(...) (...) { ... }
```

---

## 3. 八条核心规则

1. **段式 vs 单行式**：公共包 + `internal/core` + `internal/digest` + `internal/testutil`
   + 所有 `Example*` + 包级 doc 走段式；`internal/native/binding_*.go` 中带 `//export`
   的函数走单行式。
2. **段式条目**：中文段在前，英文段在后；两段之间有且仅一个空 `//` 行；每段都
   以符号名起头（Go 惯例）。
3. **单行式条目**：中英独立两行，**中间不加空行**；上中文下英文。
4. **不重写中文内容**：原中文内容字符级不修改；可新增中文行（追加而非删除）。
   若需重写以实现段式对称，参见 §7.2。
5. **代码块缩进**：保留现有 tab-缩进 `//\t...` 风格不变。
6. **术语保留**：SM2/SM3/SM4/SM9/PEM/DER/PKCS#8/PKCS#12/SPKI/CRL/CSR/OCSP/NTLS/
   JWS/JWE/JWK/RFC 7517/GM/T 0003/GB/T 32918/GB/T 32905/openssl 等不翻译。
7. **`// Output:` 行不动**：必须紧贴函数体最后一行（`go test` 工具约束）。
8. **包级注释**：第一行 `// Package xxx 中文一句话`，末尾追加
   `// Package xxx does X in English.` 一句英文总括。

---

## 4. 段式不对称的典型模式

下表列出翻译时最常丢失的语义类别。**新增双语注释时务必同时补全中英两段**：

| 模式 | 描述 |
|---|---|
| **A. 错误包装尾注缺失** | 英文含 `On failure, it returns an error wrapping an OpError describing the operation.`，中文仅有 1 段 |
| **B. 安全告警缺失** | 英文含 `nonce must be unique per key` / `ECB leaks patterns` / `Bleichenbacher padding oracle` / `SHA-1 is collision-prone`，中文无 |
| **C. 错误码清单缺失** | 英文列举 `"cipher: key length %d, want %d"` 等错误码，中文无 |
| **D. 实现细节缺失** | 英文含 `runtime.LockOSThread` / `Tongsuo SM2 provider is thread-sensitive` / `RFC 6979 deterministic` / `SHA-256 digest pipeline`，中文无 |
| **E. 边界条件缺失** | 英文含 `len(data) == 0 returns (0, nil)` / `nil receiver safe` / `ciphertext 长度约束`，中文无 |
| **F. 所有权/Close 语义缺失** | 英文含 `caller must invoke Close` / `Close is idempotent` / `not part of stable public API`，中文无 |
| **G. 互操作警告缺失** | 英文含 `openssl pkcs12` / `openssl req -verify` / `.NET Framework RSA.ToXmlString()`，中文无 |

---

## 5. 新增导出符号的对照检查清单

新增或修改公共 API 时，按本清单逐项检查：

- [ ] **段数对称**：中文段数 == 英文段数（段式按空行分隔）
- [ ] **每段以符号名起头**：`// FunctionName 中文一句话。` / `// FunctionName does X.`
- [ ] **段式：两段间空行**：`// FunctionName 中文...` + 空 `//` + `// FunctionName English...`
- [ ] **错误包装尾注**（若英文有）：中文补"失败时返回包装了 OpError 的错误"
- [ ] **安全告警**（若英文有 nonce 唯一 / ECB 弱语义 / SHA-1 弃用 / 线程安全等）：
      中文补相同告警
- [ ] **错误码清单**（若英文有 `"X: invalid Y"`）：中文补相同错误码列举
- [ ] **约束类**（若英文有 `must be non-nil` / `must be closed` / `key != KeySize returns error`）：
      中文补相同约束
- [ ] **术语保留**：SM2/SM3/SM4/AES/RSA/ECDSA/PEM/DER/PKCS#8/PKCS#12/openssl/CRL/CSR/OCSP/
      NTLS/JWK/JWS/JWE/RFC 7517 等**不翻译**
- [ ] **`// Output:` 行不动**：example_test.go 里的 Output 行字符级不变
- [ ] **包级 doc 末尾英文总括**：`// Package xxx does X in English.`
- [ ] **函数体 / import / cgo 块不动**

---

## 6. 中英对照常用动词词典（Go 惯例）

| 中文 | 英文 |
|---|---|
| 表示 | represents |
| 创建 | creates / creates a new |
| 返回 | returns |
| 解析 | parses |
| 序列化 / 导出 | serializes / marshals |
| 反序列化 / 加载 | deserializes / unmarshals / loads |
| 加密 | encrypts |
| 解密 | decrypts |
| 签名 | signs |
| 验签 | verifies |
| 释放 / 关闭 | releases / closes |
| 设置 | sets |
| 获取 | returns / gets |
| 添加 | appends / adds |
| 计算 | computes |
| 验证 | validates / verifies |
| 转换 | converts |
| 追加 | appends |
| 包含 | contains / holds |
| 支持 | supports |
| 须 | must |
| 可空 / 可为 nil | may be nil |
| 当...时返回错误 | returns an error when... |
| 失败时 | on failure |
| 幂等 | idempotent |
| 线程安全 | safe for concurrent use |
| 序列化（互斥） | serialized (mutex-protected) |
| 不可重用 | must not be reused |
| 唯一 | unique |
| 安全敏感 | security-sensitive |

---

## 7. 未来维护指引

### 7.1 新增导出符号

按本档 §5 清单逐项检查即可。中英段式写法可参照 [development-guide.md §1.5](development-guide.md)
的样例。

### 7.2 修复历史遗留不对称

如发现某符号中英段式不对称（例如翻译遗漏）：

1. 读英文段
2. 重写中文段使其**段数 == 英文段数** + 信息密度对齐
3. 中文允许**增、删、改**——只要段式对称即可
4. 严格遵守术语保留清单（§3 第 6 条）
5. 不动函数体 / import / cgo 块

### 7.3 新增 `//export` 函数

按单行式（§2）格式：中文一行 + 英文一行（**中间不空行**），两行各自以符号名
起头。