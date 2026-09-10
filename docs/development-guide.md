# 开发规范

本文档面向项目内部开发者，规定 **GoDoc 注释、命名、错误处理、内存安全、cgo、代码风格
与测试**等方面的约定。架构说明见 [architecture.md](architecture.md)，测试规范见
[testing-guide.md](testing-guide.md)。

---

## 1. GoDoc 注释规范

### 1.1 基本要求

- **所有导出符号**（包、类型、函数、方法、常量、变量）必须包含 GoDoc 注释
- 注释**以符号名开头**（Go 惯例，便于 `go doc` 检索），说明"做什么"而非"怎么做"
- 需要包含：参数/返回值含义、错误条件（何时返回 error）、安全注意事项
- 需要示例的 API 提供 `Example*` 测试函数（`_test.go` 中），会被 `go doc` 展示
- **注释必须以中文为主段**；可附一段**英文段**置于中文段之后（详见 §1.5）。
  - 中文段保持字符级不修改；英文段以符号名起头，术语保留（SM2/SM3/SM4/SM9/PEM/DER/
    PKCS#8/SPKI/CRL/CSR/OCSP/NTLS/JWS/JWE/JWK/RFC 7517 等**不翻译**）
- **禁止**：无意义注释（重复代码内容）、中英混杂于同一行

### 1.2 验收清单（段式/单行式存在性）

段式符号必须满足：经 `go doc -all` 渲染后，**首段含 CJK 字符**、**存在以符号名
起头的英文段**。

单行式 cgo binding 必须满足：`//export <Name>` 行上方紧邻两行分别为中英，**不隔
空行**。

### 1.3 各层注释侧重点

**绑定层**——注释 C 函数语义与参数约束（通常来自 OpenSSL man page）：

```go
// EVP_DigestInit_ex 初始化摘要上下文（EVP_DigestInit_ex）。
// ctx 为已分配的 EVP_MD_CTX；type 为算法指针；impl 传 nil 表示默认实现。
// 成功返回 1，失败返回 0。
```

**核心层**——注释托管语义、所有权规则、生命周期约束：

```go
// Close 释放底层句柄。幂等：重复调用安全。
// 释放后调用其他方法将返回明确的错误。
```

**API 层**——注释算法规范、使用示例、安全注意事项：

```go
// Sum 计算 data 的 SM3 摘要（GB/T 32905-2016）。
// 返回 32 字节的摘要。
func Sum(data []byte) [32]byte
```

---

### 1.4 8 条规则

所有公共 API（包级 doc、类型、函数、方法、常量、变量、`Example*`）必须包含中英
两段；`internal/native/binding_*.go` 中的 cgo binding 函数采用**单行式**。

1. **段式 vs 单行式**：公共包与 `internal/core`、`internal/digest`、`internal/testutil`、
   所有 `Example*` 与所有**包级 doc** 走**段式**；`internal/native/binding_*.go` 中的
   cgo binding 函数走**单行式**。
2. **段式条目**：中文段在前，英文段在后；两段之间有且仅一个空行；每段都以符号名
   起头（Go 惯例）。
3. **单行式条目**：中英独立两行，**中间不加空行**；上行为中文、下行为英文；两句各
   自以符号名起头。
4. **不重写中文**：原中文内容字符级不修改（单行式若原仅一行中文，则在下方补一行英
   文；段式若原有多段中文，则保留并在其末尾附段空行 + 英文段）。
5. **代码块缩进**：保留现有 tab-缩进 `//\t...` 风格不变；英文段里的代码块同样用
   tab 缩进。
6. **术语保留**：SM2/SM3/SM4/SM9/PEM/DER/PKCS#8/SPKI/CRL/CSR/OCSP/NTLS/JWS/JWE/JWK/
   RFC 7517 等**不翻译**。
7. **`// Output:` 行不动**：必须紧贴函数体最后一行（`go test` 工具约束），与上方说
   明区互相独立。
8. **包级注释**第一行 `// Package xxx 中文一句话`，末尾再加 `// Package xxx does X in
   English.` 一句英文总括。

### 1.5 模板示例

#### 段式（公共包、`internal/core`、`internal/digest`、`internal/testutil`、包级 doc、`Example*`）

```go
// LoadCertificatePEM 从 PEM 加载证书。
//
// 支持 PEM 块包含单张证书或多张证书（多张时只解析第一张）；
// 出错时返回包装的 OpError。
//
// LoadCertificatePEM parses PEM-encoded certificate data and returns a *Certificate.
//
// It accepts PEM blocks that contain a single certificate or a bundle of
// certificates; when multiple certificates are present, only the first is
// returned. Errors are wrapped as OpError.
func LoadCertificatePEM(pemBytes []byte) (*Certificate, error) { ... }
```

#### 单行式（`internal/native/binding_*.go` 的 cgo binding 函数）

```go
// Encrypt 使用 SM2 公钥加密 data。
// Encrypt encrypts data with the given SM2 public key.
//
//export Cgo_SM2_Encrypt
func Cgo_SM2_Encrypt(...) (...) { ... }
```

#### 校验脚本

辅助校验脚本位于 `/tmp/tongsuo-go-tools/check-bilingual-doc.sh`（不进仓库；仅本地
临时使用）。CI 不固化此脚本。

#### 段式对齐与维护指引

中英段式对齐的完整说明、改动统计、常见不对称类型、新增符号检查清单、中英对照常用
动词词典见 [bilingual-doc-guide.md](bilingual-doc-guide.md)。

---

## 2. 命名约定

| 元素 | 约定 | 示例 |
|------|------|------|
| 包名 | 小写单词，无下划线 | `crypto/sm3`、`pkcs/pkcs7`、`internal/core` |
| API 层导出类型/函数 | 按 **C# 语义命名**，遵循 Go 导出约定（首字母大写）；形态走 Go 惯例 | `sm3.Sum`、`sm4.NewCipher`、`sm2.Encrypt` |
| 绑定层函数 | 与铜锁 C 函数名完全一致 | `EVP_DigestInit_ex` |
| shim 包装函数 | `X_` 前缀 | `X_EVP_Digest` |
| 核心层类型 | 去 `EVP_` 前缀，上下文类加 `Ctx` 后缀 | `DigestCtx`、`CipherCtx`、`PKey` |
| 错误变量 | `Err` 前缀 + 语义 | `ErrInvalidKeyLength`、`ErrTagMismatch` |
| 句柄基类 | `handle`（小写，内部使用） | `internal/core` 内 `handle` |
| 内部辅助 | 小写，不导出 | `zeroMem`、`checkLen` |

> 命名以**语义清晰**为优先，具体符号在实现阶段可按实际调整，但三层边界与导出面约定不变。

---

## 3. cgo / 绑定层规范

- `import "C"` **仅允许**出现在 `internal/native` 包
- 绑定函数名与铜锁原生一致；shim 包装统一 `X_` 前缀
- `unsafe` 仅限绑定层与核心层使用，作用域**尽量小**
- **不在 Go 与 C 之间直接传递 Go 指针**；需要回调时经 shim + `//export` thunk 桥接
- 释放 OpenSSL 分配的内存必须用对应的 `*_free` / `OPENSSL_free`，**禁止** `C.free`
- 平台相关差异（如动态库名）用 build tags（`//go:build linux` / `darwin`）与 `#cgo`
  指令隔离

---

## 4. 核心层规范

- 所有句柄包装**继承 `handle` 基类**（`internal/core/handle.go`）
- **所有权模型**：`owned` 标识——本对象创建者持有所有权，外部传入或静态描述符不持有
- 必须提供 `Close()`，**幂等**；释放后句柄置空，后续使用返回明确错误
- `runtime.SetFinalizer` 兜底，但**不作为唯一释放途径**（见架构 §7）
- 敏感内存（密钥、明文）使用后清零——见 §6 务实说明：本库不在持有方做清零（Go 编译器允许消除无副作用清零循环）；由调用方负责源切片清零

---

## 5. 错误处理规范

- 所有可失败函数**返回 `error`**，不使用异常
- 原生失败 → `*OpError`（携带 `ERR_get_error()` 错误码）
- 上层用 `fmt.Errorf("...: %w", err)` 包裹，错误信息包含操作上下文
  （如 `sm4: encrypt: ...`）
- 参数错误 → 哨兵错误（`ErrXxx`）或参数校验错误
- **禁止 panic**（除编程错误如 nil 解引用）；文档注释中声明返回的错误

---

## 6. 内存安全规则

- 防双重释放：`Close()` 幂等 + `owned` 检查
- 防悬垂指针：句柄释放后不得再调用绑定层
- finalizer 注意事项：不保证执行，资源敏感场景必须显式 `Close()`
- **敏感缓冲区清零务实规则**：
  - Go 编译器对 `for i := range b { b[i] = 0 }` 与 `crypto/subtle` 之外的清零循环
    **允许视为无副作用并消除**；`runtime.memclrNoHeapPointers` 也可能被优化为 nop
  - 因此本库不在持有方主动清零密钥/明文切片；该责任**由调用方承担**
  - C 端由 Tongsuo `OPENSSL_cleanse` 处理会话密钥
  - 接口层面：在 `NewCipher` / `NewGCM` / `LoadPrivateKeyPEM` 等入口 GoDoc 注明
    "调用方负责清零源切片"

---

## 7. 代码风格

- 统一 `gofmt`（推荐 `gofumpt`）
- 提交前必须通过：`go vet ./...` 与 `golangci-lint`（启用 govet / staticcheck / errcheck 等）
- **表驱动测试**优先，合理使用 `t.Parallel()`
- **导出面最小化**：能被 unexported 的就不导出
- 每个包提供包文档（`doc.go` 或包注释）
- 优先显式错误处理，避免 `_ =` 吞错
- 常量用命名常量（`iota` 或显式值），不写魔法数字

---

## 8. 测试要求

- 每个公共 API 至少覆盖：**标准向量、往返、边界、错误路径**（详见
  [testing-guide.md](testing-guide.md)）
- CLI 对比测试用 `//go:build tongsuocli` 标签隔离（默认不运行）
- 每个算法子包自带 `*_test.go`，测试目录镜像源码目录

---

## 9. 构建与 CI

### 9.1 本地构建

```bash
TONGSUO_HOME=/opt/tongsuo \
LD_LIBRARY_PATH=${TONGSUO_HOME}/lib \
CGO_CFLAGS="-I${TONGSUO_HOME}/include -Wno-deprecated-declarations" \
CGO_LDFLAGS="-L${TONGSUO_HOME}/lib" \
go build ./...
```

### 9.2 CI（GitHub Actions）

- 步骤：安装铜锁（源码编译）→ `go vet` → `golangci-lint` → `go test ./...` →
  静态链接验证（`go build -tags static ./...`）
- 完整定义见 [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)；
  详细说明见 [architecture.md](architecture.md)
- 矩阵：Linux + macOS × Go 1.21 / 1.23
- 覆盖率仅作为本地参考指标，CI 不再强制门禁

---

## 10. 平台与兼容

- **Linux 优先，macOS 兼容，Windows 后置**
- 平台相关代码用 build tags 隔离
- 动态库路径差异集中在 `internal/native` 处理，不扩散到 API 层
