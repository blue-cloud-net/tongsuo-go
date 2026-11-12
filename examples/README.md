# Examples

`tongsuo-go` 的最小可运行示例。完整 API 参考见 `pkg.go.dev`。

## 运行前准备

每个示例需要铜锁 8.4.0+ 环境。统一环境变量：

```bash
export TONGSUO_HOME=/opt/tongsuo
export LD_LIBRARY_PATH=${TONGSUO_HOME}/lib64
export CGO_CFLAGS="-I${TONGSUO_HOME}/include -Wno-deprecated-declarations"
export CGO_LDFLAGS="-L${TONGSUO_HOME}/lib64"
```

> 说明：`examples/` 下的每个示例都是**独立 Go module**（各自有 `go.mod`，并通过
> `replace` 指向本仓库），请在示例目录内运行（下方命令已按此写法给出）。

## 示例清单

### [sm2](./sm2) — SM2 加解密与签名验签

密钥生成、PEM 序列化、加解密（ASN.1 DER）、签名验签（含自定义 userId）。

```bash
cd examples/sm2 && go run .
```

### [self-signed-cert](./self-signed-cert) — SM2 + SM3 自签证书

创建 X.509 v3 自签证书、SAN / KeyUsage / EKU / SKID / AKID 扩展、指纹与 PEM 往返。

```bash
cd examples/self-signed-cert && go run .
```

### [ntls-loopback](./ntls-loopback) — NTLS（国密 TLCP）回环

NTLS 双证书（签名 + 加密）握手 + 多轮回显读写。

```bash
cd examples/ntls-loopback && go run .
```

### [handshake](./handshake) — TLS / NTLS 客户端与服务端握手测试

SDK API 示例：显式 TLS/NTLS/混合端口、RFC 8998、完整证书链、ALPN、客户端认证及独立 SNI/验证名称；可选事件、trace/keylog 与 SCT 采集。
默认记录验证失败后继续，另提供 strict / none；显示失败握手的状态与验证错误，最后关闭连接。

```bash
cd examples/handshake && go run . -h
```

### [ed25519](./ed25519) — Ed25519 签名 / 验签与 PEM 序列化

Ed25519（RFC 8032）密钥生成、32B 原始种子 / 公钥互操作、64B 签名、PKCS#8 / SPKI PEM 往返。

```bash
cd examples/ed25519 && go run .
```

### [x25519](./x25519) — X25519 ECDH 共享密钥派生

X25519（RFC 7748）密钥对生成、双向共享密钥派生一致性、32B 原始字节与 PKCS#8 / SPKI PEM 互操作。

```bash
cd examples/x25519 && go run .
```

### [ecdh](./ecdh) — 曲线 ECDH（NIST / OKP）共享密钥派生

`asym` 生成 + `ecdh` 协商：P-256 / P-384 / P-521 / secp256k1（X9.63）与
X25519 / X448（RFC 7748）的密钥生成、PEM（PKCS#8 / SPKI）往返、双向共享密钥派生，
并演示曲线不可用时的降级处理。

```bash
cd examples/ecdh && go run .
```

## `0.6.0` 包级可运行示例

以下 GoDoc 示例可通过 `go test ./sym ./asym ./ecdh ./keystore` 执行，使用与主库相同的铜锁环境：

- [AES-OCB AEAD](../sym/extended_example_test.go)：密文与 tag 拼接、认证解密。
- [PKCS#8](../asym/pkcs8_example_test.go)：显式 PBES2/PRF 的加密 DER 往返。
- [EC 参数](../ecdh/parameters_example_test.go)：命名曲线参数 PEM 往返。
- [统一密钥加载](../keystore/load_example_test.go)：同一 PEM 中读取私钥与公钥。

## `0.7.0` 包级可运行示例

使用铜锁 8.4.0 的对应环境运行 `go test ./x509 ./pkcs/pkcs7`：

- [分步签发与 DER 扩展](../x509/reliability_example_test.go)：大序列号、SAN/KU/SKID/AKID、自定义 OID、最后签名并验签；签名后不可修改。
- [PKCS#7 签验与信封](../pkcs/pkcs7/operations_example_test.go)：显式信任存储、验证结果 Close、多接收者入口与 CBC 完整性边界。
- [ECDH](./ecdh/main.go)：Public 返回独立公钥与 error，公私钥均显式 Close。

## `0.8.0` 包级示例

使用固定铜锁 8.4.0/8.5.0 的对应环境执行 `go test ./sym ./asym ./ecdh ./tls`：

- [AES-GCM-SIV](../sym/gcmsiv_example_test.go)：AEAD tag 拼接与原生不支持处理（GoDoc 编译示例）。
- [Ed25519ph](../asym/eddsa_example_test.go)：原消息、上下文及不支持分支（GoDoc 编译示例）。
- [SM2DH](../ecdh/derive_example_test.go)：双方静态/临时密钥、角色、ID 与派生对称性；不含密钥确认。
- [NTLS](./ntls-loopback/main.go)：显式分配签名与加密证书 KeyUsage，兼容 8.5.0 原生用途检查。
