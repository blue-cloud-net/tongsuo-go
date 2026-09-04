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

## 示例清单

### [sm2](./sm2) — SM2 加解密与签名验签

密钥生成、PEM 序列化、加解密（ASN.1 DER）、签名验签（含自定义 userId）。

```bash
go run ./examples/sm2
```

### [self-signed-cert](./self-signed-cert) — SM2 + SM3 自签证书

创建 X.509 v3 自签证书、SAN / KeyUsage / EKU / SKID / AKID 扩展、指纹与 PEM 往返。

```bash
go run ./examples/self-signed-cert
```

### [ntls-loopback](./ntls-loopback) — NTLS（国密 TLCP）回环

NTLS 双证书（签名 + 加密）握手 + 多轮回显读写。

```bash
go run ./examples/ntls-loopback
```

### [ed25519](./ed25519) — Ed25519 签名 / 验签与 PEM 序列化

Ed25519（RFC 8032）密钥生成、32B 原始种子 / 公钥互操作、64B 签名、PKCS#8 / SPKI PEM 往返。

```bash
go run ./examples/ed25519
```

### [x25519](./x25519) — X25519 ECDH 共享密钥派生

X25519（RFC 7748）密钥对生成、双向共享密钥派生一致性、32B 原始字节与 PKCS#8 / SPKI PEM 互操作。

```bash
go run ./examples/x25519
```
