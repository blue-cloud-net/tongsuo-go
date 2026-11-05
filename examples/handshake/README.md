# TLS / NTLS 握手测试示例

这是使用公开 SDK API 的可运行示例；无第三方依赖，不包含铜锁本体。
先按上级 README 设置铜锁 8.4.0+ 的头文件、链接库与 CLI 环境。

在本目录运行。TLS 凭证文件的第一张为 leaf，后续为中间证书；不必发送信任根。
客户端默认 `-verify report`，验证失败后继续并打印失败码；连接成功不能证明证书可信。
选择 `-verify strict` 时验证失败会终止；`-verify none` 明确不执行信任验证。

```bash
# TLS 服务端，接收一次连接并回显
go run . -mode server -cert server-chain.pem -key server-key.pem -once
# TLS 客户端，严格验证并收发数据；SNI 与验证名称可分别指定
go run . -addr 127.0.0.1:4433 -servername route.example -verify-name server.example -ca ca.pem -verify strict -message ping
```

NTLS 使用不同的签名与加密私钥，两张证书应标识同一服务身份，分别具有正确 KeyUsage。
签名和加密 PEM 文件可分别包含各自中间链，SDK 合并去重为线上共享证书池。
严格验证时提供对应 CA 信任根，双向认证时同时提供客户端双证书；ECDHE-SM2 套件要求
客户端凭证。RFC 8998 国密 TLS 1.3 不属于本示例当前版本，另归 0.10.0。

```bash
go run . -mode server -protocol ntls -sign-cert sign-chain.pem -sign-key sign-key.pem -enc-cert enc-chain.pem -enc-key enc-key.pem -ciphers ECC-SM2-SM4-GCM-SM3 -once
go run . -protocol ntls -verify report -message ping
```

`-protocol mixed` 服务端同时提供 TLS 凭证和 NTLS 双证书，即可在同一端口接受两类
客户端；客户端仍显式选择 `tls` 或 `ntls`，不会失败后自动换协议重试。
`-alpn`、`-groups`、`-sigalgs`、`-ciphers` 接受逗号分隔的原生名称。
服务端使用 `-client-auth request` 或 `require` 请求客户端凭证，配合 `-verify strict`
和 `-ca` 强制验证；`-response http` 提供最小 HTTP/1.1 响应演示，不代表 SDK HTTP 集成。
握手和 I/O 默认超时为 5 秒，使用 `-timeout` 调整；`-min-version tls1.2 -max-version tls1.2`
可固定 TLS 1.2，`-min-version tls1.3` 限制 TLS 1.3；`-dh-params` 加载 DH 参数文件。
状态输出包含协商组、对端签名、验证码和失败握手的原生错误码。

SDK 的 SNI 回调可通过 GetCertificate / GetNTLSCertificate 选择凭证，或 GetConfigForClient
选择完整配置；回调可能并发执行，须及时返回，不能重入同一连接。构造后不再修改配置，
所选源证书/私钥在构造和回调期间须保持有效。基础配置限制组时，所选配置须显式指定
CurvePreferences（可 Clone 基础配置），混合模式的版本范围仅限制 TLS 一侧。

混合模式及 SNI 服务端会在每次 ClientHello 选择时读取源凭证；这些源证书/密钥应保留到服务端关闭且在途选择回调结束，再显式 Close / asym.Close。
