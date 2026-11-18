# HTTP/1.1 与 OCSP stapling

## HTTP/1.1 接入

客户端将 `tls.NewHTTPTransport` 返回的传输层交给 `http.Client`。HTTPS 使用铜锁握手，默认严格验证证书及主机名。连接池由标准库管理，结束时可调用 `CloseIdleConnections`。传输层仅支持直连 HTTPS，降级为 HTTP 的重定向会被拒绝。

```go
transport, err := tls.NewHTTPTransport(nil)
if err != nil {
    return err
}
defer transport.CloseIdleConnections()
client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
response, err := client.Get("https://service.example")
if err != nil {
    return err
}
defer response.Body.Close()
```

服务端把已有的 `http.Server` 和铜锁服务端配置交给 `tls.ListenAndServeTLS`，或用 `tls.ServeTLS` 传入已绑定的监听器。Handler 从 `tls.HTTPConnectionState(r.Context())` 读取协商结果。客户端可在 `Config.VerifyConnection` 读取铜锁状态。标准库请求及响应的 TLS 状态字段不能完整表示铜锁连接。

服务端在每条连接上分别完成握手，使用 HTTP 服务端读写超时中的最短正值，均未设置时限制为 10 秒。调用 `http.Server.Shutdown` 或 `Close` 会关闭监听器并取消尚未完成握手的连接。应在启动前完成服务器配置。

## OCSP 装订

服务端设置 `Config.OCSPStaple`，或通过 `Config.GetOCSPStaple` 按实际选中的证书返回 DER。回调优先，空响应表示不装订，错误会终止握手。应用负责获取和刷新响应。回调可能并发运行。

客户端用 `RequestOCSP` 获取 DER。显式验证时，将实际叶证书和签发者交给 `x509.ParseOCSPResponse`，检查响应状态、证书状态与有效期，再通过 `Response.Verify` 验证签名和信任。解析所得响应需关闭。

```go
response, err := x509.ParseOCSPResponse(state.OCSPResponse, leaf, issuer)
if err != nil {
    return err
}
defer response.Close()
if response.Status != 0 || response.CertStatus != x509.OCSPGood ||
    response.ThisUpdate.IsZero() || response.ThisUpdate.After(now) ||
    response.NextUpdate.IsZero() || !now.Before(response.NextUpdate) {
    return errors.New("unusable OCSP response")
}
return response.Verify(roots, []*x509.Certificate{issuer})
```

应用也可启用 `OCSPVerifyIfPresent` 或 `OCSPRequire`，两者均要求严格证书验证。内建策略允许 5 分钟时钟偏差。没有 `NextUpdate` 的响应以 `ThisUpdate` 后 24 小时为有效期上限。

`OCSPStapled` 表示当前握手取得响应。恢复时可使用会话内的响应，`OCSPFromSession` 标记该来源。启用验证后，恢复前检查响应和当前信任链。材料缺失或失效时发起完整握手。恢复成功后使用当前验证链再次检查，若握手带来新响应则优先检查新响应。会话 DER/PEM 保持原生编码，导入后可通过 `WithPeerCertificates` 和 `WithOCSPResponse` 附加材料。

NTLS 的强制策略需要验证双证书。只有单份响应时，强制验证返回能力不足。

在铜锁 8.4.0 和 8.5.0 上，HTTP/1.1 已通过 TLS 1.2、TLS 1.3、NTLS 和 RFC 8998 的 GCM/CCM 回环。两版均可在这些组合中传递单份 OCSP 响应。NTLS 的双证书强制验证会在覆盖不足时拒绝连接。
