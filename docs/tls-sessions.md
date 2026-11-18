# TLS / NTLS 会话与票据（0.11.0，未发布）

启用 OCSP 装订验证时，会话响应的来源、重新验证和回退规则见 [HTTP/1.1 与 OCSP stapling](tls-http-ocsp.md)。

## 使用入口

客户端显式配置 `Config.SessionCache`，同一配置实例的多次拨号共享会话：

```go
cache, err := tls.NewSessionCache(64)
if err != nil { return err }
config := &tls.Config{
    Verification: tls.VerifyStrict,
    RootCAs: roots,
    SessionCache: cache,
}
// 多次 DialContext 使用同一个 config；读写自动收集后续票据。
```

`ConnectionState.SessionReused` 来自原生实际恢复标志。服务端拒绝恢复时允许完整握手，
此值为 false；身份验证或应用验证回调失败则中止连接，不自动重拨。
恢复后仍按当前名称、用途、时间与信任策略重新验证（NTLS 分别验证签名与加密证书），并依次执行
`VerifyPeerCertificate`、`VerifyConnection`；前一个步骤拒绝后不执行后续步骤。
`VerifyNone` / `VerifyReport` 保持已有显式语义，不把恢复状态当作验证通过。

TLS 1.3（包括 RFC 8998）的票据在握手后到达。`Conn.SessionState()` 只读取已经取得的
可恢复会话快照；没有可用会话时返回 `ErrNoSession`。需要主动驱动读取时调用
`Conn.WaitSession(ctx)`：它遵循 context 和当前 read deadline，不修改用户期限，
与读取串行，允许另一方向写入。等待读取锁也可取消；原生 fd 等待最多按 25 ms 切片检查取消。
它将应用数据暂存最多 64 KiB，后续 `Read` 按序返回；达到上限时报错并保留数据，
调用方应先读取再继续等待。没有票据的配置应设置有界 context，握手本身不等待票据。
恢复握手未续发票据时，仍可取得已成功恢复且尚未过期的原会话。

可运行示例：[session-resumption](../examples/session-resumption/)。

## 缓存与隔离

`SessionCache` 提供 `Get(string) (*SessionState, bool)` 和
`Put(string, *SessionState)`；nil 值删除条目。`ServerSessionCache` 使用同样接口，
作用于服务端有状态会话。实现必须并发安全，回调不得重入当前连接。
`NewSessionCache(capacity)` 提供有界 LRU，拒绝非正容量，读取时淘汰过期条目并返回独立副本。
服务端默认使用独立的 256 条内存缓存；客户端默认不跨连接缓存。

默认缓存域按原始 `Config` 实例隔离，使用独立随机标识而非对象地址；内部拨号复制保留域，公开 `Clone()` 创建新域。
跨配置/进程共享使用稳定的 `SessionPolicyID`，并显式共享服务端缓存或票据管理器。
调用方必须在回调语义或闭包依赖变化时更换策略标识；SDK 不推测函数或闭包的等价性。
配置一旦用于连接就不能修改。

缓存键对端点、协议配置、SNI/验证名、客户端身份、证书链、根证书、验证策略、
ALPN、套件及参数使用无歧义编码后摘要。服务端在 SNI/凭证选择后结合实际协议与 SNI
设置会话上下文，禁止跨身份或 TLS/NTLS 恢复。
同一共享服务在不同地址测试时，客户端自动缓存仍按端点隔离；可显式导入会话测试服务端共享，
目标服务身份仍须通过当前验证。

## DER / PEM 与持久化

- `ParseSessionDER` / `ParseSessionPEM` 和 `SessionState.MarshalDER` / `MarshalPEM`
  使用原生 `SSL_SESSION` 格式，兼容铜锁 `sess_id`、`s_client -sess_in/-sess_out`。
  DER 限额 1 MiB，PEM 限额 2 MiB；拒绝尾随数据、多块 PEM 与非会话块。
- `SessionState.Metadata()` 返回版本、创建/到期时间、票据标志、可恢复状态和标识副本；
  不暴露原生句柄或会话密钥。可恢复标志不保证服务端接受下一次握手。
- 原生会话包含秘密，但不包含 SDK 的配置绑定和完整对端链。需要跨进程恢复时，单独保存
  `ConnectionState.PeerCertificates`，解析后使用 `WithPeerCertificates` 附加链，
  再显式赋给目标 `Config.Session`。附加链的叶证书必须与原生会话一致，仍须重新验证信任。
  缺少中间证书且当前信任配置无法补齐时，严格验证失败；NTLS 导入缺少双证书材料时放弃恢复，执行完整握手。
- SDK 缓存自动保留客户端收到的完整对端链。服务端将客户端链保存到原生会话附属数据，
  供票据与有状态会话恢复后验证双向认证；这些链材料不替代当前信任根。
- 外部缓存实现若序列化条目，须连同链材料保存；不得把解析成功当作验证通过。
  原生会话导入不构成对来源、服务身份或客户端身份的认证。
- 导出结果、会话文件及票据密钥都应按密钥材料保护；调用方负责清零源/输出切片，
  禁止写入普通日志。SDK 不自动读写持久化文件。

## 票据与轮换

`SessionTicketsDisabled` 禁止服务端票据签发和客户端票据扩展；不禁止 TLS 1.2 / NTLS
有状态缓存。TLS 1.3 没有票据时不能建立新的恢复会话。
`SessionTicketCount *int` 区分 nil（原生默认）和显式零；合法范围 0..16，
禁用票据与正数数量同时设置时报错。数量控制只作用于 TLS 1.3。

每个服务端默认持有独立 `TicketKeyManager`，无需后台 goroutine，每日使用时自动轮换，
按密钥实际创建时间保留七天解密窗口。`GenerateTicketKey()` 生成 64 字节密钥：
16 字节名称、16 字节 AES-128-CBC 密钥、32 字节 HMAC-SHA256 密钥。

共享一个管理器可在进程内多个 Server 同步轮换。跨进程由调用方分发同一密钥环并调用
`SetKeys([]TicketKey)`；该操作关闭自动轮换，首项签发、其余仅解密，旧密钥恢复时请求续发。
拒绝空环、重复名称及超过 32 项的密钥环。移除旧密钥后旧票据不能恢复，允许完整握手。
要跨 Server 恢复，还须使用相同 `SessionPolicyID` 与相容配置；共享票据密钥不取消隔离。

TLS 1.2 服务端可能通过有状态缓存接受仍有效的会话；若要撤销全部恢复能力，
调用方还需删除相应缓存条目或更换策略域，不能只移除票据密钥。

## 兼容边界

本版只扩充 `Config` / `ConnectionState`，使用字段名的字面量无需迁移；
无字段名的结构体字面量须改为带字段名。
TLS 1.2、TLS 1.3、NTLS、RFC 8998 两个 SM4 套件分别验收实际恢复；混合端口仍按实际协议隔离。
不提供外部 PSK、0-RTT、HTTP 集成或内置数据库，也不自动降级协议或替换密码实现。
