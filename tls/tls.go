// Package tls 基于铜锁原生实现提供 TLS 与 NTLS（国密 TLCP）传输层。
// 提供 TLS 客户端（Dial）、服务端（Server + Accept）与 net.Conn 包装（Conn），
// 支持 SM2 单证书（TLS）与双证书（NTLS：签名证书 + 加密证书）。
//
// Package tls provides TLS and NTLS (TLCP) transport-layer connections
// backed by the Tongsuo native library. It exposes a client Dial, a server
// (Server with Accept) and a net.Conn wrapper (Conn). NTLS uses the GM/T
// 0024 TLCP dual-certificate pair (sign certificate + encryption
// certificate); standard TLS uses a single certificate.
package tls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/native"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// Config 表示 TLS / NTLS 配置。
//
// Cert / Key 用于标准 TLS 路径（服务端必填，客户端用于双向认证时可选）；启用 NTLS
// 时由 SignCert / SignKey 与 EncCert / EncKey 提供 GM/T 0024 TLCP 双证书
// （签名证书 + 加密证书）。MinVersion / MaxVersion 与 CipherSuites 非空时覆盖库默认。
//
// 客户端对端验证（D1，方案 A，默认不验证）：
//
//   - RootCAs 为 nil 或 InsecureSkipVerify 为 true：客户端不验证对端证书，
//     与 crypto/tls 默认行为的语义不同（crypto/tls 默认开启）；本库出于对国密
//     生态（私有 CA、自签双证书为主）的适配默认关闭，**强烈建议生产环境显式
//     配置 RootCAs**——OpenSSL 在 PEER 模式下未提供 CA 时会立即握手失败。
//
//   - RootCAs 非 nil 且 InsecureSkipVerify == false：客户端开启 PEER 验证
//     并注入信任根；ServerName 非空时同时启用主机名校验。
//
//   - ServerName 空时 Dial 会从 network/addr  推导 host 部分。
//
// **NTLS 警告**：本库对 NTLS/TLCP 的对端验证接线遵循与 TLS 完全相同的策略；
// 但 Tongsuo NTLS 路径是否执行标准 X509_STORE 链/主机名校验依赖 Tongsuo
// 版本，生产部署前请先实测握手行为。
//
// Config represents a TLS or NTLS configuration shared by Dial and Server.
//
// See the package-level "客户端对端验证" Chinese comment above for the
// D1 default-verify policy (方案 A: VERIFY_NONE by default; PEER enabled
// only when RootCAs is set AND InsecureSkipVerify is false).
type Config struct {
	// Cert 与 Key 为 TLS 证书与私钥（服务端必填；客户端用作客户端证书时可选）。
	Cert *x509.Certificate
	Key  *sm2.PrivateKey

	// NTLS 启用国密双证书（须同时提供签名证书与加密证书）。
	NTLS     bool
	SignCert *x509.Certificate
	SignKey  *sm2.PrivateKey
	EncCert  *x509.Certificate
	EncKey   *sm2.PrivateKey

	// MinVersion / MaxVersion 为协议版本范围（0 表示不限制）。
	MinVersion uint16
	MaxVersion uint16

	// CipherSuites 为可用密码套件（空表示使用默认）。
	CipherSuites []string

	// RootCAs 为客户端用于信证书池（nil 表示不进行对端验证）；
	// InsecureSkipVerify 为 true 时强制跳过验证（覆盖 RootCAs）。
	RootCAs            []*x509.Certificate
	InsecureSkipVerify bool
	// ServerName 为对端主机名校验的预期值（空时 Dial 从 addr 推导 host）。
	ServerName string
}

// Dial 与指定地址建立 TLS 连接（含握手）；成功时返回包装底层 socket 的 *Conn 并已完成握手，失败时返回错误并关闭已部分初始化的资源。
//
// 客户端对端验证（D1 方案 A 默认行为）：
//   - config.InsecureSkipVerify 为 true：跳过验证；
//   - 否则若 config.RootCAs 非 nil 或 config.ServerName 非空：开启 PEER
//     验证 + 注入根 + 主机名校验；
//   - 否则保持 VERIFY_NONE（与 crypto/tls 默认行为不同）。
//
// 握手完成后若开启了 PEER 验证，额外调用 SSL_get_verify_result 检查错误码；
// 验证失败关闭连接并返回 *x509.VerifyError 风格的错误。
//
// Dial connects to the given network address using a TLS or NTLS client
// handshake. On success it returns a *Conn wrapping the underlying socket
// after the handshake completes; on failure it returns an error and closes
// any partially initialised resources.
// DialContext 与指定地址建立 TLS 连接。ctx 同时控制 TCP 拨号超时/取消与握手超时/取消。
//
// 握手完成后若开启了 PEER 验证，额外调用 SSL_get_verify_result 检查错误码；
// 验证失败关闭连接并返回 *HandshakeError{Kind:HandshakeErrorPeerVerify}。
//
// 取消/超时：ctx 取消/超时经 net.Dialer.DialContext 传播为底层 error；
// 握手阶段的取消由 *Conn.HandshakeContext 负责。
//
// **Linux 平台限制**：握手阶段使用 syscall.Select 等待 fd 可读，该调用
// 在 Linux 上不可从 Go 侧直接打断；ctx 触发后需等待当前 waitFD 超时
// （默认 30s）才能从 HandshakeContext 返回。建议用户使用带 deadline
// 的 ctx，或通过 SetDeadline 提前终结。完整 epoll/poll(2) 改造计划在
// v0.1.3+。
//
// DialContext dials network/addr under ctx and completes a TLS or NTLS
// handshake. Cancellation of ctx aborts the TCP dial (via net.Dialer)
// and the TLS handshake (via *Conn.HandshakeContext); the returned
// error is the raw ctx.Err() (context.Canceled or context.DeadlineExceeded).
//
// On peer-verification failure (when PEER mode is enabled) the returned
// error is a *HandshakeError{Kind:HandshakeErrorPeerVerify} wrapping
// the Tongsuo X509 verification result text.
func DialContext(ctx context.Context, network, addr string, config *Config) (net.Conn, error) {
	dialer := &net.Dialer{}
	raw, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tlsCtx, err := newContext(config, true)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	// 主机名：D1 方案 A 仅在用户显式提供 ServerName 时启用；
	// 同时支持从 addr 推导（"host:port" / "[host]:port" / "host"）。
	hostname := ""
	if !shouldSkipVerify(config) {
		if config.ServerName != "" {
			hostname = config.ServerName
		} else if host, _, e := net.SplitHostPort(addr); e == nil {
			// SplitHostPort 成功：去掉端口，得到纯主机名用作 SNI / 证书校验。
			// 去除 IPv6 字面量外层的方括号（SplitHostPort 不会去掉）。
			hostname = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
		} else if !strings.Contains(addr, ":") {
			// addr 没有冒号（裸主机名）：可直接用作 SNI。
			hostname = addr
		} else {
			// addr 含冒号但 SplitHostPort 失败（典型 IPv6 缺方括号 "::1:443"）：
			// 不强行回退到原始串，避免把 "host:port" 当 SNI 发出去；
			// 留空 hostname，由 wrapConn / 验证层使用对端 IP 作为 fallback。
			hostname = ""
		}
	}
	conn, err := wrapConnWithHostname(raw, tlsCtx, false, hostname, true)
	if err != nil {
		// wrapConnWithHostname 现在不做握手；唯一可能的失败是
		// NewSSLConn / SetHostname，都与 ctx 无关——直接返回。
		_ = raw.Close()
		_ = tlsCtx.Close()
		return nil, err
	}
	tlsConn := conn.(*Conn) // wrapConn 总是返回 *Conn
	if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
		// HandshakeContext 已经 Close 了连接。
		return nil, hsErr
	}
	// 主机名校验：握手完成后检查 Tongsuo 验证结果。
	if !shouldSkipVerify(config) {
		if code := tlsConn.ssl.VerifyResult(); code != core.VerifyOK {
			_ = tlsConn.Close()
			return nil, &HandshakeError{
				Op:   "DialContext",
				Kind: HandshakeErrorPeerVerify,
				Err:  fmt.Errorf("peer verification failed: %s", core.VerifyErrorMessage(code)),
			}
		}
	}
	return tlsConn, nil
}

// Dial 以 context.Background() 包装 DialContext，向后兼容现有调用点。
//
// Dial is a context.Background() wrapper around DialContext, kept for
// backward compatibility with callers that cannot pass a context.
func Dial(network, addr string, config *Config) (net.Conn, error) {
	return DialContext(context.Background(), network, addr, config)
}

// shouldSkipVerify 按 D1 方案 A 判定客户端是否跳过对端验证。
//
// shouldSkipVerify implements the D1 方案 A policy: VERIFY_NONE by
// default; PEER enabled only when RootCAs is non-empty AND
// InsecureSkipVerify is false.
func shouldSkipVerify(config *Config) bool {
	if config == nil {
		return true
	}
	if config.InsecureSkipVerify {
		return true
	}
	if len(config.RootCAs) == 0 && config.ServerName == "" {
		return true
	}
	return false
}

// Server 表示一个 TLS / NTLS 服务端。
//
// Server represents a TLS or NTLS server that performs handshakes on top
// of already-accepted raw connections.
type Server struct {
	ctx *core.TLSContext
}

// NewServer 创建 TLS 服务端；失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// NewServer creates a TLS or NTLS server from the given configuration.
// On failure it returns an error wrapping an OpError that describes the
// underlying operation.
func NewServer(config *Config) (*Server, error) {
	ctx, err := newContext(config, false)
	if err != nil {
		return nil, err
	}
	return &Server{ctx: ctx}, nil
}

// Accept 将已接受的原始连接包装为 TLS 连接（**惰性握手**：仅创建底层 SSL 句柄，
// 不执行服务端 Accept()）；调用方须随后调用返回 *Conn 的 Handshake /
// HandshakeContext 以驱动握手。
//
// Accept wraps an already-accepted raw connection and prepares the
// underlying SSL handle without performing the server-side handshake.
// Callers must invoke *Conn.Handshake / HandshakeContext on the
// returned *Conn to actually drive the handshake.
func (s *Server) Accept(raw net.Conn) (net.Conn, error) {
	return wrapConnWithHostname(raw, s.ctx, true, "", false)
}

// Close 释放服务端上下文（重复调用安全，幂等）。
//
// Close releases the server-side TLS context. Close is safe to call
// repeatedly (idempotent).
func (s *Server) Close() error {
	return s.ctx.Close()
}

// Conn 是一个 TLS / NTLS 连接（net.Conn），基于底层 socket fd 上的 SSL。
//
// Read 与 Write 通过内部互斥锁序列化；多 goroutine 并发调用安全但不能并行。
// Close 通过 sync.Once 保证幂等：先关闭底层 raw socket 以唤醒在途阻塞的
// SSL_read / SSL_write / select 调用，再关闭 SSL 句柄；之后 Read/Write 立即返回
// `io.EOF`/错误而非传 nil 进 cgo。
//
// Conn is a net.Conn implementation that performs TLS or NTLS I/O on top
// of an underlying socket file descriptor.
//
// Read and Write are serialized with an internal mutex; concurrent calls
// from multiple goroutines are safe but not parallel. Close uses a
// sync.Once to remain idempotent: it closes the underlying raw socket
// first (to unblock any in-progress SSL_read / SSL_write / select call)
// and then releases the SSL handle. Subsequent Read/Write calls return
// io.EOF / an error rather than passing nil across the cgo boundary.
type Conn struct {
	ssl       *core.SSLConn
	raw       net.Conn
	mu        sync.Mutex  // 序列化 Read/Write
	closeOnce sync.Once   // 保证 Close 只执行一次（幂等）
	closed    atomic.Bool // Close 完成后置位，Read/Write 入口短路

	// ownsCtx 为真时 Conn 拥有底层 *core.TLSContext，Close 时释放；
	// 服务端 Accept 路径中 sharesCtx=false，关闭 ctx 由 Server.Close 负责。
	ownsCtx bool
	ctx *core.TLSContext

	// isServer / ntls 记录握手方向与协议类型，PeerCertificates / Close 路径需要。
	isServer bool
	ntls     bool

	// handshakeOnce 与 handshakeErr 保证 Handshake / HandshakeContext 幂等。
	handshakeOnce sync.Once
	handshakeErr  error
	handshakeDone atomic.Bool
}

// wrapConnWithHostname 创建底层 SSL 句柄并构造 *Conn，但不执行握手。
// ownsCtx 为 true 时 Conn 拥有 ctx（仅 DialContext 路径为 true）；
// 服务端 Accept 路径共享 s.ctx，由 Server.Close 释放。
//
// wrapConnWithHostname creates the underlying SSL handle and returns a
// *Conn without performing the handshake. When ownsCtx is true, the
// returned *Conn owns ctx (only the DialContext path sets this); the
// server Accept path shares ctx with the Server and the Server is
// responsible for releasing it.
func wrapConnWithHostname(raw net.Conn, ctx *core.TLSContext, server bool, hostname string, ownsCtx bool) (net.Conn, error) {
	fd, err := connFD(raw)
	if err != nil {
		return nil, err
	}
	ssl, err := core.NewSSLConn(ctx, fd)
	if err != nil {
		return nil, err
	}
	if !server && hostname != "" {
		// 主机名验证必须在 Connect 之前设置；空字符串表示跳过。
		if err := ssl.SetHostname(hostname); err != nil {
			_ = ssl.Close()
			return nil, err
		}
	}
	return &Conn{
		ssl:     ssl,
		raw:     raw,
		ownsCtx: ownsCtx,
		ctx:     ctx,
		isServer: server,
		ntls:     ctx.IsNTLS(),
	}, nil
}

// Handshake 驱动 TLS / NTLS 握手。是 HandshakeContext(context.Background()) 的别名。
//
// Handshake performs the TLS / NTLS handshake; it is a shortcut for
// HandshakeContext(context.Background()). Handshake is idempotent: the
// handshake is driven exactly once per *Conn, and the result is cached.
// Returns the cached error on subsequent calls.
//
// **API 注意**：Server.Accept 当前是惰性的；服务端连接在 Accept 后必须调
// 用 Handshake / HandshakeContext 才会真正完成握手。
func (c *Conn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

// HandshakeContext 在 ctx 的控制下驱动 TLS / NTLS 握手。握手在后台 goroutine
// 中执行；ctx 取消时立即关闭底层 socket 使 select 唤醒、握手退出，等待
// goroutine 收敛后返回 ctx.Err()。握手完成后必须 Close 才能彻底释放。
//
// 返回的错误可能为：
//   - context.Canceled / context.DeadlineExceeded：ctx 取消/超时；
//   - *HandshakeError：握手本身失败（版本/套件/对端验证等）；
//   - core.OpError：底层 Tongsuo 错误未分类。
//
// HandshakeContext drives the TLS / NTLS handshake under ctx. The
// handshake runs on a helper goroutine; ctx cancellation closes the
// underlying socket to wake up the poll-based retry loop, then waits
// for the helper goroutine to converge before returning ctx.Err().
//
// The handshake is executed exactly once per *Conn; subsequent calls
// return the cached error (or nil if the first call succeeded).
func (c *Conn) HandshakeContext(ctx context.Context) error {
	if c == nil {
		return errors.New("tls: nil Conn")
	}
	c.handshakeOnce.Do(func() {
		// 校验 ctx：HandshakeContext 拒绝 nil；DialContext 已早一步传
		// Background() 进来，因此只针对外部直接调用此方法的场景。
		if ctx == nil {
			c.handshakeErr = errors.New("tls: HandshakeContext requires non-nil ctx")
			return
		}
		if c.handshakeDone.Load() {
			return
		}
		// 句柄已关闭：直接报错（Close 后不可再 Handshake）。
		if c.ssl == nil {
			c.handshakeErr = errors.New("tls: SSL closed")
			return
		}
		errCh := make(chan error, 1)
		go func() {
			var hsErr error
			if c.isServer {
				hsErr = c.ssl.Accept()
			} else {
				hsErr = c.ssl.Connect()
			}
			errCh <- hsErr
		}()
		select {
		case hsErr := <-errCh:
			c.handshakeErr = hsErr
		case <-ctx.Done():
			// 唤醒握手中的 SSL_read/SSL_write 等待。
			//
			// 仅关 raw socket 在 Linux 上不一定能立刻打断 syscall.Select
			// （fd 仍存在但无数据），所以同时把 SSLConn 的 deadline 设为
			// 「现在」让后续 waitFD 立即返回 timeout；二者联合保证后台
			// goroutine 能在毫秒级退出。
			_ = c.ssl.SetDeadline(time.Now())
			_ = c.raw.Close()
			// 等后台 goroutine 退出后再返回 ctx.Err，避免泄漏。
			<-errCh
			c.handshakeErr = ctx.Err()
		}
		if c.handshakeErr == nil {
			c.handshakeDone.Store(true)
		}
	})
	if c.handshakeErr == nil {
		return nil
	}
	// 包装握手错误为 HandshakeError（保留 context 取消/超时原样）。
	if errors.Is(c.handshakeErr, context.Canceled) || errors.Is(c.handshakeErr, context.DeadlineExceeded) {
		return c.handshakeErr
	}
	return classifyHandshakeErr("HandshakeContext", c.handshakeErr)
}

// classifyHandshakeErr 将底层错误包装为 *HandshakeError（仅握手阶段）。
// 取消/超时已在调用方拦截；其余错误按最近的 Tongsuo 错误码分类。
//
// classifyHandshakeErr wraps a non-context error from the handshake path
// as a *HandshakeError, using the most recent Tongsuo error code on the
// thread's error queue as the classification signal.
func classifyHandshakeErr(op string, err error) error {
	if err == nil {
		return nil
	}
	// 先把队列里残留的错误全部弹出，再用最后一次弹出的码分类。
	var last uint64
	for {
		code := native.PopError()
		if code == 0 {
			break
		}
		last = code
	}
	kind := classifyOpenSSLError(last)
	if kind == HandshakeErrorOther {
		// 无可分类错误码：归到 Network 类。
		kind = HandshakeErrorNetwork
	}
	return &HandshakeError{Op: op, Kind: kind, Err: err}
}

// Read 读取解密后的应用层数据。
//
// 与同一 Conn 上的并发 Write 调用互斥序列化。连接已关闭时返回 io.EOF；
// 短读返回 n > 0 与 nil（与 io.Reader 契约一致）。
//
// Read reads decrypted application data from the TLS or NTLS connection
// into b.
//
// Read is serialized with concurrent Write calls on the same Conn.
// Returns io.EOF after Close. Returns (n, nil) for partial reads
// (matching the io.Reader contract).
func (c *Conn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, io.EOF
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return 0, io.EOF
	}
	n, err := c.ssl.Read(b)
	if err != nil && c.closed.Load() {
		// 关闭后读返回 io.EOF，便于 io.Copy 等感知对端正常关闭。
		return n, io.EOF
	}
	if err != nil && isCleanShutdownErr(err) {
		// 对端发来 close_notify：标准库返回 io.EOF 0,nil；本库保持 n,nil。
		return n, io.EOF
	}
	return n, err
}

// Write 加密并发送应用层数据。
//
// 与同一 Conn 上的并发 Read 调用互斥序列化。连接已关闭时返回 ErrClosed。
//
// Write encrypts and sends application data b over the TLS or NTLS
// connection.
//
// Write is serialized with concurrent Read calls on the same Conn.
// Returns ErrClosed after Close.
func (c *Conn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return 0, ErrClosed
	}
	return c.ssl.Write(b)
}

// ErrClosed 表示对 tls.Conn 的 I/O 操作因连接已关闭而失败。
//
// ErrClosed is returned by Write (and similar methods) when the
// underlying tls.Conn has already been closed.
var ErrClosed = errors.New("tls: connection closed")

// isCleanShutdownErr 判定 ssl.Read 返回的 "tls: connection closed" 是否
// 表示对端 close_notify（OpenSSL 的 SSL_ERROR_ZERO_RETURN）。
func isCleanShutdownErr(err error) bool {
	return err != nil && err.Error() == "tls: connection closed"
}

// Close 关闭 TLS 连接与底层连接。幂等（多次调用安全）。先关闭底层 raw
// socket 以唤醒任何在途阻塞的 SSL_read / SSL_write / select 调用，再释
// 放 SSL 句柄与 raw 连接。
//
// Close shuts down the TLS or NTLS session, closes the underlying socket,
// and (when ownsCtx is true — the DialContext path) releases the
// *core.TLSContext. The call is idempotent — multiple invocations return
// the same error as the first. The raw socket is closed first so that
// any in-progress SSL_read / SSL_write / select call wakes up immediately.
func (c *Conn) Close() error {
	if c == nil {
		return nil
	}
	var firstErr error
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		// 1) 关 raw socket：唤醒在途 SSL_read/SSL_write 的 select/waitFD 与
		//    syscall；之后 ssl.Close 仅释放 native 句柄不再操作已关闭的 fd。
		if c.raw != nil {
			if err := c.raw.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		// 2) 释放 SSL 句柄。
		if c.ssl != nil {
			if err := c.ssl.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		// 3) DialContext 路径上 Conn 拥有 ctx，必须释放（避免 leak）。
		//    Accept 路径 ownsCtx=false，跳过（Server.Close 负责）。
		if c.ownsCtx && c.ctx != nil {
			if err := c.ctx.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	})
	return firstErr
}

// LocalAddr 返回本地地址。
//
// LocalAddr returns the local network address of the underlying socket.
func (c *Conn) LocalAddr() net.Addr { return c.raw.LocalAddr() }

// RemoteAddr 返回远端地址。
//
// RemoteAddr returns the remote network address of the underlying socket.
func (c *Conn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

// SetDeadline 设置 handshake 与后续 Read/Write 的累计 deadline（影响 SSL 层的
// waitFD 等待）；同时转给 raw socket 影响 TCP 层。
//
// SetDeadline sets the cumulative handshake + Read/Write deadline
// (propagated to SSL's waitFD retry loop) and also to the underlying
// socket.
func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.ssl.SetDeadline(t); err != nil {
		return err
	}
	return c.raw.SetDeadline(t)
}

// SetReadDeadline 设置读取期限（仅 SSL 层；raw socket 层同时设置）。
// 同时清空 raw socket 的写入 deadline，避免用户后续 Write 因旧写入
// deadline 而意外超时。
//
// SetReadDeadline sets the read deadline on both the SSL and the
// underlying socket; the raw socket's write deadline is also cleared to
// zero so that subsequent Write calls are not impacted by a stale write
// timeout.
func (c *Conn) SetReadDeadline(t time.Time) error {
	if err := c.ssl.SetDeadline(t); err != nil {
		return err
	}
	if err := c.raw.SetReadDeadline(t); err != nil {
		return err
	}
	// 关键修复：SetReadDeadline 不应影响写入侧 deadline，显式置零。
	// Critical fix: SetReadDeadline must not affect the write side; reset it explicitly.
	return c.raw.SetWriteDeadline(time.Time{})
}

// SetWriteDeadline 设置写入期限（仅 SSL 层；raw socket 层同时设置）。
// 同时清空 raw socket 的读取 deadline，避免用户后续 Read 因旧读取
// deadline 而意外超时。
//
// SetWriteDeadline sets the write deadline on both the SSL and the
// underlying socket; the raw socket's read deadline is also cleared to
// zero so that subsequent Read calls are not impacted by a stale read
// timeout.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if err := c.ssl.SetDeadline(t); err != nil {
		return err
	}
	if err := c.raw.SetWriteDeadline(t); err != nil {
		return err
	}
	// 配对修复：SetWriteDeadline 不应影响读取侧 deadline。
	// Matching fix: SetWriteDeadline must not affect the read side.
	return c.raw.SetReadDeadline(time.Time{})
}

// Version 返回协商后的协议版本。
//
// Version returns the negotiated protocol version string (for example "TLSv1.2" or "NTLS").
func (c *Conn) Version() string { return c.ssl.Version() }

// CipherName 返回协商后的密码套件。
//
// CipherName returns the name of the negotiated cipher suite.
func (c *Conn) CipherName() string { return c.ssl.CipherName() }

// PeerCertificates 返回对端证书链（leaf→root，已按签发者顺序重排）。
// 返回的每张 *x509.Certificate 为 owned（X509_dup 副本），调用方须在用毕
// 后调用 Close 释放。
//
// 普通 TLS 与 NTLS 行为略有差异：
//
//   - 客户端：peer_chain 已是「签名叶 + 后续链」；按签发者重构。
//   - 服务端：peer_chain 不含叶；另用 peer_certificate 取叶再重构。
//   - 无对端证书（非 mTLS 服务端路径）：返回 (nil, nil)。
//
// PeerCertificates returns the peer's certificate chain rebuilt in
// leaf→root order (issuer walk). Each returned *x509.Certificate is an
// owned copy (X509_dup); the caller should Close it. Returns (nil, nil)
// when the peer did not present any certificate.
func (c *Conn) PeerCertificates() ([]*x509.Certificate, error) {
	if c == nil {
		return nil, errors.New("tls: nil Conn")
	}
	if !c.handshakeDone.Load() {
		return nil, errors.New("tls: PeerCertificates before handshake")
	}
	pool, err := c.ssl.PeerCertificates()
	if err != nil {
		return nil, err
	}
	leafCore, err := c.ssl.PeerCertificate()
	if err != nil {
		return nil, err
	}
	return c.peerCertificateChain(leafCore, pool)
}

// PeerEncCertificates 返回对端 NTLS 加密证书链（仅在 NTLS 下有意义；
// 普通 TLS 始终返回 nil, nil）。
//
// Tongsuo NTLS 下对端证书链布局（来源：ssl/statem_ntls/ntls_statem_clnt.c
// 与 ntls_statem_srvr.c 的代码注释）：
//
//   - 客户端：peer_chain[0] = 对端签名证书；peer_chain[1] = 对端加密证书；
//     其后为额外链证书。peer == peer_chain[0]（签名叶）。
//   - 服务端：peer = 客户端签名证书；peer_chain[0] = 客户端加密证书。
//
// 本方法按角色定位加密叶并按签发者重构 leaf→root。依赖 Tongsuo 内部栈
// 布局，代码注释已标注。
//
// PeerEncCertificates returns the NTLS encryption certificate chain
// rebuilt leaf→root. Returns (nil, nil) for non-NTLS connections or when
// no encryption certificate is present. Depends on Tongsuo's internal
// peer_chain layout.
func (c *Conn) PeerEncCertificates() ([]*x509.Certificate, error) {
	if c == nil {
		return nil, errors.New("tls: nil Conn")
	}
	if !c.handshakeDone.Load() {
		return nil, errors.New("tls: PeerEncCertificates before handshake")
	}
	if !c.ntls {
		return nil, nil
	}
	pool, err := c.ssl.PeerCertificates()
	if err != nil {
		return nil, err
	}
	if len(pool) == 0 {
		return nil, nil
	}
	// 按角色定位加密叶起点。
	switch c.isServer {
	case true:
		// 服务端：加密叶 = peer_chain[0]；栈只此一张。
		return c.peerCertificateChain(pool[0], pool[:0])
	default:
		// 客户端：加密叶 = peer_chain[1]；后续为链证书。
		if len(pool) < 2 {
			return nil, nil
		}
		return c.peerCertificateChain(pool[1], pool[2:])
	}
}

// newContext 根据配置创建客户端/服务端上下文并加载证书。
//
// newContext builds the underlying Tongsuo TLS context (NTLS, client, or
// server) from config and loads the configured certificates / keys onto it.
func newContext(config *Config, client bool) (*core.TLSContext, error) {
	var (
		ctx *core.TLSContext
		err error
	)
	ntls := config != nil && config.NTLS
	switch {
	case ntls:
		ctx, err = core.NewNTLSContext()
	case client:
		ctx, err = core.NewClientTLSContext()
	default:
		ctx, err = core.NewServerTLSContext()
	}
	if err != nil {
		return nil, err
	}
	if config == nil {
		return ctx, nil
	}

	// 加载证书与私钥。
	if ntls {
		if config.SignCert != nil && config.SignKey != nil {
			if err := ctx.UseSignCertificate(config.SignCert.Core(), config.SignKey.Key()); err != nil {
				_ = ctx.Close()
				return nil, err
			}
		}
		if config.EncCert != nil && config.EncKey != nil {
			if err := ctx.UseEncryptCertificate(config.EncCert.Core(), config.EncKey.Key()); err != nil {
				_ = ctx.Close()
				return nil, err
			}
		}
	} else if config.Cert != nil && config.Key != nil {
		if err := ctx.UseCertificate(config.Cert.Core(), config.Key.Key()); err != nil {
			_ = ctx.Close()
			return nil, err
		}
	}

	if config.MinVersion != 0 {
		if err := ctx.SetMinProtoVersion(config.MinVersion); err != nil {
			_ = ctx.Close()
			return nil, err
		}
	}
	if config.MaxVersion != 0 {
		if err := ctx.SetMaxProtoVersion(config.MaxVersion); err != nil {
			_ = ctx.Close()
			return nil, err
		}
	}
	if len(config.CipherSuites) > 0 {
		if err := applyCipherSuites(ctx, config.CipherSuites); err != nil {
			_ = ctx.Close()
			return nil, err
		}
	}

	// 客户端对端验证（D1 方案 A）：仅在 !shouldSkipVerify 时启用 PEER
	// 并注入用户提供的根 CA。NTLS 同理，但 Tongsuo TLCP 是否执行标准
	// X509_STORE 链验证待实测（实现期验证点）。
	if client && !shouldSkipVerify(config) {
		if err := ctx.SetVerifyMode(core.VerifyModePeer); err != nil {
			_ = ctx.Close()
			return nil, err
		}
		if err := ctx.SetVerifyDepth(defaultVerifyDepth); err != nil {
			_ = ctx.Close()
			return nil, err
		}
		if len(config.RootCAs) > 0 {
			certs := make([]*core.Certificate, 0, len(config.RootCAs))
			for _, c := range config.RootCAs {
				if c == nil {
					continue
				}
				certs = append(certs, c.Core())
			}
			if err := ctx.AddVerifyRoots(certs); err != nil {
				_ = ctx.Close()
				return nil, err
			}
		}
	}
	return ctx, nil
}

// defaultVerifyDepth 为对端证书链验证默认深度上限（100，覆盖常规 CA 路径长度）。
const defaultVerifyDepth = 100

// connFD 获取 net.Conn 底层的 socket fd。
//
// connFD extracts the underlying TCP socket file descriptor from conn.
// It returns an error for any net.Conn that is not a *net.TCPConn.
func connFD(conn net.Conn) (int, error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, fmt.Errorf("tls: unsupported connection type %T", conn)
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		fd   int
		serr error
	)
	if err := raw.Control(func(f uintptr) {
		fd = int(f)
	}); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, serr
	}
	return fd, nil
}

// 暴露协议版本常量，便于用户配置 MinVersion / MaxVersion。
//
// ProtocolVersion exposes TLS protocol version constants suitable for Config.MinVersion and Config.MaxVersion.
//
// Wire-format IANA TLS protocol version values (RFC 5246 / RFC 8446); also
// consumed by core.TLSContext.SetMinProtoVersion / SetMaxProtoVersion.
const (
	TLS1Version   uint16 = 0x0301
	TLS1_1Version uint16 = 0x0302
	TLS1_2Version uint16 = 0x0303
	TLS1_3Version uint16 = 0x0304
)
