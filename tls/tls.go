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
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/x509"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/native"
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
	RootCAs           []*x509.Certificate
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
func Dial(network, addr string, config *Config) (net.Conn, error) {
	raw, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	ctx, err := newContext(config, true)
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
			hostname = host
		} else {
			hostname = addr
		}
	}
	conn, err := wrapConnWithHostname(raw, ctx, false, hostname)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	// 主机名校验：在 wrapConn 之后、返回前检查。
	if !shouldSkipVerify(config) {
		tlsConn, ok := conn.(*Conn)
		if !ok {
			return conn, nil // 防御：理论上不可达（wrapConn 总是返回 *Conn）
		}
		if code := tlsConn.ssl.VerifyResult(); code != core.VerifyOK {
			_ = tlsConn.Close()
			return nil, fmt.Errorf("tls: peer verification failed: %s",
				core.VerifyErrorMessage(code))
		}
	}
	return conn, nil
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

// Accept 将已接受的原始连接包装为 TLS 连接（执行服务端握手）；失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// Accept wraps an already-accepted raw connection and drives the TLS or
// NTLS server handshake. On failure it returns an error wrapping an
// OpError that describes the underlying operation.
func (s *Server) Accept(raw net.Conn) (net.Conn, error) {
	return wrapConn(raw, s.ctx, true)
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
	ssl      *core.SSLConn
	raw      net.Conn
	mu       sync.Mutex   // 序列化 Read/Write
	closeOnce sync.Once    // 保证 Close 只执行一次（幂等）
	closed    atomic.Bool  // Close 完成后置位，Read/Write 入口短路
}

func wrapConn(raw net.Conn, ctx *core.TLSContext, server bool) (net.Conn, error) {
	return wrapConnWithHostname(raw, ctx, server, "")
}

// wrapConnWithHostname 是 wrapConn 的扩展版本：客户端路径可在 Connect 之前
// 设置预期对端主机名（用于主机名校验）；服务端忽略。
//
// wrapConnWithHostname is wrapConn with an extra hostname argument used by
// the client path to set the expected peer hostname before Connect.
func wrapConnWithHostname(raw net.Conn, ctx *core.TLSContext, server bool, hostname string) (net.Conn, error) {
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
	if server {
		if err := ssl.Accept(); err != nil {
			_ = ssl.Close()
			return nil, err
		}
	} else {
		if err := ssl.Connect(); err != nil {
			_ = ssl.Close()
			return nil, err
		}
	}
	return &Conn{ssl: ssl, raw: raw}, nil
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
// Close shuts down the TLS or NTLS session and then closes the
// underlying socket connection. The call is idempotent — multiple
// invocations return the same error as the first. The raw socket is
// closed first so that any in-progress SSL_read / SSL_write / select
// call wakes up immediately.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		// 先关 raw socket：唤醒在途 SSL_read/SSL_write 的 select/waitFD 与
		// syscall；之后 ssl.Close 仅释放 native 句柄不再操作已关闭的 fd。
		_ = c.raw.Close()
		_ = c.ssl.Close()
	})
	return err
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
//
// SetReadDeadline sets the read deadline on both the SSL and the
// underlying socket.
func (c *Conn) SetReadDeadline(t time.Time) error {
	if err := c.ssl.SetDeadline(t); err != nil {
		return err
	}
	return c.raw.SetReadDeadline(t)
}

// SetWriteDeadline 设置写入期限（仅 SSL 层；raw socket 层同时设置）。
//
// SetWriteDeadline sets the write deadline on both the SSL and the
// underlying socket.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if err := c.ssl.SetDeadline(t); err != nil {
		return err
	}
	return c.raw.SetWriteDeadline(t)
}

// Version 返回协商后的协议版本。
//
// Version returns the negotiated protocol version string (for example "TLSv1.2" or "NTLS").
func (c *Conn) Version() string { return c.ssl.Version() }

// CipherName 返回协商后的密码套件。
//
// CipherName returns the name of the negotiated cipher suite.
func (c *Conn) CipherName() string { return c.ssl.CipherName() }

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
		if err := ctx.SetCipherList(strings.Join(config.CipherSuites, ":")); err != nil {
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
const (
	TLS1Version   = native.TLS1Version
	TLS1_1Version = native.TLS1_1Version
	TLS1_2Version = native.TLS1_2Version
	TLS1_3Version = native.TLS1_3Version
)
