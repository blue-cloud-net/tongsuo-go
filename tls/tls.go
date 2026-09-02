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
	"fmt"
	"net"
	"strings"
	"sync"
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
// Config represents a TLS or NTLS configuration shared by Dial and Server.
//
// Cert and Key hold the certificate and private key for the standard TLS path
// (required on the server side, optional for client authentication). When NTLS
// is enabled, SignCert/SignKey and EncCert/EncKey supply the GM/T 0024 TLCP
// dual-certificate pair (sign certificate and encryption certificate). The
// version range and cipher suite list, when non-zero / non-empty, override the
// library defaults.
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
}

// Dial 与指定地址建立 TLS 连接（含握手）；成功时返回包装底层 socket 的 *Conn 并已完成握手，失败时返回错误并关闭已部分初始化的资源。
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
	conn, err := wrapConn(raw, ctx, false)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
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
//
// Conn is a net.Conn implementation that performs TLS or NTLS I/O on top
// of an underlying socket file descriptor.
//
// Read and Write are serialized with an internal mutex; concurrent calls
// from multiple goroutines are safe but not parallel.
type Conn struct {
	ssl *core.SSLConn
	raw net.Conn
	mu  sync.Mutex // 序列化读写
}

func wrapConn(raw net.Conn, ctx *core.TLSContext, server bool) (net.Conn, error) {
	fd, err := connFD(raw)
	if err != nil {
		return nil, err
	}
	ssl, err := core.NewSSLConn(ctx, fd)
	if err != nil {
		return nil, err
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
// 与同一 Conn 上的并发 Write 调用互斥序列化。
//
// Read reads decrypted application data from the TLS or NTLS connection
// into b.
//
// Read is serialized with concurrent Write calls on the same Conn.
func (c *Conn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ssl.Read(b)
}

// Write 加密并发送应用层数据。
//
// 与同一 Conn 上的并发 Read 调用互斥序列化。
//
// Write encrypts and sends application data b over the TLS or NTLS
// connection.
//
// Write is serialized with concurrent Read calls on the same Conn.
func (c *Conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ssl.Write(b)
}

// Close 关闭 TLS 连接与底层连接。
//
// Close shuts down the TLS or NTLS session and then closes the underlying socket connection.
func (c *Conn) Close() error {
	_ = c.ssl.Close()
	return c.raw.Close()
}

// LocalAddr 返回本地地址。
//
// LocalAddr returns the local network address of the underlying socket.
func (c *Conn) LocalAddr() net.Addr { return c.raw.LocalAddr() }

// RemoteAddr 返回远端地址。
//
// RemoteAddr returns the remote network address of the underlying socket.
func (c *Conn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

// SetDeadline 设置读写期限。
//
// SetDeadline sets the read and write deadlines associated with the underlying socket.
func (c *Conn) SetDeadline(t time.Time) error { return c.raw.SetDeadline(t) }

// SetReadDeadline 设置读取期限。
//
// SetReadDeadline sets the read deadline associated with the underlying socket.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.raw.SetReadDeadline(t) }

// SetWriteDeadline 设置写入期限。
//
// SetWriteDeadline sets the write deadline associated with the underlying socket.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

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
	return ctx, nil
}

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
