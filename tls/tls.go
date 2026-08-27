// Package tls 基于铜锁原生实现提供 TLS 与 NTLS（国密 TLCP）传输层。
//
// 提供 TLS 客户端（Dial）、服务端（Server + Accept）与 net.Conn 包装（Conn），
// 支持 SM2 单证书（TLS）与双证书（NTLS：签名证书 + 加密证书）。
package tls

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/crypto/x509"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// Config 表示 TLS / NTLS 配置。
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

// Dial 与指定地址建立 TLS 连接（含握手）。
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
type Server struct {
	ctx *core.TLSContext
}

// NewServer 创建 TLS 服务端。
func NewServer(config *Config) (*Server, error) {
	ctx, err := newContext(config, false)
	if err != nil {
		return nil, err
	}
	return &Server{ctx: ctx}, nil
}

// Accept 将已接受的原始连接包装为 TLS 连接（执行服务端握手）。
func (s *Server) Accept(raw net.Conn) (net.Conn, error) {
	return wrapConn(raw, s.ctx, true)
}

// Close 释放服务端上下文。
func (s *Server) Close() error {
	return s.ctx.Close()
}

// Conn 是一个 TLS 连接（net.Conn），基于底层 socket fd 上的 SSL。
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

// Read 读取解密数据。
func (c *Conn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ssl.Read(b)
}

// Write 写入数据。
func (c *Conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ssl.Write(b)
}

// Close 关闭 TLS 连接与底层连接。
func (c *Conn) Close() error {
	_ = c.ssl.Close()
	return c.raw.Close()
}

// LocalAddr 返回本地地址。
func (c *Conn) LocalAddr() net.Addr { return c.raw.LocalAddr() }

// RemoteAddr 返回远端地址。
func (c *Conn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

// SetDeadline 设置读写期限。
func (c *Conn) SetDeadline(t time.Time) error { return c.raw.SetDeadline(t) }

// SetReadDeadline 设置读取期限。
func (c *Conn) SetReadDeadline(t time.Time) error { return c.raw.SetReadDeadline(t) }

// SetWriteDeadline 设置写入期限。
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

// Version 返回协商后的协议版本。
func (c *Conn) Version() string { return c.ssl.Version() }

// CipherName 返回协商后的密码套件。
func (c *Conn) CipherName() string { return c.ssl.CipherName() }

// newContext 根据配置创建客户端/服务端上下文并加载证书。
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
const (
	TLS1Version   = native.TLS1Version
	TLS1_1Version = native.TLS1_1Version
	TLS1_2Version = native.TLS1_2Version
	TLS1_3Version = native.TLS1_3Version
)
