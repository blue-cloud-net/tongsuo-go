package tls

import (
	"fmt"
	"net"
	"sync"
)

// Listener 是把原始 net.Listener 包装为 TLS / NTLS 监听器的接口实现。
// Accept 返回的连接**已完成握手**，可直接读写；握手失败时原始连接会被关闭，
// Accept 返回错误而不是半握手的连接。
//
// Listener wraps a raw net.Listener into a TLS / NTLS listener. The
// connections returned by Accept have already completed the handshake
// and are ready for I/O; when the handshake fails the raw connection is
// closed and Accept reports the error instead of returning a
// half-handshaked connection.
type Listener struct {
	server *Server
	raw    net.Listener
	once   sync.Once
	err    error
}

// NewListener 用 config 构建 TLS / NTLS 服务端并把原始监听器包装为
// 自动握手的监听器（等价于 `tls.Listen`）。
//
// config 必须提供服务端证书与私钥（NTLS 时为签名证书/私钥与加密证书/私钥）。
// 本函数会**先校验这套凭证是否齐备**（NewServer 本身不校验，只建上下文），
// 缺失时立即返回错误，避免服务起来后每个连接才握手失败。构建上下文失败时
// 返回包装了 OpError 的错误；这两类失败都不会关闭 ln（调用方仍持有它）。
// ln 为 nil 时返回错误。
//
// 与 Server.Accept 的惰性语义不同：本监听器的 Accept 内部调用
// (*Conn).Handshake，因此返回的连接无需再握手。握手失败会关闭连接并返回
// 分类后的错误（见 HandshakeError）。
//
// NewListener builds a TLS / NTLS server from config and wraps the raw
// listener into one that handshakes inside Accept (the equivalent of
// `tls.Listen`).
//
// config must supply the server certificate and key (signing and
// encryption certificates plus keys for NTLS). This function validates
// that the credential set is complete up front (NewServer itself only
// builds the context), so a missing certificate fails immediately
// instead of failing the handshake of every later connection. A context
// build failure returns an error wrapping an OpError; neither failure
// closes ln, which the caller still owns. A nil ln is an error.
//
// Unlike Server.Accept, which is lazy, this listener calls
// (*Conn).Handshake inside Accept, so returned connections need no
// further handshaking. A failed handshake closes the connection and
// returns the classified error (see HandshakeError).
func NewListener(config *Config, ln net.Listener) (*Listener, error) {
	if ln == nil {
		return nil, fmt.Errorf("tls: nil listener")
	}
	if err := validateServerConfig(config); err != nil {
		return nil, err
	}
	srv, err := NewServer(config)
	if err != nil {
		return nil, err
	}
	return &Listener{server: srv, raw: ln}, nil
}

// validateServerConfig 校验服务端凭证是否齐备。
// TLS 模式需 Cert + Key；NTLS 模式需 SignCert / SignKey / EncCert / EncKey。
//
// validateServerConfig checks that the server credentials are complete.
// TLS mode needs Cert + Key; NTLS mode needs SignCert, SignKey, EncCert
// and EncKey.
func validateServerConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("tls: nil config")
	}
	if config.NTLS {
		if config.SignCert == nil || config.SignKey == nil {
			return fmt.Errorf("tls: NTLS server config requires SignCert and SignKey")
		}
		if config.EncCert == nil || config.EncKey == nil {
			return fmt.Errorf("tls: NTLS server config requires EncCert and EncKey")
		}
		return nil
	}
	if config.Cert == nil || config.Key == nil {
		return fmt.Errorf("tls: server config requires Cert and Key")
	}
	return nil
}

// Accept 等待并接受一个连接，并在返回前完成 TLS / NTLS 握手。
// 底层 Accept 失败时原样返回其错误（含 net.ErrClosed）；握手失败时关闭连接
// 并返回包装后的错误。
//
// Accept waits for and accepts one connection and completes the
// TLS / NTLS handshake before returning. Errors from the underlying
// Accept (including net.ErrClosed) are returned as-is; handshake
// failures close the connection and return a wrapped error.
func (l *Listener) Accept() (net.Conn, error) {
	raw, err := l.raw.Accept()
	if err != nil {
		return nil, err
	}
	wrapped, err := l.server.Accept(raw)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	conn, ok := wrapped.(*Conn)
	if !ok {
		// 理论上不会发生：Server.Accept 只会返回 *Conn。
		// 仍做防御，避免把未握手的连接交给调用方。
		_ = wrapped.Close()
		return nil, fmt.Errorf("tls: unexpected connection type %T", wrapped)
	}
	if err := conn.Handshake(); err != nil {
		// Conn.Close 会把底层 socket 一并关闭。
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// Close 关闭监听器与 TLS 上下文；重复调用安全（幂等），并发调用同样安全。
// 关闭后 Accept 返回底层 net.ErrClosed 风格的错误。
//
// Close closes the listener and the TLS context; it is safe to call
// repeatedly and from multiple goroutines (idempotent). After Close,
// Accept returns the underlying net.ErrClosed-style error.
func (l *Listener) Close() error {
	l.once.Do(func() {
		rawErr := l.raw.Close()
		ctxErr := l.server.Close()
		if rawErr != nil {
			l.err = rawErr
			return
		}
		l.err = ctxErr
	})
	return l.err
}

// Addr 返回底层监听器的地址（Close 之后仍可调用）。
//
// Addr returns the address of the underlying listener (still valid
// after Close).
func (l *Listener) Addr() net.Addr {
	return l.raw.Addr()
}
