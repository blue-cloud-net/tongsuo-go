package tls

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

const httpHandshakeTimeout = 10 * time.Second

// HTTPTransport 为 http.Client 提供 HTTPS 直连与 HTTP/1.1 连接池。
//
// HTTPTransport provides direct HTTPS and HTTP/1.1 pooling for http.Client.
type HTTPTransport struct{ transport *http.Transport }

// NewHTTPTransport 创建使用铜锁握手的 HTTP/1.1 客户端传输层。
//
// NewHTTPTransport creates an HTTP/1.1 client transport that uses Tongsuo for handshakes.
func NewHTTPTransport(config *Config) (*HTTPTransport, error) {
	if config == nil {
		config = &Config{}
	}
	cfg := config.Clone()
	if cfg.Verification == VerifyDefault && !cfg.InsecureSkipVerify {
		cfg.Verification = VerifyStrict
	}
	cfg.NextProtos = []string{"http/1.1"}
	if err := validateConfig(cfg, true); err != nil {
		return nil, err
	}
	t := &http.Transport{MaxIdleConns: 100, IdleConnTimeout: 90 * time.Second}
	t.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		raw, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		conn, err := newClient(raw, cfg, addr)
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		ctx, cancel := context.WithTimeout(ctx, httpHandshakeTimeout)
		defer cancel()
		if err := handshakeHTTP(ctx, conn); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
	return &HTTPTransport{transport: t}, nil
}

// RoundTrip 发送 HTTPS 请求，其他 scheme 返回错误。
//
// RoundTrip sends an HTTPS request and returns an error for other schemes.
func (t *HTTPTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL == nil || r.URL.Scheme != "https" {
		if r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, errors.New("tls: HTTP transport requires HTTPS")
	}
	return t.transport.RoundTrip(r)
}

// CloseIdleConnections 关闭连接池中的空闲连接。
//
// CloseIdleConnections closes idle pooled connections.
func (t *HTTPTransport) CloseIdleConnections() { t.transport.CloseIdleConnections() }

func handshakeHTTP(ctx context.Context, c *Conn) error {
	if err := c.HandshakeContext(ctx); err != nil {
		return err
	}
	if p := c.ConnectionState().NegotiatedProtocol; p != "" && p != "http/1.1" {
		return errors.New("tls: unexpected HTTP ALPN protocol")
	}
	return nil
}

type httpConnKey struct{}

// HTTPConnectionState 从服务端请求 context 读取铜锁连接状态。
//
// HTTPConnectionState returns the Tongsuo connection state from a server request context.
func HTTPConnectionState(ctx context.Context) (ConnectionState, bool) {
	c, ok := ctx.Value(httpConnKey{}).(*httpConn)
	if !ok {
		return ConnectionState{}, false
	}
	s := c.ConnectionState()
	return s, s.HandshakeComplete
}

type httpListener struct {
	*Listener
	timeout time.Duration
	mu      sync.Mutex
	closed  bool
	pending map[*httpConn]struct{}
}

type httpConn struct {
	*Conn
	listener *httpListener
	once     sync.Once
	err      error
}

func (l *httpListener) Accept() (net.Conn, error) {
	raw, err := l.raw.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		_ = raw.Close()
		return nil, net.ErrClosed
	}
	wrapped, err := l.server.Accept(raw)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	c := &httpConn{Conn: wrapped.(*Conn), listener: l}
	l.pending[c] = struct{}{}
	return c, nil
}

func (l *httpListener) Close() error {
	l.mu.Lock()
	l.closed = true
	pending := l.pending
	l.pending = nil
	l.mu.Unlock()
	err := l.Listener.Close()
	for c := range pending {
		_ = c.Close()
	}
	return err
}

func (c *httpConn) handshake() error {
	c.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), c.listener.timeout)
		defer cancel()
		c.err = handshakeHTTP(ctx, c.Conn)
		c.untrack()
	})
	return c.err
}

func (c *httpConn) untrack() {
	c.listener.mu.Lock()
	delete(c.listener.pending, c)
	c.listener.mu.Unlock()
}

func (c *httpConn) Close() error {
	c.untrack()
	return c.Conn.Close()
}

var httpReadBuffers = sync.Pool{New: func() any { return new([16 * 1024]byte) }}

func (c *httpConn) Read(p []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	// net/http can pass a slice into a struct containing Go pointers.
	// Use standalone byte storage at the cgo boundary.
	if len(p) == 0 {
		return 0, nil
	}
	buf := httpReadBuffers.Get().(*[16 * 1024]byte)

	n, err := c.Conn.Read(buf[:min(len(p), len(buf))])
	copy(p, buf[:n])
	clear(buf[:n])
	httpReadBuffers.Put(buf)
	return n, err
}

func (c *httpConn) Write(p []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func httpServerConfig(config *Config) *Config {
	if config == nil {
		return nil
	}
	cfg := config.Clone()
	cfg.NextProtos = []string{"http/1.1"}
	if selectConfig := cfg.GetConfigForClient; selectConfig != nil {
		cfg.GetConfigForClient = func(info *ClientHelloInfo) (*Config, error) {
			selected, err := selectConfig(info)
			if err != nil || selected == nil {
				return nil, err
			}
			selected = selected.Clone()
			selected.NextProtos = []string{"http/1.1"}
			return selected, nil
		}
	}
	return cfg
}

// ServeTLS 在 ln 上运行使用铜锁的 HTTP/1.1 服务。初始化失败时 ln 仍归调用方。
//
// ServeTLS serves HTTP/1.1 using Tongsuo on ln. Initialization failure leaves ln with the caller.
func ServeTLS(server *http.Server, ln net.Listener, config *Config) error {
	if server == nil {
		return errors.New("tls: nil HTTP server")
	}
	wrapped, err := NewListener(httpServerConfig(config), ln)
	if err != nil {
		return err
	}
	timeout := time.Duration(0)
	header := server.ReadHeaderTimeout
	if header == 0 {
		header = server.ReadTimeout
	}
	for _, d := range []time.Duration{header, server.ReadTimeout, server.WriteTimeout} {
		if d > 0 && (timeout == 0 || d < timeout) {
			timeout = d
		}
	}
	if timeout == 0 {
		timeout = httpHandshakeTimeout
	}
	listener := &httpListener{Listener: wrapped, timeout: timeout, pending: make(map[*httpConn]struct{})}
	previous := server.ConnContext
	server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		if previous != nil {
			ctx = previous(ctx, c)
		}
		if conn, ok := c.(*httpConn); ok {
			return context.WithValue(ctx, httpConnKey{}, conn)
		}
		return ctx
	}
	defer func() { server.ConnContext = previous }()
	return server.Serve(listener)
}

// ListenAndServeTLS 监听 server.Addr 并启动铜锁 HTTP/1.1 服务，空地址使用 :https。
//
// ListenAndServeTLS listens on server.Addr and serves HTTP/1.1 using Tongsuo. An empty address uses :https.
func ListenAndServeTLS(server *http.Server, config *Config) error {
	if server == nil {
		return errors.New("tls: nil HTTP server")
	}
	addr := server.Addr
	if addr == "" {
		addr = ":https"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	return ServeTLS(server, ln, config)
}
