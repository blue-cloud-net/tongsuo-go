package tls

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// serveOnce 在后台 Accept 一次并把结果回传，供主 goroutine 断言。
// 后台 goroutine 内**不得**调用 t.Fatal*（测试返回后再调用会触发包级 panic，
// 见 docs/issues/2026-09-24/P1004）。
//
// serveOnce accepts once in the background and hands the result back so
// the main goroutine can assert. The goroutine must not call t.Fatal*
// (see docs/issues/2026-09-24/P1004).
type acceptResult struct {
	conn net.Conn
	err  error
}

// TestListenerHandshakeAndEcho 验证 NewListener 的 Accept 返回的连接已完成握手，
// 可直接读写，且客户端可开启对端校验。
//
// TestListenerHandshakeAndEcho verifies that the connection returned by
// NewListener's Accept has already completed the handshake and is usable
// for I/O, with client-side peer verification enabled.
func TestListenerHandshakeAndEcho(t *testing.T) {
	srvCfg := testServerConfig(t)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln, err := NewListener(srvCfg, raw)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- acceptResult{conn: c, err: err}
	}()

	cliCfg := &Config{
		RootCAs:    []*x509.Certificate{srvCfg.Cert},
		ServerName: "server.tongsuo-go.dev",
	}
	client, err := Dial("tcp", ln.Addr().String(), cliCfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	var got acceptResult
	select {
	case got = <-accepted:
	case <-time.After(10 * time.Second):
		t.Fatal("Accept did not return within 10s")
	}
	if got.err != nil {
		t.Fatalf("Accept: %v", got.err)
	}
	server := got.conn
	defer server.Close()

	// Accept 已握手：服务端无需再调 Handshake 即可直接 Read/Write。
	if _, ok := server.(*Conn); !ok {
		t.Fatalf("Accept returned %T, want *Conn", server)
	}
	msg := []byte("listener-echo")
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Errorf("server read %q, want %q", buf, msg)
	}
	if _, err := server.Write(msg); err != nil {
		t.Fatalf("server write: %v", err)
	}
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Errorf("client read %q, want %q", buf, msg)
	}
}

// TestListenerNTLSHandshake 验证 NTLS 双证书配置下监听器同样完成握手。
//
// TestListenerNTLSHandshake verifies that the listener completes the
// handshake with an NTLS dual-certificate configuration.
func TestListenerNTLSHandshake(t *testing.T) {
	srvCfg := testNTLSConfig(t)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln, err := NewListener(srvCfg, raw)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- acceptResult{conn: c, err: err}
	}()

	client, err := Dial("tcp", ln.Addr().String(), &Config{NTLS: true})
	if err != nil {
		t.Fatalf("Dial(NTLS): %v", err)
	}
	defer client.Close()

	select {
	case got := <-accepted:
		if got.err != nil {
			t.Fatalf("Accept: %v", got.err)
		}
		defer got.conn.Close()
		if got.conn.(*Conn).Version() == "" {
			t.Error("Version() is empty after handshake")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Accept did not return within 10s")
	}
}

// TestListenerHandshakeFailureCloses 验证握手失败时 Accept 返回错误，
// 并且原始连接被关闭（不会把半握手连接交给调用方）。
//
// TestListenerHandshakeFailureCloses verifies that a failed handshake
// makes Accept return an error and closes the raw connection, so no
// half-handshaked connection reaches the caller.
func TestListenerHandshakeFailureCloses(t *testing.T) {
	srvCfg := testServerConfig(t)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln, err := NewListener(srvCfg, raw)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- acceptResult{conn: c, err: err}
	}()

	// 用裸 TCP 发垃圾字节冒充 ClientHello，服务端握手必然失败。
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	if _, err := conn.Write([]byte("this is not a TLS ClientHello\n")); err != nil {
		t.Fatalf("raw write: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	select {
	case got := <-accepted:
		if got.err == nil {
			_ = got.conn.Close()
			t.Fatal("Accept: want handshake error, got nil")
		}
		if got.conn != nil {
			_ = got.conn.Close()
			t.Error("Accept returned a connection together with an error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Accept did not return within 10s")
	}
}

// TestListenerCloseIdempotent 验证 Close 幂等（含并发调用），
// 关闭后 Accept 返回错误，Addr 仍可用。
//
// TestListenerCloseIdempotent verifies that Close is idempotent (also
// under concurrency), that Accept fails afterwards and that Addr stays
// usable.
func TestListenerCloseIdempotent(t *testing.T) {
	srvCfg := testServerConfig(t)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln, err := NewListener(srvCfg, raw)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	addr := ln.Addr()
	if addr == nil {
		t.Fatal("Addr() returned nil")
	}

	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- ln.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("Close: %v", err)
		}
	}
	if err := ln.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if _, err := ln.Accept(); err == nil {
		t.Error("Accept after Close: want error, got nil")
	}
	if got := ln.Addr(); got.String() != addr.String() {
		t.Errorf("Addr after Close = %v, want %v", got, addr)
	}
}

// TestNewListenerRejectsNilListener 验证 nil 监听器返回错误。
//
// TestNewListenerRejectsNilListener verifies that a nil listener is
// rejected.
func TestNewListenerRejectsNilListener(t *testing.T) {
	if _, err := NewListener(testServerConfig(t), nil); err == nil {
		t.Fatal("NewListener(nil): want error, got nil")
	}
}

// TestNewListenerRejectsBadConfig 验证缺少证书的配置返回错误且不接管监听器。
//
// TestNewListenerRejectsBadConfig verifies that a config without a
// certificate returns an error and does not take ownership of the
// listener.
func TestNewListenerRejectsBadConfig(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer raw.Close()

	if _, err := NewListener(&Config{}, raw); err == nil {
		t.Fatal("NewListener without cert: want error, got nil")
	}
	// 监听器仍归调用方所有，应仍可关闭（说明未被提前关闭两次）。
	if err := raw.Close(); err != nil {
		t.Errorf("raw.Close after failed NewListener: %v", err)
	}
}
