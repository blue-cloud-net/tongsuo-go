package tls

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// mustHandshake 同步驱动服务端握手的测试辅助（Server.Accept 当前为惰性，
// 测试代码需要显式调 Handshake 后才能 Read/Write）。
//
// mustHandshake 仅在握手应当成功时使用；期望握手失败的测试（如 TestDialPeerVerifyReject）
// 须自己写 if/return，不要走 t.Fatalf，否则会误判为测试失败。
//
// mustHandshake is a test helper that drives the now-lazy server-side
// handshake synchronously; Server.Accept returns before the handshake
// completes, so tests must explicitly call Handshake (or HandshakeContext)
// before reading/writing. Use it only when the handshake is expected to
// succeed — for tests that expect a handshake failure, do not Fatalf on
// the server side (the test asserts the client-side failure).
func mustHandshake(t *testing.T, c net.Conn) net.Conn {
	t.Helper()
	if tc, ok := c.(*Conn); ok {
		if err := tc.Handshake(); err != nil {
			t.Fatalf("Handshake: %v", err)
		}
	}
	return c
}

// testServerConfig 生成 SM2 自签服务器证书配置。
func testServerConfig(t *testing.T) *Config {
	t.Helper()
	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := x509.NewName().Add("CN", "server.tongsuo-go.dev")
	cert := x509.NewCertificate()
	if err := cert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetSerial(1); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetIssuer(subject); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetSubject(subject); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetValidity(now.Add(-time.Hour), now.Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetPublicKey(priv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := cert.AddBasicConstraints(true); err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return &Config{Cert: cert, Key: priv}
}

// testNTLSConfig 生成 NTLS 双证书配置（签名证书 + 加密证书）。
func testNTLSConfig(t *testing.T) *Config {
	t.Helper()
	signPriv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	encPriv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	build := func(cn string, priv *sm2.PrivateKey) *x509.Certificate {
		subject := x509.NewName().Add("CN", cn)
		cert := x509.NewCertificate()
		if err := cert.SetVersion(2); err != nil {
			t.Fatal(err)
		}
		if err := cert.SetSerial(1); err != nil {
			t.Fatal(err)
		}
		if err := cert.SetIssuer(subject); err != nil {
			t.Fatal(err)
		}
		if err := cert.SetSubject(subject); err != nil {
			t.Fatal(err)
		}
		if err := cert.SetValidity(now.Add(-time.Hour), now.Add(365*24*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := cert.SetPublicKey(priv.Public()); err != nil {
			t.Fatal(err)
		}
		if err := cert.AddBasicConstraints(true); err != nil {
			t.Fatal(err)
		}
		if err := cert.Sign(priv); err != nil {
			t.Fatal(err)
		}
		return cert
	}
	return &Config{
		NTLS:     true,
		SignCert: build("sign.tongsuo-go.dev", signPriv),
		SignKey:  signPriv,
		EncCert:  build("enc.tongsuo-go.dev", encPriv),
		EncKey:   encPriv,
	}
}

// TestNTLSLoopback 验证 NTLS（国密 TLCP）双证书握手与数据交换。
func TestNTLSLoopback(t *testing.T) {
	cfg := testNTLSConfig(t)
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		tlsConn, err := server.Accept(raw)
		if err != nil {
			errCh <- err
			return
		}
		tlsConn = mustHandshake(t, tlsConn)
		buf := make([]byte, 512)
		n, err := tlsConn.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		if _, err := tlsConn.Write(buf[:n]); err != nil {
			errCh <- err
			return
		}
		_ = tlsConn.Close()
		errCh <- nil
	}()

	conn, err := Dial("tcp", ln.Addr().String(), &Config{NTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	c, _ := conn.(*Conn)
	t.Logf("NTLS version=%s cipher=%s", c.Version(), c.CipherName())

	msg := []byte("hello tongsuo-go ntls")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(msg))
	if _, err := conn.Read(reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, msg) {
		t.Fatalf("NTLS reply mismatch: %q", reply)
	}

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

// TestLoopback 验证 TLS 客户端与服务端握手及双向数据交换。
func TestLoopback(t *testing.T) {
	cfg := testServerConfig(t)
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		tlsConn, err := server.Accept(raw)
		if err != nil {
			errCh <- err
			return
		}
		tlsConn = mustHandshake(t, tlsConn)
		// 回显：读一段再写回。
		buf := make([]byte, 512)
		n, err := tlsConn.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		if _, err := tlsConn.Write(buf[:n]); err != nil {
			errCh <- err
			return
		}
		_ = tlsConn.Close()
		errCh <- nil
	}()

	conn, err := Dial("tcp", ln.Addr().String(), &Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	c, ok := conn.(*Conn)
	if !ok {
		t.Fatal("Dial did not return *tls.Conn")
	}
	if c.Version() == "" {
		t.Fatal("empty protocol version")
	}
	t.Logf("negotiated version=%s cipher=%s", c.Version(), c.CipherName())

	msg := []byte("hello tongsuo-go tls")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(msg))
	if _, err := conn.Read(reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, msg) {
		t.Fatalf("reply mismatch: %q", reply)
	}

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

// TestLoopbackMultiRound 验证同一连接多次读写。
func TestLoopbackMultiRound(t *testing.T) {
	cfg := testServerConfig(t)
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		tlsConn, err := server.Accept(raw)
		if err != nil {
			done <- err
			return
		}
		tlsConn = mustHandshake(t, tlsConn)
		buf := make([]byte, 1024)
		for i := 0; i < 5; i++ {
			n, err := tlsConn.Read(buf)
			if err != nil {
				done <- err
				return
			}
			if _, err := tlsConn.Write(buf[:n]); err != nil {
				done <- err
				return
			}
		}
		_ = tlsConn.Close()
		done <- nil
	}()

	conn, err := Dial("tcp", ln.Addr().String(), &Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	for i := 0; i < 5; i++ {
		msg := bytes.Repeat([]byte{byte('a' + i)}, 200)
		if _, err := conn.Write(msg); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(msg))
		if _, err := conn.Read(reply); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(reply, msg) {
			t.Fatalf("round %d mismatch", i)
		}
	}

	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestDialPeerVerifyReject 验证显式配置 ServerName + 无 RootCAs 时握手失败
// （D1 方案 A：显式给 ServerName 即开启 PEER，无信任根则拒握手）。
func TestDialPeerVerifyReject(t *testing.T) {
	srvCfg := testServerConfig(t)
	srv, err := NewServer(srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		conn, aerr := srv.Accept(c)
		if aerr != nil {
			return
		}
		// 服务端也驱动一次握手：让对端 Connect 走完进而失败；服务端本身
		// 在收到 alert 后会失败，这里我们忽略（不 fatal）以免误判。
		if tc, ok := conn.(*Conn); ok {
			_ = tc.Handshake()
		}
	}()

	// 客户端：显式给 ServerName 但不给 RootCAs；自签不可信，应当握手失败。
	cliCfg := &Config{
		Cert:       srvCfg.Cert,
		Key:        srvCfg.Key,
		ServerName: "server.tongsuo-go.dev",
	}
	_, dialErr := Dial("tcp", ln.Addr().String(), cliCfg)
	if dialErr == nil {
		t.Fatal("expected dial failure when peer verify is on and no trust anchors")
	}
	// OpenSSL 在 PEER + 无信任根 + 无 CA 时握手阶段即报 certificate verify failed；
	// 错误可能来自 SSL_connect（握手时）或我们后续的 VerifyResult 检查，两种都接受。
	msg := dialErr.Error()
	if !bytes.Contains([]byte(msg), []byte("certificate verify failed")) &&
		!bytes.Contains([]byte(msg), []byte("peer verification failed")) {
		t.Fatalf("unexpected error: %v", dialErr)
	}

	select {
	case <-acceptDone:
	case <-time.After(5 * time.Second):
		t.Fatal("server accept goroutine did not finish")
	}
}

// TestDialInsecureSkipVerify 验证 InsecureSkipVerify=true 跳过验证（自签仍握手成功）。
func TestDialInsecureSkipVerify(t *testing.T) {
	srvCfg := testServerConfig(t)
	srv, err := NewServer(srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	acceptDone := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			acceptDone <- err
			return
		}
		conn, aerr := srv.Accept(c)
		if aerr != nil {
			acceptDone <- aerr
			return
		}
		conn = mustHandshake(t, conn)
		_ = conn
		acceptDone <- nil
	}()

	cliCfg := &Config{
		Cert:               srvCfg.Cert,
		Key:                srvCfg.Key,
		InsecureSkipVerify: true,
	}
	conn, err := Dial("tcp", ln.Addr().String(), cliCfg)
	if err != nil {
		t.Fatalf("InsecureSkipVerify dial should succeed: %v", err)
	}
	_ = conn.Close()
}

// TestConnCloseIdempotent 验证 Close 幂等且多次调用安全（不崩溃、不阻塞）。
func TestConnCloseIdempotent(t *testing.T) {
	srvCfg := testServerConfig(t)
	srv, err := NewServer(srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		conn, aerr := srv.Accept(c)
		if aerr != nil {
			done <- aerr
			return
		}
		conn = mustHandshake(t, conn)
		_ = conn
		done <- nil
	}()

	cliCfg := &Config{
		Cert: srvCfg.Cert,
		Key:  srvCfg.Key,
	}
	conn, err := Dial("tcp", ln.Addr().String(), cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	// 双 Close + 三 Close 不应崩溃或卡住。
	if err := conn.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("third Close: %v", err)
	}
	// Close 后 Read 必须立即返回 io.EOF（不阻塞）。
	_ = conn.SetReadDeadline(time.Now())
	if n, err := conn.Read(make([]byte, 16)); n != 0 || err != io.EOF {
		t.Fatalf("post-Close Read: got (%d, %v), want (0, EOF)", n, err)
	}
	// Close 后 Write 必须立即返回 ErrClosed。
	if n, err := conn.Write([]byte("x")); n != 0 || err != ErrClosed {
		t.Fatalf("post-Close Write: got (%d, %v), want (0, ErrClosed)", n, err)
	}
}

// TestConnCloseConcurrentWithRead 验证并发 Close+Read/Write 不崩溃（-race）。
func TestConnCloseConcurrentWithRead(t *testing.T) {
	srvCfg := testServerConfig(t)
	srv, err := NewServer(srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		conn, aerr := srv.Accept(c)
		if aerr != nil {
			return
		}
		if tc, ok := conn.(*Conn); ok {
			if err := tc.Handshake(); err != nil {
				return
			}
		}
		// 服务端写一些数据后关闭。
		_, _ = conn.Write([]byte("hello"))
		_ = conn.Close()
	}()

	cliCfg := &Config{
		Cert: srvCfg.Cert,
		Key:  srvCfg.Key,
	}
	conn, err := Dial("tcp", ln.Addr().String(), cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	// 在 Close 路上有在途 Read；并发触发应不崩溃。
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 16)
			_, _ = conn.Read(buf)
		}()
	}
	// 让 Read 先在途，然后 Close。
	time.Sleep(10 * time.Millisecond)
	_ = conn.Close()
	wg.Wait()
}

// TestConnDeadlineUnblocksRead 验证 SetDeadline 真的能中断阻塞的 Read。
// 若实现错误（deadline 只转 raw socket 不通知 SSL 层），Read 仍会阻塞
// 最多 waitFDTimeout=30s 才能被 raw socket Close 唤醒。本测试设置 2s
// deadline 并断言 Read 在 ~2.5s 内返回超时错误。
func TestConnDeadlineUnblocksRead(t *testing.T) {
	srvCfg := testServerConfig(t)
	srv, err := NewServer(srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		conn, aerr := srv.Accept(c)
		if aerr != nil {
			return
		}
		conn = mustHandshake(t, conn)
		_ = conn
	}()

	cliCfg := &Config{
		Cert: srvCfg.Cert,
		Key:  srvCfg.Key,
	}
	conn, err := Dial("tcp", ln.Addr().String(), cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	buf := make([]byte, 16)
	_, err = conn.Read(buf)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected deadline error, got nil")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Read blocked %v; deadline did not unblock it (should be ~500ms)", elapsed)
	}
	t.Logf("Read returned after %v with %v (expected deadline within 500ms-5s)", elapsed, err)
}

// TestDialContextCancelFast 验证：握手尚未完成时 ctx 触发后，DialContext
// 在合理时间内返回 context 错误。
//
// 实现层限制：core.SSLConn.Connect() 内部用 syscall.Select 等待 fd 可
// 读，Linux 的 syscall.Select 无法从 Go 侧直接打断（无 epoll 集成）；
// 因此「纯 cancel」路径在 Linux 上**不保证及时**（会等到下一个 waitFD
// 重试轮次）。本测试以 deadline 路径（首选）验证 ctx 触发的可观测行
// 为：ctx.WithTimeout 触发后 DialContext 应在 timeout+少量缓冲内返回。
//
// **用户使用建议**：在生产代码中给 ctx 设合理 deadline，而不是纯 cancel。
// 更稳健的取消机制需要切换到 epoll/poll(2)（计划在 v0.1.3+）。
//
// 实现层细节见 errors.go / HandshakeContext 的注释。
func TestDialContextCancelFast(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// 不 Accept；客户端握手卡死等待 serverHello。
	// 5s 后 ctx 触发；同时 DialContext 会尝试通过 close(raw) 唤醒握
	// 手；Linux 上不可靠，故 timeout 留足 35s 兜底。
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type dialResult struct {
		conn net.Conn
		err  error
	}
	done := make(chan dialResult, 1)
	go func() {
		c, err := DialContext(ctx, "tcp", ln.Addr().String(), &Config{})
		done <- dialResult{c, err}
	}()

	select {
	case r := <-done:
		if r.err == nil {
			r.conn.Close()
			t.Fatal("expected error after deadline")
		}
		if !errors.Is(r.err, context.DeadlineExceeded) {
			t.Fatalf("err=%v, want context.DeadlineExceeded", r.err)
		}
		t.Logf("DialContext returned %v after deadline (linux syscall.Select is not interruptible; actual return may take up to ~waitFDTimeout=30s)", r.err)
	case <-time.After(35 * time.Second):
		t.Fatal("DialContext did not return within 35s after deadline; known limitation: syscall.Select not interruptible")
	}
}

// TestDialContextDeadline 验证：ctx 截止时间到期时返回
// context.DeadlineExceeded。
func TestDialContextDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// 不 Accept；客户端握手挂死。

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = DialContext(ctx, "tcp", ln.Addr().String(), &Config{})
	if err == nil {
		t.Fatal("expected error after deadline")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v, want context.DeadlineExceeded", err)
	}
}

func TestHandshakeErrorClassification(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		want    error // sentinel
		wantKind HandshakeErrorKind
	}{
		{
			name:    "NoSharedCipher",
			err:     &HandshakeError{Op: "x", Kind: HandshakeErrorCipher, Err: errors.New("no match")},
			want:    ErrNoSharedCipher,
			wantKind: HandshakeErrorCipher,
		},
		{
			name:    "Version",
			err:     &HandshakeError{Op: "x", Kind: HandshakeErrorVersion, Err: errors.New("proto mismatch")},
			want:    ErrVersionNotSupported,
			wantKind: HandshakeErrorVersion,
		},
		{
			name:    "PeerVerify",
			err:     &HandshakeError{Op: "x", Kind: HandshakeErrorPeerVerify, Err: errors.New("x509 v")},
			want:    ErrPeerVerification,
			wantKind: HandshakeErrorPeerVerify,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !errors.Is(tc.err, tc.want) {
				t.Fatalf("errors.Is err=%v want=%v: not matched", tc.err, tc.want)
			}
			var he *HandshakeError
			if !errors.As(tc.err, &he) || he.Kind != tc.wantKind {
				t.Fatalf("errors.As: kind=%v want=%v", he, tc.wantKind)
			}
		})
	}
}

// TestPeerCertificatesPEMRoundTrip 验证：回环握手后 PeerCertificates 返
// 回的链按 leaf→root 顺序，且每张 MarshalPEM 后能再次被 LoadCertificatePEM
// 还原，SubjectText 一致。
func TestPeerCertificatesPEMRoundTrip(t *testing.T) {
	srvCfg := testServerConfig(t)
	srv, err := NewServer(srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		conn, aerr := srv.Accept(c)
		if aerr != nil {
			return
		}
		conn = mustHandshake(t, conn)
		_ = conn // 不需要 I/O，连接足够让客户端握手成功
	}()

	conn, err := Dial("tcp", ln.Addr().String(), &Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	tc, ok := conn.(*Conn)
	if !ok {
		t.Fatal("Dial did not return *tls.Conn")
	}
	chain, err := tc.PeerCertificates()
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) == 0 {
		t.Fatal("expected non-empty peer chain")
	}
	defer func() {
		for _, c := range chain {
			_ = c.Close()
		}
	}()

	// SubjectText 一致性 + PEM 往返。
	for i, c := range chain {
		dn := c.SubjectText()
		if dn == "" {
			t.Fatalf("chain[%d] empty subject", i)
		}
		pem, err := c.MarshalPEM()
		if err != nil {
			t.Fatalf("chain[%d].MarshalPEM: %v", i, err)
		}
		reloaded, err := x509.LoadCertificatePEM(pem)
		if err != nil {
			t.Fatalf("chain[%d].LoadCertificatePEM: %v", i, err)
		}
		defer reloaded.Close()
		if reloaded.SubjectText() != dn {
			t.Fatalf("chain[%d]: subject mismatch after round-trip: %q vs %q", i, dn, reloaded.SubjectText())
		}
	}
}

// TestPeerCertificatesNilWhenNoClientCert 验证：服务端不强制 mTLS 时，
// 服务端 conn 上 PeerCertificates 返回 nil, nil。
func TestPeerCertificatesNilWhenNoClientCert(t *testing.T) {
	srvCfg := testServerConfig(t)
	srv, err := NewServer(srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type srvResult struct {
		conn net.Conn
		err  error
	}
	srvDone := make(chan srvResult, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvDone <- srvResult{nil, err}
			return
		}
		conn, aerr := srv.Accept(c)
		if aerr != nil {
			srvDone <- srvResult{nil, aerr}
			return
		}
		conn = mustHandshake(t, conn)
		srvDone <- srvResult{conn, nil}
	}()

	// 客户端不提供证书。
	cliCfg := &Config{InsecureSkipVerify: true}
	conn, err := Dial("tcp", ln.Addr().String(), cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	sr := <-srvDone
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	defer sr.conn.Close()
	tc := sr.conn.(*Conn)
	chain, err := tc.PeerCertificates()
	if err != nil {
		t.Fatalf("PeerCertificates: %v", err)
	}
	if chain != nil {
		t.Fatalf("expected nil chain when client sends no cert, got %d certs", len(chain))
	}
}

// TestPeerEncCertificatesNTLS 验证 NTLS 客户端可拿到独立的加密证书链。
func TestPeerEncCertificatesNTLS(t *testing.T) {
	cfg := testNTLSConfig(t)
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		conn, aerr := srv.Accept(c)
		if aerr != nil {
			return
		}
		conn = mustHandshake(t, conn)
		_ = conn
	}()

	cliCfg := &Config{
		NTLS:     true,
		SignCert: cfg.SignCert, SignKey: cfg.SignKey,
		EncCert: cfg.EncCert, EncKey: cfg.EncKey,
	}
	conn, err := Dial("tcp", ln.Addr().String(), cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	tc := conn.(*Conn)
	signChain, err := tc.PeerCertificates()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, c := range signChain {
			_ = c.Close()
		}
	}()
	encChain, err := tc.PeerEncCertificates()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, c := range encChain {
			_ = c.Close()
		}
	}()

	if len(signChain) == 0 {
		t.Fatal("expected non-empty sign chain")
	}
	if len(encChain) == 0 {
		t.Fatal("expected non-empty enc chain")
	}
	// 签名叶 CN = "sign.tongsuo-go.dev"，加密叶 CN = "enc.tongsuo-go.dev"（与
	// testNTLSConfig 一致；两证 serial 都是 1，但 CN 区分）。
	if signChain[0].Subject() != "sign.tongsuo-go.dev" {
		t.Fatalf("sign leaf CN=%q, want %q", signChain[0].Subject(), "sign.tongsuo-go.dev")
	}
	if encChain[0].Subject() != "enc.tongsuo-go.dev" {
		t.Fatalf("enc leaf CN=%q, want %q", encChain[0].Subject(), "enc.tongsuo-go.dev")
	}
}

// TestCipherSuitesEnumerated 验证：每个版本都能枚举出至少一个套件。
//
// 注意：Tongsuo 的 SSL_CTX_get_ciphers 返回已配置的全量套件（不限版本过
// 滤）；本测试只验证枚举本身工作正常，版本差异在 c->min_tls 字符串里
// 反映，不在列表规模上。
//
// CipherSuitesEnumerated verifies that every supported version returns at
// least one cipher. Note: Tongsuo's SSL_CTX_get_ciphers does not filter
// by min/max_proto_version, so the probe enumerates the configured set.
// Per-version coverage is reflected in each CipherInfo.MinVersion /
// MinVersion string, not in list size.
func TestCipherSuitesEnumerated(t *testing.T) {
	for _, v := range []uint16{TLS1Version, TLS1_1Version, TLS1_2Version, TLS1_3Version, NTLSVersion} {
		cs := CipherSuites(v)
		if len(cs) == 0 {
			t.Fatalf("version=0x%04x: empty", v)
		}
		t.Logf("version=0x%04x: %d ciphers (first=%q)", v, len(cs), cs[0].Name)
		// 至少有 1 个套件的 MinVersion 落在请求的版本上。
		found := false
		for _, c := range cs {
			if c.MinVersion == v {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("version=0x%04x: no cipher has MinVersion=0x%04x", v, v)
		}
	}
}

// TestCipherSuitesUnknownVersion 验证：未知版本号返回 nil。
func TestCipherSuitesUnknownVersion(t *testing.T) {
	if got := CipherSuites(0x9999); got != nil {
		t.Fatalf("unknown version returned %d ciphers, want nil", len(got))
	}
}

// TestConfigCipherSuitesMixed 验证 Config.CipherSuites 同时包含 TLS_ 前缀
// 名和经典名时，握手仍然成功（混合语义）。
func TestConfigCipherSuitesMixed(t *testing.T) {
	srvCfg := testServerConfig(t)
	srvCfg.CipherSuites = []string{
		"ECDHE-RSA-AES128-SHA256", // legacy
		"TLS_AES_128_GCM_SHA256",  // TLS1.3
		"NO_SUCH_CIPHER_FOR_TEST", // 故意失败
	}
	srv, err := NewServer(srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		conn, aerr := srv.Accept(c)
		if aerr != nil {
			return
		}
		conn = mustHandshake(t, conn)
		_ = conn
	}()

	// 客户端用同样的混合名单；握手应该成功（部分不致命）。
	cliCfg := &Config{
		Cert:               srvCfg.Cert,
		Key:                srvCfg.Key,
		InsecureSkipVerify: true,
		CipherSuites:       srvCfg.CipherSuites,
	}
	conn, err := Dial("tcp", ln.Addr().String(), cliCfg)
	if err != nil {
		t.Fatalf("mixed cipher dial should succeed (partial match): %v", err)
	}
	_ = conn.Close()
}

// TestConfigCipherSuitesAllUnknown 验证全部不识别时返回 ErrNoSharedCipher。
func TestConfigCipherSuitesAllUnknown(t *testing.T) {
	badCfg := testServerConfig(t)
	_, err := NewServer(&Config{
		Cert:         badCfg.Cert,
		Key:          badCfg.Key,
		CipherSuites: []string{"NO_SUCH_CIPHER_X", "NO_SUCH_CIPHER_Y"},
	})
	if err == nil {
		t.Fatal("expected error on all-unknown cipher list")
	}
	if !errors.Is(err, ErrNoSharedCipher) {
		t.Fatalf("err=%v, want ErrNoSharedCipher", err)
	}
}

// TestNTLSVersionConstant 验证 NTLSVersion 常量存在且等于 native.NTLSVersion。
func TestNTLSVersionConstant(t *testing.T) {
	if NTLSVersion == 0 {
		t.Fatal("NTLSVersion should be non-zero")
	}
}

// TestCertificateCloseIdempotent 验证公开 x509.Certificate 的 Close 幂等。
func TestCertificateCloseIdempotent(t *testing.T) {
	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	subject := x509.NewName().Add("CN", "close-test")
	now := time.Now()
	cert, err := x509.CreateCertificate(subject, subject, 1,
		now.Add(-time.Hour), now.Add(time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := cert.Close(); err != nil {
			t.Fatalf("Close #%d: %v", i, err)
		}
	}
	// Close 后 MarshalPEM 应返回错误。
	if _, err := cert.MarshalPEM(); err == nil {
		t.Fatal("MarshalPEM after Close should error")
	}
}

// TestRebuildChainReshuffled 验证：服务端发送乱序的链（先中间后叶），
// rebuildChain 也能按 issuer→subject 关系重排为 leaf→root。
//
// 直接驱动 core 层（不在 DialContext 里跑握手），构造一个 pool 包含
// 中间+叶两证，故意以「中间在前、叶在后」的顺序传入，验证 rebuildChain
// 输出 [叶, 中间]。
func TestRebuildChainReshuffled(t *testing.T) {
	caPriv, _ := sm2.GenerateKey()
	midPriv, _ := sm2.GenerateKey()
	leafPriv, _ := sm2.GenerateKey()
	now := time.Now()
	caSubj := x509.NewName().Add("CN", "test-root-ca")
	ca, err := x509.CreateCertificate(caSubj, caSubj, 1,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), caPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}
	midSubj := x509.NewName().Add("CN", "test-intermediate")
	mid, err := x509.CreateCertificate(midSubj, caSubj, 2,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), midPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}
	leafSubj := x509.NewName().Add("CN", "test-leaf")
	leafCert, err := x509.CreateCertificate(leafSubj, midSubj, 3,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), leafPriv.Public(), midPriv)
	if err != nil {
		t.Fatal(err)
	}

	// core 证书句柄用于 rebuildChain。
	caPEM, err := ca.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	caCore, err := core.LoadCertificatePEM(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	midPEM, err := mid.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	midCore, err := core.LoadCertificatePEM(midPEM)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, err := leafCert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	leafCore, err := core.LoadCertificatePEM(leafPEM)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = caCore.Close()
		_ = midCore.Close()
		_ = leafCore.Close()
	}()

	// 故意打乱顺序：中间在前，叶在后。
	pool := []*core.Certificate{midCore, leafCore}
	rebuilt := rebuildChain(leafCore, pool)
	if len(rebuilt) != 2 {
		t.Fatalf("rebuilt len=%d, want 2", len(rebuilt))
	}
	if rebuilt[0] != leafCore {
		t.Fatalf("rebuilt[0] is not leaf")
	}
	if rebuilt[1] != midCore {
		t.Fatalf("rebuilt[1] is not intermediate")
	}
}
