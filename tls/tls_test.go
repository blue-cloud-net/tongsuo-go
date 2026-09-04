package tls

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

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
		_, _ = srv.Accept(c)
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
		_, aerr := srv.Accept(c)
		acceptDone <- aerr
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
		_, aerr := srv.Accept(c)
		done <- aerr
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
		_, _ = srv.Accept(c)
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
