package tls

import (
	"bytes"
	"net"
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
