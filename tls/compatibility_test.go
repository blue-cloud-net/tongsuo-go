package tls

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// TestNTLSRejectSwappedCertificateUsage 验证 8.5 的双证书用途检查拒绝互换身份。
//
// TestNTLSRejectSwappedCertificateUsage checks that 8.5 rejects swapped sign/encryption identities.
func TestNTLSRejectSwappedCertificateUsage(t *testing.T) {
	if meta.VersionNum() < 0x30500000 {
		return
	} // This check was enabled by default in 8.5.
	cfg := testNTLSConfig(t)
	defer cfg.SignCert.Close()
	defer cfg.EncCert.Close()
	defer asym.Close(cfg.SignKey)
	defer asym.Close(cfg.EncKey)
	cfg.SignCert, cfg.EncCert = cfg.EncCert, cfg.SignCert
	cfg.SignKey, cfg.EncKey = cfg.EncKey, cfg.SignKey
	srv, err := NewServer(cfg)
	if err != nil {
		if !strings.Contains(err.Error(), "SSL_CTX_use_sign_certificate") {
			t.Fatal(err)
		}
		return
	}
	defer srv.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		raw, e := ln.Accept()
		if e != nil {
			done <- e
			return
		}
		defer raw.Close()
		conn, e := srv.Accept(raw)
		if e != nil {
			done <- e
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		done <- handshakeErr(conn)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialContext(ctx, "tcp", ln.Addr().String(), &Config{NTLS: true})
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("swapped certificate usage accepted")
	}
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("server accepted swapped usage")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("server did not finish")
	}
}
