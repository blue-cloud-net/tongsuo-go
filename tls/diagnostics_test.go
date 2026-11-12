package tls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	stdtls "crypto/tls"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"github.com/blue-cloud-net/tongsuo-go/x509"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestSCTCapture 验证 SCT 来源、顺序、重复项及快照所有权。
//
// TestSCTCapture checks SCT source, order, duplicates and snapshot ownership.
func TestSCTCapture(t *testing.T) {
	sc, _ := testChainIdentity(t, false)
	certPEM, err := sc.Cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := sc.Key.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	pair, err := stdtls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	sct := make([]byte, 47)
	sct[43], sct[44] = 4, 3
	signature := []byte{0x30, 6, 2, 1, 1, 2, 1, 1}
	binary.BigEndian.PutUint16(sct[45:], uint16(len(signature)))
	sct = append(sct, signature...)
	second := append([]byte(nil), sct...)
	second[32] = 1
	// Embed an additional certificate-source SCT; only TLS-extension items may escape.
	parsed, err := stdx509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	parsed.ExtraExtensions = nil
	embedded := append([]byte{0, byte(len(second) + 2), 0, byte(len(second))}, second...)
	encoded, err := asn1.Marshal(embedded)
	if err != nil {
		t.Fatal(err)
	}
	parsed.ExtraExtensions = append(parsed.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, Value: encoded})
	parsed.Issuer = parsed.Subject
	parsed.IsCA = true
	parsed.BasicConstraintsValid = true
	parsed.KeyUsage |= stdx509.KeyUsageCertSign
	signer := pair.PrivateKey.(crypto.Signer)
	der, err := stdx509.CreateCertificate(rand.Reader, parsed, parsed, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	pair.Certificate = [][]byte{der}
	root, err := x509.LoadCertificateDER(der)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	pair.SignedCertificateTimestamps = [][]byte{sct, second, sct}
	for _, enabled := range []bool{false, true} {
		for _, policy := range []VerificationPolicy{VerifyNone, VerifyReport, VerifyStrict} {
			ln, err := stdtls.Listen("tcp", "127.0.0.1:0", &stdtls.Config{Certificates: []stdtls.Certificate{pair}, MinVersion: stdtls.VersionTLS12, MaxVersion: stdtls.VersionTLS12})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				c, e := ln.Accept()
				if e != nil {
					done <- e
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_, e = c.Write([]byte("sct"))
				done <- e
			}()
			cfg := &Config{CaptureSCT: enabled, Verification: policy, MinVersion: TLS1_2Version, MaxVersion: TLS1_2Version}
			if policy == VerifyStrict {
				cfg.RootCAs = []*x509.Certificate{root}
			}
			c, err := Dial("tcp", ln.Addr().String(), cfg)
			if err != nil {
				_ = ln.Close()
				t.Fatal(err)
			}
			st := c.(*Conn).ConnectionState()
			if enabled {
				got := st.SignedCertificateTimestamps
				if len(got) != 3 || !bytes.Equal(got[0], sct) || !bytes.Equal(got[1], second) || !bytes.Equal(got[2], sct) {
					t.Fatal("SCT wire encoding/order mismatch")
				}
				got[0][0] ^= 255
				if !bytes.Equal(c.(*Conn).ConnectionState().SignedCertificateTimestamps[0], sct) {
					t.Fatal("SCT snapshot aliases retained state")
				}
			} else if len(st.SignedCertificateTimestamps) != 0 {
				t.Fatal("capture disabled")
			}
			if !st.SecureRenegotiation {
				t.Fatal("TLS 1.2 secure renegotiation missing")
			}
			buf := make([]byte, 3)
			_, err = io.ReadFull(c, buf)
			if err != nil || string(buf) != "sct" {
				t.Fatalf("data: %v", err)
			}
			_ = c.Close()
			_ = ln.Close()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TestDiagnosticProtocolMatrix 验证 TLS/NTLS 诊断、并发读写与独立连接序号。
//
// TestDiagnosticProtocolMatrix checks TLS/NTLS diagnostics, concurrent I/O and independent connection sequences.
func TestDiagnosticProtocolMatrix(t *testing.T) {
	for _, protocol := range []string{"tls12", "tls13", "ntls-ecc", "ntls-ecdhe"} {
		t.Run(protocol, func(t *testing.T) {
			sc, _ := testChainIdentity(t, false)
			cc := &Config{Verification: VerifyNone}
			if protocol == "tls12" {
				sc.MaxVersion = TLS1_2Version
				cc.MaxVersion = TLS1_2Version
			}
			if protocol == "tls13" {
				sc.MinVersion = TLS1_3Version
				cc.MinVersion = TLS1_3Version
			}
			if protocol == "ntls-ecc" || protocol == "ntls-ecdhe" {
				sc = testNTLSConfig(t)
				cc.NTLS = true
				cc.SignCert, cc.SignKey, cc.EncCert, cc.EncKey = sc.SignCert, sc.SignKey, sc.EncCert, sc.EncKey
				suite := "ECC-SM2-SM4-GCM-SM3"
				if protocol == "ntls-ecdhe" {
					suite = "ECDHE-SM2-SM4-GCM-SM3"
				}
				sc.CipherSuites, cc.CipherSuites = []string{suite}, []string{suite}
			}
			var mu sync.Mutex
			var events []HandshakeEvent
			var trace, keylog bytes.Buffer
			cc.Diagnostics = &DiagnosticsConfig{OnEvent: func(e HandshakeEvent) error { mu.Lock(); defer mu.Unlock(); events = append(events, e); return nil }, TraceWriter: &trace, KeyLogWriter: &keylog}
			c, s, ce, se := handshakePair(t, sc, cc)
			if ce != nil || se != nil {
				t.Fatalf("client=%v server=%v", ce, se)
			}
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			_ = s.SetDeadline(time.Now().Add(2 * time.Second))
			var wg sync.WaitGroup
			errs := make(chan error, 4)
			for _, conn := range []net.Conn{c, s} {
				wg.Add(2)
				go func(c net.Conn) { defer wg.Done(); _, e := c.Write([]byte("duplex")); errs <- e }(conn)
				go func(c net.Conn) {
					defer wg.Done()
					b := make([]byte, 6)
					_, e := io.ReadFull(c, b)
					if e == nil && string(b) != "duplex" {
						t.Error("payload mismatch")
					}
					errs <- e
				}(conn)
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			_ = c.Close()
			_ = s.Close()
			mu.Lock()
			defer mu.Unlock()
			if len(events) == 0 || trace.Len() == 0 || keylog.Len() == 0 {
				t.Fatal("missing protocol diagnostics")
			}
			for i, e := range events {
				if e.Sequence != uint64(i+1) {
					t.Fatal("sequence mismatch")
				}
			}
		})
	}
}

// TestDiagnosticCloseDuringRead 验证诊断启用时关闭能唤醒等待中的读操作。
//
// TestDiagnosticCloseDuringRead checks closing wakes a pending read with diagnostics enabled.
func TestDiagnosticCloseDuringRead(t *testing.T) {
	sc, _ := testChainIdentity(t, false)
	c, _, ce, se := handshakePair(t, sc, &Config{Verification: VerifyNone, Diagnostics: &DiagnosticsConfig{OnEvent: func(HandshakeEvent) error { return nil }}})
	if ce != nil || se != nil {
		t.Fatalf("client=%v server=%v", ce, se)
	}
	started, done := make(chan struct{}), make(chan error, 1)
	go func() { close(started); _, err := c.Read(make([]byte, 1)); done <- err }()
	<-started
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read succeeded after close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close/read deadlock")
	}
}

// TestDiagnosticCancelledHandshake 验证取消握手保留开始/失败结束事件且不泄漏 goroutine。
//
// TestDiagnosticCancelledHandshake checks cancellation preserves start/failure events and converges the handshake goroutine.
func TestDiagnosticCancelledHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := ln.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer := <-accepted
	defer peer.Close()
	var events []HandshakeEvent
	c, err := Client(raw, &Config{Verification: VerifyNone, Diagnostics: &DiagnosticsConfig{OnEvent: func(e HandshakeEvent) error { events = append(events, e); return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err = c.HandshakeContext(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
	if len(events) < 2 || events[0].Kind != "start" || events[len(events)-1].Kind != "end" || !errors.Is(events[len(events)-1].Err, context.DeadlineExceeded) {
		t.Fatal("missing cancellation lifecycle")
	}
}
