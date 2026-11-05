package tls

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

func handshakePair(t *testing.T, sc, cc *Config) (*Conn, *Conn, error, error) {
	t.Helper()
	srv, err := NewServer(sc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	type result struct {
		c   *Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			ch <- result{err: err}
			return
		}
		wrapped, err := srv.Accept(raw)
		if err != nil {
			_ = raw.Close()
			ch <- result{err: err}
			return
		}
		c := wrapped.(*Conn)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		err = c.HandshakeContext(ctx)
		ch <- result{c, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, ce := DialContext(ctx, "tcp", ln.Addr().String(), cc)
	var client *Conn
	if raw != nil {
		client = raw.(*Conn)
		t.Cleanup(func() { _ = client.Close() })
	}
	sr := <-ch
	if sr.c != nil {
		t.Cleanup(func() { _ = sr.c.Close() })
	}
	return client, sr.c, ce, sr.err
}

// TestHandshakeALPNAndState 验证 ALPN、名称解耦与独立状态快照。
//
// TestHandshakeALPNAndState verifies ALPN, independent names and copied state snapshots.
func TestHandshakeALPNAndState(t *testing.T) {
	sc := testServerConfig(t)
	sc.NextProtos = []string{"test/2", "test/1"}
	cc := &Config{NextProtos: []string{"test/1", "test/2"}, Verification: VerifyStrict, RootCAs: []*x509.Certificate{sc.Cert}, VerificationName: "server.tongsuo-go.dev", ServerName: "route.example"}
	c, s, ce, se := handshakePair(t, sc, cc)
	if ce != nil || se != nil {
		t.Fatalf("client=%v server=%v", ce, se)
	}
	for _, conn := range []*Conn{c, s} {
		state := conn.ConnectionState()
		if !state.HandshakeComplete || state.NegotiatedProtocol != "test/2" || state.ServerName != "route.example" || state.CipherSuite == 0 {
			t.Fatalf("state=%+v", state)
		}
	}
	state := c.ConnectionState()
	if state.Verification != VerificationPassed || len(state.VerifiedChains) == 0 {
		t.Fatalf("verification=%+v", state)
	}
	original := append([]byte(nil), state.PeerCertificates[0]...)
	state.PeerCertificates[0][0] ^= 255
	if !bytes.Equal(c.ConnectionState().PeerCertificates[0], original) {
		t.Fatal("state aliases internal DER")
	}
	if err := c.VerifyHostname("server.tongsuo-go.dev"); err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyHostname("other.example"); err == nil {
		t.Fatal("hostname mismatch accepted")
	}
	_ = c.Close()
	if !c.ConnectionState().HandshakeComplete {
		t.Fatal("closed connection lost snapshot")
	}
}

// TestHandshakeVerificationPolicies 验证三种策略分别表达连接结果与验证事实。
//
// TestHandshakeVerificationPolicies verifies that policies separate connection results from verification facts.
func TestHandshakeVerificationPolicies(t *testing.T) {
	for _, policy := range []VerificationPolicy{VerifyNone, VerifyReport, VerifyStrict} {
		t.Run([]string{"default", "none", "report", "strict"}[policy], func(t *testing.T) {
			sc := testServerConfig(t)
			cc := &Config{Verification: policy, VerificationName: "server.tongsuo-go.dev"}
			c, _, ce, _ := handshakePair(t, sc, cc)
			if policy == VerifyStrict {
				if !errors.Is(ce, ErrPeerVerification) {
					t.Fatalf("strict error=%v", ce)
				}
				return
			}
			if ce != nil {
				t.Fatal(ce)
			}
			state := c.ConnectionState()
			if policy == VerifyNone && state.Verification != VerificationNotPerformed {
				t.Fatalf("unverified=%+v", state)
			}
			if policy == VerifyReport && (state.Verification != VerificationFailed || len(state.VerificationErrors) == 0) {
				t.Fatalf("report=%+v", state)
			}
		})
	}
}

// TestHandshakeSNIConfig 验证 SNI 切换凭证、ALPN 与客户端认证配置。
//
// TestHandshakeSNIConfig verifies SNI switches credentials, ALPN and client authentication.
func TestHandshakeSNIConfig(t *testing.T) {
	base := testServerConfig(t)
	selected := testServerConfigWithSubject(t, x509.NewName().Add("CN", "selected.example"))
	selected.NextProtos = []string{"selected/1"}
	selected.ClientAuth = RequireAndVerifyClientCert
	selected.ClientCAs = []*x509.Certificate{base.Cert}
	base.GetConfigForClient = func(info *ClientHelloInfo) (*Config, error) {
		if info.ServerName != "selected.example" || info.NTLS {
			return nil, errors.New("unexpected hello")
		}
		return selected, nil
	}
	cc := &Config{ServerName: "selected.example", Verification: VerifyStrict, RootCAs: []*x509.Certificate{selected.Cert}, Cert: base.Cert, Key: base.Key, NextProtos: []string{"selected/1"}}
	c, s, ce, se := handshakePair(t, base, cc)
	if ce != nil || se != nil {
		t.Fatalf("client=%v server=%v", ce, se)
	}
	if c.ConnectionState().NegotiatedProtocol != "selected/1" || s.ConnectionState().Verification != VerificationPassed {
		t.Fatal("SNI configuration not applied")
	}
	der, _ := selected.Cert.MarshalDER()
	if !bytes.Equal(c.ConnectionState().PeerCertificates[0], der) {
		t.Fatal("wrong SNI leaf")
	}
}

// TestHandshakeCertificateCallback 验证动态签名凭证选择。
//
// TestHandshakeCertificateCallback verifies dynamic signing credential selection.
func TestHandshakeCertificateCallback(t *testing.T) {
	sc := testServerConfig(t)
	selected := testServerConfig(t)
	sc.GetCertificate = func(info *ClientHelloInfo) (*Certificate, error) {
		return &Certificate{Leaf: selected.Cert, PrivateKey: selected.Key}, nil
	}
	c, _, ce, se := handshakePair(t, sc, &Config{Verification: VerifyNone})
	if ce != nil || se != nil {
		t.Fatalf("client=%v server=%v", ce, se)
	}
	der, _ := selected.Cert.MarshalDER()
	if !bytes.Equal(c.ConnectionState().PeerCertificates[0], der) {
		t.Fatal("certificate callback ignored")
	}
}

// TestHandshakeClientAuthentication 验证客户端证书的要求与信任。
//
// TestHandshakeClientAuthentication verifies client certificate requirements and trust.
func TestHandshakeClientAuthentication(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "present"}[present], func(t *testing.T) {
			sc := testServerConfig(t)
			identity := testServerConfig(t)
			sc.ClientAuth = RequireAndVerifyClientCert
			sc.ClientCAs = []*x509.Certificate{identity.Cert}
			cc := &Config{Verification: VerifyNone}
			if present {
				cc.Cert, cc.Key = identity.Cert, identity.Key
			}
			_, s, ce, se := handshakePair(t, sc, cc)
			if !present {
				if se == nil {
					t.Fatal("missing client certificate accepted")
				}
				return
			}
			if ce != nil || se != nil {
				t.Fatalf("client=%v server=%v", ce, se)
			}
			if s.ConnectionState().Verification != VerificationPassed {
				t.Fatal("client not verified")
			}
		})
	}
}

// TestHandshakeCallbacksAlwaysReject 验证诊断模式不会吞掉应用验证错误。
//
// TestHandshakeCallbacksAlwaysReject verifies diagnostic mode never swallows application verification errors.
func TestHandshakeCallbacksAlwaysReject(t *testing.T) {
	rejected := errors.New("application rejects peer")
	for _, which := range []string{"certificate", "connection"} {
		t.Run(which, func(t *testing.T) {
			cc := &Config{Verification: VerifyReport}
			if which == "certificate" {
				cc.VerifyPeerCertificate = func(raw [][]byte, chains [][][]byte) error {
					if len(raw) == 0 {
						return errors.New("no raw certificates")
					}
					return rejected
				}
			} else {
				cc.VerifyConnection = func(state ConnectionState) error { return rejected }
			}
			_, _, ce, _ := handshakePair(t, testServerConfig(t), cc)
			if !errors.Is(ce, rejected) || !errors.Is(ce, ErrPeerVerification) {
				t.Fatalf("callback error=%v", ce)
			}
		})
	}
}

// TestHandshakeMixedProtocols 验证混合上下文按实际协议报告状态。
//
// TestHandshakeMixedProtocols verifies mixed contexts report the actual negotiated protocol.
func TestHandshakeMixedProtocols(t *testing.T) {
	sc, _ := testNTLSIdentity(t, "ntls.example")
	tlsIdentity := testServerConfig(t)
	sc.Protocol = ProtocolMixed
	sc.NTLS = false
	sc.Cert, sc.Key = tlsIdentity.Cert, tlsIdentity.Key
	for _, mode := range []ProtocolMode{ProtocolTLS, ProtocolNTLS} {
		t.Run(map[ProtocolMode]string{ProtocolTLS: "tls", ProtocolNTLS: "ntls"}[mode], func(t *testing.T) {
			c, s, ce, se := handshakePair(t, sc, &Config{Protocol: mode, Verification: VerifyNone})
			if ce != nil || se != nil {
				t.Fatalf("client=%v server=%v", ce, se)
			}
			if c.ConnectionState().NTLS != (mode == ProtocolNTLS) || s.ConnectionState().NTLS != (mode == ProtocolNTLS) {
				t.Fatal("mixed context reported configured rather than negotiated protocol")
			}
			if mode == ProtocolNTLS {
				chain, err := c.PeerEncCertificates()
				if err != nil || len(chain) == 0 {
					t.Fatalf("NTLS encryption chain=%d err=%v", len(chain), err)
				}
				for _, cert := range chain {
					_ = cert.Close()
				}
			}
		})
	}
}

// TestHandshakeDuplexAndIndependentDeadlines 验证并发双向读写和独立期限。
//
// TestHandshakeDuplexAndIndependentDeadlines verifies full duplex I/O and independent deadlines.
func TestHandshakeDuplexAndIndependentDeadlines(t *testing.T) {
	c, s, ce, se := handshakePair(t, testServerConfig(t), &Config{Verification: VerifyNone})
	if ce != nil || se != nil {
		t.Fatalf("client=%v server=%v", ce, se)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_ = s.SetDeadline(time.Now().Add(3 * time.Second))
	read := make(chan error, 1)
	go func() {
		buf := make([]byte, 4)
		_, err := io.ReadFull(c, buf)
		if err == nil && string(buf) != "pong" {
			err = errors.New("unexpected pong")
		}
		read <- err
	}()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(s, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatal("unexpected ping")
	}
	if _, err := s.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	_ = c.SetWriteDeadline(time.Now().Add(-time.Second))
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := s.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read inherited write deadline: %v", err)
	}
	if _, err := c.Write([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write deadline cleared by SetReadDeadline: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(-time.Second))
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte("next")); err != nil {
		t.Fatalf("write inherited read deadline: %v", err)
	}
	if _, err := c.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read deadline cleared: %v", err)
	}
	if _, err := io.ReadFull(s, buf); err != nil {
		t.Fatal(err)
	}
}

// TestHandshakeBadConfigurations 验证非法协议、参数和凭证配置被拒绝。
//
// TestHandshakeBadConfigurations verifies invalid protocols, parameters and credential settings are rejected.
func TestHandshakeBadConfigurations(t *testing.T) {
	cases := []*Config{{Protocol: ProtocolMixed}, {Protocol: ProtocolTLS, NTLS: true}, {Verification: VerifyStrict, InsecureSkipVerify: true}, {MinVersion: TLS1_3Version, MaxVersion: TLS1_2Version}, {NextProtos: []string{""}}, {NextProtos: []string{string(make([]byte, 256))}}, {StrictConfig: true, CipherSuites: []string{"not-a-cipher"}}, {CurvePreferences: []string{"not-a-group"}}, {SignatureAlgorithms: []string{"not-a-signature"}}, {DHParameters: []byte("not parameters")}, {Options: 1}, {Protocol: ProtocolNTLS, MinVersion: TLS1_2Version}, {MinVersion: NTLSVersion}, {CurvePreferences: []string{""}}, {SignatureAlgorithms: []string{""}}, {HostnameOptions: HostnameOptions{Flags: 128}}}
	for i, cfg := range cases {
		ctx, err := newContext(cfg, true)
		if err == nil {
			_ = ctx.Close()
			t.Errorf("case %d accepted", i)
		}
	}
}

// TestHandshakeStateCloseConcurrent 验证状态快照与并发关闭。
//
// TestHandshakeStateCloseConcurrent verifies state snapshots during concurrent Close.
func TestHandshakeStateCloseConcurrent(t *testing.T) {
	c, _, ce, se := handshakePair(t, testServerConfig(t), &Config{Verification: VerifyNone})
	if ce != nil || se != nil {
		t.Fatalf("client=%v server=%v", ce, se)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				_ = c.ConnectionState()
			}
			_ = c.Close()
		}()
	}
	wg.Wait()
}

// TestNTLSHandshakeAuthentication 验证 CA 签发的双证书在四个 NTLS 套件中互认证。
//
// TestNTLSHandshakeAuthentication verifies CA-issued dual credentials authenticate with four NTLS suites.
func TestNTLSHandshakeAuthentication(t *testing.T) {
	for _, suite := range []string{"ECC-SM2-SM4-GCM-SM3", "ECDHE-SM2-SM4-GCM-SM3", "ECC-SM2-SM4-CBC-SM3", "ECDHE-SM2-SM4-CBC-SM3"} {
		t.Run(suite, func(t *testing.T) {
			sc, serverCA := testNTLSIdentity(t, "ntls.example")
			cc, clientCA := testNTLSIdentity(t, "client.example")
			sc.ClientAuth = RequireAndVerifyClientCert
			sc.ClientCAs = []*x509.Certificate{clientCA}
			cc.Verification = VerifyStrict
			cc.RootCAs = []*x509.Certificate{serverCA}
			cc.VerificationName = "ntls.example"
			sc.StrictConfig = true
			sc.CipherSuites = []string{suite}
			cc.StrictConfig = true
			cc.CipherSuites = []string{suite}
			c, s, ce, se := handshakePair(t, sc, cc)
			if ce != nil || se != nil {
				t.Fatalf("client=%v server=%v", ce, se)
			}
			if c.ConnectionState().Verification != VerificationPassed || s.ConnectionState().Verification != VerificationPassed {
				t.Fatalf("client=%+v server=%+v", c.ConnectionState(), s.ConnectionState())
			}
			for _, conn := range []*Conn{c, s} {
				if conn.CipherName() != suite {
					t.Fatalf("cipher=%s", conn.CipherName())
				}
				enc, err := conn.PeerEncCertificates()
				if err != nil || len(enc) == 0 {
					t.Fatalf("enc=%d err=%v", len(enc), err)
				}
				for _, cert := range enc {
					_ = cert.Close()
				}
			}
		})
	}
}

// TestNTLSVerificationBothCredentials 验证诊断结果保留双证书各自的信任失败。
//
// TestNTLSVerificationBothCredentials verifies diagnostic results preserve trust failures for both credentials.
func TestNTLSVerificationBothCredentials(t *testing.T) {
	for _, policy := range []VerificationPolicy{VerifyReport, VerifyStrict} {
		t.Run(map[VerificationPolicy]string{VerifyReport: "report", VerifyStrict: "strict"}[policy], func(t *testing.T) {
			sc, _ := testNTLSIdentity(t, "ntls.example")
			c, _, ce, _ := handshakePair(t, sc, &Config{NTLS: true, Verification: policy, VerificationName: "ntls.example"})
			if policy == VerifyStrict {
				if !errors.Is(ce, ErrPeerVerification) {
					t.Fatalf("error=%v", ce)
				}
				return
			}
			if ce != nil {
				t.Fatal(ce)
			}
			failures := c.ConnectionState().VerificationErrors
			sign, _ := sc.SignCert.MarshalDER()
			enc, _ := sc.EncCert.MarshalDER()
			seenSign, seenEnc := false, false
			for _, failure := range failures {
				seenSign = seenSign || bytes.Equal(failure.Certificate, sign)
				seenEnc = seenEnc || bytes.Equal(failure.Certificate, enc)
			}
			if !seenSign || !seenEnc {
				t.Fatalf("both credential failures not preserved: sign=%v enc=%v", seenSign, seenEnc)
			}
		})
	}
}

// TestHandshakeNTLSSNICallback 验证 SNI 切换完整 NTLS 双证书。
//
// TestHandshakeNTLSSNICallback verifies SNI selects complete NTLS dual credentials.
func TestHandshakeNTLSSNICallback(t *testing.T) {
	sc, _ := testNTLSIdentity(t, "ntls.example")
	selected, selectedCA := testNTLSIdentity(t, "selected.example")
	sc.GetNTLSCertificate = func(info *ClientHelloInfo) (*NTLSCertificate, error) {
		if !info.NTLS || info.ServerName != "selected.example" {
			return nil, errors.New("wrong hello")
		}
		return &NTLSCertificate{Sign: Certificate{Leaf: selected.SignCert, PrivateKey: selected.SignKey}, Enc: Certificate{Leaf: selected.EncCert, PrivateKey: selected.EncKey}}, nil
	}
	c, _, ce, se := handshakePair(t, sc, &Config{NTLS: true, ServerName: "selected.example", Verification: VerifyStrict, RootCAs: []*x509.Certificate{selectedCA}, NextProtos: []string{"ntls/1"}})
	if ce != nil || se != nil {
		t.Fatalf("client=%v server=%v", ce, se)
	}
	sign, _ := selected.SignCert.MarshalDER()
	if !bytes.Equal(c.ConnectionState().PeerCertificates[0], sign) {
		t.Fatal("NTLS SNI identity ignored")
	}
}

// TestHandshakeMixedPortConcurrent 验证同端口并发接受 TLS 和 NTLS。
//
// TestHandshakeMixedPortConcurrent verifies concurrent TLS and NTLS acceptance on one port.
func TestHandshakeMixedPortConcurrent(t *testing.T) {
	sc, _ := testNTLSIdentity(t, "ntls.example")
	identity := testServerConfig(t)
	sc.Protocol = ProtocolMixed
	sc.NTLS = false
	sc.Cert, sc.Key = identity.Cert, identity.Key
	srv, err := NewServer(sc)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const connections = 8
	results := make(chan error, connections*2)
	go func() {
		for i := 0; i < connections; i++ {
			raw, err := ln.Accept()
			if err != nil {
				results <- err
				continue
			}
			go func() {
				wrapped, err := srv.Accept(raw)
				if err != nil {
					_ = raw.Close()
					results <- err
					return
				}
				defer wrapped.Close()
				c := wrapped.(*Conn)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				err = c.HandshakeContext(ctx)
				if err == nil {
					if c.ConnectionState().Version != NTLSVersion && c.ConnectionState().Version != TLS1_3Version && c.ConnectionState().Version != TLS1_2Version {
						err = errors.New("invalid actual protocol")
					}
				}
				results <- err
			}()
		}
	}()
	for i := 0; i < connections; i++ {
		mode := ProtocolTLS
		if i%2 == 1 {
			mode = ProtocolNTLS
		}
		go func(mode ProtocolMode) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			c, err := DialContext(ctx, "tcp", ln.Addr().String(), &Config{Protocol: mode, Verification: VerifyNone})
			if err == nil {
				if c.(*Conn).ConnectionState().NTLS != (mode == ProtocolNTLS) {
					err = errors.New("wrong negotiated protocol")
				}
				_ = c.Close()
			}
			results <- err
		}(mode)
	}
	for i := 0; i < connections*2; i++ {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
}

// TestHandshakeALPNMismatch 验证 ALPN 不匹配时双方握手失败。
//
// TestHandshakeALPNMismatch verifies both handshakes fail on ALPN mismatch.
func TestHandshakeALPNMismatch(t *testing.T) {
	sc := testServerConfig(t)
	sc.NextProtos = []string{"server/1"}
	_, _, ce, se := handshakePair(t, sc, &Config{Verification: VerifyNone, NextProtos: []string{"client/1"}})
	if ce == nil || se == nil {
		t.Fatalf("ALPN mismatch accepted: client=%v server=%v", ce, se)
	}
}

// TestHandshakeStrictCipherUnion 验证严格配置保留套件并集并清空其他套件。
//
// TestHandshakeStrictCipherUnion verifies strict settings retain the suite union and clear other suites.
func TestHandshakeStrictCipherUnion(t *testing.T) {
	ctx, err := newContext(&Config{StrictConfig: true, CipherSuites: []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Close()
	found := map[string]bool{}
	for _, suite := range ctx.CipherList() {
		found[suite.Name] = true
	}
	if !found["TLS_AES_128_GCM_SHA256"] || !found["TLS_AES_256_GCM_SHA384"] || len(found) != 2 {
		t.Fatalf("strict cipher union=%v", found)
	}
}

func testNTLSIdentity(t testing.TB, name string) (*Config, *x509.Certificate) {
	t.Helper()
	caKey, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = asym.Close(caKey) })
	caName := x509.NewName().Add("CN", name+" CA")
	build := func(subject, issuer *x509.Name, serial int64, key, signer asym.PrivateKey, isCA bool, usage string) *x509.Certificate {
		cert := x509.NewCertificate()
		t.Cleanup(func() { _ = cert.Close() })
		pub := key.Public()
		for _, err := range []error{cert.SetVersion(2), cert.SetSerial(serial), cert.SetIssuer(issuer), cert.SetSubject(subject), cert.SetValidity(time.Now().Add(-time.Hour), time.Now().Add(time.Hour)), cert.SetPublicKey(pub), cert.AddBasicConstraints(isCA), cert.AddKeyUsage(usage)} {
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := cert.Sign(signer); err != nil {
			t.Fatal(err)
		}
		return cert
	}
	ca := build(caName, caName, 1, caKey, caKey, true, "critical,keyCertSign,cRLSign")
	signKey, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = asym.Close(signKey) })
	encKey, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = asym.Close(encKey) })
	subject := x509.NewName().Add("CN", name)
	sign := build(subject, caName, 2, signKey, caKey, false, "critical,digitalSignature")
	enc := build(subject, caName, 3, encKey, caKey, false, "critical,keyEncipherment,dataEncipherment,keyAgreement")
	return &Config{NTLS: true, SignCert: sign, SignKey: signKey, EncCert: enc, EncKey: encKey}, ca
}

// TestHandshakeVerificationNameDoesNotSetSNI 验证名称配置不隐式改变 SNI。
//
// TestHandshakeVerificationNameDoesNotSetSNI verifies verification names do not implicitly change SNI.
func TestHandshakeVerificationNameDoesNotSetSNI(t *testing.T) {
	sc := testServerConfig(t)
	c, s, ce, se := handshakePair(t, sc, &Config{Verification: VerifyStrict, RootCAs: []*x509.Certificate{sc.Cert}, VerificationName: "server.tongsuo-go.dev"})
	if ce != nil || se != nil {
		t.Fatalf("client=%v server=%v", ce, se)
	}
	if c.ConnectionState().ServerName != "" || s.ConnectionState().ServerName != "" {
		t.Fatal("verification name changed SNI")
	}
}

// TestHandshakeSNIExactCipherSelection 验证 SNI 配置精确替换套件集合。
//
// TestHandshakeSNIExactCipherSelection verifies SNI exactly replaces the suite set.
func TestHandshakeSNIExactCipherSelection(t *testing.T) {
	sc, _ := testChainIdentity(t, false)
	selected := sc.Clone()
	sc.CipherSuites = []string{"TLS_AES_128_GCM_SHA256"}
	sc.StrictConfig = true
	selected.CipherSuites = []string{"TLS_AES_256_GCM_SHA384"}
	selected.StrictConfig = true
	sc.GetConfigForClient = func(*ClientHelloInfo) (*Config, error) { return selected, nil }
	cc := &Config{Verification: VerifyNone, CipherSuites: []string{"TLS_AES_256_GCM_SHA384"}, StrictConfig: true, MinVersion: TLS1_3Version}
	c, _, ce, se := handshakePair(t, sc, cc)
	if ce != nil || se != nil {
		t.Fatalf("client=%v server=%v", ce, se)
	}
	if c.CipherName() != "TLS_AES_256_GCM_SHA384" {
		t.Fatal("SNI cipher restriction ignored")
	}
}

// TestHandshakeCredentialValidation 验证缺失、错误配对与已关闭证书被拒绝。
//
// TestHandshakeCredentialValidation verifies incomplete, mismatched and closed credentials are rejected.
func TestHandshakeCredentialValidation(t *testing.T) {
	identity := testServerConfig(t)
	other := testServerConfig(t)
	for name, cfg := range map[string]*Config{
		"missing-key":        {Cert: identity.Cert},
		"missing-leaf":       {Key: identity.Key},
		"mismatch":           {Cert: identity.Cert, Key: other.Key},
		"chain-without-leaf": {CertChain: []*x509.Certificate{identity.Cert}},
		"ntls-sign-mismatch": {NTLS: true, SignCert: identity.Cert, SignKey: other.Key},
		"ntls-enc-mismatch":  {NTLS: true, EncCert: identity.Cert, EncKey: other.Key},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, err := newContext(cfg, false)
			if err == nil {
				_ = ctx.Close()
				t.Fatal("invalid credentials accepted")
			}
		})
	}
	if err := identity.Cert.Close(); err != nil {
		t.Fatal(err)
	}
	if ctx, err := newContext(identity, false); err == nil {
		_ = ctx.Close()
		t.Fatal("closed certificate accepted")
	}
}

// TestHandshakeSNIGroupSelection 验证完整配置替换组限制并拒绝模糊重置。
//
// TestHandshakeSNIGroupSelection verifies group replacement and rejects ambiguous resets.
func TestHandshakeSNIGroupSelection(t *testing.T) {
	base, _ := testChainIdentity(t, false)
	selected := base.Clone()
	base.CurvePreferences = []string{"P-256"}
	selected.CurvePreferences = []string{"P-384"}
	base.GetConfigForClient = func(*ClientHelloInfo) (*Config, error) { return selected, nil }
	cc := &Config{Verification: VerifyNone, CurvePreferences: []string{"P-384"}, MinVersion: TLS1_3Version}
	c, _, ce, se := handshakePair(t, base, cc)
	if ce != nil || se != nil {
		t.Fatalf("client=%v server=%v", ce, se)
	}
	if got := c.ConnectionState().NegotiatedGroup; got != "secp384r1" && got != "P-384" {
		t.Fatalf("selected group=%q", got)
	}
	selected.CurvePreferences = nil
	if ctx, err := selectServerConfig(base, "", false); err == nil {
		_ = ctx.Close()
		t.Fatal("ambiguous group reset accepted")
	}
}

// TestHandshakeWriteTimeoutIsTerminal 验证已开始的写入超时不会复用另一调用的数据。
//
// TestHandshakeWriteTimeoutIsTerminal verifies a timed-out native write cannot reuse another call's data.
func TestHandshakeWriteTimeoutIsTerminal(t *testing.T) {
	c, s, ce, se := handshakePair(t, testServerConfig(t), &Config{Verification: VerifyNone})
	if ce != nil || se != nil {
		t.Fatalf("client=%v server=%v", ce, se)
	}
	if err := c.UnderlyingConn().(*net.TCPConn).SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
	if err := s.UnderlyingConn().(*net.TCPConn).SetReadBuffer(4096); err != nil {
		t.Fatal(err)
	}
	if err := c.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, err := c.Write(make([]byte, 8<<20))
	if n >= 8<<20 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write=%d err=%v", n, err)
	}
	if err := c.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if n, retry := c.Write([]byte("different")); n != 0 || !errors.Is(retry, os.ErrDeadlineExceeded) {
		t.Fatalf("retry=%d err=%v", n, retry)
	}
}

// TestHandshakeMixedTLSBounds 验证混合端口的 TLS 版本限制不阻断 NTLS。
//
// TestHandshakeMixedTLSBounds verifies TLS bounds on a mixed port do not block NTLS.
func TestHandshakeMixedTLSBounds(t *testing.T) {
	for _, callback := range []bool{false, true} {
		sc, _ := testNTLSIdentity(t, "ntls.example")
		identity, _ := testChainIdentity(t, false)
		sc.Protocol, sc.NTLS = ProtocolMixed, false
		sc.Cert, sc.Key, sc.CertChain = identity.Cert, identity.Key, identity.CertChain
		sc.MinVersion, sc.MaxVersion = TLS1_2Version, TLS1_2Version
		if callback {
			sc.GetConfigForClient = func(*ClientHelloInfo) (*Config, error) { return nil, nil }
		}
		for _, protocol := range []ProtocolMode{ProtocolTLS, ProtocolNTLS} {
			c, _, ce, se := handshakePair(t, sc, &Config{Protocol: protocol, Verification: VerifyNone})
			if ce != nil || se != nil {
				t.Fatalf("callback=%v protocol=%v client=%v server=%v", callback, protocol, ce, se)
			}
			want := TLS1_2Version
			if protocol == ProtocolNTLS {
				want = NTLSVersion
			}
			if c.ConnectionState().Version != want {
				t.Fatalf("version=%x want=%x", c.ConnectionState().Version, want)
			}
		}
	}
}

// TestNTLSIndependentIntermediateChains 验证双凭证的不同中间链均被发送并严格验证。
//
// TestNTLSIndependentIntermediateChains verifies both distinct intermediate chains are sent and strictly verified.
func TestNTLSIndependentIntermediateChains(t *testing.T) {
	makeKey := func() asym.PrivateKey {
		key, err := asym.GenerateSM2()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = asym.Close(key) })
		return key
	}
	build := func(subject, issuer string, serial int64, key, signer asym.PrivateKey, ca bool, usage string) *x509.Certificate {
		cert := x509.NewCertificate()
		t.Cleanup(func() { _ = cert.Close() })
		for _, err := range []error{cert.SetVersion(2), cert.SetSerial(serial), cert.SetSubject(x509.NewName().Add("CN", subject)), cert.SetIssuer(x509.NewName().Add("CN", issuer)), cert.SetValidity(time.Now().Add(-time.Hour), time.Now().Add(time.Hour)), cert.SetPublicKey(key.Public()), cert.AddBasicConstraints(ca), cert.AddKeyUsage(usage)} {
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := cert.Sign(signer); err != nil {
			t.Fatal(err)
		}
		return cert
	}
	rootKey, signIssuerKey, encIssuerKey, signKey, encKey := makeKey(), makeKey(), makeKey(), makeKey(), makeKey()
	root := build("root CA", "root CA", 100, rootKey, rootKey, true, "critical,keyCertSign,cRLSign")
	signIssuer := build("sign CA", "root CA", 101, signIssuerKey, rootKey, true, "critical,keyCertSign,cRLSign")
	encIssuer := build("enc CA", "root CA", 102, encIssuerKey, rootKey, true, "critical,keyCertSign,cRLSign")
	sign := build("chained.example", "sign CA", 103, signKey, signIssuerKey, false, "critical,digitalSignature")
	enc := build("chained.example", "enc CA", 104, encKey, encIssuerKey, false, "critical,keyEncipherment,dataEncipherment,keyAgreement")
	for _, suite := range []string{"ECC-SM2-SM4-GCM-SM3", "ECDHE-SM2-SM4-GCM-SM3"} {
		sc := &Config{Protocol: ProtocolNTLS, SignCert: sign, SignKey: signKey, EncCert: enc, EncKey: encKey, SignChain: []*x509.Certificate{signIssuer}, EncChain: []*x509.Certificate{encIssuer}, ClientAuth: RequireAndVerifyClientCert, ClientCAs: []*x509.Certificate{root}, CipherSuites: []string{suite}, StrictConfig: true}
		cc := sc.Clone()
		cc.ClientAuth = NoClientCert
		cc.Verification = VerifyStrict
		cc.RootCAs = []*x509.Certificate{root}
		cc.VerificationName = "chained.example"
		c, s, ce, se := handshakePair(t, sc, cc)
		if ce != nil || se != nil {
			t.Fatalf("suite=%s client=%v server=%v", suite, ce, se)
		}
		for _, conn := range []*Conn{c, s} {
			state := conn.ConnectionState()
			if state.Verification != VerificationPassed || len(state.PeerCertificates) != 4 {
				t.Fatalf("incomplete shared pool: %+v", state)
			}
			signChain, err := conn.PeerCertificates()
			if err != nil {
				t.Fatal(err)
			}
			encChain, err := conn.PeerEncCertificates()
			if err != nil {
				t.Fatal(err)
			}
			for _, chain := range [][]*x509.Certificate{signChain, encChain} {
				if len(chain) != 2 {
					t.Fatalf("chain length=%d want=2", len(chain))
				}
				for _, cert := range chain {
					_ = cert.Close()
				}
			}
		}
		cc.EncChain = nil
		_, _, ce, se = handshakePair(t, sc, cc)
		if ce == nil && se == nil {
			t.Fatal("missing client encryption intermediate accepted")
		}
	}
}
