package tls

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

func rfc8998Identity(t *testing.T) *Config {
	t.Helper()
	key, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = asym.Close(key) })
	cert, err := x509.CreateSelfSigned(x509.NewName().Add("CN", "rfc8998.example"), 1, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cert.Close() })
	return &Config{RFC8998: true, Cert: cert, Key: key}
}

// TestRFC8998RoundTrip 验证两个套件、双向认证与诊断输出。
//
// TestRFC8998RoundTrip checks both suites, mutual authentication and diagnostics.
func TestRFC8998RoundTrip(t *testing.T) {
	for _, suite := range []string{"TLS_SM4_GCM_SM3", "TLS_SM4_CCM_SM3"} {
		for _, mutual := range []bool{false, true} {
			name := suite
			if mutual {
				name += "/mutual"
			}
			t.Run(name, func(t *testing.T) {
				sc := rfc8998Identity(t)
				sc.CipherSuites = []string{suite}
				cc := &Config{RFC8998: true, CipherSuites: []string{suite}, Verification: VerifyStrict, RootCAs: []*x509.Certificate{sc.Cert}, VerificationName: "rfc8998.example", CaptureSCT: true}
				if mutual {
					id := rfc8998Identity(t)
					cc.Cert, cc.Key = id.Cert, id.Key
					sc.ClientAuth = RequireAndVerifyClientCert
					sc.ClientCAs = []*x509.Certificate{id.Cert}
					sc.Verification = VerifyStrict
				}
				var events []HandshakeEvent
				var trace, keylog bytes.Buffer
				cc.Diagnostics = &DiagnosticsConfig{OnEvent: func(e HandshakeEvent) error { events = append(events, e); return nil }, TraceWriter: &trace, KeyLogWriter: &keylog}
				c, s, ce, se := handshakePair(t, sc, cc)
				if ce != nil || se != nil {
					t.Fatalf("client=%v server=%v", ce, se)
				}
				st := c.ConnectionState()
				if st.Version != 0x0304 || st.CipherName != suite || st.NegotiatedGroup != "SM2" && st.NegotiatedGroup != "curveSM2" || !st.HandshakeComplete || st.Verification != VerificationPassed {
					t.Fatalf("state=%+v", st)
				}
				expectedID := uint16(0x00c6)
				if suite == "TLS_SM4_CCM_SM3" {
					expectedID = 0x00c7
				}
				if st.CipherSuite != expectedID {
					t.Fatalf("wire cipher ID=%x", st.CipherSuite)
				}
				// SSL_get_peer_signature_nid reports the digest NID; verify the wire scheme below.
				if st.PeerSignatureAlgorithm != "SM3" {
					t.Fatalf("peer signature state=%q", st.PeerSignatureAlgorithm)
				}
				if len(st.SignedCertificateTimestamps) != 0 || st.SecureRenegotiation {
					t.Fatal("unexpected SCT or renegotiation")
				}
				if trace.Len() == 0 || keylog.Len() == 0 {
					t.Fatal("missing explicit diagnostic output")
				}
				lines := strings.Split(strings.TrimSpace(keylog.String()), "\n")
				for _, line := range lines {
					if len(strings.Fields(line)) != 3 {
						t.Fatal("invalid keylog format")
					}
				}
				starts, ends, messages := 0, 0, 0
				receivedVerify, sentVerify := false, false
				for i, e := range events {
					if e.Sequence != uint64(i+1) {
						t.Fatal("event sequence")
					}
					switch e.Kind {
					case "start":
						starts++
					case "end":
						ends++
						if e.Err != nil {
							t.Fatal(e.Err)
						}
					case "message":
						messages++
						if e.ContentType == 22 && len(e.Data) >= 6 && e.Data[0] == 15 {
							if e.Data[4] != 0x07 || e.Data[5] != 0x08 {
								t.Fatalf("non-SM2 CertificateVerify scheme: %x", e.Data[4:6])
							}
							if e.Write {
								sentVerify = true
							} else {
								receivedVerify = true
							}
						}
					}
				}
				if !receivedVerify || mutual && !sentVerify {
					t.Fatal("missing SM2 CertificateVerify")
				}
				if starts != 1 || ends != 1 || messages == 0 {
					t.Fatalf("start=%d end=%d messages=%d", starts, ends, messages)
				}
				payload := []byte("RFC 8998 payload")
				done := make(chan error, 1)
				go func() { _, err := s.Write(payload); done <- err }()
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				got := make([]byte, len(payload))
				_, err := io.ReadFull(c, got)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("round trip: %v", err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// TestRFC8998RejectConflicts 验证严格配置拒绝冲突且不修改源配置。
//
// TestRFC8998RejectConflicts verifies conflict rejection without mutating source configurations.
func TestRFC8998RejectConflicts(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Config)
	}{
		{"ntls", func(c *Config) { c.NTLS = true }}, {"mixed", func(c *Config) { c.Protocol = ProtocolMixed }},
		{"version", func(c *Config) { c.MinVersion = 0x0303 }}, {"cipher", func(c *Config) { c.CipherSuites = []string{"TLS_AES_128_GCM_SHA256"} }},
		{"group", func(c *Config) { c.CurvePreferences = []string{"P-256"} }}, {"signature", func(c *Config) { c.SignatureAlgorithms = []string{"rsa_pss_rsae_sha256"} }},
		{"limits", func(c *Config) { c.Diagnostics = &DiagnosticsConfig{MaxBytes: -1} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{RFC8998: true}
			tc.change(cfg)
			if err := validateConfig(cfg, true); err == nil {
				t.Fatal("conflict accepted")
			}
		})
	}
	cfg := &Config{RFC8998: true}
	ctx, err := newContext(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	_ = ctx.Close()
	if cfg.MinVersion != 0 || len(cfg.CipherSuites) != 0 {
		t.Fatal("source mutated")
	}
	base := &Config{RFC8998: true, GetConfigForClient: func(*ClientHelloInfo) (*Config, error) { return &Config{}, nil }}
	if _, err := selectServerConfig(base, "x", false); err == nil {
		t.Fatal("SNI downgrade accepted")
	}
}

type failingDiagnosticWriter struct {
	err   error
	short bool
}

func (w failingDiagnosticWriter) Write(p []byte) (int, error) {
	if w.short {
		return 0, nil
	}
	return 0, w.err
}

// TestDiagnosticFailures 验证输出错误、短写与超限中断连接并保留原始错误。
//
// TestDiagnosticFailures checks output errors, short writes and limits abort connections and retain causes.
func TestDiagnosticFailures(t *testing.T) {
	sentinel := errors.New("consumer failed")
	for _, kind := range []string{"event", "trace", "keylog", "short", "limit", "count"} {
		t.Run(kind, func(t *testing.T) {
			sc := testServerConfig(t)
			d := &DiagnosticsConfig{}
			want := sentinel
			switch kind {
			case "event":
				d.OnEvent = func(e HandshakeEvent) error {
					if e.Kind == "message" {
						return sentinel
					}
					return nil
				}
			case "trace":
				d.TraceWriter = failingDiagnosticWriter{err: sentinel}
			case "keylog":
				d.KeyLogWriter = failingDiagnosticWriter{err: sentinel}
			case "short":
				d.TraceWriter = failingDiagnosticWriter{short: true}
				want = io.ErrShortWrite
			case "count":
				d.OnEvent = func(HandshakeEvent) error { return nil }
				d.MaxEvents = 1
				want = ErrDiagnosticLimit
			case "limit":
				d.OnEvent = func(HandshakeEvent) error { return nil }
				d.MaxBytes = 1
				want = ErrDiagnosticLimit
			}
			_, _, ce, _ := handshakePair(t, sc, &Config{Verification: VerifyNone, Diagnostics: d})
			if !errors.Is(ce, want) {
				t.Fatalf("got %v, want %v", ce, want)
			}
		})
	}
}

// TestDiagnosticFailedVerification 验证失败握手仍交付验证与结束事件。
//
// TestDiagnosticFailedVerification checks failed handshakes still deliver verification and completion events.
func TestDiagnosticFailedVerification(t *testing.T) {
	sc := testServerConfig(t)
	var events []HandshakeEvent
	_, _, ce, _ := handshakePair(t, sc, &Config{Verification: VerifyStrict, Diagnostics: &DiagnosticsConfig{OnEvent: func(e HandshakeEvent) error { events = append(events, e); return nil }}})
	if ce == nil {
		t.Fatal("untrusted certificate accepted")
	}
	verified, ended := false, false
	for _, e := range events {
		if e.Kind == "verify" && e.Code != 0 {
			verified = true
		}
		if e.Kind == "end" && e.Err != nil {
			ended = true
		}
	}
	if !verified || !ended {
		t.Fatal("missing failure diagnostics")
	}
}

// TestDiagnosticContextCancellation 验证取消错误仍可识别。
//
// TestDiagnosticContextCancellation verifies cancellation remains identifiable.
func TestDiagnosticContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DialContext(ctx, "tcp", "127.0.0.1:1", &Config{RFC8998: true})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// TestRFC8998SNI 验证 SNI 严格配置切换与诊断连续性。
//
// TestRFC8998SNI checks strict SNI switching and diagnostic continuity.
func TestRFC8998SNI(t *testing.T) {
	base := rfc8998Identity(t)
	var serverEvents []HandshakeEvent
	var serverTrace, serverKeylog bytes.Buffer
	base.Diagnostics = &DiagnosticsConfig{OnEvent: func(e HandshakeEvent) error { serverEvents = append(serverEvents, e); return nil }, TraceWriter: &serverTrace, KeyLogWriter: &serverKeylog}
	selected := rfc8998Identity(t)
	selected.CipherSuites = []string{"TLS_SM4_CCM_SM3"}
	base.GetConfigForClient = func(info *ClientHelloInfo) (*Config, error) {
		if info.ServerName != "route.example" {
			return nil, errors.New("wrong SNI")
		}
		return selected, nil
	}
	var events []HandshakeEvent
	cc := &Config{RFC8998: true, ServerName: "route.example", VerificationName: "rfc8998.example", Verification: VerifyStrict, RootCAs: []*x509.Certificate{selected.Cert}, Diagnostics: &DiagnosticsConfig{OnEvent: func(e HandshakeEvent) error { events = append(events, e); return nil }}}
	c, _, ce, se := handshakePair(t, base, cc)
	if ce != nil || se != nil {
		t.Fatalf("client=%v server=%v", ce, se)
	}
	if len(serverEvents) == 0 || serverTrace.Len() == 0 || serverKeylog.Len() == 0 {
		t.Fatal("SNI lost base diagnostics")
	}
	for i, e := range serverEvents {
		if e.Sequence != uint64(i+1) {
			t.Fatal("server SNI diagnostic sequence")
		}
	}
	if c.ConnectionState().CipherName != "TLS_SM4_CCM_SM3" {
		t.Fatal("selected cipher not enforced")
	}
	for i, e := range events {
		if e.Sequence != uint64(i+1) {
			t.Fatal("diagnostic sequence interrupted")
		}
	}
}

// TestRFC8998RejectCertificate 验证证书算法、用途及密钥配对限制。
//
// TestRFC8998RejectCertificate checks certificate algorithms, usage and key matching.
func TestRFC8998RejectCertificate(t *testing.T) {
	t.Run("algorithm", func(t *testing.T) {
		cfg, _ := testChainIdentity(t, false)
		cfg.RFC8998 = true
		if _, err := NewServer(cfg); err == nil {
			t.Fatal("non-SM2 credentials accepted")
		}
	})
	t.Run("key-mismatch", func(t *testing.T) {
		cfg, other := rfc8998Identity(t), rfc8998Identity(t)
		cfg.Key = other.Key
		if _, err := NewServer(cfg); err == nil {
			t.Fatal("mismatched signing key accepted")
		}
	})
	t.Run("key-usage", func(t *testing.T) {
		cfg := rfc8998Identity(t)
		cert := x509.NewCertificate()
		t.Cleanup(func() { _ = cert.Close() })
		subject := x509.NewName().Add("CN", "non-signing.example")
		pub := cfg.Key.Public()
		defer asym.Close(pub)
		for _, err := range []error{cert.SetVersion(2), cert.SetSerial(2), cert.SetIssuer(subject), cert.SetSubject(subject), cert.SetValidity(time.Now().Add(-time.Hour), time.Now().Add(time.Hour)), cert.SetPublicKey(pub), cert.AddKeyUsage("critical,keyEncipherment")} {
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := cert.Sign(cfg.Key); err != nil {
			t.Fatal(err)
		}
		cfg.Cert = cert
		if _, err := NewServer(cfg); err == nil {
			t.Fatal("non-signing certificate accepted")
		}
	})
}

// TestDiagnosticFailureSnapshot 验证结束回调失败保留协商状态并禁止后续 I/O。
//
// TestDiagnosticFailureSnapshot verifies completion callback failures preserve negotiated state and reject subsequent I/O.
func TestDiagnosticFailureSnapshot(t *testing.T) {
	sentinel := errors.New("end callback failed")
	sc := testServerConfig(t)
	sc.Diagnostics = &DiagnosticsConfig{OnEvent: func(e HandshakeEvent) error {
		if e.Kind == "end" {
			return sentinel
		}
		return nil
	}}
	_, s, _, se := handshakePair(t, sc, &Config{Verification: VerifyNone})
	if !errors.Is(se, sentinel) {
		t.Fatalf("error=%v", se)
	}
	state := s.ConnectionState()
	if state.HandshakeComplete || state.CipherSuite == 0 {
		t.Fatalf("lost failed-handshake snapshot: %+v", state)
	}
	if _, err := s.Write([]byte("forbidden")); !errors.Is(err, sentinel) {
		t.Fatalf("subsequent I/O error=%v", err)
	}
}
