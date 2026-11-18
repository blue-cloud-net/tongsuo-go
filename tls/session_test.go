package tls

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

type sessionPeer struct {
	conn *Conn
	err  error
}

func sessionEndpoint(t *testing.T, sc *Config) (string, func() sessionPeer) {
	t.Helper()
	server, err := NewServer(sc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	results := make(chan sessionPeer, 8)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				wrapped, err := server.Accept(raw)
				if err != nil {
					_ = raw.Close()
					results <- sessionPeer{err: err}
					return
				}
				c := wrapped.(*Conn)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				err = c.HandshakeContext(ctx)
				results <- sessionPeer{c, err}
			}()
		}
	}()
	return ln.Addr().String(), func() sessionPeer {
		select {
		case r := <-results:
			if r.conn != nil {
				t.Cleanup(func() { _ = r.conn.Close() })
			}
			return r
		case <-time.After(4 * time.Second):
			t.Fatal("server handshake timeout")
			return sessionPeer{}
		}
	}
}
func sessionDial(t *testing.T, addr string, cc *Config) (*Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, err := DialContext(ctx, "tcp", addr, cc)
	if err != nil {
		return nil, err
	}
	c := raw.(*Conn)
	t.Cleanup(func() { _ = c.Close() })
	return c, nil
}

// TestSessionProtocolMatrix 检查各协议实际恢复、票据等待与两个验证回调。
//
// TestSessionProtocolMatrix checks actual resumption, ticket waiting and both verification callbacks for each protocol.
func TestSessionProtocolMatrix(t *testing.T) {
	for _, protocol := range []string{"TLS12", "TLS13", "NTLS", "RFC8998-GCM", "RFC8998-CCM"} {
		t.Run(protocol, func(t *testing.T) {
			sc, root := testChainIdentity(t, false)
			cc := &Config{Verification: VerifyStrict, RootCAs: []*x509.Certificate{root}, VerificationName: "leaf.example"}
			switch protocol {
			case "TLS12":
				sc.MinVersion, sc.MaxVersion = TLS1_2Version, TLS1_2Version
				cc.MinVersion, cc.MaxVersion = TLS1_2Version, TLS1_2Version
			case "TLS13":
				sc.MinVersion, sc.MaxVersion = TLS1_3Version, TLS1_3Version
				cc.MinVersion, cc.MaxVersion = TLS1_3Version, TLS1_3Version
			case "NTLS":
				var ca *x509.Certificate
				sc, ca = testNTLSIdentity(t, "ntls.example")
				cc = &Config{NTLS: true, Verification: VerifyStrict, RootCAs: []*x509.Certificate{ca}, VerificationName: "ntls.example"}
			default:
				sc = rfc8998Identity(t)
				suite := "TLS_SM4_GCM_SM3"
				if protocol == "RFC8998-CCM" {
					suite = "TLS_SM4_CCM_SM3"
				}
				sc.CipherSuites = []string{suite}
				cc = &Config{RFC8998: true, CipherSuites: []string{suite}, Verification: VerifyStrict, RootCAs: []*x509.Certificate{sc.Cert}, VerificationName: "rfc8998.example"}
			}
			cache, err := NewSessionCache(4)
			if err != nil {
				t.Fatal(err)
			}
			cc.SessionCache = cache
			var peerCalls, connCalls atomic.Int32
			cc.VerifyPeerCertificate = func(peers [][]byte, chains [][][]byte) error {
				if len(peers) == 0 {
					return errors.New("missing resumed certificate")
				}
				peerCalls.Add(1)
				return nil
			}
			cc.VerifyConnection = func(state ConnectionState) error { connCalls.Add(1); return nil }
			addr, accept := sessionEndpoint(t, sc)
			for i := 0; i < 2; i++ {
				c, err := sessionDial(t, addr, cc)
				s := accept()
				if err != nil || s.err != nil {
					t.Fatalf("attempt %d: client=%v server=%v", i, err, s.err)
				}
				if c.ConnectionState().SessionReused != (i == 1) || s.conn.ConnectionState().SessionReused != (i == 1) {
					t.Fatalf("attempt %d reused client=%v server=%v", i, c.ConnectionState().SessionReused, s.conn.ConnectionState().SessionReused)
				}
				if _, err := s.conn.Write([]byte("ticket flush")); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				state, err := c.WaitSession(ctx)
				cancel()
				if err != nil {
					t.Fatalf("attempt %d wait: %v raw=%d", i, err, len(c.ssl.SessionDER()))
				}
				der, err := state.MarshalDER()
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := ParseSessionDER(der)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := ParseSessionDER(append(append([]byte(nil), der...), 0)); err == nil {
					t.Fatal("session DER trailing bytes accepted")
				}
				metadata := state.Metadata()
				if len(metadata.ID) > 0 {
					original := metadata.ID[0]
					metadata.ID[0] ^= 255
					if state.Metadata().ID[0] != original {
						t.Fatal("metadata shares mutable session ID")
					}
				}
				pem, err := decoded.MarshalPEM()
				if err != nil {
					t.Fatal(err)
				}
				if _, err = ParseSessionPEM(pem); err != nil {
					t.Fatal(err)
				}
				if !state.Metadata().Resumable {
					t.Fatal("session is not resumable")
				}
				_ = c.Close()
				_ = s.conn.Close()
			}
			if peerCalls.Load() != 2 || connCalls.Load() != 2 {
				t.Fatalf("callbacks peer=%d connection=%d", peerCalls.Load(), connCalls.Load())
			}
		})
	}
}

// TestSessionWaitCancellationAndData 检查无票据超时、取消和应用数据完整性。
//
// TestSessionWaitCancellationAndData checks ticketless timeout, cancellation and application data integrity.
func TestSessionWaitCancellationAndData(t *testing.T) {
	sc := testServerConfig(t)
	sc.MinVersion, sc.MaxVersion = TLS1_3Version, TLS1_3Version
	zero := 0
	sc.SessionTicketCount = &zero
	addr, accept := sessionEndpoint(t, sc)
	c, err := sessionDial(t, addr, &Config{})
	s := accept()
	if err != nil || s.err != nil {
		t.Fatalf("%v %v", err, s.err)
	}
	done := make(chan error, 1)
	go func() { _, err := s.conn.Write([]byte("retained application data")); done <- err }()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if _, err := c.WaitSession(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait=%v", err)
	}
	got := make([]byte, len("retained application data"))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "retained application data" {
		t.Fatalf("data=%q", got)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestSessionCacheAndEncoding 检查 LRU、过期、独立副本及损坏输入。
//
// TestSessionCacheAndEncoding checks LRU eviction, expiry, independent copies and malformed inputs.
func TestSessionCacheAndEncoding(t *testing.T) {
	if _, err := NewSessionCache(0); err == nil {
		t.Fatal("zero capacity accepted")
	}
	cache, _ := NewSessionCache(1)
	s := &SessionState{info: core.SessionInfo{Created: time.Now(), Expires: time.Now().Add(time.Hour), Resumable: true}}
	cache.Put("a", s)
	cache.Put("b", s)
	if _, ok := cache.Get("a"); ok {
		t.Fatal("LRU failed")
	}
	cache.Put("b", nil)
	if _, ok := cache.Get("b"); ok {
		t.Fatal("delete failed")
	}
	for _, data := range [][]byte{nil, []byte("invalid"), bytes.Repeat([]byte{1}, (1<<20)+1)} {
		if _, err := ParseSessionDER(data); err == nil {
			t.Fatal("invalid DER accepted")
		}
	}
	if _, err := ParseSessionPEM([]byte("invalid")); err == nil {
		t.Fatal("invalid PEM accepted")
	}
}

func receiveSession(t *testing.T, c, s *Conn) *SessionState {
	t.Helper()
	if _, err := s.Write([]byte("flush")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	state, err := c.WaitSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return state
}
func importSession(t *testing.T, s *SessionState) *SessionState {
	t.Helper()
	der, err := s.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	out, err := ParseSessionDER(der)
	if err != nil {
		t.Fatal(err)
	}
	out, err = out.WithPeerCertificates(s.peers)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestSessionRotationAndSharing 检查旧密钥过渡、移除、跨实例共享和服务端策略隔离。
//
// TestSessionRotationAndSharing checks old-key transition, removal, cross-instance sharing and server policy isolation.
func TestSessionRotationAndSharing(t *testing.T) {
	for _, version := range []uint16{TLS1_2Version, TLS1_3Version} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			sc, root := testChainIdentity(t, false)
			sc.MinVersion, sc.MaxVersion = version, version
			sc.SessionPolicyID = "shared-server-policy"
			manager, err := NewTicketKeyManager()
			if err != nil {
				t.Fatal(err)
			}
			old, err := GenerateTicketKey()
			if err != nil {
				t.Fatal(err)
			}
			fresh, err := GenerateTicketKey()
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.SetKeys([]TicketKey{old}); err != nil {
				t.Fatal(err)
			}
			sc.TicketKeys = manager
			cc := &Config{MinVersion: version, MaxVersion: version, Verification: VerifyStrict, RootCAs: []*x509.Certificate{root}, VerificationName: "leaf.example"}
			addr, accept := sessionEndpoint(t, sc)
			c, err := sessionDial(t, addr, cc)
			s := accept()
			if err != nil || s.err != nil {
				t.Fatalf("%v %v", err, s.err)
			}
			saved := importSession(t, receiveSession(t, c, s.conn))
			_ = c.Close()
			_ = s.conn.Close()
			if err := manager.SetKeys([]TicketKey{fresh, old}); err != nil {
				t.Fatal(err)
			}
			for _, scenario := range []string{"old-key", "shared-server", "removed-key", "policy-change"} {
				cc.Session = saved
				useAddr, useAccept := addr, accept
				if scenario == "shared-server" {
					useAddr, useAccept = sessionEndpoint(t, sc.Clone())
				}
				if scenario == "removed-key" {
					if err := manager.SetKeys([]TicketKey{fresh}); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "policy-change" {
					other := sc.Clone()
					other.SessionPolicyID = "different-policy"
					useAddr, useAccept = sessionEndpoint(t, other)
				}
				c, err := sessionDial(t, useAddr, cc)
				s := useAccept()
				if err != nil || s.err != nil {
					t.Fatalf("%s: %v %v", scenario, err, s.err)
				}
				want := scenario == "old-key" || scenario == "shared-server"
				if c.ConnectionState().SessionReused != want || s.conn.ConnectionState().SessionReused != want {
					t.Fatalf("%s reused client=%v server=%v", scenario, c.ConnectionState().SessionReused, s.conn.ConnectionState().SessionReused)
				}
				_ = c.Close()
				_ = s.conn.Close()
			}
		})
	}
}

// TestSessionStatefulAndIsolation 检查有状态缓存、配置实例隔离、回调拒绝与名称变化。
//
// TestSessionStatefulAndIsolation checks stateful caching, configuration instance isolation, callback rejection and name changes.
func TestSessionStatefulAndIsolation(t *testing.T) {
	sc, root := testChainIdentity(t, false)
	sc.MinVersion, sc.MaxVersion = TLS1_2Version, TLS1_2Version
	sc.SessionTicketsDisabled = true
	cache, _ := NewSessionCache(8)
	cc := &Config{MinVersion: TLS1_2Version, MaxVersion: TLS1_2Version, SessionCache: cache, SessionTicketsDisabled: true, Verification: VerifyStrict, RootCAs: []*x509.Certificate{root}, VerificationName: "leaf.example"}
	var reject atomic.Bool
	rejection := errors.New("session rejected by application")
	cc.VerifyConnection = func(st ConnectionState) error {
		if reject.Load() && st.SessionReused {
			return rejection
		}
		return nil
	}
	addr, accept := sessionEndpoint(t, sc)
	c, err := sessionDial(t, addr, cc)
	s := accept()
	if err != nil || s.err != nil {
		t.Fatalf("%v %v", err, s.err)
	}
	saved := receiveSession(t, c, s.conn)
	if saved.Metadata().HasTicket {
		t.Fatal("ticket emitted when disabled")
	}
	_ = c.Close()
	_ = s.conn.Close()
	c, err = sessionDial(t, addr, cc)
	s = accept()
	if err != nil || s.err != nil {
		t.Fatalf("%v %v", err, s.err)
	}
	if !c.ConnectionState().SessionReused {
		t.Fatal("stateful cache not used")
	}
	_ = c.Close()
	_ = s.conn.Close()
	other := cc.Clone()
	c, err = sessionDial(t, addr, other)
	s = accept()
	if err != nil || s.err != nil {
		t.Fatalf("%v %v", err, s.err)
	}
	if c.ConnectionState().SessionReused {
		t.Fatal("cache crossed config instances")
	}
	_ = c.Close()
	_ = s.conn.Close()
	// Importing is explicit; strict verification still rejects a wrong target name.
	other.Session = importSession(t, saved)
	other.VerificationName = "wrong.example"
	c, err = sessionDial(t, addr, other)
	s = accept()
	if err == nil {
		t.Fatal("wrong resumed hostname accepted")
	}
	if c != nil {
		_ = c.Close()
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	reject.Store(true)
	_, err = sessionDial(t, addr, cc)
	s = accept()
	if !errors.Is(err, rejection) {
		t.Fatalf("callback rejection lost: %v", err)
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

// TestSessionMutualAuthentication 检查恢复后双方证书链验证与回调。
//
// TestSessionMutualAuthentication checks both peer chains and callbacks after mutual-authentication resumption.
func TestSessionMutualAuthentication(t *testing.T) {
	for _, version := range []uint16{TLS1_2Version, TLS1_3Version} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			sc, serverRoot := testChainIdentity(t, false)
			id, clientRoot := testChainIdentity(t, false)
			sc.MinVersion, sc.MaxVersion = version, version
			sc.ClientAuth = RequireAndVerifyClientCert
			sc.ClientCAs = []*x509.Certificate{clientRoot}
			var serverCalls atomic.Int32
			sc.VerifyPeerCertificate = func(peers [][]byte, chains [][][]byte) error {
				if len(chains) == 0 || len(chains[0]) != 3 {
					return errors.New("missing verified client chain")
				}
				serverCalls.Add(1)
				return nil
			}
			cache, _ := NewSessionCache(4)
			cc := &Config{MinVersion: version, MaxVersion: version, Cert: id.Cert, Key: id.Key, CertChain: id.CertChain, RootCAs: []*x509.Certificate{serverRoot}, Verification: VerifyStrict, VerificationName: "leaf.example", SessionCache: cache}
			addr, accept := sessionEndpoint(t, sc)
			for i := 0; i < 2; i++ {
				c, err := sessionDial(t, addr, cc)
				s := accept()
				if err != nil || s.err != nil {
					t.Fatalf("attempt %d %v %v", i, err, s.err)
				}
				if c.ConnectionState().SessionReused != (i == 1) {
					t.Fatal("incorrect reuse")
				}
				receiveSession(t, c, s.conn)
				_ = c.Close()
				_ = s.conn.Close()
			}
			if serverCalls.Load() != 2 {
				t.Fatalf("server callback count=%d", serverCalls.Load())
			}
		})
	}
}

// TestTicketKeyValidationAndRotation 检查密钥环校验、自动轮换和保留期限。
//
// TestTicketKeyValidationAndRotation checks key-ring validation, automatic rotation and retention.
func TestTicketKeyValidationAndRotation(t *testing.T) {
	m, err := NewTicketKeyManager()
	if err != nil {
		t.Fatal(err)
	}
	old, _ := m.selectKey(nil, true)
	m.created = time.Now().Add(-25 * time.Hour)
	m.ages[0] = m.created
	fresh, status := m.selectKey(nil, true)
	if status != 1 || bytes.Equal(old, fresh) {
		t.Fatal("automatic rotation failed")
	}
	if _, status := m.selectKey(old[:16], false); status != 2 {
		t.Fatal("old key not retained for renewal")
	}
	m.ages[len(m.ages)-1] = time.Now().Add(-8 * 24 * time.Hour)
	if _, status := m.selectKey(old[:16], false); status != 0 {
		t.Fatal("expired key retained")
	}
	if err := m.SetKeys(nil); err == nil {
		t.Fatal("empty ring accepted")
	}
	var key TicketKey
	if err := m.SetKeys([]TicketKey{key, key}); err == nil {
		t.Fatal("duplicate name accepted")
	}
}

// TestSessionNationalRotationAndIsolation 验证国密协议的票据轮换与服务身份隔离。
//
// TestSessionNationalRotationAndIsolation verifies ticket rotation and service identity isolation for national-crypto protocols.
func TestSessionNationalRotationAndIsolation(t *testing.T) {
	for _, protocol := range []string{"NTLS", "RFC8998-GCM", "RFC8998-CCM"} {
		t.Run(protocol, func(t *testing.T) {
			var sc, cc *Config
			if protocol == "NTLS" {
				var root *x509.Certificate
				sc, root = testNTLSIdentity(t, "ntls.example")
				cc = &Config{NTLS: true, Verification: VerifyStrict, RootCAs: []*x509.Certificate{root}, VerificationName: "ntls.example", ServerName: "service.example"}
			} else {
				sc = rfc8998Identity(t)
				suite := "TLS_SM4_GCM_SM3"
				if protocol == "RFC8998-CCM" {
					suite = "TLS_SM4_CCM_SM3"
				}
				sc.CipherSuites = []string{suite}
				cc = &Config{RFC8998: true, CipherSuites: []string{suite}, RootCAs: []*x509.Certificate{sc.Cert}, Verification: VerifyStrict, VerificationName: "rfc8998.example", ServerName: "service.example"}
			}
			manager, err := NewTicketKeyManager()
			if err != nil {
				t.Fatal(err)
			}
			old, err := GenerateTicketKey()
			if err != nil {
				t.Fatal(err)
			}
			fresh, err := GenerateTicketKey()
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.SetKeys([]TicketKey{old}); err != nil {
				t.Fatal(err)
			}
			sc.TicketKeys = manager
			addr, accept := sessionEndpoint(t, sc)
			c, err := sessionDial(t, addr, cc)
			s := accept()
			if err != nil || s.err != nil {
				t.Fatalf("%v %v", err, s.err)
			}
			saved := importSession(t, receiveSession(t, c, s.conn))
			_ = c.Close()
			_ = s.conn.Close()
			if err := manager.SetKeys([]TicketKey{fresh, old}); err != nil {
				t.Fatal(err)
			}
			for _, scenario := range []string{"rotated", "other-sni", "removed"} {
				other := cc.Clone()
				other.Session = saved
				if scenario == "other-sni" {
					other.ServerName = "other.example"
				}
				if scenario == "removed" {
					if err := manager.SetKeys([]TicketKey{fresh}); err != nil {
						t.Fatal(err)
					}
				}
				c, err := sessionDial(t, addr, other)
				s := accept()
				if err != nil || s.err != nil {
					t.Fatalf("%s: %v %v", scenario, err, s.err)
				}
				if c.ConnectionState().SessionReused != (scenario == "rotated") {
					t.Fatalf("%s reuse=%v", scenario, c.ConnectionState().SessionReused)
				}
				_ = c.Close()
				_ = s.conn.Close()
			}
		})
	}
}

// TestSessionMixedPort 检查同端口 TLS/NTLS 的独立缓存与恢复。
//
// TestSessionMixedPort checks independent TLS/NTLS caching and resumption on one port.
func TestSessionMixedPort(t *testing.T) {
	sc, ntlsRoot := testNTLSIdentity(t, "ntls.example")
	id, tlsRoot := testChainIdentity(t, false)
	sc.Protocol, sc.NTLS = ProtocolMixed, false
	sc.Cert, sc.Key, sc.CertChain = id.Cert, id.Key, id.CertChain
	cache, _ := NewSessionCache(8)
	clients := []*Config{{MinVersion: TLS1_2Version, MaxVersion: TLS1_2Version, SessionCache: cache, Verification: VerifyStrict, RootCAs: []*x509.Certificate{tlsRoot}, VerificationName: "leaf.example"}, {NTLS: true, SessionCache: cache, Verification: VerifyStrict, RootCAs: []*x509.Certificate{ntlsRoot}, VerificationName: "ntls.example"}}
	addr, accept := sessionEndpoint(t, sc)
	for i := 0; i < 2; i++ {
		for _, cc := range clients {
			c, err := sessionDial(t, addr, cc)
			s := accept()
			if err != nil || s.err != nil {
				t.Fatalf("%v %v", err, s.err)
			}
			if c.ConnectionState().SessionReused != (i == 1) {
				t.Fatalf("attempt %d ntls=%v reused=%v", i, cc.NTLS, c.ConnectionState().SessionReused)
			}
			receiveSession(t, c, s.conn)
			_ = c.Close()
			_ = s.conn.Close()
		}
	}
}

// TestSessionCacheKeyBoundaries 检查字符串边界与公开配置克隆的隔离。
//
// TestSessionCacheKeyBoundaries checks string boundaries and public configuration clone isolation.
func TestSessionCacheKeyBoundaries(t *testing.T) {
	cfg := &Config{SessionPolicyID: "shared", NextProtos: []string{"a b"}}
	a, err := sessionDomain(cfg, "endpoint")
	if err != nil {
		t.Fatal(err)
	}
	other := cfg.Clone()
	other.NextProtos = []string{"a", "b"}
	b, err := sessionDomain(other, "endpoint")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("ambiguous protocol list cache key")
	}
	cfg.SessionPolicyID = ""
	a, err = sessionDomain(cfg.cloneRuntime(), "endpoint")
	if err != nil {
		t.Fatal(err)
	}
	b, err = sessionDomain(cfg.Clone().cloneRuntime(), "endpoint")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("public clone retained isolation domain")
	}
}

// TestSessionWaitDeadlinesAndClose 检查等待读锁、读取期限和关闭的有界退出。
//
// TestSessionWaitDeadlinesAndClose checks bounded exit while waiting for readers, read deadlines and Close.
func TestSessionWaitDeadlinesAndClose(t *testing.T) {
	for _, mode := range []string{"reader", "deadline", "close"} {
		t.Run(mode, func(t *testing.T) {
			sc := testServerConfig(t)
			sc.MinVersion, sc.MaxVersion = TLS1_3Version, TLS1_3Version
			zero := 0
			sc.SessionTicketCount = &zero
			addr, accept := sessionEndpoint(t, sc)
			c, err := sessionDial(t, addr, &Config{})
			s := accept()
			if err != nil || s.err != nil {
				t.Fatalf("%v %v", err, s.err)
			}
			if mode == "reader" {
				started := make(chan struct{})
				reader := make(chan error, 1)
				go func() { close(started); _, err := c.Read(make([]byte, 1)); reader <- err }()
				<-started
				// Taking the same lock ensures the cancellation path cannot wait indefinitely.
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
				defer cancel()
				if _, err := c.WaitSession(ctx); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("wait=%v", err)
				}
				_ = c.Close()
				select {
				case <-reader:
				case <-time.After(time.Second):
					t.Fatal("reader did not exit after Close")
				}
			} else if mode == "deadline" {
				if err := c.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				_, err := c.WaitSession(context.Background())
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatalf("deadline=%v", err)
				}
				if err := c.SetReadDeadline(time.Time{}); err != nil {
					t.Fatal(err)
				}
				if _, err := s.conn.Write([]byte{7}); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 1)
				if _, err := io.ReadFull(c, buf); err != nil || buf[0] != 7 {
					t.Fatalf("read after timeout: %v %v", buf, err)
				}
			} else {
				done := make(chan error, 1)
				go func() { _, err := c.WaitSession(context.Background()); done <- err }()
				_ = c.Close()
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("closed wait succeeded")
					}
				case <-time.After(time.Second):
					t.Fatal("wait did not exit after Close")
				}
			}
		})
	}
}

// TestSessionWaitBufferLimit 检查等待上限不会丢失已读应用数据。
//
// TestSessionWaitBufferLimit checks that the waiting buffer limit does not lose consumed application data.
func TestSessionWaitBufferLimit(t *testing.T) {
	sc := testServerConfig(t)
	sc.MinVersion, sc.MaxVersion = TLS1_3Version, TLS1_3Version
	zero := 0
	sc.SessionTicketCount = &zero
	addr, accept := sessionEndpoint(t, sc)
	c, err := sessionDial(t, addr, &Config{})
	s := accept()
	if err != nil || s.err != nil {
		t.Fatalf("%v %v", err, s.err)
	}
	data := bytes.Repeat([]byte("x"), 65537)
	written := make(chan error, 1)
	go func() { _, err := s.conn.Write(data); written <- err }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := c.WaitSession(ctx); err == nil || !strings.Contains(err.Error(), "buffer limit") {
		t.Fatalf("wait=%v", err)
	}
	got := make([]byte, len(data))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("buffer limit lost application data")
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

// TestSessionTicketCount 检查 TLS 1.3 显式多张票据与参数冲突。
//
// TestSessionTicketCount checks explicit multiple TLS 1.3 tickets and configuration conflicts.
func TestSessionTicketCount(t *testing.T) {
	sc := testServerConfig(t)
	sc.MinVersion, sc.MaxVersion = TLS1_3Version, TLS1_3Version
	count := 3
	sc.SessionTicketCount = &count
	var received atomic.Int32
	cc := &Config{Diagnostics: &DiagnosticsConfig{OnEvent: func(event HandshakeEvent) error {
		if event.Kind == "message" && !event.Write && event.ContentType == 22 && len(event.Data) > 0 && event.Data[0] == 4 {
			received.Add(1)
		}
		return nil
	}}}
	addr, accept := sessionEndpoint(t, sc)
	c, err := sessionDial(t, addr, cc)
	s := accept()
	if err != nil || s.err != nil {
		t.Fatalf("%v %v", err, s.err)
	}
	receiveSession(t, c, s.conn)
	// Read the application marker, driving any remaining queued tickets first.
	marker := make([]byte, 5)
	if _, err := io.ReadFull(c, marker); err != nil {
		t.Fatal(err)
	}
	if received.Load() != 3 {
		t.Fatalf("ticket count=%d", received.Load())
	}
	negative := -1
	tooMany := 17
	positive := 1
	for _, cfg := range []*Config{{SessionTicketCount: &negative}, {SessionTicketCount: &tooMany}, {SessionTicketsDisabled: true, SessionTicketCount: &positive}} {
		if err := validateConfig(cfg, false); err == nil {
			t.Fatal("invalid ticket configuration accepted")
		}
	}
}

// TestSessionCacheConcurrency 检查共享缓存和显式密钥更新的并发访问。
//
// TestSessionCacheConcurrency checks concurrent shared-cache access and explicit key updates.
func TestSessionCacheConcurrency(t *testing.T) {
	cache, _ := NewSessionCache(8)
	manager, err := NewTicketKeyManager()
	if err != nil {
		t.Fatal(err)
	}
	key, err := GenerateTicketKey()
	if err != nil {
		t.Fatal(err)
	}
	state := &SessionState{info: core.SessionInfo{Expires: time.Now().Add(time.Hour), Resumable: true}}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			name := fmt.Sprint(i)
			for j := 0; j < 30; j++ {
				cache.Put(name, state)
				cache.Get(name)
				if j%2 == 0 {
					if err := manager.SetKeys([]TicketKey{key}); err != nil {
						t.Error(err)
					}
				} else {
					manager.selectKey(key[:16], false)
				}
			}
		}(i)
	}
	workers.Wait()
	expired := copySession(state)
	expired.info.Expires = time.Now().Add(-time.Second)
	cache.Put("expired", expired)
	if _, ok := cache.Get("expired"); ok {
		t.Fatal("expired entry returned")
	}
}

// TestSessionNTLSEncryptionCertificateExpiry 检查恢复后仍验证加密证书有效期。
//
// TestSessionNTLSEncryptionCertificateExpiry checks that resumption still validates encryption-certificate expiry.
func TestSessionNTLSEncryptionCertificateExpiry(t *testing.T) {
	generate := func() asym.PrivateKey {
		key, err := asym.GenerateSM2()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = asym.Close(key) })
		return key
	}
	caKey, signKey, encKey := generate(), generate(), generate()
	expires := time.Now().Add(2 * time.Second).Truncate(time.Second)
	build := func(cn, issuer string, key, signer asym.PrivateKey, serial int64, ca bool, usage string, end time.Time) *x509.Certificate {
		cert := x509.NewCertificate()
		t.Cleanup(func() { _ = cert.Close() })
		pub := key.Public()
		for _, err := range []error{cert.SetVersion(2), cert.SetSerial(serial), cert.SetSubject(x509.NewName().Add("CN", cn)), cert.SetIssuer(x509.NewName().Add("CN", issuer)), cert.SetValidity(time.Now().Add(-time.Hour), end), cert.SetPublicKey(pub), cert.AddBasicConstraints(ca), cert.AddKeyUsage(usage), cert.Sign(signer)} {
			if err != nil {
				t.Fatal(err)
			}
		}
		return cert
	}
	root := build("root.example", "root.example", caKey, caKey, 1, true, "critical,keyCertSign,cRLSign", time.Now().Add(time.Hour))
	sign := build("ntls.example", "root.example", signKey, caKey, 2, false, "critical,digitalSignature", time.Now().Add(time.Hour))
	enc := build("ntls.example", "root.example", encKey, caKey, 3, false, "critical,keyEncipherment,dataEncipherment,keyAgreement", expires)
	sc := &Config{NTLS: true, SignCert: sign, SignKey: signKey, EncCert: enc, EncKey: encKey}
	cache, _ := NewSessionCache(4)
	cc := &Config{NTLS: true, Verification: VerifyStrict, RootCAs: []*x509.Certificate{root}, VerificationName: "ntls.example", SessionCache: cache}
	addr, accept := sessionEndpoint(t, sc)
	c, err := sessionDial(t, addr, cc)
	s := accept()
	if err != nil || s.err != nil {
		t.Fatalf("initial %v %v", err, s.err)
	}
	receiveSession(t, c, s.conn)
	_ = c.Close()
	_ = s.conn.Close()
	time.Sleep(time.Until(expires.Add(50 * time.Millisecond)))
	_, err = sessionDial(t, addr, cc)
	s = accept()
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected encryption-certificate expiry rejection, got %v", err)
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

// TestSessionNationalMutualAuthentication 检查国密双向认证恢复后仍有双方身份材料。
//
// TestSessionNationalMutualAuthentication checks both peers retain identity material after national-crypto mutual-authentication resumption.
func TestSessionNationalMutualAuthentication(t *testing.T) {
	for _, protocol := range []string{"NTLS", "RFC8998"} {
		t.Run(protocol, func(t *testing.T) {
			var sc, cc *Config
			if protocol == "NTLS" {
				var serverRoot, clientRoot *x509.Certificate
				sc, serverRoot = testNTLSIdentity(t, "server.example")
				cc, clientRoot = testNTLSIdentity(t, "client.example")
				cc.RootCAs = []*x509.Certificate{serverRoot}
				cc.VerificationName = "server.example"
				sc.ClientCAs = []*x509.Certificate{clientRoot}
			} else {
				sc = rfc8998Identity(t)
				cc = rfc8998Identity(t)
				cc.RootCAs = []*x509.Certificate{sc.Cert}
				cc.VerificationName = "rfc8998.example"
				sc.ClientCAs = []*x509.Certificate{cc.Cert}
			}
			sc.ClientAuth = RequireAndVerifyClientCert
			cc.Verification = VerifyStrict
			cache, _ := NewSessionCache(4)
			cc.SessionCache = cache
			var serverCalls atomic.Int32
			sc.VerifyConnection = func(st ConnectionState) error {
				if protocol == "NTLS" && len(st.PeerCertificates) < 2 {
					return errors.New("missing resumed client encryption certificate")
				}
				if st.Verification != VerificationPassed || len(st.PeerCertificates) == 0 || len(st.VerifiedChains) == 0 {
					return errors.New("missing resumed client identity")
				}
				serverCalls.Add(1)
				return nil
			}
			addr, accept := sessionEndpoint(t, sc)
			for i := 0; i < 2; i++ {
				c, err := sessionDial(t, addr, cc)
				s := accept()
				if err != nil || s.err != nil {
					t.Fatalf("attempt %d: %v %v", i, err, s.err)
				}
				if c.ConnectionState().SessionReused != (i == 1) {
					t.Fatalf("attempt %d reuse=%v", i, c.ConnectionState().SessionReused)
				}
				receiveSession(t, c, s.conn)
				_ = c.Close()
				_ = s.conn.Close()
			}
			if serverCalls.Load() != 2 {
				t.Fatalf("server callbacks=%d", serverCalls.Load())
			}
		})
	}
}

// TestSessionClientIdentityIsolation 检查显式共享策略与缓存时仍隔离不同客户端凭证。
//
// TestSessionClientIdentityIsolation checks different client credentials remain isolated with an explicitly shared policy and cache.
func TestSessionClientIdentityIsolation(t *testing.T) {
	for _, version := range []uint16{TLS1_2Version, TLS1_3Version} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			sc, serverRoot := testChainIdentity(t, false)
			first, firstRoot := testChainIdentity(t, false)
			second, _ := testChainIdentity(t, false)
			secondCert, err := x509.CreateSelfSigned(x509.NewName().Add("CN", "client-b.example"), 8, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), second.Key.Public(), second.Key)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = secondCert.Close() })
			second.Cert, second.CertChain = secondCert, nil
			secondRoot := secondCert
			sc.MinVersion, sc.MaxVersion = version, version
			sc.ClientAuth = RequireAndVerifyClientCert
			sc.ClientCAs = []*x509.Certificate{firstRoot, secondRoot}
			cache, _ := NewSessionCache(4)
			a := &Config{MinVersion: version, MaxVersion: version, SessionPolicyID: "same-policy", SessionCache: cache, Cert: first.Cert, Key: first.Key, CertChain: first.CertChain, RootCAs: []*x509.Certificate{serverRoot}, Verification: VerifyStrict, VerificationName: "leaf.example"}
			b := a.Clone()
			b.Cert, b.Key, b.CertChain = second.Cert, second.Key, second.CertChain
			addr, accept := sessionEndpoint(t, sc)
			for i, cc := range []*Config{a, a, b, b} {
				c, err := sessionDial(t, addr, cc)
				s := accept()
				if err != nil || s.err != nil {
					t.Fatalf("attempt %d: %v %v", i, err, s.err)
				}
				if c.ConnectionState().SessionReused != (i%2 == 1) {
					t.Fatalf("attempt %d reused=%v", i, c.ConnectionState().SessionReused)
				}
				want, err := cc.Cert.MarshalDER()
				if err != nil {
					t.Fatal(err)
				}
				got := s.conn.ConnectionState().PeerCertificates
				if len(got) == 0 || !bytes.Equal(got[0], want) {
					t.Fatal("server observed wrong client identity")
				}
				receiveSession(t, c, s.conn)
				_ = c.Close()
				_ = s.conn.Close()
			}
		})
	}
}

// TestSessionRevalidationDiagnostics 检查恢复验证事件在握手结束前派发，且消费者错误中止握手。
//
// TestSessionRevalidationDiagnostics checks resumed verification events precede handshake completion and consumer errors abort the handshake.
func TestSessionRevalidationDiagnostics(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprint(reject), func(t *testing.T) {
			sc, root := testChainIdentity(t, false)
			sc.MinVersion, sc.MaxVersion = TLS1_3Version, TLS1_3Version
			cache, _ := NewSessionCache(4)
			var resumed atomic.Bool
			var lastVerify, verifyCallback, ended uint64
			failure := errors.New("resumed verification diagnostic rejected")
			cc := &Config{SessionCache: cache, Verification: VerifyStrict, RootCAs: []*x509.Certificate{root}, VerificationName: "leaf.example", Diagnostics: &DiagnosticsConfig{OnEvent: func(e HandshakeEvent) error {
				if resumed.Load() {
					switch e.Kind {
					case "verify":
						lastVerify = e.Sequence
						if reject {
							return failure
						}
					case "verify_callback":
						verifyCallback = e.Sequence
					case "end":
						ended = e.Sequence
					}
				}
				return nil
			}}, VerifyConnection: func(ConnectionState) error { return nil }}
			addr, accept := sessionEndpoint(t, sc)
			c, err := sessionDial(t, addr, cc)
			s := accept()
			if err != nil || s.err != nil {
				t.Fatalf("initial %v %v", err, s.err)
			}
			receiveSession(t, c, s.conn)
			_ = c.Close()
			_ = s.conn.Close()
			resumed.Store(true)
			c, err = sessionDial(t, addr, cc)
			s = accept()
			if reject {
				if !errors.Is(err, failure) {
					t.Fatalf("diagnostic error not propagated during handshake: %v", err)
				}
			} else {
				if err != nil || s.err != nil {
					t.Fatalf("resume %v %v", err, s.err)
				}
				if lastVerify == 0 || verifyCallback <= lastVerify || ended <= verifyCallback {
					t.Fatalf("event order verify=%d callback=%d end=%d", lastVerify, verifyCallback, ended)
				}
			}
			if c != nil {
				_ = c.Close()
			}
			if s.conn != nil {
				_ = s.conn.Close()
			}
		})
	}
}

// TestSessionConfigurationScopeConcurrency 检查同配置并发初始化保持同域，公开克隆生成新域。
//
// TestSessionConfigurationScopeConcurrency checks concurrent initialization shares one domain while public clones obtain fresh domains.
func TestSessionConfigurationScopeConcurrency(t *testing.T) {
	cfg := &Config{}
	keys := make(chan string, 32)
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			key, err := sessionDomain(cfg.cloneRuntime(), "service:443")
			if err != nil {
				t.Error(err)
				return
			}
			keys <- key
		}()
	}
	workers.Wait()
	close(keys)
	first := ""
	for key := range keys {
		if first == "" {
			first = key
		}
		if key != first {
			t.Fatal("concurrent initialization split the configuration domain")
		}
	}
	if first == "" {
		t.Fatal("scope initialization failed")
	}
	other, err := sessionDomain(cfg.Clone().cloneRuntime(), "service:443")
	if err != nil {
		t.Fatal(err)
	}
	if first == other {
		t.Fatal("public clone reused the original domain")
	}
}
