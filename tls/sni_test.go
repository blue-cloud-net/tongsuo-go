package tls

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	ttx509 "github.com/blue-cloud-net/tongsuo-go/x509"
)

// 回归测试：客户端必须发送 SNI（server_name 扩展）。
//
// 背景（2026-09-11 实测发现）：在引入本测试之前，DialContext 只在**开启对端
// 验证**时才推导主机名，且只调 SSL_set1_host（校验用），从未调
// SSL_set_tlsext_host_name（SNI）。后果：
//   - VERIFY_NONE（InsecureSkipVerify=true，诊断/探针类工具的必用配置）
//     → ClientHello 无 SNI；
//   - 绝大多数真实站点（CDN / 虚拟主机 / 多证书部署）直接回
//     `sslv3 alert handshake failure`（alert 40），握手在验证之前就失败。
//
// 判别证据：`openssl s_client -connect example.com:443 -noservername` 复现同一
// alert，加 `-servername` 则正常 ⇒ SNI 是**路由**信息，必须与验证模式解耦。
//
// These tests lock the SNI behaviour: SNI must be sent regardless of whether
// peer verification is enabled.

// sniRecordingServer 是记录了 ClientHello.ServerName 的本地 stdlib TLS 服务端。
type sniRecordingServer struct {
	srv *httptest.Server

	mu  sync.Mutex
	sni string
}

func (s *sniRecordingServer) addr() string { return s.srv.Listener.Addr().String() }

func (s *sniRecordingServer) sniOf() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sni
}

// waitSNI 轮询等待服务端记录到 SNI（GetConfigForClient 在握手过程中被调用）。
func (s *sniRecordingServer) waitSNI(d time.Duration) string {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if v := s.sniOf(); v != "" {
			return v
		}
		time.Sleep(20 * time.Millisecond)
	}
	return s.sniOf()
}

// certPEM 返回服务端自签证书的 PEM（用作可信任根，以便构造"验证开启"的用例）。
func (s *sniRecordingServer) certPEM(t *testing.T) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.srv.Certificate().Raw})
}

func newSNIRecordingServer(t *testing.T) *sniRecordingServer {
	t.Helper()

	s := &sniRecordingServer{}
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	s.srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			s.mu.Lock()
			s.sni = hi.ServerName
			s.mu.Unlock()
			return nil, nil
		},
	}
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	return s
}

// TestDialContextSendsSNI_VerifyNone 核心场景：InsecureSkipVerify=true
// （VERIFY_NONE）时**仍然**发送 SNI —— 这正是修复前失效的路径。
func TestDialContextSendsSNI_VerifyNone(t *testing.T) {
	s := newSNIRecordingServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := DialContext(ctx, "tcp", s.addr(), &Config{
		ServerName:         "probe.example.test",
		InsecureSkipVerify: true, // 与 ittools ssl-check 探针一致
	})
	if err != nil {
		t.Fatalf("DialContext 失败：%v", err)
	}
	defer func() { _ = conn.Close() }()

	if got := s.waitSNI(2 * time.Second); got != "probe.example.test" {
		t.Fatalf("ClientHello.ServerName = %q，期望 %q（SNI 未发送）", got, "probe.example.test")
	}
}

// TestDialContextSendsSNI_VerifyPeer 开启对端验证（PEER）时同样发送 SNI。
//
// 用服务端自签证书作为唯一信任根，使握手能走到验证阶段；
// 主机名不匹配导致的验证失败不影响"SNI 已发出"这一断言。
func TestDialContextSendsSNI_VerifyPeer(t *testing.T) {
	s := newSNIRecordingServer(t)

	root, err := ttx509.LoadCertificatePEM(s.certPEM(t))
	if err != nil {
		t.Fatalf("加载服务端证书失败：%v", err)
	}
	defer func() { _ = root.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 预期可能因主机名不匹配而报验证错，或（无 SNI 检查时）成功——都不影响断言。
	conn, _ := DialContext(ctx, "tcp", s.addr(), &Config{
		ServerName: "verify.example.test",
		RootCAs:    []*ttx509.Certificate{root},
	})
	if conn != nil {
		_ = conn.Close()
	}

	if got := s.waitSNI(2 * time.Second); got != "verify.example.test" {
		t.Fatalf("ClientHello.ServerName = %q，期望 %q（SNI 未发送）", got, "verify.example.test")
	}
}

// TestDialContextNoSNIForIPLiteral IP 字面量不作为 SNI 发送
// （RFC 6066 §3：SNI 只允许 DNS 主机名）。
func TestDialContextNoSNIForIPLiteral(t *testing.T) {
	s := newSNIRecordingServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := DialContext(ctx, "tcp", s.addr(), &Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("IP 字面量拨号应成功：%v", err)
	}
	defer func() { _ = conn.Close() }()

	// s.addr() 形如 "127.0.0.1:port"：host 为 IP 字面量 → 不发 SNI。
	time.Sleep(200 * time.Millisecond)
	if got := s.sniOf(); got != "" {
		t.Fatalf("IP 字面量不应发送 SNI，实际 %q", got)
	}
}

// TestSetServerNameRejectsClosedConn 已关闭连接上 SetServerName 应报错（守卫 API 语义）。
func TestSetServerNameRejectsClosedConn(t *testing.T) {
	s := newSNIRecordingServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := DialContext(ctx, "tcp", s.addr(), &Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("DialContext 失败：%v", err)
	}
	tc, ok := conn.(*Conn)
	if !ok {
		t.Fatalf("DialContext 应返回 *Conn，实际 %T", conn)
	}
	_ = tc.Close()
	if serr := tc.ssl.SetServerName("example.test"); serr == nil {
		t.Fatal("已关闭连接上 SetServerName 应返回错误")
	}
}
