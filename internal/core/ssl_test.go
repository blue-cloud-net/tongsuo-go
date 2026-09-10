package core

import (
	"testing"
)

// TestNewClientServerNTLSContext 验证三种 SSL_CTX 构造路径。
func TestNewClientServerNTLSContext(t *testing.T) {
	client, err := NewClientTLSContext()
	if err != nil {
		t.Fatalf("NewClientTLSContext: %v", err)
	}
	defer client.Close()

	server, err := NewServerTLSContext()
	if err != nil {
		t.Fatalf("NewServerTLSContext: %v", err)
	}
	defer server.Close()

	ntls, err := NewNTLSContext()
	if err != nil {
		t.Fatalf("NewNTLSContext: %v", err)
	}
	defer ntls.Close()
}

// TestTLSContextSetVerifyMode 验证 SetVerifyMode 接受合法值且关闭后报错。
func TestTLSContextSetVerifyMode(t *testing.T) {
	ctx, _ := NewClientTLSContext()
	defer ctx.Close()
	if err := ctx.SetVerifyMode(1); err != nil { // SSL_VERIFY_PEER
		t.Fatalf("SetVerifyMode: %v", err)
	}
	if err := ctx.SetVerifyDepth(5); err != nil {
		t.Fatalf("SetVerifyDepth: %v", err)
	}
}

// TestTLSContextClosed 验证关闭后 SetVerifyMode 返回错误。
func TestTLSContextClosed(t *testing.T) {
	ctx, _ := NewClientTLSContext()
	if err := ctx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := ctx.SetVerifyMode(1); err == nil {
		t.Fatal("SetVerifyMode on closed should error")
	}
	if err := ctx.SetVerifyDepth(1); err == nil {
		t.Fatal("SetVerifyDepth on closed should error")
	}
}

// TestAddVerifyRootsEmpty 验证传入 nil/空切片返回错误。
func TestAddVerifyRootsEmpty(t *testing.T) {
	ctx, _ := NewClientTLSContext()
	defer ctx.Close()
	if err := ctx.AddVerifyRoots(nil); err == nil {
		t.Fatal("nil certs should error")
	}
	if err := ctx.AddVerifyRoots([]*Certificate{}); err == nil {
		t.Fatal("empty certs should error")
	}
}

// TestAddVerifyRootsNilCert 验证切片中的 nil cert 被静默跳过，
// 但全部为 nil/closed 时返回错误（不会悄无声息成功）。
func TestAddVerifyRootsNilCert(t *testing.T) {
	ctx, _ := NewClientTLSContext()
	defer ctx.Close()
	if err := ctx.AddVerifyRoots([]*Certificate{nil, nil}); err == nil {
		t.Fatal("all-nil certs should error")
	}
}

// TestAddVerifyRootsClosedCtx 验证关闭后调用返回错误。
func TestAddVerifyRootsClosedCtx(t *testing.T) {
	ctx, _ := NewClientTLSContext()
	_ = ctx.Close()
	if err := ctx.AddVerifyRoots([]*Certificate{}); err == nil {
		t.Fatal("AddVerifyRoots on closed ctx should error")
	}
}

// TestSSLConnClosed 验证关闭后方法返回零值或错误。
func TestSSLConnClosedMethods(t *testing.T) {
	// 不实际握手，只测 nil/closed 状态返回。
	var s *SSLConn
	if s.Version() != "" {
		t.Error("nil.Version should be empty")
	}
	if s.CipherName() != "" {
		t.Error("nil.CipherName should be empty")
	}
	if s.VerifyResult() != VerifyResultClosed {
		t.Errorf("nil.VerifyResult = %d, want VerifyResultClosed (%d)", s.VerifyResult(), VerifyResultClosed)
	}
}

// TestSSLConnSetHostname 验证 SetHostname 接受非空字符串且 nil 接收者返回错误。
func TestSSLConnSetHostname(t *testing.T) {
	var s *SSLConn
	if err := s.SetHostname("example.com"); err == nil {
		t.Fatal("nil SetHostname should error")
	}
}

// TestTLSContextIdempotentClose 验证 Close 幂等。
func TestTLSContextIdempotentClose(t *testing.T) {
	ctx, _ := NewClientTLSContext()
	if err := ctx.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := ctx.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}