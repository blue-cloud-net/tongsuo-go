package core

import (
	"errors"
	"strings"
	"testing"
)

// TestNewOpErrorWithCode 验证 NewOpError 填充 Op/Code/Msg。
func TestNewOpErrorWithCode(t *testing.T) {
	const op = "test: dummy op"
	const code = uint64(0xdeadbeef)
	e := NewOpError(op, code)
	if e.Op != op {
		t.Fatalf("Op: got %q want %q", e.Op, op)
	}
	if e.Code != code {
		t.Fatalf("Code: got %#x want %#x", e.Code, code)
	}
	if e.Msg == "" {
		t.Fatal("Msg should be non-empty (ERR_error_string_n produces a message for any code)")
	}
}

// TestOpErrorString 验证 Error() 输出格式。
func TestOpErrorString(t *testing.T) {
	e := &OpError{Op: "sm4: encrypt", Code: 0x1234, Msg: "bad data"}
	got := e.Error()
	want := "sm4: encrypt: tongsuo error 0x1234 (bad data)"
	if got != want {
		t.Fatalf("Error(): got %q want %q", got, want)
	}
}

// TestOpErrorStringNoMsg 验证 Msg 为空时的回退格式。
func TestOpErrorStringNoMsg(t *testing.T) {
	e := &OpError{Op: "sm4: encrypt", Code: 0x1234}
	got := e.Error()
	want := "sm4: encrypt: tongsuo error 0x1234"
	if got != want {
		t.Fatalf("Error() no-Msg: got %q want %q", got, want)
	}
}

// TestOpErrorUnwrapChain 验证 errors.Is / errors.As 能穿透 OpError.Unwrap。
func TestOpErrorUnwrapChain(t *testing.T) {
	sentinel := errors.New("sentinel")
	e := NewOpError("test: chain", 0x42)
	e.Err = sentinel

	// errors.Is 应能找到 sentinel。
	if !errors.Is(e, sentinel) {
		t.Fatal("errors.Is should find sentinel through OpError.Unwrap")
	}

	// errors.As 应能提取 *OpError。
	var asOp *OpError
	if !errors.As(e, &asOp) {
		t.Fatal("errors.As should extract *OpError")
	}
	if asOp.Op != "test: chain" {
		t.Fatalf("As: Op got %q want %q", asOp.Op, "test: chain")
	}
}

// TestOpErrorUnwrapNil 验证 e.Err 为 nil 时错误链终止于 OpError。
func TestOpErrorUnwrapNil(t *testing.T) {
	e := NewOpError("test: nil-unwrap", 0x99)
	if err := e.Unwrap(); err != nil {
		t.Fatalf("Unwrap() should return nil when Err is nil, got %v", err)
	}
	if errors.Unwrap(e) != nil {
		t.Fatal("errors.Unwrap should return nil when Err is nil")
	}
}

// TestOpErrorImplementsError 验证 *OpError 实现 error 接口。
func TestOpErrorImplementsError(t *testing.T) {
	var _ error = (*OpError)(nil)
	var e error = NewOpError("test: iface", 0)
	if !strings.Contains(e.Error(), "test: iface") {
		t.Fatalf("Error() should contain op: %q", e.Error())
	}
}
