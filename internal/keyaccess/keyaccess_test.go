package keyaccess

import (
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// 编译期断言：*core.PKey 与 pkeyHolder 形态均被识别。
//
// Compile-time guard: both *core.PKey (direct) and the pkeyHolder shape
// (via interface satisfaction) must be accepted by PKey.
var (
	_ = func() any {
		var v any = &core.PKey{}
		_, _ = PKey(v)
		return nil
	}
)

// fakeHolder 用于测试 pkeyHolder 形状的 happy path。
//
// fakeHolder is a minimal pkeyHolder implementation used by the happy
// path test.
type fakeHolder struct {
	k *core.PKey
}

func (f *fakeHolder) Key() *core.PKey { return f.k }

// TestPKey_NilReceiver 验证 nil 输入不 panic、返回 (nil, false)。
func TestPKey_NilReceiver(t *testing.T) {
	got, ok := PKey(nil)
	if ok {
		t.Errorf("PKey(nil) ok = true, want false")
	}
	if got != nil {
		t.Errorf("PKey(nil) got = %v, want nil", got)
	}
}

// TestPKey_DirectCorePKey 验证 *core.PKey 输入走快路径。
func TestPKey_DirectCorePKey(t *testing.T) {
	k := &core.PKey{}
	defer k.Close()

	got, ok := PKey(k)
	if !ok {
		t.Fatal("PKey(*core.PKey) ok = false, want true")
	}
	if got != k {
		t.Errorf("PKey returned %p, want %p", got, k)
	}
}

// TestPKey_HolderShape 验证实现 pkeyHolder 形状的对象被识别。
func TestPKey_HolderShape(t *testing.T) {
	k := &core.PKey{}
	defer k.Close()

	got, ok := PKey(&fakeHolder{k: k})
	if !ok {
		t.Fatal("PKey(fakeHolder) ok = false, want true")
	}
	if got != k {
		t.Errorf("PKey returned %p, want %p", got, k)
	}
}

// TestPKey_UnsupportedType 验证不持原生句柄的类型返回 (nil, false) 而非 panic。
func TestPKey_UnsupportedType(t *testing.T) {
	for _, v := range []any{
		"string",
		42,
		struct{}{},
		[]byte{1, 2, 3},
	} {
		got, ok := PKey(v)
		if ok {
			t.Errorf("PKey(%T) ok = true, want false", v)
		}
		if got != nil {
			t.Errorf("PKey(%T) got = %v, want nil", v, got)
		}
	}
}
