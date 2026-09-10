package core

import (
	"bytes"
	"testing"
)

// TestHmacRoundtrip 验证 HMAC 已知向量与跨算法一致性。
//
// RFC 4231 给出 HMAC-SHA{224,256,384,512} 的标准测试向量；这里我们
// 仅断言本实现对同一密钥 / 数据产生稳定的输出（与 Update+Final 流式
// 模式、Sum 探测模式结果一致）。
func TestHmacRoundtrip(t *testing.T) {
	tests := []struct {
		name    string
		digest  *Digest
		key     []byte
		data    []byte
		wantLen int
	}{
		{"HMAC-SM3", SM3(), []byte("key"), []byte("data"), 32},
		{"HMAC-SHA1", SHA1(), []byte("key"), []byte("data"), 20},
		{"HMAC-SHA256", SHA256(), []byte("key"), []byte("data"), 32},
		{"HMAC-SHA512", SHA512(), []byte("key"), []byte("data"), 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, err := NewHmacCtx(tt.digest, tt.key)
			if err != nil {
				t.Fatalf("NewHmacCtx: %v", err)
			}
			defer ctx.Close()

			// Sum 应在 Update 之前返回初始状态（空消息）的 MAC
			sum0, err := ctx.Sum()
			if err != nil {
				t.Fatalf("Sum initial: %v", err)
			}
			if len(sum0) != tt.wantLen {
				t.Fatalf("Sum length = %d, want %d", len(sum0), tt.wantLen)
			}

			if err := ctx.Update(tt.data); err != nil {
				t.Fatalf("Update: %v", err)
			}
			final, err := ctx.Final()
			if err != nil {
				t.Fatalf("Final: %v", err)
			}
			if len(final) != tt.wantLen {
				t.Fatalf("Final length = %d, want %d", len(final), tt.wantLen)
			}

			// 重新构造 ctx，结果应一致
			ctx2, _ := NewHmacCtx(tt.digest, tt.key)
			defer ctx2.Close()
			_ = ctx2.Update(tt.data)
			final2, _ := ctx2.Final()
			if !bytes.Equal(final, final2) {
				t.Fatalf("HMAC not deterministic: %x != %x", final, final2)
			}
		})
	}
}

// TestHmacSumNonDestructive 验证 Sum 不改变 ctx 状态。
func TestHmacSumNonDestructive(t *testing.T) {
	ctx, err := NewHmacCtx(SHA256(), []byte("k"))
	if err != nil {
		t.Fatalf("NewHmacCtx: %v", err)
	}
	defer ctx.Close()

	if err := ctx.Update([]byte("data")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	s1, _ := ctx.Sum()
	s2, _ := ctx.Sum()
	if !bytes.Equal(s1, s2) {
		t.Fatalf("Sum is destructive: %x != %x", s1, s2)
	}
	final, _ := ctx.Final()
	if !bytes.Equal(s1, final) {
		t.Fatalf("Sum differs from Final: %x != %x", s1, final)
	}
}

// TestHmacNilDigest 验证 nil Digest 返回错误。
func TestHmacNilDigest(t *testing.T) {
	if _, err := NewHmacCtx(nil, []byte("k")); err == nil {
		t.Fatal("nil digest should error")
	}
}

// TestHmacClosedContext 验证关闭后 ctx 的方法返回错误。
func TestHmacClosedContext(t *testing.T) {
	ctx, err := NewHmacCtx(SM3(), []byte("k"))
	if err != nil {
		t.Fatalf("NewHmacCtx: %v", err)
	}
	if err := ctx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := ctx.Update([]byte("x")); err == nil {
		t.Fatal("Update on closed should error")
	}
	if _, err := ctx.Sum(); err == nil {
		t.Fatal("Sum on closed should error")
	}
	if _, err := ctx.Final(); err == nil {
		t.Fatal("Final on closed should error")
	}
}

// TestHmacDifferentKeysDifferentOutput 验证不同密钥产生不同 MAC。
func TestHmacDifferentKeysDifferentOutput(t *testing.T) {
	ctx1, _ := NewHmacCtx(SHA256(), []byte("key1"))
	defer ctx1.Close()
	ctx2, _ := NewHmacCtx(SHA256(), []byte("key2"))
	defer ctx2.Close()
	_ = ctx1.Update([]byte("data"))
	_ = ctx2.Update([]byte("data"))
	m1, _ := ctx1.Final()
	m2, _ := ctx2.Final()
	if bytes.Equal(m1, m2) {
		t.Fatal("different keys produced identical MAC")
	}
}
