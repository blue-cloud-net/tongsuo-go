package core

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestMACFetchUnknown 验证未知 MAC 算法名返回错误。
//
// TestMACFetchUnknown verifies that an unknown MAC algorithm name is
// rejected.
func TestMACFetchUnknown(t *testing.T) {
	if _, err := MACFetch("NO-SUCH-MAC"); err == nil {
		t.Fatal("MACFetch: expected error for unknown algorithm")
	}
	if _, err := MACFetch(""); err == nil {
		t.Fatal("MACFetch: expected error for empty algorithm name")
	}
}

// TestMACCtxFamilies 验证 CMAC / HMAC / KMAC / Poly1305 / SipHash / EIA3
// 各家族能构造上下文并产出长度正确的标签。
//
// TestMACCtxFamilies verifies that the CMAC, HMAC, KMAC, Poly1305, SipHash
// and EIA3 families build a context and produce a tag of the expected
// length.
func TestMACCtxFamilies(t *testing.T) {
	key16 := bytes.Repeat([]byte{0x0b}, 16)
	key32 := bytes.Repeat([]byte{0x0b}, 32)
	tests := []struct {
		name    string
		alg     string
		key     []byte
		opts    *MACOptions
		wantLen int
	}{
		{"CMAC-SM4", "CMAC", key16, &MACOptions{Cipher: "SM4"}, 16},
		{"CMAC-AES128", "CMAC", key16, &MACOptions{Cipher: "AES-128-CBC"}, 16},
		{"GMAC-AES128", "GMAC", key16, &MACOptions{Cipher: "AES-128-GCM", IV: bytes.Repeat([]byte{0x01}, 12)}, 16},
		{"HMAC-SM3", "HMAC", key16, &MACOptions{Digest: "SM3"}, 32},
		{"KMAC-128", "KMAC-128", key32, &MACOptions{OutputLen: 32, Custom: []byte("c")}, 32},
		{"KMAC-256", "KMAC-256", key32, &MACOptions{OutputLen: 32, Custom: []byte("c")}, 32},
		{"POLY1305", "POLY1305", key32, nil, 16},
		{"SIPHASH", "SIPHASH", key16, &MACOptions{OutputLen: 8}, 8},
		{"EIA3", "EIA3", key16, &MACOptions{IV: bytes.Repeat([]byte{0x02}, 5)}, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := MACFetch(tt.alg)
			if err != nil {
				t.Fatalf("MACFetch(%s): %v", tt.alg, err)
			}
			defer m.Close()
			ctx, err := NewMACCtx(m, tt.key, tt.opts)
			if err != nil {
				t.Fatalf("NewMACCtx(%s): %v", tt.alg, err)
			}
			defer ctx.Close()
			if ctx.Size() != tt.wantLen {
				t.Fatalf("Size = %d, want %d", ctx.Size(), tt.wantLen)
			}
			if err := ctx.Update([]byte("hello world")); err != nil {
				t.Fatalf("Update: %v", err)
			}
			tag, err := ctx.Final()
			if err != nil {
				t.Fatalf("Final: %v", err)
			}
			if len(tag) != tt.wantLen {
				t.Fatalf("tag length = %d, want %d", len(tag), tt.wantLen)
			}
			if bytes.Equal(tag, make([]byte, len(tag))) {
				t.Fatal("tag is all zero")
			}
		})
	}
}

// TestMACCtxSumIsNonDestructive 验证 Sum 不改变上下文状态，
// Final 仍能给出与 Sum 相同的结果。
//
// TestMACCtxSumIsNonDestructive verifies that Sum does not mutate the
// context state and that Final still yields the same result afterwards.
func TestMACCtxSumIsNonDestructive(t *testing.T) {
	m, err := MACFetch("HMAC")
	if err != nil {
		t.Fatalf("MACFetch: %v", err)
	}
	defer m.Close()
	ctx, err := NewMACCtx(m, []byte("key"), &MACOptions{Digest: "SHA256"})
	if err != nil {
		t.Fatalf("NewMACCtx: %v", err)
	}
	defer ctx.Close()
	if err := ctx.Update([]byte("data")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	sum, err := ctx.Sum()
	if err != nil {
		t.Fatalf("Sum: %v", err)
	}
	final, err := ctx.Final()
	if err != nil {
		t.Fatalf("Final: %v", err)
	}
	if !bytes.Equal(sum, final) {
		t.Fatalf("Sum %x != Final %x", sum, final)
	}
}

// TestMACCtxReset 验证 Reset 后上下文可复用且结果与新建上下文一致。
//
// TestMACCtxReset verifies that a reset context can be reused and yields
// the same result as a freshly created one.
func TestMACCtxReset(t *testing.T) {
	m, err := MACFetch("HMAC")
	if err != nil {
		t.Fatalf("MACFetch: %v", err)
	}
	defer m.Close()
	ctx, err := NewMACCtx(m, []byte("key"), &MACOptions{Digest: "SHA256"})
	if err != nil {
		t.Fatalf("NewMACCtx: %v", err)
	}
	defer ctx.Close()
	if err := ctx.Update([]byte("first")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := ctx.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if err := ctx.Update([]byte("second")); err != nil {
		t.Fatalf("Update after reset: %v", err)
	}
	got, err := ctx.Final()
	if err != nil {
		t.Fatalf("Final: %v", err)
	}
	m2, _ := MACFetch("HMAC")
	defer m2.Close()
	ctx2, err := NewMACCtx(m2, []byte("key"), &MACOptions{Digest: "SHA256"})
	if err != nil {
		t.Fatalf("NewMACCtx: %v", err)
	}
	defer ctx2.Close()
	_ = ctx2.Update([]byte("second"))
	want, err := ctx2.Final()
	if err != nil {
		t.Fatalf("Final: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("after Reset got %x, want %x", got, want)
	}
}

// TestMACCtxClosed 验证上下文关闭后操作返回明确错误。
//
// TestMACCtxClosed verifies that operations on a closed context report a
// clear error.
func TestMACCtxClosed(t *testing.T) {
	m, err := MACFetch("HMAC")
	if err != nil {
		t.Fatalf("MACFetch: %v", err)
	}
	defer m.Close()
	ctx, err := NewMACCtx(m, []byte("key"), &MACOptions{Digest: "SHA256"})
	if err != nil {
		t.Fatalf("NewMACCtx: %v", err)
	}
	if err := ctx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close 必须幂等。
	if err := ctx.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := ctx.Update([]byte("x")); err == nil {
		t.Fatal("Update after Close: expected error")
	}
	if _, err := ctx.Final(); err == nil {
		t.Fatal("Final after Close: expected error")
	}
	if _, err := ctx.Sum(); err == nil {
		t.Fatal("Sum after Close: expected error")
	}
	if err := ctx.Reset(); err == nil {
		t.Fatal("Reset after Close: expected error")
	}
}

// TestMACPoly1305KnownVector 验证 Poly1305 对 RFC 8439 §2.5.2 的标准向量。
//
// TestMACPoly1305KnownVector verifies Poly1305 against the RFC 8439
// section 2.5.2 test vector.
func TestMACPoly1305KnownVector(t *testing.T) {
	key, err := hex.DecodeString(
		"85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	msg := []byte("Cryptographic Forum Research Group")
	m, err := MACFetch("POLY1305")
	if err != nil {
		t.Fatalf("MACFetch: %v", err)
	}
	defer m.Close()
	ctx, err := NewMACCtx(m, key, nil)
	if err != nil {
		t.Fatalf("NewMACCtx: %v", err)
	}
	defer ctx.Close()
	if err := ctx.Update(msg); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := ctx.Final()
	if err != nil {
		t.Fatalf("Final: %v", err)
	}
	want, err := hex.DecodeString("a8061dc1305136c6c22b8baf0c0127a9")
	if err != nil {
		t.Fatalf("decode want: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Poly1305 = %x, want %x", got, want)
	}
}

// TestMACEIA3KnownVector 验证 EIA3 对铜锁自带测试向量。
//
// TestMACEIA3KnownVector verifies EIA3 against the Tongsuo test vector.
func TestMACEIA3KnownVector(t *testing.T) {
	m, err := MACFetch("EIA3")
	if err != nil {
		t.Fatalf("MACFetch: %v", err)
	}
	defer m.Close()
	ctx, err := NewMACCtx(m, bytes.Repeat([]byte{0x00}, 16),
		&MACOptions{IV: bytes.Repeat([]byte{0x00}, 5)})
	if err != nil {
		t.Fatalf("NewMACCtx: %v", err)
	}
	defer ctx.Close()
	if err := ctx.Update([]byte{0x00}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := ctx.Final()
	if err != nil {
		t.Fatalf("Final: %v", err)
	}
	want, err := hex.DecodeString("390a91b7")
	if err != nil {
		t.Fatalf("decode want: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("EIA3 = %x, want %x", got, want)
	}
}
