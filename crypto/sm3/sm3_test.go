package sm3

import (
	"bytes"
	"encoding/hex"
	"hash"
	"strings"
	"testing"
)

// TestSumStandardVectors 使用 GB/T 32905-2016 附录 A 的标准测试向量验证 Sum。
// 向量值由铜锁 openssl dgst -sm3 生成并核对。
func TestSumStandardVectors(t *testing.T) {
	vectors := []struct {
		name string
		in   string
		want string
	}{
		// 空输入（GB/T 32905 附录 A.1 推导）
		{"empty", "", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"},
		// "abc"
		{"abc", "abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
		// "abcd" × 16（64 字节，块对齐）
		{"block-aligned", strings.Repeat("abcd", 16), "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"},
	}
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			got := Sum([]byte(v.in))
			want, err := hex.DecodeString(v.want)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got[:], want) {
				t.Fatalf("Sum(%q) = %x, want %x", v.in, got, want)
			}
		})
	}
}

// TestHashStreamMatchesSum 验证流式写入与一次性 Sum 结果一致。
func TestHashStreamMatchesSum(t *testing.T) {
	data := bytes.Repeat([]byte("tongsuo-go"), 10) // 80 字节，跨多个分组
	want := Sum(data)

	h := New()
	h.Write(data[:7])
	h.Write(data[7:33])
	h.Write(data[33:])
	got := h.Sum(nil)
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("stream = %x, want %x", got, want)
	}
}

// TestSumDoesNotAffectWriter 验证调用 Sum 后仍可继续 Write。
func TestSumDoesNotAffectWriter(t *testing.T) {
	h := New()
	h.Write([]byte("abc"))
	_ = h.Sum(nil)
	h.Write([]byte("def"))
	want := Sum([]byte("abcdef"))
	got := h.Sum(nil)
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("after Sum+Write = %x, want %x", got, want)
	}
}

// TestReset 验证 Reset 后可重新计算。
func TestReset(t *testing.T) {
	h := New()
	h.Write([]byte("abc"))
	h.Reset()
	h.Write([]byte("abc"))
	want := Sum([]byte("abc"))
	got := h.Sum(nil)
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("reset = %x, want %x", got, want)
	}
}

// TestDistinctInputs 验证不同输入产生不同摘要。
func TestDistinctInputs(t *testing.T) {
	a := Sum([]byte("hello"))
	b := Sum([]byte("world"))
	if bytes.Equal(a[:], b[:]) {
		t.Fatal("distinct inputs produced equal digests")
	}
}

// TestIdempotent 验证相同输入结果一致。
func TestIdempotent(t *testing.T) {
	a := Sum([]byte("data"))
	b := Sum([]byte("data"))
	if !bytes.Equal(a[:], b[:]) {
		t.Fatal("idempotency violated")
	}
}

// TestHashInterface 验证 New 返回的对象实现了 hash.Hash。
func TestHashInterface(t *testing.T) {
	var _ hash.Hash = New()
}

// TestEmptyViaHash 验证 hash.Hash 接口下的空输入。
func TestEmptyViaHash(t *testing.T) {
	h := New()
	want := Sum(nil)
	got := h.Sum(nil)
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("empty = %x, want %x", got, want)
	}
}
