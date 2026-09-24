package digest

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestSumStandardVectors 用铜锁 openssl dgst 实测取得的标准向量验证 7 种算法
// 对空输入与 "abc" 的输出。
func TestSumStandardVectors(t *testing.T) {
	vectors := []struct {
		name string // 算法名
		in   string // 输入
		want string // 期望摘要（hex）
	}{
		// 空输入
		{"SM3", "", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"},
		{"MD5", "", "d41d8cd98f00b204e9800998ecf8427e"},
		{"SHA1", "", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
		{"SHA224", "", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
		{"SHA256", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"SHA384", "", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"},
		{"SHA512", "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
		// "abc"
		{"SM3", "abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
		{"MD5", "abc", "900150983cd24fb0d6963f7d28e17f72"},
		{"SHA1", "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
		{"SHA224", "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
		{"SHA256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"SHA384", "abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
		{"SHA512", "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
	}
	for _, v := range vectors {
		t.Run(v.name+"/"+v.in, func(t *testing.T) {
			got := typedSum(v.name, []byte(v.in))
			want, err := hex.DecodeString(v.want)
			if err != nil {
				t.Fatalf("bad want hex: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("Sum%s(%q) = %x, want %s", v.name, v.in, got, v.want)
			}
		})
	}
}

// TestStreamMatchesSumAll 验证 7 种算法的流式结果与一次性结果一致（跨分组边界）。
func TestStreamMatchesSumAll(t *testing.T) {
	data := bytes.Repeat([]byte("tongsuo-go"), 20) // 200 字节，跨多个分组
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			want := typedSum(name, data)

			h, err := New(name)
			if err != nil {
				t.Fatalf("New(%q) error: %v", name, err)
			}
			// 分三段写入，验证内部缓冲不会丢数据
			for _, seg := range [][]byte{data[:7], data[7:101], data[101:]} {
				if _, err := h.Write(seg); err != nil {
					t.Fatalf("Write error: %v", err)
				}
			}
			got := h.Sum(nil)
			if !bytes.Equal(got, want) {
				t.Fatalf("stream(%q) = %x, want %x", name, got, want)
			}
		})
	}
}

// TestResetAll 验证 7 种算法 Reset 后可重新计算。
func TestResetAll(t *testing.T) {
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			h, err := New(name)
			if err != nil {
				t.Fatalf("New(%q) error: %v", name, err)
			}
			if _, err := h.Write([]byte("first")); err != nil {
				t.Fatalf("Write error: %v", err)
			}
			h.Reset()
			if _, err := h.Write([]byte("abc")); err != nil {
				t.Fatalf("Write error: %v", err)
			}
			got := h.Sum(nil)
			want := typedSum(name, []byte("abc"))
			if !bytes.Equal(got, want) {
				t.Fatalf("after Reset(%q) = %x, want %x", name, got, want)
			}
		})
	}
}

// TestSumDoesNotMutateStateAll 验证调用 Sum 后仍可继续 Write。
func TestSumDoesNotMutateStateAll(t *testing.T) {
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			h, err := New(name)
			if err != nil {
				t.Fatalf("New(%q) error: %v", name, err)
			}
			if _, err := h.Write([]byte("abc")); err != nil {
				t.Fatalf("Write error: %v", err)
			}
			_ = h.Sum(nil)
			if _, err := h.Write([]byte("def")); err != nil {
				t.Fatalf("Write error: %v", err)
			}
			got := h.Sum(nil)
			want := typedSum(name, []byte("abcdef"))
			if !bytes.Equal(got, want) {
				t.Fatalf("Sum-then-Write(%q) = %x, want %x", name, got, want)
			}
		})
	}
}

// TestIdempotentAll 验证 7 种算法对相同输入结果一致。
func TestIdempotentAll(t *testing.T) {
	data := []byte("same input, same output")
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			a := typedSum(name, data)
			b := typedSum(name, data)
			if !bytes.Equal(a, b) {
				t.Fatalf("%s not idempotent: %x vs %x", name, a, b)
			}
		})
	}
}

// TestDistinctInputsAll 验证 7 种算法对不同输入产生不同摘要。
func TestDistinctInputsAll(t *testing.T) {
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			a := typedSum(name, []byte("hello"))
			b := typedSum(name, []byte("world"))
			if bytes.Equal(a, b) {
				t.Fatalf("%s produced equal digests for distinct inputs", name)
			}
		})
	}
}

// TestDigestLengths 验证类型化 Sum* 返回值长度与常量一致。
func TestDigestLengths(t *testing.T) {
	data := []byte("length check")
	if got := len(typedSum("SM3", data)); got != SM3Size {
		t.Errorf("SM3 digest len = %d, want %d", got, SM3Size)
	}
	if got := len(typedSum("MD5", data)); got != MD5Size {
		t.Errorf("MD5 digest len = %d, want %d", got, MD5Size)
	}
	if got := len(typedSum("SHA1", data)); got != SHA1Size {
		t.Errorf("SHA1 digest len = %d, want %d", got, SHA1Size)
	}
	if got := len(typedSum("SHA224", data)); got != SHA224Size {
		t.Errorf("SHA224 digest len = %d, want %d", got, SHA224Size)
	}
	if got := len(typedSum("SHA256", data)); got != SHA256Size {
		t.Errorf("SHA256 digest len = %d, want %d", got, SHA256Size)
	}
	if got := len(typedSum("SHA384", data)); got != SHA384Size {
		t.Errorf("SHA384 digest len = %d, want %d", got, SHA384Size)
	}
	if got := len(typedSum("SHA512", data)); got != SHA512Size {
		t.Errorf("SHA512 digest len = %d, want %d", got, SHA512Size)
	}
}

// BenchmarkSumSM3 测量 SM3 一次性摘要吞吐。
func BenchmarkSumSM3(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SumSM3(data)
	}
}

// BenchmarkSumSHA256 测量 SHA-256 一次性摘要吞吐。
func BenchmarkSumSHA256(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SumSHA256(data)
	}
}

// BenchmarkSumByName 测量按名分发的额外开销。
func BenchmarkSumByName(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Sum("SM3", data)
	}
}
