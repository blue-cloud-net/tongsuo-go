package mac

import (
	"bytes"
	"errors"
	"hash"
	"io"
	"strings"
	"testing"
)

// typedSum 按 HMAC-* 算法名调用对应的 Sum* 助手，便于表驱动比对。
//
// typedSum dispatches to the matching SumHMAC* helper and returns the
// tag as a slice for uniform table-driven comparison.
func typedSum(name string, key, data []byte) []byte {
	switch name {
	case "HMAC-SM3":
		return SumHMACSM3(key, data)
	case "HMAC-MD5":
		return SumHMACMD5(key, data)
	case "HMAC-SHA1":
		return SumHMACSHA1(key, data)
	case "HMAC-SHA224":
		return SumHMACSHA224(key, data)
	case "HMAC-SHA256":
		return SumHMACSHA256(key, data)
	case "HMAC-SHA384":
		return SumHMACSHA384(key, data)
	case "HMAC-SHA512":
		return SumHMACSHA512(key, data)
	}
	panic("typedSum: unknown name " + name)
}

// TestNames 验证 Names 返回稳定且完整的算法列表。
func TestNames(t *testing.T) {
	want := []string{"HMAC-SM3", "HMAC-MD5", "HMAC-SHA1", "HMAC-SHA224", "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"}
	got := Names()
	if len(got) != len(want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Names()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	again := Names()
	if strings.Join(again, ",") != strings.Join(got, ",") {
		t.Fatalf("Names() not stable: %v then %v", got, again)
	}
}

// TestUnknownAlgorithm 验证按名入口对未知算法名返回 ErrUnknownAlgorithm。
func TestUnknownAlgorithm(t *testing.T) {
	const bad = "NO-SUCH-ALGORITHM"
	key := []byte{0x00, 0x01, 0x02, 0x03}

	t.Run("New", func(t *testing.T) {
		if _, err := New(bad, key, nil); !errors.Is(err, ErrUnknownAlgorithm) {
			t.Errorf("New(%q) err = %v, want ErrUnknownAlgorithm", bad, err)
		}
	})
	t.Run("Sum", func(t *testing.T) {
		if _, err := Sum(bad, key, []byte("abc"), nil); !errors.Is(err, ErrUnknownAlgorithm) {
			t.Errorf("Sum(%q) err = %v, want ErrUnknownAlgorithm", bad, err)
		}
	})
	t.Run("SumReader", func(t *testing.T) {
		if _, err := SumReader(bad, key, strings.NewReader("abc"), nil); !errors.Is(err, ErrUnknownAlgorithm) {
			t.Errorf("SumReader(%q) err = %v, want ErrUnknownAlgorithm", bad, err)
		}
	})
	t.Run("Empty", func(t *testing.T) {
		if _, err := New("", key, nil); !errors.Is(err, ErrUnknownAlgorithm) {
			t.Errorf("New(\"\") err = %v, want ErrUnknownAlgorithm", err)
		}
	})
}

// TestNameCaseInsensitive 验证算法名大小写不敏感。
func TestNameCaseInsensitive(t *testing.T) {
	key := []byte("k")
	data := []byte("d")
	want := SumHMACSHA256(key, data)
	for _, name := range []string{"HMAC-SHA256", "hmac-sha256", "Hmac-Sha256", " HMAC-SHA256 "} {
		got, err := Sum(name, key, data, nil)
		if err != nil {
			t.Fatalf("Sum(%q) error: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("Sum(%q) = %x, want %x", name, got, want)
		}
	}
}

// TestSumByNameMatchesTyped 验证按名 Sum 与类型化 Sum* 助手一致。
func TestSumByNameMatchesTyped(t *testing.T) {
	key := []byte("the quick brown fox")
	data := []byte("jumps over the lazy dog")
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			got, err := Sum(name, key, data, nil)
			if err != nil {
				t.Fatalf("Sum(%q) error: %v", name, err)
			}
			want := typedSum(name, key, data)
			if !bytes.Equal(got, want) {
				t.Errorf("Sum(%q) = %x, want %x", name, got, want)
			}
		})
	}
}

// TestNewReturnsMatchingTagSize 验证按名 New 返回的 hash.Hash 报告正确标签长度。
func TestNewReturnsMatchingTagSize(t *testing.T) {
	wantSizes := map[string]int{
		"HMAC-SM3": 32, "HMAC-MD5": 16, "HMAC-SHA1": 20, "HMAC-SHA224": 28,
		"HMAC-SHA256": 32, "HMAC-SHA384": 48, "HMAC-SHA512": 64,
	}
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			h, err := New(name, []byte("k"), nil)
			if err != nil {
				t.Fatalf("New(%q) error: %v", name, err)
			}
			if h.Size() != wantSizes[name] {
				t.Errorf("New(%q).Size() = %d, want %d", name, h.Size(), wantSizes[name])
			}
			tag := h.Sum(nil)
			if len(tag) != wantSizes[name] {
				t.Errorf("Sum %s tag len = %d, want %d", name, len(tag), wantSizes[name])
			}
		})
	}
}

// TestStreamMatchesSum 验证流式与一次性结果一致（跨分组边界）。
func TestStreamMatchesSum(t *testing.T) {
	key := []byte("stream-key")
	data := bytes.Repeat([]byte("X"), 200) // 跨多个 HMAC 分组
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			want := SumHMACSM3(key, data) // 占位作重检查 Sum 流程
			if name == "HMAC-SM3" {
				// 已确认；下面用 typedSum 通用
			}
			want = typedSum(name, key, data)

			h, err := New(name, key, nil)
			if err != nil {
				t.Fatalf("New(%q) error: %v", name, err)
			}
			if _, err := h.Write(data[:5]); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if _, err := h.Write(data[5:101]); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if _, err := h.Write(data[101:]); err != nil {
				t.Fatalf("Write: %v", err)
			}
			got := h.Sum(nil)
			if !bytes.Equal(got, want) {
				t.Errorf("stream(%q) = %x, want %x", name, got, want)
			}
		})
	}
}

// TestResetAll 验证 Reset 后可复用 hash.Hash 实例。
func TestResetAll(t *testing.T) {
	key := []byte("reset-key")
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			h, err := New(name, key, nil)
			if err != nil {
				t.Fatalf("New(%q) error: %v", name, err)
			}
			if _, err := h.Write([]byte("first")); err != nil {
				t.Fatalf("Write: %v", err)
			}
			h.Reset()
			if _, err := h.Write([]byte("abc")); err != nil {
				t.Fatalf("Write: %v", err)
			}
			got := h.Sum(nil)
			want := typedSum(name, key, []byte("abc"))
			if !bytes.Equal(got, want) {
				t.Errorf("after Reset(%q) = %x, want %x", name, got, want)
			}
		})
	}
}

// TestSumDoesNotMutateStateAll 验证 Sum 调用后仍可继续 Write。
func TestSumDoesNotMutateStateAll(t *testing.T) {
	key := []byte("append-key")
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			h, err := New(name, key, nil)
			if err != nil {
				t.Fatalf("New(%q) error: %v", name, err)
			}
			if _, err := h.Write([]byte("abc")); err != nil {
				t.Fatalf("Write: %v", err)
			}
			_ = h.Sum(nil)
			if _, err := h.Write([]byte("def")); err != nil {
				t.Fatalf("Write: %v", err)
			}
			got := h.Sum(nil)
			want := typedSum(name, key, []byte("abcdef"))
			if !bytes.Equal(got, want) {
				t.Errorf("Sum+Write+Append(%q) = %x, want %x", name, got, want)
			}
		})
	}
}

// TestSumReaderMatchesSum 验证 SumReader 与 Sum 结果一致。
func TestSumReaderMatchesSum(t *testing.T) {
	key := []byte("reader-key")
	data := []byte("feed me through an io.Reader, please")
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			got, err := SumReader(name, key, bytes.NewReader(data), nil)
			if err != nil {
				t.Fatalf("SumReader(%q) error: %v", name, err)
			}
			want := typedSum(name, key, data)
			if !bytes.Equal(got, want) {
				t.Errorf("SumReader(%q) = %x, want %x", name, got, want)
			}
		})
	}
}

// errReader 模拟一个总是返回错误的 io.Reader。
//
// errReader is an io.Reader that always fails, used to verify SumReader
// propagates read errors.
type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("boom")
}

// TestSumReaderPropagatesReadError 验证 SumReader 包装读错误而非报 ErrUnknownAlgorithm。
func TestSumReaderPropagatesReadError(t *testing.T) {
	_, err := SumReader("HMAC-SHA256", []byte("k"), errReader{}, nil)
	if err == nil {
		t.Fatal("SumReader(errReader) err = nil, want non-nil")
	}
	if errors.Is(err, ErrUnknownAlgorithm) {
		t.Errorf("read error wrongly reported as ErrUnknownAlgorithm: %v", err)
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("error %v does not wrap the underlying read error", err)
	}
}

// closeTracker 记录 Close 是否被调用，验证 SumReader 不关闭调用方 reader。
//
// closeTracker records whether Close was called, verifying SumReader
// leaves the caller's reader open.
type closeTracker struct {
	io.Reader
	closed bool
}

func (c *closeTracker) Close() error {
	c.closed = true
	return nil
}

// TestSumReaderDoesNotClose 验证 SumReader 不关闭传入的 reader。
func TestSumReaderDoesNotClose(t *testing.T) {
	ct := &closeTracker{Reader: strings.NewReader("abc")}
	if _, err := SumReader("HMAC-SM3", []byte("k"), ct, nil); err != nil {
		t.Fatalf("SumReader error: %v", err)
	}
	if ct.closed {
		t.Error("SumReader closed the caller's reader; it must not")
	}
}

// 编译期断言：所有类型化 NewHMAC* 均实现 hash.Hash。
var (
	_ hash.Hash = NewHMACSM3([]byte("k"))
	_ hash.Hash = NewHMACMD5([]byte("k"))
	_ hash.Hash = NewHMACSHA1([]byte("k"))
	_ hash.Hash = NewHMACSHA224([]byte("k"))
	_ hash.Hash = NewHMACSHA256([]byte("k"))
	_ hash.Hash = NewHMACSHA384([]byte("k"))
	_ hash.Hash = NewHMACSHA512([]byte("k"))
)
