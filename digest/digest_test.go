package digest

import (
	"bytes"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"strings"
	"testing"
)

// typedSum 按算法名调用对应的类型化 Sum*，返回切片形式，便于表驱动比对。
//
// typedSum dispatches to the matching typed Sum* helper and returns the
// digest as a slice so table-driven tests can compare uniformly.
func typedSum(name string, data []byte) []byte {
	switch name {
	case "SM3":
		s := SumSM3(data)
		return s[:]
	case "MD5":
		s := SumMD5(data)
		return s[:]
	case "SHA1":
		s := SumSHA1(data)
		return s[:]
	case "SHA224":
		s := SumSHA224(data)
		return s[:]
	case "SHA256":
		s := SumSHA256(data)
		return s[:]
	case "SHA384":
		s := SumSHA384(data)
		return s[:]
	case "SHA512":
		s := SumSHA512(data)
		return s[:]
	}
	panic("typedSum: unknown name " + name)
}

// TestNames 验证 Names 返回稳定且完整的算法列表。
func TestNames(t *testing.T) {
	want := []string{"SM3", "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"}
	got := Names()
	if len(got) != len(want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Names()[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
	// 再次调用应得到相同顺序（稳定性）
	again := Names()
	if strings.Join(again, ",") != strings.Join(got, ",") {
		t.Fatalf("Names() not stable: %v then %v", got, again)
	}
}

// TestSizeAndBlockSizeByName 验证按名查询的摘要长度与分组长度
// （含 SHA-384 的 128 字节分组）。
func TestSizeAndBlockSizeByName(t *testing.T) {
	cases := []struct {
		name      string
		size      int
		blockSize int
	}{
		{"SM3", 32, 64},
		{"MD5", 16, 64},
		{"SHA1", 20, 64},
		{"SHA224", 28, 64},
		{"SHA256", 32, 64},
		{"SHA384", 48, 128},
		{"SHA512", 64, 128},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotSize, err := Size(c.name)
			if err != nil {
				t.Fatalf("Size(%q) error: %v", c.name, err)
			}
			if gotSize != c.size {
				t.Errorf("Size(%q) = %d, want %d", c.name, gotSize, c.size)
			}
			gotBlock, err := BlockSize(c.name)
			if err != nil {
				t.Fatalf("BlockSize(%q) error: %v", c.name, err)
			}
			if gotBlock != c.blockSize {
				t.Errorf("BlockSize(%q) = %d, want %d", c.name, gotBlock, c.blockSize)
			}
		})
	}
}

// TestConstantsMatchRegistry 验证导出的尺寸常量与按名查询结果一致。
func TestConstantsMatchRegistry(t *testing.T) {
	cases := []struct {
		name      string
		size      int
		blockSize int
	}{
		{"SM3", SM3Size, SM3BlockSize},
		{"MD5", MD5Size, MD5BlockSize},
		{"SHA1", SHA1Size, SHA1BlockSize},
		{"SHA224", SHA224Size, SHA224BlockSize},
		{"SHA256", SHA256Size, SHA256BlockSize},
		{"SHA384", SHA384Size, SHA384BlockSize},
		{"SHA512", SHA512Size, SHA512BlockSize},
	}
	for _, c := range cases {
		gotSize, err := Size(c.name)
		if err != nil {
			t.Fatalf("Size(%q) error: %v", c.name, err)
		}
		if gotSize != c.size {
			t.Errorf("%sSize = %d but Size(%q) = %d", c.name, c.size, c.name, gotSize)
		}
		gotBlock, err := BlockSize(c.name)
		if err != nil {
			t.Fatalf("BlockSize(%q) error: %v", c.name, err)
		}
		if gotBlock != c.blockSize {
			t.Errorf("%sBlockSize = %d but BlockSize(%q) = %d", c.name, c.blockSize, c.name, gotBlock)
		}
	}
}

// TestUnknownAlgorithm 验证所有按名入口对未知算法名返回 ErrUnknownAlgorithm。
func TestUnknownAlgorithm(t *testing.T) {
	const bad = "NO-SUCH-ALGORITHM"

	t.Run("Size", func(t *testing.T) {
		if _, err := Size(bad); !errors.Is(err, ErrUnknownAlgorithm) {
			t.Errorf("Size(%q) err = %v, want ErrUnknownAlgorithm", bad, err)
		}
	})
	t.Run("BlockSize", func(t *testing.T) {
		if _, err := BlockSize(bad); !errors.Is(err, ErrUnknownAlgorithm) {
			t.Errorf("BlockSize(%q) err = %v, want ErrUnknownAlgorithm", bad, err)
		}
	})
	t.Run("New", func(t *testing.T) {
		if _, err := New(bad); !errors.Is(err, ErrUnknownAlgorithm) {
			t.Errorf("New(%q) err = %v, want ErrUnknownAlgorithm", bad, err)
		}
	})
	t.Run("Sum", func(t *testing.T) {
		if _, err := Sum(bad, []byte("abc")); !errors.Is(err, ErrUnknownAlgorithm) {
			t.Errorf("Sum(%q) err = %v, want ErrUnknownAlgorithm", bad, err)
		}
	})
	t.Run("SumReader", func(t *testing.T) {
		if _, err := SumReader(bad, strings.NewReader("abc")); !errors.Is(err, ErrUnknownAlgorithm) {
			t.Errorf("SumReader(%q) err = %v, want ErrUnknownAlgorithm", bad, err)
		}
	})
	t.Run("Empty", func(t *testing.T) {
		if _, err := Size(""); !errors.Is(err, ErrUnknownAlgorithm) {
			t.Errorf("Size(\"\") err = %v, want ErrUnknownAlgorithm", err)
		}
	})
}

// TestNameIsCaseInsensitive 验证按名入口对算法名大小写不敏感。
func TestNameIsCaseInsensitive(t *testing.T) {
	data := []byte("abc")
	want := typedSum("SHA256", data)
	for _, name := range []string{"SHA256", "sha256", "Sha256", " sha256 "} {
		got, err := Sum(name, data)
		if err != nil {
			t.Fatalf("Sum(%q) error: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("Sum(%q) = %x, want %x", name, got, want)
		}
	}
}

// TestSumByNameMatchesTyped 验证按名 Sum 与类型化 Sum* 结果一致。
func TestSumByNameMatchesTyped(t *testing.T) {
	data := []byte("tongsuo-go digest dispatch")
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			got, err := Sum(name, data)
			if err != nil {
				t.Fatalf("Sum(%q) error: %v", name, err)
			}
			want := typedSum(name, data)
			if !bytes.Equal(got, want) {
				t.Errorf("Sum(%q) = %x, want %x", name, got, want)
			}
		})
	}
}

// TestNewByNameMatchesSizeBlock 验证按名 New 返回的 hash.Hash 报告正确尺寸。
func TestNewByNameMatchesSizeBlock(t *testing.T) {
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			h, err := New(name)
			if err != nil {
				t.Fatalf("New(%q) error: %v", name, err)
			}
			size, _ := Size(name)
			block, _ := BlockSize(name)
			if h.Size() != size {
				t.Errorf("New(%q).Size() = %d, want %d", name, h.Size(), size)
			}
			if h.BlockSize() != block {
				t.Errorf("New(%q).BlockSize() = %d, want %d", name, h.BlockSize(), block)
			}
		})
	}
}

// TestNewByNameStreamMatchesSum 验证按名流式与按名一次性结果一致。
func TestNewByNameStreamMatchesSum(t *testing.T) {
	data := bytes.Repeat([]byte("chunk"), 50)
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			h, err := New(name)
			if err != nil {
				t.Fatalf("New(%q) error: %v", name, err)
			}
			if _, err := h.Write(data[:13]); err != nil {
				t.Fatalf("Write error: %v", err)
			}
			if _, err := h.Write(data[13:]); err != nil {
				t.Fatalf("Write error: %v", err)
			}
			got := h.Sum(nil)

			want, err := Sum(name, data)
			if err != nil {
				t.Fatalf("Sum(%q) error: %v", name, err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("stream(%q) = %x, want %x", name, got, want)
			}
		})
	}
}

// TestSumReaderMatchesSum 验证 SumReader 与 Sum 结果一致（含分块边界）。
func TestSumReaderMatchesSum(t *testing.T) {
	data := []byte("stream me through an io.Reader, please")
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			got, err := SumReader(name, bytes.NewReader(data))
			if err != nil {
				t.Fatalf("SumReader(%q) error: %v", name, err)
			}
			want, err := Sum(name, data)
			if err != nil {
				t.Fatalf("Sum(%q) error: %v", name, err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("SumReader(%q) = %x, want %x", name, got, want)
			}
		})
	}
}

// errReader 是一个恒定返回错误的 io.Reader，用于验证 SumReader 的错误传播。
//
// errReader is an io.Reader that always fails, used to verify SumReader
// propagates read errors.
type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("boom")
}

// TestSumReaderPropagatesReadError 验证 SumReader 把读取错误包装返回
// （且不误报为 ErrUnknownAlgorithm）。
func TestSumReaderPropagatesReadError(t *testing.T) {
	_, err := SumReader("SHA256", errReader{})
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

// closeTracker 记录 Close 是否被调用，用于验证 SumReader 不会关闭输入流。
//
// closeTracker records whether Close was called, verifying SumReader
// leaves the input reader open.
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
	if _, err := SumReader("SM3", ct); err != nil {
		t.Fatalf("SumReader error: %v", err)
	}
	if ct.closed {
		t.Error("SumReader closed the caller's reader; it must not")
	}
}

// TestSumByNameHexKnown 用 SM3 的已知向量交叉校验按名入口的编码正确性。
func TestSumByNameHexKnown(t *testing.T) {
	got, err := Sum("SM3", []byte("abc"))
	if err != nil {
		t.Fatalf("Sum(SM3) error: %v", err)
	}
	const want = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
	if hex.EncodeToString(got) != want {
		t.Errorf("Sum(SM3, abc) = %x, want %s", got, want)
	}
}

// 编译期断言：所有类型化 New* 均实现 hash.Hash。
var (
	_ hash.Hash = NewSM3()
	_ hash.Hash = NewMD5()
	_ hash.Hash = NewSHA1()
	_ hash.Hash = NewSHA224()
	_ hash.Hash = NewSHA256()
	_ hash.Hash = NewSHA384()
	_ hash.Hash = NewSHA512()
)
