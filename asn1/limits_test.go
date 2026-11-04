package asn1

import (
	stdasn1 "encoding/asn1"
	"errors"
	"testing"
)

// TestParseWithLimitsBoundaries 验证相关操作的正确性、边界与错误处理。
//
// TestParseWithLimitsBoundaries checks operation correctness, boundaries and error handling.
func TestParseWithLimitsBoundaries(t *testing.T) {
	der := []byte{0x30, 6, 2, 1, 1, 2, 1, 2}
	for _, tc := range []struct {
		depth, nodes int
		want         error
	}{{1, 3, nil}, {1, 2, ErrNodeLimit}, {0, 3, nil}, {1, 0, nil}} {
		n, err := ParseWithLimits(der, tc.depth, tc.nodes)
		if tc.depth <= 0 || tc.nodes <= 0 {
			if err == nil || n != nil {
				t.Fatal("invalid limits accepted")
			}
			continue
		}
		if tc.want != nil {
			if !errors.Is(err, tc.want) || n != nil {
				t.Fatalf("got %v %v", n, err)
			}
			continue
		}
		if err != nil || len(n.Children) != 2 || n.Children[1].Offset != 5 {
			t.Fatalf("tree: %v %v", n, err)
		}
	}
	nested := []byte{0x30, 2, 0x30, 0}
	if _, err := ParseWithLimits(nested, 1, 3); !errors.Is(err, ErrDepthLimit) {
		t.Fatalf("depth: %v", err)
	}
	if _, err := ParseWithLimits(nested, 2, 2); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, {0x30, 0x80}, {0x30, 2, 2}, {2, 1, 1, 0}} {
		if n, err := ParseWithLimits(bad, 10, 10); err == nil || n != nil {
			t.Fatalf("accepted %x", bad)
		}
	}
}

// TestParseWithLimitsDeep 验证相关操作的正确性、边界与错误处理。
//
// TestParseWithLimitsDeep checks operation correctness, boundaries and error handling.
func TestParseWithLimitsDeep(t *testing.T) {
	der := []byte{5, 0}
	for i := 0; i < 2000; i++ {
		var err error
		der, err = stdasn1.Marshal(stdasn1.RawValue{Tag: 16, IsCompound: true, Bytes: der})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ParseWithLimits(der, 2000, 2001); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseWithLimits(der, 1999, 2001); !errors.Is(err, ErrDepthLimit) {
		t.Fatal(err)
	}
	if _, err := Parse(der); err == nil {
		t.Fatal("legacy depth guard lost")
	}
}

// FuzzParseWithLimits 验证相关操作的正确性、边界与错误处理。
//
// FuzzParseWithLimits checks operation correctness, boundaries and error handling.
func FuzzParseWithLimits(f *testing.F) {
	f.Add([]byte{0x30, 3, 2, 1, 1})
	f.Add([]byte{0x30, 0x80})
	f.Fuzz(func(t *testing.T, data []byte) {
		n, err := ParseWithLimits(data, 32, 64)
		if err != nil && n != nil {
			t.Fatal("partial tree")
		}
	})
}

// BenchmarkParseWithLimits 验证相关操作的正确性、边界与错误处理。
//
// BenchmarkParseWithLimits checks operation correctness, boundaries and error handling.
func BenchmarkParseWithLimits(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := ParseWithLimits([]byte{0x30, 3, 2, 1, 1}, 8, 8); err != nil {
			b.Fatal(err)
		}
	}
}
