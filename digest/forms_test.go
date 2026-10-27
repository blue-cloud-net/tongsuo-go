package digest_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/digest"
	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// TestSumSourceMatchesSum 验证 SumSource 与一次性 Sum 结果一致，
// 且对 bytes / reader / 文件三种源都成立。
//
// TestSumSourceMatchesSum verifies that SumSource agrees with the
// one-shot Sum for bytes, reader and file sources.
func TestSumSourceMatchesSum(t *testing.T) {
	data := []byte("abc")
	want, err := digest.Sum("SM3", data)
	if err != nil {
		t.Fatalf("Sum: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "abc.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	fileSrc, err := meta.NewFileSource(path)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}

	cases := []struct {
		name string
		src  *meta.Source
	}{
		{"bytes", meta.NewBytesSource(data)},
		{"reader", meta.NewReaderSource(bytes.NewReader(data))},
		{"file", fileSrc},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := digest.SumSource("SM3", tc.src)
			if err != nil {
				t.Fatalf("SumSource: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("SumSource = %x, want %x", got, want)
			}
		})
	}

	// SumFile 走同一条路径。
	got, err := digest.SumFile("SM3", path)
	if err != nil {
		t.Fatalf("SumFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("SumFile = %x, want %x", got, want)
	}
}

// TestSumToEncoding 验证 SumTo 按 sink 编码写出（raw / hex / base64）。
//
// TestSumToEncoding verifies that SumTo honours the sink encoding
// (raw / hex / base64).
func TestSumToEncoding(t *testing.T) {
	data := []byte("abc")
	raw, err := digest.Sum("SM3", data)
	if err != nil {
		t.Fatalf("Sum: %v", err)
	}
	hexWant, err := meta.Encode(raw, meta.EncodingHex)
	if err != nil {
		t.Fatalf("Encode hex: %v", err)
	}

	cases := []struct {
		name string
		enc  meta.Encoding
		want []byte
	}{
		{"raw", meta.EncodingRaw, raw},
		{"hex", meta.EncodingHex, hexWant},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			sink := meta.NewBytesSink()
			if err := sink.SetEncoding(tc.enc); err != nil {
				t.Fatalf("SetEncoding: %v", err)
			}
			if err := digest.SumTo("SM3", meta.NewBytesSource(data), sink); err != nil {
				t.Fatalf("SumTo: %v", err)
			}
			if err := sink.Close(); err != nil {
				t.Fatalf("sink.Close: %v", err)
			}
			if !bytes.Equal(sink.Bytes(), tc.want) {
				t.Errorf("SumTo output = %q, want %q", sink.Bytes(), tc.want)
			}
		})
	}
}

// TestSumReaderTo 验证 SumReaderTo 与 SumTo 等价（同为流式）。
//
// TestSumReaderTo verifies that SumReaderTo matches SumTo (both stream).
func TestSumReaderTo(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789"), 1024)
	want, err := digest.Sum("SHA256", data)
	if err != nil {
		t.Fatalf("Sum: %v", err)
	}
	sink := meta.NewBytesSink()
	if err := digest.SumReaderTo("SHA256", bytes.NewReader(data), sink); err != nil {
		t.Fatalf("SumReaderTo: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("sink.Close: %v", err)
	}
	if !bytes.Equal(sink.Bytes(), want) {
		t.Errorf("SumReaderTo = %x, want %x", sink.Bytes(), want)
	}
}

// TestSumSourceUnknownAlgorithm 验证未知算法名返回 ErrUnknownAlgorithm。
//
// TestSumSourceUnknownAlgorithm verifies that an unknown algorithm name
// yields ErrUnknownAlgorithm.
func TestSumSourceUnknownAlgorithm(t *testing.T) {
	if _, err := digest.SumSource("NOSUCHDIGEST", meta.NewBytesSource([]byte("x"))); err == nil {
		t.Fatal("SumSource: want error, got nil")
	}
}
