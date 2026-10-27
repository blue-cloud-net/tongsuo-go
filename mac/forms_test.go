package mac_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/mac"
	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// TestSumSourceMatchesSum 验证 SumSource / SumFile 与一次性 Sum 结果一致。
//
// TestSumSourceMatchesSum verifies that SumSource and SumFile agree with
// the one-shot Sum.
func TestSumSourceMatchesSum(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 16)
	data := []byte("what do ya want for nothing?")

	want, err := mac.Sum("HMAC-SHA256", key, data, nil)
	if err != nil {
		t.Fatalf("Sum: %v", err)
	}

	got, err := mac.SumSource("HMAC-SHA256", key, meta.NewBytesSource(data), nil)
	if err != nil {
		t.Fatalf("SumSource: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("SumSource = %x, want %x", got, want)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	got, err = mac.SumFile("HMAC-SHA256", key, path, nil)
	if err != nil {
		t.Fatalf("SumFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("SumFile = %x, want %x", got, want)
	}
}

// TestSumToEncoding 验证 SumTo 按 sink 编码写出。
//
// TestSumToEncoding verifies that SumTo honours the sink encoding.
func TestSumToEncoding(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 16)
	data := []byte("stream me")
	want, err := mac.Sum("HMAC-SM3", key, data, nil)
	if err != nil {
		t.Fatalf("Sum: %v", err)
	}
	hexWant, err := meta.Encode(want, meta.EncodingHex)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	sink := meta.NewBytesSink()
	if err := sink.SetEncoding(meta.EncodingHex); err != nil {
		t.Fatalf("SetEncoding: %v", err)
	}
	if err := mac.SumTo("HMAC-SM3", key, meta.NewBytesSource(data), sink, nil); err != nil {
		t.Fatalf("SumTo: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("sink.Close: %v", err)
	}
	if !bytes.Equal(sink.Bytes(), hexWant) {
		t.Errorf("SumTo output = %q, want %q", sink.Bytes(), hexWant)
	}
}

// TestSumSourceNeedsOptions 验证 CMAC 缺少 cipher 选项时返回 ErrInvalidOptions。
//
// TestSumSourceNeedsOptions verifies that CMAC without a cipher option
// returns ErrInvalidOptions.
func TestSumSourceNeedsOptions(t *testing.T) {
	_, err := mac.SumSource("CMAC", bytes.Repeat([]byte{1}, 16),
		meta.NewBytesSource([]byte("x")), nil)
	if err == nil {
		t.Fatal("CMAC without cipher: want error, got nil")
	}
}
