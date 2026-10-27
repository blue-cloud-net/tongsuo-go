package meta

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// TestParseEncoding 验证编码名解析与归一化。
//
// TestParseEncoding verifies the parsing and normalisation of encoding
// names.
func TestParseEncoding(t *testing.T) {
	tests := []struct {
		in      string
		want    Encoding
		wantErr bool
	}{
		{"raw", EncodingRaw, false},
		{"binary", EncodingRaw, false},
		{"none", EncodingRaw, false},
		{"", EncodingRaw, false},
		{"HEX", EncodingHex, false},
		{"  hex  ", EncodingHex, false},
		{"base64", EncodingBase64, false},
		{"B64", EncodingBase64, false},
		{"rot13", "", true},
	}
	for _, tt := range tests {
		got, err := ParseEncoding(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseEncoding(%q): expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseEncoding(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseEncoding(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestEncodeDecodeRoundtrip 验证三种编码的编解码往返一致。
//
// TestEncodeDecodeRoundtrip verifies that encoding then decoding returns
// the original bytes for all three encodings.
func TestEncodeDecodeRoundtrip(t *testing.T) {
	data := []byte("tongsuo-go encoding roundtrip \x00\x01\xfe\xff")
	for _, enc := range []Encoding{EncodingRaw, EncodingHex, EncodingBase64} {
		encoded, err := Encode(data, enc)
		if err != nil {
			t.Fatalf("Encode(%s): %v", enc, err)
		}
		decoded, err := Decode(encoded, enc)
		if err != nil {
			t.Fatalf("Decode(%s): %v", enc, err)
		}
		if !bytes.Equal(decoded, data) {
			t.Fatalf("%s roundtrip = %x, want %x", enc, decoded, data)
		}
	}
}

// TestEncodeKnownVectors 验证 hex 与 base64 的编码结果与标准实现一致。
//
// TestEncodeKnownVectors verifies that the hex and base64 encodings match
// the standard implementations.
func TestEncodeKnownVectors(t *testing.T) {
	data := []byte("hello")
	enc, err := Encode(data, EncodingHex)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if string(enc) != "68656c6c6f" {
		t.Errorf("hex = %q, want %q", string(enc), "68656c6c6f")
	}
	if got := Hex(data); got != "68656c6c6f" {
		t.Errorf("Hex = %q, want %q", got, "68656c6c6f")
	}
	enc, err = Encode(data, EncodingBase64)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if string(enc) != base64.StdEncoding.EncodeToString(data) {
		t.Errorf("base64 = %q, want %q", string(enc), base64.StdEncoding.EncodeToString(data))
	}
	if got := Base64(data); got != "aGVsbG8=" {
		t.Errorf("Base64 = %q, want %q", got, "aGVsbG8=")
	}
}

// TestDecodeRejectsInvalid 验证非法输入被拒绝。
//
// TestDecodeRejectsInvalid verifies that malformed input is rejected.
func TestDecodeRejectsInvalid(t *testing.T) {
	if _, err := Decode([]byte("zz"), EncodingHex); err == nil {
		t.Error("Decode(hex): expected error for non-hex input")
	}
	if _, err := Decode([]byte("!!!!"), EncodingBase64); err == nil {
		t.Error("Decode(base64): expected error for non-base64 input")
	}
	if _, err := Encode(nil, Encoding("rot13")); err == nil {
		t.Error("Encode: expected error for unknown encoding")
	}
	if _, err := Decode(nil, Encoding("rot13")); err == nil {
		t.Error("Decode: expected error for unknown encoding")
	}
}

// TestDecodeIgnoresWhitespace 验证 hex 解码忽略空白、base64 解码忽略换行。
//
// TestDecodeIgnoresWhitespace verifies that hex decoding ignores
// whitespace and base64 decoding ignores newlines.
func TestDecodeIgnoresWhitespace(t *testing.T) {
	got, err := Decode([]byte("68 65\n6c\t6c6f"), EncodingHex)
	if err != nil {
		t.Fatalf("Decode(hex): %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("hex decode = %q, want %q", string(got), "hello")
	}
	got, err = Decode([]byte("aGVsbG8=\n"), EncodingBase64)
	if err != nil {
		t.Fatalf("Decode(base64): %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("base64 decode = %q, want %q", string(got), "hello")
	}
}

// TestDump 验证 hexdump 视图的形状与可打印字符列。
//
// TestDump verifies the shape of the hexdump view and its printable
// character column.
func TestDump(t *testing.T) {
	if got := Dump(nil); got != "" {
		t.Errorf("Dump(nil) = %q, want empty", got)
	}
	got := Dump([]byte("hello"))
	if !strings.HasPrefix(got, "00000000  ") {
		t.Errorf("Dump prefix = %q, want %q", got, "00000000  ")
	}
	if !strings.Contains(got, "|hello|") {
		t.Errorf("Dump = %q, want a printable column showing hello", got)
	}
	// 超过 16 字节时按行切分。
	long := Dump(bytes.Repeat([]byte{0x41}, 17))
	if n := strings.Count(long, "\n"); n != 1 {
		t.Errorf("Dump of 17 bytes has %d newlines, want 1", n)
	}
}
