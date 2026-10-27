package kdf_test

import (
	"bytes"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/kdf"
	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// TestDeriveTo 验证 DeriveTo 按 sink 编码写出，且与 Derive 结果一致。
//
// TestDeriveTo verifies that DeriveTo honours the sink encoding and
// matches Derive byte for byte.
func TestDeriveTo(t *testing.T) {
	opts := &kdf.Options{
		Digest: kdf.HashSHA256,
		Secret: []byte("shared secret"),
		Info:   []byte("context"),
		Length: 32,
	}
	want, err := kdf.Derive("SSKDF", opts)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	hexWant, err := meta.Encode(want, meta.EncodingHex)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	cases := []struct {
		name string
		enc  meta.Encoding
		want []byte
	}{
		{"raw", meta.EncodingRaw, want},
		{"hex", meta.EncodingHex, hexWant},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			sink := meta.NewBytesSink()
			if err := sink.SetEncoding(tc.enc); err != nil {
				t.Fatalf("SetEncoding: %v", err)
			}
			if err := kdf.DeriveTo("SSKDF", opts, sink); err != nil {
				t.Fatalf("DeriveTo: %v", err)
			}
			if err := sink.Close(); err != nil {
				t.Fatalf("sink.Close: %v", err)
			}
			if !bytes.Equal(sink.Bytes(), tc.want) {
				t.Errorf("DeriveTo output = %q, want %q", sink.Bytes(), tc.want)
			}
		})
	}
}

// TestDeriveToErrors 验证 DeriveTo 透传 Derive 的参数校验错误。
//
// TestDeriveToErrors verifies that DeriveTo propagates the validation
// errors raised by Derive.
func TestDeriveToErrors(t *testing.T) {
	if err := kdf.DeriveTo("SSKDF", &kdf.Options{Length: 16}, meta.NewBytesSink()); err == nil {
		t.Fatal("DeriveTo without digest: want error, got nil")
	}
	if err := kdf.DeriveTo("NOSUCHKDF", &kdf.Options{Length: 16}, meta.NewBytesSink()); err == nil {
		t.Fatal("DeriveTo with unknown algorithm: want error, got nil")
	}
}
