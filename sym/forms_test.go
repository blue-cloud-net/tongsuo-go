package sym_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/meta"
	"github.com/blue-cloud-net/tongsuo-go/sym"
)

// TestCryptSourceRoundTrip 验证流式加解密对多种模式与分块输入可往返，
// 且与一次性 Encrypt/Decrypt 结果逐字节一致。
//
// TestCryptSourceRoundTrip verifies that streaming encryption round-trips
// for several modes and chunked inputs and agrees byte for byte with the
// one-shot Encrypt / Decrypt.
func TestCryptSourceRoundTrip(t *testing.T) {
	// 跨越 streamChunk（64 KiB）的多分块输入，长度故意不是分组整数倍。
	data := bytes.Repeat([]byte("tongsuo-go streaming "), 4000)

	cases := []struct {
		name string
		key  []byte
		iv   []byte
	}{
		{"SM4-CBC", bytes.Repeat([]byte{0x01}, sym.SM4KeySize), bytes.Repeat([]byte{0x02}, sym.BlockSize)},
		{"SM4-CTR", bytes.Repeat([]byte{0x03}, sym.SM4KeySize), bytes.Repeat([]byte{0x04}, sym.BlockSize)},
		{"SM4-OFB", bytes.Repeat([]byte{0x05}, sym.SM4KeySize), bytes.Repeat([]byte{0x06}, sym.BlockSize)},
		{"SM4-CFB", bytes.Repeat([]byte{0x07}, sym.SM4KeySize), bytes.Repeat([]byte{0x08}, sym.BlockSize)},
		{"AES-128-CBC", bytes.Repeat([]byte{0x09}, sym.AES128KeySize), bytes.Repeat([]byte{0x0a}, sym.BlockSize)},
		{"AES-192-CTR", bytes.Repeat([]byte{0x0b}, sym.AES192KeySize), bytes.Repeat([]byte{0x0c}, sym.BlockSize)},
		{"AES-256-ECB", bytes.Repeat([]byte{0x0d}, sym.AES256KeySize), nil},
		{"ChaCha20", bytes.Repeat([]byte{0x0e}, sym.ChaCha20KeySize), bytes.Repeat([]byte{0x0f}, sym.ChaCha20IVSize)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cipherSink := meta.NewBytesSink()
			if err := sym.EncryptSource(tc.name, tc.key, tc.iv,
				meta.NewBytesSource(data), cipherSink); err != nil {
				t.Fatalf("EncryptSource: %v", err)
			}
			if err := cipherSink.Close(); err != nil {
				t.Fatalf("cipher sink close: %v", err)
			}

			// 与一次性入口对拍。
			want, err := sym.Encrypt(tc.name, tc.key, tc.iv, data, nil)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if !bytes.Equal(cipherSink.Bytes(), want) {
				t.Fatalf("stream ciphertext differs from one-shot (%d vs %d bytes)",
					len(cipherSink.Bytes()), len(want))
			}

			plainSink := meta.NewBytesSink()
			if err := sym.DecryptSource(tc.name, tc.key, tc.iv,
				meta.NewBytesSource(cipherSink.Bytes()), plainSink); err != nil {
				t.Fatalf("DecryptSource: %v", err)
			}
			if err := plainSink.Close(); err != nil {
				t.Fatalf("plain sink close: %v", err)
			}
			if !bytes.Equal(plainSink.Bytes(), data) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d",
					len(plainSink.Bytes()), len(data))
			}
		})
	}
}

// TestCryptSourceEmptyInput 验证空输入走 PKCS#7 填充分支仍可往返。
//
// TestCryptSourceEmptyInput verifies that empty input still round-trips
// through the PKCS#7 padding branch.
func TestCryptSourceEmptyInput(t *testing.T) {
	key := bytes.Repeat([]byte{0x21}, sym.SM4KeySize)
	iv := bytes.Repeat([]byte{0x22}, sym.BlockSize)

	cipherSink := meta.NewBytesSink()
	if err := sym.EncryptSource("SM4-CBC", key, iv, meta.NewBytesSource(nil), cipherSink); err != nil {
		t.Fatalf("EncryptSource: %v", err)
	}
	if err := cipherSink.Close(); err != nil {
		t.Fatalf("cipher sink close: %v", err)
	}
	if got := len(cipherSink.Bytes()); got != sym.BlockSize {
		t.Fatalf("ciphertext length = %d, want %d (one padding block)", got, sym.BlockSize)
	}

	plainSink := meta.NewBytesSink()
	if err := sym.DecryptSource("SM4-CBC", key, iv, meta.NewBytesSource(cipherSink.Bytes()), plainSink); err != nil {
		t.Fatalf("DecryptSource: %v", err)
	}
	if err := plainSink.Close(); err != nil {
		t.Fatalf("plain sink close: %v", err)
	}
	if len(plainSink.Bytes()) != 0 {
		t.Fatalf("plaintext length = %d, want 0", len(plainSink.Bytes()))
	}
}

// TestCryptSourceRejectsAEAD 验证 AEAD 与 XTS 模式返回 ErrUnsupported。
//
// TestCryptSourceRejectsAEAD verifies that the AEAD and XTS modes return
// ErrUnsupported.
func TestCryptSourceRejectsAEAD(t *testing.T) {
	key := bytes.Repeat([]byte{0x31}, sym.SM4KeySize)
	iv := bytes.Repeat([]byte{0x32}, sym.NonceSize)

	for _, name := range []string{"SM4-GCM", "SM4-CCM", "AES-128-GCM", "ChaCha20-Poly1305", "SM4-XTS"} {
		t.Run(name, func(t *testing.T) {
			err := sym.EncryptSource(name, key, iv, meta.NewBytesSource([]byte("x")), meta.NewBytesSink())
			if !errors.Is(err, sym.ErrUnsupported) {
				t.Fatalf("err = %v, want ErrUnsupported", err)
			}
		})
	}
}

// TestCryptSourceKeyLength 验证密钥长度不符返回 ErrInvalidKeyLength。
//
// TestCryptSourceKeyLength verifies that a wrong key length returns
// ErrInvalidKeyLength.
func TestCryptSourceKeyLength(t *testing.T) {
	err := sym.EncryptSource("SM4-CBC", bytes.Repeat([]byte{1}, 8),
		make([]byte, sym.BlockSize), meta.NewBytesSource([]byte("x")), meta.NewBytesSink())
	if !errors.Is(err, sym.ErrInvalidKeyLength) {
		t.Fatalf("err = %v, want ErrInvalidKeyLength", err)
	}
}

// TestCryptSourceBadPadding 验证解密时坏填充被报告为错误（不放宽校验）。
//
// TestCryptSourceBadPadding verifies that a corrupt padding is reported
// as an error rather than silently accepted.
func TestCryptSourceBadPadding(t *testing.T) {
	key := bytes.Repeat([]byte{0x41}, sym.SM4KeySize)
	iv := bytes.Repeat([]byte{0x42}, sym.BlockSize)

	cipherSink := meta.NewBytesSink()
	if err := sym.EncryptSource("SM4-CBC", key, iv, meta.NewBytesSource([]byte("hello")), cipherSink); err != nil {
		t.Fatalf("EncryptSource: %v", err)
	}
	if err := cipherSink.Close(); err != nil {
		t.Fatalf("cipher sink close: %v", err)
	}

	ct := cipherSink.Bytes()
	ct[len(ct)-1] ^= 0xff // 破坏最后一个密文块，使填充校验失败

	if err := sym.DecryptSource("SM4-CBC", key, iv, meta.NewBytesSource(ct), meta.NewBytesSink()); err == nil {
		t.Fatal("DecryptSource with corrupt padding: want error, got nil")
	}
}
