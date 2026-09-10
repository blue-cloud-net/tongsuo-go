package core

import (
	"bytes"
	"testing"
)

// TestCipherMetadata 验证 SM4 系列描述符的元数据缓存正确。
// 注意：CTR / OFB / CFB 是流模式，OpenSSL EVP_CIPHER_block_size 返回 1；
// ECB / CBC 是分组模式，返回 16。
func TestCipherMetadata(t *testing.T) {
	tests := []struct {
		name      string
		cipher    *Cipher
		blockSize int
		keySize   int
		ivSize    int
	}{
		{"SM4ECB", SM4ECB(), 16, 16, 0},
		{"SM4CBC", SM4CBC(), 16, 16, 16},
		// 流模式：OpenSSL 把它们的 block size 报告为 1（"产生 1 字节输出"）
		{"SM4CTR", SM4CTR(), 1, 16, 16},
		{"SM4OFB", SM4OFB(), 1, 16, 16},
		{"SM4CFB", SM4CFB(), 1, 16, 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cipher == nil {
				t.Fatalf("%s returned nil", tt.name)
			}
			if got := tt.cipher.BlockSize(); got != tt.blockSize {
				t.Errorf("BlockSize = %d, want %d", got, tt.blockSize)
			}
			if got := tt.cipher.KeySize(); got != tt.keySize {
				t.Errorf("KeySize = %d, want %d", got, tt.keySize)
			}
			if got := tt.cipher.IVSize(); got != tt.ivSize {
				t.Errorf("IVSize = %d, want %d", got, tt.ivSize)
			}
		})
	}
}

// TestCipherRoundtrip 验证 SM4-CBC 加解密往返。
func TestCipherRoundtrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16)
	iv := bytes.Repeat([]byte{0x02}, 16)
	plaintext := []byte("SM4 roundtrip test 16B pad")

	enc, err := NewCipherCtx(SM4CBC(), key, iv, true)
	if err != nil {
		t.Fatalf("NewCipherCtx(enc): %v", err)
	}
	defer enc.Close()

	ct1, err := enc.Update(plaintext)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	ct2, err := enc.Final()
	if err != nil {
		t.Fatalf("Final: %v", err)
	}
	ciphertext := append(ct1, ct2...)
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext equals plaintext (no encryption happened)")
	}

	dec, err := NewCipherCtx(SM4CBC(), key, iv, false)
	if err != nil {
		t.Fatalf("NewCipherCtx(dec): %v", err)
	}
	defer dec.Close()
	pt1, err := dec.Update(ciphertext)
	if err != nil {
		t.Fatalf("dec Update: %v", err)
	}
	pt2, err := dec.Final()
	if err != nil {
		t.Fatalf("dec Final: %v", err)
	}
	decrypted := append(pt1, pt2...)
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("roundtrip mismatch: got %q want %q", decrypted, plaintext)
	}
}

// TestCipherInvalidKeyLength 验证错误密钥长度返回明确错误。
func TestCipherInvalidKeyLength(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 8) // 错误长度
	iv := bytes.Repeat([]byte{0x02}, 16)
	if _, err := NewCipherCtx(SM4CBC(), key, iv, true); err == nil {
		t.Fatal("invalid key length should error")
	}
}

// TestCipherInvalidIVLength 验证错误 IV 长度返回明确错误。
func TestCipherInvalidIVLength(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16)
	iv := bytes.Repeat([]byte{0x02}, 8) // 错误长度
	if _, err := NewCipherCtx(SM4CBC(), key, iv, true); err == nil {
		t.Fatal("invalid iv length should error")
	}
}

// TestCipherNilCipher 验证 nil cipher 返回错误。
func TestCipherNilCipher(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16)
	iv := bytes.Repeat([]byte{0x02}, 16)
	if _, err := NewCipherCtx(nil, key, iv, true); err == nil {
		t.Fatal("nil cipher should error")
	}
}

// TestCipherClosedContext 验证关闭后的 ctx 操作返回错误。
func TestCipherClosedContext(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16)
	iv := bytes.Repeat([]byte{0x02}, 16)
	c, err := NewCipherCtx(SM4CBC(), key, iv, true)
	if err != nil {
		t.Fatalf("NewCipherCtx: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := c.Update([]byte("hello")); err == nil {
		t.Fatal("Update on closed ctx should error")
	}
	if _, err := c.Final(); err == nil {
		t.Fatal("Final on closed ctx should error")
	}
	if err := c.SetPadding(false); err == nil {
		t.Fatal("SetPadding on closed ctx should error")
	}
}

// TestCipherIdempotentClose 验证 CipherCtx.Close 幂等。
func TestCipherIdempotentClose(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16)
	iv := bytes.Repeat([]byte{0x02}, 16)
	c, err := NewCipherCtx(SM4CBC(), key, iv, true)
	if err != nil {
		t.Fatalf("NewCipherCtx: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
