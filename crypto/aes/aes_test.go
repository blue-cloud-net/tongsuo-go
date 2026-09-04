package aes

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// NIST FIPS 197 附录 B/C 标准向量（ECB 单块，无填充）。
func TestBlockStandardVectors(t *testing.T) {
	vectors := []struct {
		name string
		key  string
		in   string
		want string
	}{
		{"aes-128", "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"},
		{"aes-256", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"},
	}
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			key := mustHex(t, v.key)
			in := mustHex(t, v.in)
			want := mustHex(t, v.want)
			blk, err := NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			var out [BlockSize]byte
			blk.Encrypt(out[:], in)
			if !bytes.Equal(out[:], want) {
				t.Fatalf("AES encrypt = %x, want %x", out, want)
			}
			var back [BlockSize]byte
			blk.Decrypt(back[:], out[:])
			if !bytes.Equal(back[:], in) {
				t.Fatalf("AES decrypt = %x, want %x", back, in)
			}
		})
	}
}

// TestBlockWithStdlibCBC 验证 cipher.Block 可与标准库 CBC 组合。
func TestBlockWithStdlibCBC(t *testing.T) {
	key := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	blk, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	var _ cipher.Block = blk
	iv := bytes.Repeat([]byte{0x11}, BlockSize)
	data := bytes.Repeat([]byte("aes-cbc-data"), 16) // 128 字节，块对齐
	enc := cipher.NewCBCEncrypter(blk, iv)
	ct := make([]byte, len(data))
	enc.CryptBlocks(ct, data)
	dec := cipher.NewCBCDecrypter(blk, iv)
	pt := make([]byte, len(ct))
	dec.CryptBlocks(pt, ct)
	if !bytes.Equal(pt, data) {
		t.Fatal("stdlib CBC roundtrip mismatch")
	}
}

// modeRoundTrip 表驱动验证各模式往返。
func modeRoundTrip(t *testing.T, name string, keyLen int,
	enc, dec func(key, iv, data []byte) ([]byte, error)) {
	t.Helper()
	key := bytes.Repeat([]byte{byte(keyLen)}, keyLen)
	iv := bytes.Repeat([]byte{0x33}, BlockSize)
	for _, data := range [][]byte{
		{},
		[]byte("a"),
		bytes.Repeat([]byte("y"), 15),
		bytes.Repeat([]byte("y"), 16),
		bytes.Repeat([]byte("y"), 17),
		bytes.Repeat([]byte("y"), 100),
	} {
		ct, err := enc(key, iv, data)
		if err != nil {
			t.Fatalf("%s enc: %v", name, err)
		}
		pt, err := dec(key, iv, ct)
		if err != nil {
			t.Fatalf("%s dec: %v", name, err)
		}
		if !bytes.Equal(pt, data) {
			t.Fatalf("%s roundtrip mismatch for len %d", name, len(data))
		}
	}
}

// TestECBRoundTrip 验证 AES-128/256 ECB 往返（PKCS7 填充）。
func TestECBRoundTrip(t *testing.T) {
	for _, keyLen := range []int{16, 32} {
		key := bytes.Repeat([]byte{byte(keyLen)}, keyLen)
		for _, data := range [][]byte{{}, []byte("x"), bytes.Repeat([]byte("z"), 33)} {
			ct, err := EncryptECB(key, data)
			if err != nil {
				t.Fatal(err)
			}
			pt, err := DecryptECB(key, ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pt, data) {
				t.Fatalf("ECB roundtrip mismatch for keylen %d", keyLen)
			}
		}
	}
}

func TestCBCRoundTrip(t *testing.T) {
	modeRoundTrip(t, "CBC-128", 16, EncryptCBC, DecryptCBC)
	modeRoundTrip(t, "CBC-256", 32, EncryptCBC, DecryptCBC)
}

func TestCTRRoundTrip(t *testing.T) {
	modeRoundTrip(t, "CTR-128", 16, EncryptCTR, DecryptCTR)
	modeRoundTrip(t, "CTR-256", 32, EncryptCTR, DecryptCTR)
}

// TestGCMRoundTrip 验证 AES-GCM 加解密往返（含 AAD）。
func TestGCMRoundTrip(t *testing.T) {
	for _, keyLen := range []int{16, 32} {
		key := bytes.Repeat([]byte{byte(keyLen)}, keyLen)
		nonce := bytes.Repeat([]byte{0x44}, NonceSize)
		aad := []byte("aad")
		plain := bytes.Repeat([]byte("gcm"), 10)
		ct, tag, err := EncryptGCM(key, nonce, plain, aad)
		if err != nil {
			t.Fatal(err)
		}
		if len(tag) != TagSize {
			t.Fatalf("tag len %d", len(tag))
		}
		pt, err := DecryptGCM(key, nonce, ct, tag, aad)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pt, plain) {
			t.Fatal("GCM roundtrip mismatch")
		}
	}
}

// TestGCMTamper 验证篡改 tag 解密失败。
func TestGCMTamper(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16)
	nonce := bytes.Repeat([]byte{0x44}, NonceSize)
	ct, tag, err := EncryptGCM(key, nonce, []byte("data"), nil)
	if err != nil {
		t.Fatal(err)
	}
	badTag := append([]byte(nil), tag...)
	badTag[0] ^= 0x01
	if _, err := DecryptGCM(key, nonce, ct, badTag, nil); err == nil {
		t.Fatal("expected error for tampered tag")
	}
}

// TestAEADInterface 验证 NewGCM 实现 cipher.AEAD。
func TestAEADInterface(t *testing.T) {
	key := bytes.Repeat([]byte{0x02}, 32)
	aead, err := NewGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	var _ cipher.AEAD = aead
	nonce := bytes.Repeat([]byte{0x55}, NonceSize)
	plain := []byte("sealed")
	sealed := aead.Seal(nil, nonce, plain, nil)
	opened, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plain) {
		t.Fatal("AEAD roundtrip mismatch")
	}
}

// TestInvalidKey 验证非法密钥长度返回错误。
func TestInvalidKey(t *testing.T) {
	if _, err := NewCipher([]byte("short")); err == nil {
		t.Fatal("expected error for short key")
	}
	if _, err := EncryptECB([]byte("short"), []byte("data")); err == nil {
		t.Fatal("expected error for short key")
	}
}

// TestBlockConcurrent 验证 cipher.Block 可被多 goroutine 并发复用（stdlib 契约）。
// 启用 -race 时会捕获对共享原生 EVP_CIPHER_CTX 的数据竞争。
func TestBlockConcurrent(t *testing.T) {
	key := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	in := mustHex(t, "00112233445566778899aabbccddeeff")
	want := mustHex(t, "69c4e0d86a7b0430d8cdb78070b4c55a")
	blk, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	const goroutines = 32
	done := make(chan struct{}, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			var out [BlockSize]byte
			for j := 0; j < 100; j++ {
				blk.Encrypt(out[:], in)
				if !bytes.Equal(out[:], want) {
					t.Errorf("concurrent encrypt mismatch: got %x want %x", out[:], want)
					return
				}
			}
		}()
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
}
