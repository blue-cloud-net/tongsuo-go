package sm4

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

// GB/T 32907-2016 附录 A 标准向量：密钥与明文均为 0123456789abcdeffedcba9876543210。
var (
	vectorKey = mustHexT("0123456789abcdeffedcba9876543210")
	vectorIn  = mustHexT("0123456789abcdeffedcba9876543210")
)

func mustHexT(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// TestBlockStandardVector 验证 SM4 单块加密标准向量。
// 明文 0123456789abcdeffedcba9876543210 → 密文 681edf34d206965e86b3e94f536e4246。
func TestBlockStandardVector(t *testing.T) {
	want := mustHex(t, "681edf34d206965e86b3e94f536e4246")
	blk, err := NewCipher(vectorKey)
	if err != nil {
		t.Fatal(err)
	}
	var out [BlockSize]byte
	blk.Encrypt(out[:], vectorIn)
	if !bytes.Equal(out[:], want) {
		t.Fatalf("SM4 encrypt = %x, want %x", out, want)
	}
	var back [BlockSize]byte
	blk.Decrypt(back[:], out[:])
	if !bytes.Equal(back[:], vectorIn) {
		t.Fatalf("SM4 decrypt = %x, want %x", back, vectorIn)
	}
}

// TestBlockInterface 验证 NewCipher 返回的对象实现了 cipher.Block。
func TestBlockInterface(t *testing.T) {
	var _ cipher.Block
	blk, err := NewCipher(vectorKey)
	if err != nil {
		t.Fatal(err)
	}
	var _ cipher.Block = blk
	if blk.BlockSize() != BlockSize {
		t.Fatalf("BlockSize = %d, want %d", blk.BlockSize(), BlockSize)
	}
}

// TestBlockWithStdlibCBC 验证 cipher.Block 可与标准库 cipher.NewCBCEncrypter 组合。
func TestBlockWithStdlibCBC(t *testing.T) {
	blk, err := NewCipher(vectorKey)
	if err != nil {
		t.Fatal(err)
	}
	iv := bytes.Repeat([]byte{0x22}, BlockSize)
	data := bytes.Repeat([]byte("tongsuo-cbc"), 16) // 176 字节，块对齐

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

// TestZeroPaddingECBRoundTrip 验证 SM4-ECB Zero 填充加解密往返。
func TestZeroPaddingECBRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef")
	for _, data := range [][]byte{
		[]byte("a"),
		bytes.Repeat([]byte("x"), 15),
		bytes.Repeat([]byte("x"), 16),
		bytes.Repeat([]byte("tongsuo"), 7), // 49 字节
	} {
		ct, err := EncryptECBZero(key, data)
		if err != nil {
			t.Fatal(err)
		}
		if len(ct)%BlockSize != 0 {
			t.Fatalf("ciphertext not block aligned: %d", len(ct))
		}
		pt, err := DecryptECBZero(key, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pt, data) {
			t.Fatalf("zero-padding ECB roundtrip mismatch: got %q want %q", pt, data)
		}
	}
}

// TestZeroPaddingCBCRoundTrip 验证 SM4-CBC Zero 填充加解密往返。
func TestZeroPaddingCBCRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := bytes.Repeat([]byte{0x11}, BlockSize)
	for _, data := range [][]byte{
		[]byte("a"),
		bytes.Repeat([]byte("y"), 32),
		bytes.Repeat([]byte("tongsuo-cbc"), 5), // 60 字节
	} {
		ct, err := EncryptCBCZero(key, iv, data)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := DecryptCBCZero(key, iv, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pt, data) {
			t.Fatalf("zero-padding CBC roundtrip mismatch: got %q want %q", pt, data)
		}
	}
}

// TestZeroPaddingInvalidIV 验证 Zero 填充 CBC 对非法 IV 报错。
func TestZeroPaddingInvalidIV(t *testing.T) {
	if _, err := EncryptCBCZero([]byte("0123456789abcdef"), []byte("short"), []byte("x")); err == nil {
		t.Fatal("expected error for short IV")
	}
}

// TestECBRoundTrip 验证 SM4-ECB 加解密往返（含不同长度与填充）。
func TestECBRoundTrip(t *testing.T) {
	for _, data := range [][]byte{
		{},
		[]byte("a"),
		bytes.Repeat([]byte("x"), 15),
		bytes.Repeat([]byte("x"), 16),
		bytes.Repeat([]byte("x"), 17),
		bytes.Repeat([]byte("x"), 64),
	} {
		ct, err := EncryptECB(vectorKey, data)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := DecryptECB(vectorKey, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pt, data) {
			t.Fatalf("ECB roundtrip mismatch: in=%x out=%x", data, pt)
		}
	}
}

// TestCBCRoundTrip 验证 SM4-CBC 加解密往返。
func TestCBCRoundTrip(t *testing.T) {
	iv := bytes.Repeat([]byte{0x11}, BlockSize)
	data := bytes.Repeat([]byte("tongsuo"), 20) // 非块对齐长度
	ct, err := EncryptCBC(vectorKey, iv, data)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := DecryptCBC(vectorKey, iv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, data) {
		t.Fatal("CBC roundtrip mismatch")
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

// TestInvalidIV 验证非法 IV 长度返回错误。
func TestInvalidIV(t *testing.T) {
	if _, err := EncryptCBC(vectorKey, []byte("bad"), []byte("data")); err == nil {
		t.Fatal("expected error for bad iv")
	}
}

// TestWrongKeyDecrypt 验证使用错误密钥解密不会得到原明文。
func TestWrongKeyDecrypt(t *testing.T) {
	ct, err := EncryptECB(vectorKey, []byte("secret message"))
	if err != nil {
		t.Fatal(err)
	}
	other := bytes.Repeat([]byte{0xAB}, KeySize)
	pt, _ := DecryptECB(other, ct)
	if bytes.Equal(pt, []byte("secret message")) {
		t.Fatal("decrypt with wrong key returned plaintext")
	}
}

// streamRoundTrip 表驱动验证流模式（CTR/OFB/CFB）往返。
func streamRoundTrip(t *testing.T, name string, enc, dec func(key, iv, data []byte) ([]byte, error)) {
	t.Helper()
	iv := bytes.Repeat([]byte{0x33}, BlockSize)
	for _, data := range [][]byte{
		{},
		[]byte("a"),
		bytes.Repeat([]byte("y"), 15),
		bytes.Repeat([]byte("y"), 16),
		bytes.Repeat([]byte("y"), 17),
		bytes.Repeat([]byte("y"), 100),
	} {
		ct, err := enc(vectorKey, iv, data)
		if err != nil {
			t.Fatalf("%s encrypt: %v", name, err)
		}
		if len(ct) != len(data) {
			t.Fatalf("%s output length %d, want %d", name, len(ct), len(data))
		}
		pt, err := dec(vectorKey, iv, ct)
		if err != nil {
			t.Fatalf("%s decrypt: %v", name, err)
		}
		if !bytes.Equal(pt, data) {
			t.Fatalf("%s roundtrip mismatch", name)
		}
	}
}

// TestCTRRoundTrip 验证 SM4-CTR 往返（流模式，长度不变）。
func TestCTRRoundTrip(t *testing.T) {
	streamRoundTrip(t, "CTR", EncryptCTR, DecryptCTR)
}

// TestOFBRoundTrip 验证 SM4-OFB 往返。
func TestOFBRoundTrip(t *testing.T) {
	streamRoundTrip(t, "OFB", EncryptOFB, DecryptOFB)
}

// TestCFBRoundTrip 验证 SM4-CFB 往返。
func TestCFBRoundTrip(t *testing.T) {
	streamRoundTrip(t, "CFB", EncryptCFB, DecryptCFB)
}

// TestGCMRoundTrip 验证 SM4-GCM 认证加解密往返（含 AAD）。
func TestGCMRoundTrip(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x44}, NonceSize)
	aad := []byte("associated data")
	plain := bytes.Repeat([]byte("gcm-data"), 10)

	ct, tag, err := EncryptGCM(vectorKey, nonce, plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != len(plain) {
		t.Fatalf("ciphertext length %d, want %d", len(ct), len(plain))
	}
	if len(tag) != TagSize {
		t.Fatalf("tag length %d, want %d", len(tag), TagSize)
	}
	pt, err := DecryptGCM(vectorKey, nonce, ct, tag, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, plain) {
		t.Fatal("GCM roundtrip mismatch")
	}
}

// TestGCMAADMismatch 验证 AAD 不一致时解密失败。
func TestGCMAADMismatch(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x44}, NonceSize)
	plain := []byte("hello gcm")
	ct, tag, err := EncryptGCM(vectorKey, nonce, plain, []byte("aad-A"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptGCM(vectorKey, nonce, ct, tag, []byte("aad-B")); err == nil {
		t.Fatal("expected error for mismatched AAD")
	}
}

// TestGCMTamper 验证篡改密文或 tag 均解密失败。
func TestGCMTamper(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x44}, NonceSize)
	plain := bytes.Repeat([]byte("tamper-me"), 5)
	ct, tag, err := EncryptGCM(vectorKey, nonce, plain, nil)
	if err != nil {
		t.Fatal(err)
	}

	// 篡改密文末尾字节
	badCt := append([]byte(nil), ct...)
	badCt[len(badCt)-1] ^= 0x01
	if _, err := DecryptGCM(vectorKey, nonce, badCt, tag, nil); err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}

	// 篡改 tag
	badTag := append([]byte(nil), tag...)
	badTag[0] ^= 0x01
	if _, err := DecryptGCM(vectorKey, nonce, ct, badTag, nil); err == nil {
		t.Fatal("expected error for tampered tag")
	}
}

// TestGCMInvalidNonce 验证空 nonce 返回错误。
func TestGCMInvalidNonce(t *testing.T) {
	if _, _, err := EncryptGCM(vectorKey, nil, []byte("x"), nil); err == nil {
		t.Fatal("expected error for empty nonce")
	}
}

// TestAEADInterface 验证 NewGCM 返回的对象实现了 cipher.AEAD 且 Seal/Open 往返。
func TestAEADInterface(t *testing.T) {
	aead, err := NewGCM(vectorKey)
	if err != nil {
		t.Fatal(err)
	}
	var _ cipher.AEAD = aead
	if aead.NonceSize() != NonceSize || aead.Overhead() != TagSize {
		t.Fatalf("NonceSize=%d Overhead=%d", aead.NonceSize(), aead.Overhead())
	}

	nonce := bytes.Repeat([]byte{0x55}, NonceSize)
	plain := []byte("sealed message")
	aad := []byte("aad")
	sealed := aead.Seal(nil, nonce, plain, aad)
	if len(sealed) != len(plain)+TagSize {
		t.Fatalf("sealed length %d, want %d", len(sealed), len(plain)+TagSize)
	}
	opened, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plain) {
		t.Fatal("AEAD roundtrip mismatch")
	}
}

// TestGCMBlockAligned 验证任意长度明文（含块对齐）GCM 往返。
func TestGCMBlockAligned(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x66}, NonceSize)
	for _, n := range []int{0, 1, 15, 16, 17, 64} {
		plain := bytes.Repeat([]byte{0x77}, n)
		ct, tag, err := EncryptGCM(vectorKey, nonce, plain, nil)
		if err != nil {
			t.Fatalf("encrypt len %d: %v", n, err)
		}
		pt, err := DecryptGCM(vectorKey, nonce, ct, tag, nil)
		if err != nil {
			t.Fatalf("decrypt len %d: %v", n, err)
		}
		if !bytes.Equal(pt, plain) {
			t.Fatalf("roundtrip mismatch for len %d", n)
		}
	}
}

// TestBlockConcurrent 验证 cipher.Block 可被多 goroutine 并发复用（stdlib 契约）。
// 启用 -race 时会捕获对共享原生 EVP_CIPHER_CTX 的数据竞争。
func TestBlockConcurrent(t *testing.T) {
	blk, err := NewCipher(vectorKey)
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "681edf34d206965e86b3e94f536e4246")
	const goroutines = 32
	done := make(chan struct{}, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			var out [BlockSize]byte
			for j := 0; j < 100; j++ {
				blk.Encrypt(out[:], vectorIn)
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
