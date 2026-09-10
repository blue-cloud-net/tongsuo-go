package sm4

import (
	"bytes"
	"testing"
)

// FuzzRoundTrip 模糊测试 SM4 各模式加解密往返。
func FuzzRoundTrip(f *testing.F) {
	// seed corpus
	f.Add([]byte("hello"), []byte("0123456789abcdef"), []byte("fedcba9876543210"), byte(0))
	f.Add([]byte(""), []byte("0123456789abcdef"), []byte("fedcba9876543210"), byte(1))
	f.Add(bytes.Repeat([]byte{0xff}, 64), []byte("0123456789abcdef"), []byte("fedcba9876543210"), byte(2))
	f.Add(bytes.Repeat([]byte{0x00}, 64), []byte("0123456789abcdef"), []byte("fedcba9876543210"), byte(3))

	f.Fuzz(func(t *testing.T, plaintext, key, iv []byte, mode byte) {
		// SM4 密钥必须为 16 字节；测试仅在合法长度下进行
		if len(key) != 16 {
			return
		}
		// IV 长度要求因模式而异（CBC/CTR/OFB/CFB = 16，ECB = 0）
		switch mode % 5 {
		case 0: // ECB
			ct, err := EncryptECB(key, plaintext)
			if err != nil {
				return
			}
			pt, err := DecryptECB(key, ct)
			if err != nil {
				return
			}
			if !bytes.Equal(pt, plaintext) {
				t.Errorf("ECB mismatch\n got  %x\n want %x", pt, plaintext)
			}
		case 1: // CBC
			if len(iv) != 16 {
				return
			}
			ct, err := EncryptCBC(key, iv, plaintext)
			if err != nil {
				return
			}
			pt, err := DecryptCBC(key, iv, ct)
			if err != nil {
				return
			}
			if !bytes.Equal(pt, plaintext) {
				t.Errorf("CBC mismatch\n got  %x\n want %x", pt, plaintext)
			}
		case 2: // CTR
			if len(iv) != 16 {
				return
			}
			ct, err := EncryptCTR(key, iv, plaintext)
			if err != nil {
				return
			}
			pt, err := DecryptCTR(key, iv, ct)
			if err != nil {
				return
			}
			if !bytes.Equal(pt, plaintext) {
				t.Errorf("CTR mismatch\n got  %x\n want %x", pt, plaintext)
			}
		case 3: // OFB
			if len(iv) != 16 {
				return
			}
			ct, err := EncryptOFB(key, iv, plaintext)
			if err != nil {
				return
			}
			pt, err := DecryptOFB(key, iv, ct)
			if err != nil {
				return
			}
			if !bytes.Equal(pt, plaintext) {
				t.Errorf("OFB mismatch\n got  %x\n want %x", pt, plaintext)
			}
		case 4: // CFB
			if len(iv) != 16 {
				return
			}
			ct, err := EncryptCFB(key, iv, plaintext)
			if err != nil {
				return
			}
			pt, err := DecryptCFB(key, iv, ct)
			if err != nil {
				return
			}
			if !bytes.Equal(pt, plaintext) {
				t.Errorf("CFB mismatch\n got  %x\n want %x", pt, plaintext)
			}
		}
	})
}