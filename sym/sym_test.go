package sym

import (
	"bytes"
	"errors"
	"testing"
)

// TestAESKeyBasic 验证 AESKey 构造、长度、相等性。
func TestAESKeyBasic(t *testing.T) {
	raw := bytes.Repeat([]byte{0xab}, AES128KeySize)
	k, err := NewAESKey(raw)
	if err != nil {
		t.Fatalf("NewAESKey: %v", err)
	}
	if k.Algorithm() != AlgAES128 {
		t.Errorf("alg = %s, want AES-128", k.Algorithm())
	}
	if k.Size() != AES128KeySize {
		t.Errorf("size = %d, want %d", k.Size(), AES128KeySize)
	}
	if !bytes.Equal(k.Bytes(), raw) {
		t.Errorf("Bytes = %x, want %x", k.Bytes(), raw)
	}

	// 修改 Bytes 不影响内部状态
	got := k.Bytes()
	got[0] = 0x00
	if k.Bytes()[0] != 0xab {
		t.Error("Bytes should be a copy")
	}

	// Equal 与不同算法 / 不同字节
	k2, _ := NewAESKey(bytes.Repeat([]byte{0xcd}, AES128KeySize))
	if k.Equal(k2) {
		t.Error("different bytes should not be equal")
	}
	if !k.Equal(k) {
		t.Error("same key should equal itself")
	}
	if k.Equal(nil) {
		t.Error("Equal(nil) must return false")
	}
}

// TestAESKeyInvalidSize 验证 AES 密钥长度校验。
func TestAESKeyInvalidSize(t *testing.T) {
	if _, err := NewAESKey(make([]byte, 24)); err == nil {
		t.Error("want error for invalid AES key size 24")
	}
}

// TestAESKey256 验证 AES-256 密钥构造。
func TestAESKey256(t *testing.T) {
	raw := bytes.Repeat([]byte{0x11}, AES256KeySize)
	k, err := NewAESKey(raw)
	if err != nil {
		t.Fatalf("NewAESKey(AES-256): %v", err)
	}
	if k.Algorithm() != AlgAES256 {
		t.Errorf("alg = %s, want AES-256", k.Algorithm())
	}
	if k.Size() != AES256KeySize {
		t.Errorf("size = %d, want %d", k.Size(), AES256KeySize)
	}
}

// TestSM4KeyBasic 验证 SM4Key 构造与 Marshal/Parse 往返。
func TestSM4KeyBasic(t *testing.T) {
	raw := bytes.Repeat([]byte{0x42}, SM4KeySize)
	k, err := NewSM4Key(raw)
	if err != nil {
		t.Fatalf("NewSM4Key: %v", err)
	}
	if k.Algorithm() != AlgSM4 {
		t.Errorf("alg = %s, want SM4", k.Algorithm())
	}
	if k.Size() != SM4KeySize {
		t.Errorf("size = %d, want %d", k.Size(), SM4KeySize)
	}

	// Marshal / Parse 往返
	pem, err := k.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	k2, err := ParseSymmetricKey(pem)
	if err != nil {
		t.Fatalf("ParseSymmetricKey: %v", err)
	}
	if !k.Equal(k2) {
		t.Error("Marshal/Parse round-trip not equal")
	}

	// Equal 与 nil
	if k.Equal(nil) {
		t.Error("Equal(nil) must return false")
	}

	// invalid size
	if _, err := NewSM4Key(make([]byte, 17)); err == nil {
		t.Error("want error for invalid SM4 key size 17")
	}
}

// TestGenerateSymmetricKey 验证 GenerateSymmetricKey 三种算法。
func TestGenerateSymmetricKey(t *testing.T) {
	for _, alg := range []Algorithm{AlgAES128, AlgAES256, AlgSM4} {
		t.Run(string(alg), func(t *testing.T) {
			k, err := GenerateSymmetricKey(alg)
			if err != nil {
				t.Fatalf("GenerateSymmetricKey(%s): %v", alg, err)
			}
			if k.Algorithm() != alg {
				t.Errorf("alg = %s, want %s", k.Algorithm(), alg)
			}
		})
	}
	// 未知算法返回 ErrUnknownAlgorithm
	if _, err := GenerateSymmetricKey(Algorithm("RSA")); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Errorf("GenerateSymmetricKey(RSA) err = %v, want ErrUnknownAlgorithm", err)
	}
}

// TestParseSymmetricKeyInvalid 验证 ParseSymmetricKey 错误路径。
func TestParseSymmetricKeyInvalid(t *testing.T) {
	if _, err := ParseSymmetricKey(nil); err == nil {
		t.Error("want error for nil PEM")
	}
	if _, err := ParseSymmetricKey([]byte("not pem")); err == nil {
		t.Error("want error for non-PEM data")
	}
	// 未知算法 PEM
	bad := []byte("-----BEGIN SYMMETRIC KEY-----\n" +
		"Algorithm: NO-SUCH\n" +
		"\n" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n" +
		"-----END SYMMETRIC KEY-----\n")
	if _, err := ParseSymmetricKey(bad); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Errorf("bad algorithm err = %v, want ErrUnknownAlgorithm", err)
	}
}

// TestEncryptAES128ECBCLI 验证 EncryptAESECB 与铜锁 CLI 字节级一致。
// Tongsuo 8.5.0-pre2 实测：16 字节 raw key（"0123456789abcdef" ASCII）、
// data="Hello, sym!"、PKCS#7 padding → 16 字节密文 = 9b45fc900938bfd7b436a9fb338e1dd0
func TestEncryptAES128ECBCLI(t *testing.T) {
	const wantHex = "9b45fc900938bfd7b436a9fb338e1dd0"
	key := []byte("0123456789abcdef")
	data := []byte("Hello, sym!")

	got, err := EncryptAESECB(key, data)
	if err != nil {
		t.Fatalf("EncryptAESECB: %v", err)
	}
	want, _ := hexDecode(wantHex)
	if !bytes.Equal(got, want) {
		t.Errorf("EncryptAESECB = %x, want %s", got, wantHex)
	}

	// 解密回 round-trip
	back, err := DecryptAESECB(key, got)
	if err != nil {
		t.Fatalf("DecryptAESECB: %v", err)
	}
	if !bytes.Equal(back, data) {
		t.Errorf("decrypt = %q, want %q", back, data)
	}
}

// TestEncryptAES256CBCCLI 验证 AES-256-CBC 与 CLI 对拍。
func TestEncryptAES256CBCCLI(t *testing.T) {
	const wantHex = "7c434b3d90fc09b517deb8fc86d012a7"
	key := []byte("0123456789abcdef0123456789abcdef")
	iv := []byte("fedcba9876543210")
	data := []byte("Hello, sym!")

	got, err := EncryptAESCBC(key, iv, data)
	if err != nil {
		t.Fatalf("EncryptAESCBC: %v", err)
	}
	want, _ := hexDecode(wantHex)
	if !bytes.Equal(got, want) {
		t.Errorf("EncryptAESCBC = %x, want %s", got, wantHex)
	}

	back, err := DecryptAESCBC(key, iv, got)
	if err != nil {
		t.Fatalf("DecryptAESCBC: %v", err)
	}
	if !bytes.Equal(back, data) {
		t.Errorf("decrypt = %q, want %q", back, data)
	}
}

// TestEncryptSM4ECBCLI 验证 SM4-ECB 与 CLI 对拍。
func TestEncryptSM4ECBCLI(t *testing.T) {
	const wantHex = "073e53512b2430a5f1f30c8dab29e658"
	key := []byte("0123456789abcdef")
	data := []byte("Hello, sym!")

	got, err := EncryptSM4ECB(key, data)
	if err != nil {
		t.Fatalf("EncryptSM4ECB: %v", err)
	}
	want, _ := hexDecode(wantHex)
	if !bytes.Equal(got, want) {
		t.Errorf("EncryptSM4ECB = %x, want %s", got, wantHex)
	}

	back, err := DecryptSM4ECB(key, got)
	if err != nil {
		t.Fatalf("DecryptSM4ECB: %v", err)
	}
	if !bytes.Equal(back, data) {
		t.Errorf("decrypt = %q, want %q", back, data)
	}
}

// TestEncryptSM4CBCCLI 验证 SM4-CBC 与 CLI 对拍。
func TestEncryptSM4CBCCLI(t *testing.T) {
	const wantHex = "c186f65ec5ec257e74bdd73d4cdf98c9"
	key := []byte("0123456789abcdef")
	iv := []byte("fedcba9876543210")
	data := []byte("Hello, sym!")

	got, err := EncryptSM4CBC(key, iv, data)
	if err != nil {
		t.Fatalf("EncryptSM4CBC: %v", err)
	}
	want, _ := hexDecode(wantHex)
	if !bytes.Equal(got, want) {
		t.Errorf("EncryptSM4CBC = %x, want %s", got, wantHex)
	}

	back, err := DecryptSM4CBC(key, iv, got)
	if err != nil {
		t.Fatalf("DecryptSM4CBC: %v", err)
	}
	if !bytes.Equal(back, data) {
		t.Errorf("decrypt = %q, want %q", back, data)
	}
}

// TestNewCipher 验证按名 NewCipher 的成功/失败路径。
func TestNewCipher(t *testing.T) {
	t.Run("AES-128-CBC", func(t *testing.T) {
		b, err := NewCipher("AES-128-CBC", make([]byte, AES128KeySize))
		if err != nil {
			t.Fatal(err)
		}
		if b.BlockSize() != BlockSize {
			t.Errorf("BlockSize = %d, want %d", b.BlockSize(), BlockSize)
		}
	})
	t.Run("AES-256-ECB", func(t *testing.T) {
		b, err := NewCipher("AES-256-ECB", make([]byte, AES256KeySize))
		if err != nil {
			t.Fatal(err)
		}
		if b.BlockSize() != BlockSize {
			t.Errorf("BlockSize = %d", b.BlockSize())
		}
	})
	t.Run("SM4-CBC", func(t *testing.T) {
		b, err := NewCipher("SM4-CBC", make([]byte, SM4KeySize))
		if err != nil {
			t.Fatal(err)
		}
		if b.BlockSize() != BlockSize {
			t.Errorf("BlockSize = %d", b.BlockSize())
		}
	})
	t.Run("GCM-not-supported", func(t *testing.T) {
		_, err := NewCipher("AES-128-GCM", make([]byte, AES128KeySize))
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("NewCipher(GCM) err = %v, want ErrUnsupported", err)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		_, err := NewCipher("XX-128-CBC", make([]byte, AES128KeySize))
		if !errors.Is(err, ErrUnknownAlgorithm) {
			t.Errorf("NewCipher(unknown) err = %v, want ErrUnknownAlgorithm", err)
		}
	})
	t.Run("key-length", func(t *testing.T) {
		_, err := NewCipher("AES-256-CBC", make([]byte, AES128KeySize))
		if !errors.Is(err, ErrInvalidKeyLength) {
			t.Errorf("NewCipher(wrong-key) err = %v, want ErrInvalidKeyLength", err)
		}
	})
}

// TestNewGCM 验证按名 NewGCM。
func TestNewGCM(t *testing.T) {
	t.Run("AES-128-GCM", func(t *testing.T) {
		aead, err := NewGCM("AES-128-GCM", make([]byte, AES128KeySize))
		if err != nil {
			t.Fatal(err)
		}
		if aead.NonceSize() != NonceSize {
			t.Errorf("NonceSize = %d, want %d", aead.NonceSize(), NonceSize)
		}
		if aead.Overhead() != TagSize {
			t.Errorf("Overhead = %d, want %d", aead.Overhead(), TagSize)
		}
	})
	t.Run("SM4-GCM", func(t *testing.T) {
		aead, err := NewGCM("SM4-GCM", make([]byte, SM4KeySize))
		if err != nil {
			t.Fatal(err)
		}
		if aead.NonceSize() != NonceSize {
			t.Errorf("NonceSize = %d", aead.NonceSize())
		}
	})
	t.Run("non-GCM", func(t *testing.T) {
		_, err := NewGCM("AES-128-CBC", make([]byte, AES128KeySize))
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("NewGCM(non-GCM) err = %v, want ErrUnsupported", err)
		}
	})
}

// TestNames 验证 Names 返回稳定且完整。
func TestNames(t *testing.T) {
	want := []string{
		"AES-128-CBC", "AES-128-CTR", "AES-128-ECB", "AES-128-GCM",
		"AES-256-CBC", "AES-256-CTR", "AES-256-ECB", "AES-256-GCM",
		"SM4-CBC", "SM4-CTR", "SM4-ECB", "SM4-OFB", "SM4-CFB", "SM4-GCM",
	}
	got := Names()
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestEncryptByName 验证按名 Encrypt/Decrypt 路径一致（round-trip）。
func TestEncryptByName(t *testing.T) {
	cases := []struct {
		name string
		key  []byte
		iv   []byte
	}{
		{"AES-128-CBC", make([]byte, AES128KeySize), make([]byte, BlockSize)},
		{"AES-128-CTR", make([]byte, AES128KeySize), make([]byte, BlockSize)},
		{"AES-128-ECB", make([]byte, AES128KeySize), nil},
		{"AES-256-CBC", make([]byte, AES256KeySize), make([]byte, BlockSize)},
		{"SM4-CBC", make([]byte, SM4KeySize), make([]byte, BlockSize)},
		{"SM4-CTR", make([]byte, SM4KeySize), make([]byte, BlockSize)},
		{"SM4-ECB", make([]byte, SM4KeySize), nil},
		{"SM4-OFB", make([]byte, SM4KeySize), make([]byte, BlockSize)},
		{"SM4-CFB", make([]byte, SM4KeySize), make([]byte, BlockSize)},
	}
	data := []byte("the quick brown fox jumps over the lazy dog")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ct, err := Encrypt(c.name, c.key, c.iv, data, nil)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			pt, err := Decrypt(c.name, c.key, c.iv, ct, nil)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(pt, data) {
				t.Errorf("round-trip = %q, want %q", pt, data)
			}
		})
	}
}

// TestEncryptGCMByName 验证按名 GCM 路径。
func TestEncryptGCMByName(t *testing.T) {
	cases := []struct {
		name string
		key  []byte
	}{
		{"AES-128-GCM", make([]byte, AES128KeySize)},
		{"AES-256-GCM", make([]byte, AES256KeySize)},
		{"SM4-GCM", make([]byte, SM4KeySize)},
	}
	nonce := make([]byte, NonceSize)
	data := []byte("hello sym gcm")
	aad := []byte("aad-context")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ct, tag, err := EncryptGCM(c.name, c.key, nonce, data, aad)
			if err != nil {
				t.Fatalf("EncryptGCM: %v", err)
			}
			if len(tag) != TagSize {
				t.Errorf("tag len = %d, want %d", len(tag), TagSize)
			}
			pt, err := DecryptGCM(c.name, c.key, nonce, ct, tag, aad)
			if err != nil {
				t.Fatalf("DecryptGCM: %v", err)
			}
			if !bytes.Equal(pt, data) {
				t.Errorf("round-trip = %q, want %q", pt, data)
			}

			// tag 错误应该报错
			badTag := make([]byte, TagSize)
			if _, err := DecryptGCM(c.name, c.key, nonce, ct, badTag, aad); err == nil {
				t.Error("want error for tampered tag")
			}
		})
	}
}

// hexDecode 是 encoding/hex.DecodeString 的本地短别名。
func hexDecode(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		var hi, lo byte
		var err error
		if hi, err = unhex(s[i*2]); err != nil {
			return nil, err
		}
		if lo, err = unhex(s[i*2+1]); err != nil {
			return nil, err
		}
		out[i] = (hi << 4) | lo
	}
	return out, nil
}

func unhex(c byte) (byte, error) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', nil
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, nil
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, errors.New("invalid hex")
}
