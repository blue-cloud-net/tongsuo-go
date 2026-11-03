package sym

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// desCases 覆盖 DES 家族的全部「算法-模式」名及其密钥长度。
//
// desCases covers every DES-family algorithm-mode name and its key
// length.
var desCases = []struct {
	name string
	key  []byte
	iv   []byte
}{
	{"DES-ECB", bytes.Repeat([]byte{0x01}, DESKeySize), nil},
	{"DES-CBC", bytes.Repeat([]byte{0x01}, DESKeySize), bytes.Repeat([]byte{0x02}, DESBlockSize)},
	{"DES-EDE-ECB", bytes.Repeat([]byte{0x03}, DESEDEKeySize), nil},
	{"DES-EDE-CBC", bytes.Repeat([]byte{0x03}, DESEDEKeySize), bytes.Repeat([]byte{0x02}, DESBlockSize)},
	{"DES-EDE3-ECB", bytes.Repeat([]byte{0x04}, DESEDE3KeySize), nil},
	{"DES-EDE3-CBC", bytes.Repeat([]byte{0x04}, DESEDE3KeySize), bytes.Repeat([]byte{0x02}, DESBlockSize)},
}

// TestDESNamesRegistered 验证 DES 家族的六个名字已进入 Names()。
//
// TestDESNamesRegistered verifies the six DES-family names are listed by
// Names().
func TestDESNamesRegistered(t *testing.T) {
	names := Names()
	for _, want := range []string{
		"DES-ECB", "DES-CBC",
		"DES-EDE-ECB", "DES-EDE-CBC",
		"DES-EDE3-ECB", "DES-EDE3-CBC",
	} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Names() missing %q", want)
		}
	}
}

// TestDESRoundTrip 验证 DES 家族的往返加解密（PKCS#7 填充）。
//
// TestDESRoundTrip verifies the DES-family round trip with PKCS#7 padding.
func TestDESRoundTrip(t *testing.T) {
	plain := []byte("The quick brown fox jumps over 13 lazy dogs.")
	for _, c := range desCases {
		t.Run(c.name, func(t *testing.T) {
			ct, err := Encrypt(c.name, c.key, c.iv, plain, nil)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if bytes.Equal(ct, plain) {
				t.Fatal("ciphertext equals plaintext")
			}
			pt, err := Decrypt(c.name, c.key, c.iv, ct, nil)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(pt, plain) {
				t.Errorf("round trip = %q, want %q", pt, plain)
			}
		})
	}
}

// TestDESEmptyAndAligned 验证空明文与分组整数倍明文的往返。
//
// TestDESEmptyAndAligned verifies round trips for empty and block-aligned
// plaintext.
func TestDESEmptyAndAligned(t *testing.T) {
	for _, c := range desCases {
		t.Run(c.name, func(t *testing.T) {
			for _, plain := range [][]byte{{}, bytes.Repeat([]byte{0x5a}, 2*DESBlockSize)} {
				ct, err := Encrypt(c.name, c.key, c.iv, plain, nil)
				if err != nil {
					t.Fatalf("Encrypt(%d bytes): %v", len(plain), err)
				}
				if len(ct)%DESBlockSize != 0 {
					t.Errorf("ciphertext length %d is not a multiple of %d", len(ct), DESBlockSize)
				}
				pt, err := Decrypt(c.name, c.key, c.iv, ct, nil)
				if err != nil {
					t.Fatalf("Decrypt: %v", err)
				}
				if !bytes.Equal(pt, plain) {
					t.Errorf("round trip = %x, want %x", pt, plain)
				}
			}
		})
	}
}

// TestDESSingleEqualsEDE3WithRepeatedKey 验证实现所依赖的数学事实：
// 单 DES 的输出与「同一密钥重复三份」的 DES-EDE3 逐字节相同。
//
// TestDESSingleEqualsEDE3WithRepeatedKey verifies the mathematical fact
// the implementation relies on: single DES output is byte-identical to
// DES-EDE3 keyed with the same 8-byte key repeated three times.
func TestDESSingleEqualsEDE3WithRepeatedKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x7e}, DESKeySize)
	rep := append(append(append([]byte{}, key...), key...), key...)
	iv := bytes.Repeat([]byte{0x11}, DESBlockSize)
	plain := []byte("single DES must equal EDE3 with K||K||K")

	singleECB, err := Encrypt("DES-ECB", key, nil, plain, nil)
	if err != nil {
		t.Fatalf("DES-ECB: %v", err)
	}
	ede3ECB, err := Encrypt("DES-EDE3-ECB", rep, nil, plain, nil)
	if err != nil {
		t.Fatalf("DES-EDE3-ECB: %v", err)
	}
	if !bytes.Equal(singleECB, ede3ECB) {
		t.Errorf("DES-ECB != DES-EDE3-ECB(K||K||K):\n  %x\n  %x", singleECB, ede3ECB)
	}

	singleCBC, err := Encrypt("DES-CBC", key, iv, plain, nil)
	if err != nil {
		t.Fatalf("DES-CBC: %v", err)
	}
	ede3CBC, err := Encrypt("DES-EDE3-CBC", rep, iv, plain, nil)
	if err != nil {
		t.Fatalf("DES-EDE3-CBC: %v", err)
	}
	if !bytes.Equal(singleCBC, ede3CBC) {
		t.Errorf("DES-CBC != DES-EDE3-CBC(K||K||K):\n  %x\n  %x", singleCBC, ede3CBC)
	}
}

// TestDESKeyAndIVErrors 验证密钥与 IV 长度错误路径。
//
// TestDESKeyAndIVErrors verifies the key and IV length error paths.
func TestDESKeyAndIVErrors(t *testing.T) {
	plain := []byte("0123456789abcdef")
	if _, err := Encrypt("DES-CBC", make([]byte, 7), make([]byte, DESBlockSize), plain, nil); !errors.Is(err, ErrInvalidKeyLength) {
		t.Errorf("DES-CBC short key: err = %v, want ErrInvalidKeyLength", err)
	}
	if _, err := Encrypt("DES-EDE3-CBC", make([]byte, DESEDEKeySize), make([]byte, DESBlockSize), plain, nil); !errors.Is(err, ErrInvalidKeyLength) {
		t.Errorf("DES-EDE3-CBC 16-byte key: err = %v, want ErrInvalidKeyLength", err)
	}
	if _, err := Encrypt("DES-CBC", make([]byte, DESKeySize), make([]byte, 7), plain, nil); err == nil ||
		!strings.Contains(err.Error(), "invalid iv size") {
		t.Errorf("DES-CBC short iv: err = %v, want invalid iv size", err)
	}
}

// TestNewDESCipher 验证单 DES 的 cipher.Block 形态。
//
// TestNewDESCipher verifies the single-DES cipher.Block form.
func TestNewDESCipher(t *testing.T) {
	key := bytes.Repeat([]byte{0x2f}, DESKeySize)
	b, err := NewDESCipher(key)
	if err != nil {
		t.Fatalf("NewDESCipher: %v", err)
	}
	if b.BlockSize() != DESBlockSize {
		t.Errorf("BlockSize = %d, want %d", b.BlockSize(), DESBlockSize)
	}
	src := bytes.Repeat([]byte{0xa5}, DESBlockSize)
	dst := make([]byte, DESBlockSize)
	b.Encrypt(dst, src)
	if bytes.Equal(dst, src) {
		t.Fatal("Encrypt did not change the block")
	}
	back := make([]byte, DESBlockSize)
	b.Decrypt(back, dst)
	if !bytes.Equal(back, src) {
		t.Errorf("block round trip = %x, want %x", back, src)
	}

	if _, err := NewDESCipher(make([]byte, 7)); !errors.Is(err, ErrInvalidKeyLength) {
		t.Errorf("short key: err = %v, want ErrInvalidKeyLength", err)
	}
}

// TestNewCipherDESNames 验证按名取 cipher.Block 覆盖 DES 家族。
//
// TestNewCipherDESNames verifies by-name cipher.Block retrieval across
// the DES family.
func TestNewCipherDESNames(t *testing.T) {
	for _, c := range desCases {
		b, err := NewCipher(c.name, c.key)
		if err != nil {
			t.Errorf("NewCipher(%q): %v", c.name, err)
			continue
		}
		if b.BlockSize() != DESBlockSize {
			t.Errorf("NewCipher(%q).BlockSize() = %d, want %d", c.name, b.BlockSize(), DESBlockSize)
		}
	}
}

// TestDESAvailable 验证 DES 家族在当前铜锁构建中可用。
//
// TestDESAvailable verifies the DES family is available in the current
// Tongsuo build.
func TestDESAvailable(t *testing.T) {
	for _, c := range desCases {
		if !Available(c.name) {
			t.Errorf("Available(%q) = false, want true", c.name)
		}
	}
}
