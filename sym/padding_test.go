package sym

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// TestPaddingMatrix 验证 Supports / Paddings 公布的「名字 × 填充」矩阵。
//
// TestPaddingMatrix verifies the name/padding matrix exposed by Supports
// and Paddings.
func TestPaddingMatrix(t *testing.T) {
	blockModes := []string{PaddingPKCS7, PaddingZero, PaddingNone}

	blockNames := []string{
		"AES-128-CBC", "AES-256-ECB", "AES-192-CBC",
		"SM4-CBC", "SM4-ECB",
		"DES-ECB", "DES-CBC",
		"DES-EDE-ECB", "DES-EDE-CBC",
		"DES-EDE3-ECB", "DES-EDE3-CBC",
	}
	for _, name := range blockNames {
		got, err := Paddings(name)
		if err != nil {
			t.Fatalf("Paddings(%q): %v", name, err)
		}
		if !reflect.DeepEqual(got, blockModes) {
			t.Errorf("Paddings(%q) = %v, want %v", name, got, blockModes)
		}
		for _, p := range blockModes {
			ok, err := Supports(name, p)
			if err != nil || !ok {
				t.Errorf("Supports(%q, %q) = (%v, %v), want (true, nil)", name, p, ok, err)
			}
		}
		// 空串等价于 pkcs7
		if ok, err := Supports(name, ""); err != nil || !ok {
			t.Errorf("Supports(%q, \"\") = (%v, %v), want (true, nil)", name, ok, err)
		}
	}

	streamNames := []string{
		"AES-128-CTR", "AES-256-OFB", "AES-192-CFB",
		"SM4-CTR", "SM4-OFB", "SM4-CFB",
		"ChaCha20", "SM4-XTS",
	}
	for _, name := range streamNames {
		got, err := Paddings(name)
		if err != nil {
			t.Fatalf("Paddings(%q): %v", name, err)
		}
		if !reflect.DeepEqual(got, []string{PaddingNone}) {
			t.Errorf("Paddings(%q) = %v, want [none]", name, got)
		}
		if ok, _ := Supports(name, PaddingNone); !ok {
			t.Errorf("Supports(%q, none) = false, want true", name)
		}
		if ok, _ := Supports(name, ""); !ok {
			t.Errorf("Supports(%q, \"\") = false, want true", name)
		}
		if ok, _ := Supports(name, PaddingPKCS7); ok {
			t.Errorf("Supports(%q, pkcs7) = true, want false", name)
		}
	}

	for _, name := range []string{"AES-128-GCM", "SM4-GCM", "SM4-CCM", "ChaCha20-Poly1305"} {
		got, err := Paddings(name)
		if err != nil {
			t.Fatalf("Paddings(%q): %v", name, err)
		}
		if len(got) != 0 {
			t.Errorf("Paddings(%q) = %v, want empty", name, got)
		}
	}

	// 未知算法名返回 ErrUnknownAlgorithm
	if _, err := Supports("NOPE-1-CBC", PaddingPKCS7); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Errorf("Supports(unknown) err = %v, want ErrUnknownAlgorithm", err)
	}
	if _, err := Paddings("NOPE-1-CBC"); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Errorf("Paddings(unknown) err = %v, want ErrUnknownAlgorithm", err)
	}
	// 未知填充名返回 (false, nil)——不提交数据即可判定
	if ok, err := Supports("AES-128-CBC", "no-such-padding"); ok || err != nil {
		t.Errorf("Supports(AES-128-CBC, bogus) = (%v, %v), want (false, nil)", ok, err)
	}
}

// TestPaddingRejectedWithoutData 验证非法组合在「不发数据」时即被拒绝。
//
// TestPaddingRejectedWithoutData verifies illegal combinations are
// rejected without submitting any data.
func TestPaddingRejectedWithoutData(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, AES128KeySize)
	iv := bytes.Repeat([]byte{0x02}, BlockSize)

	if _, err := Encrypt("AES-128-CTR", key, iv, nil, &Options{Padding: PaddingPKCS7}); !errors.Is(err, ErrUnsupportedPadding) {
		t.Errorf("AES-128-CTR + pkcs7: err = %v, want ErrUnsupportedPadding", err)
	}
	if _, err := Encrypt("AES-128-CBC", key, iv, nil, &Options{Padding: "bogus"}); !errors.Is(err, ErrUnsupportedPadding) {
		t.Errorf("AES-128-CBC + bogus: err = %v, want ErrUnsupportedPadding", err)
	}
	if _, err := Decrypt("SM4-CTR", bytes.Repeat([]byte{1}, SM4KeySize), iv, nil, &Options{Padding: PaddingZero}); !errors.Is(err, ErrUnsupportedPadding) {
		t.Errorf("SM4-CTR + zero: err = %v, want ErrUnsupportedPadding", err)
	}
}

// TestAESCBCPaddingHonored 验证 AES-CBC 真正消费 Options.Padding
// （0.5.0 及之前该参数被静默忽略）。
//
// TestAESCBCPaddingHonored verifies AES-CBC actually honours
// Options.Padding (silently ignored up to 0.5.0).
func TestAESCBCPaddingHonored(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, AES128KeySize)
	iv := bytes.Repeat([]byte{0x0c}, BlockSize)
	plain := bytes.Repeat([]byte{0x41}, 2*BlockSize) // 已对齐

	pkcs7, err := Encrypt("AES-128-CBC", key, iv, plain, nil)
	if err != nil {
		t.Fatalf("pkcs7 Encrypt: %v", err)
	}
	if len(pkcs7) != len(plain)+BlockSize {
		t.Errorf("pkcs7 ciphertext length = %d, want %d", len(pkcs7), len(plain)+BlockSize)
	}

	none, err := Encrypt("AES-128-CBC", key, iv, plain, &Options{Padding: PaddingNone})
	if err != nil {
		t.Fatalf("none Encrypt: %v", err)
	}
	if len(none) != len(plain) {
		t.Errorf("none ciphertext length = %d, want %d", len(none), len(plain))
	}
	if bytes.Equal(none, pkcs7) {
		t.Error("none and pkcs7 ciphertext must differ")
	}
	// 无填充的密文可与 pkcs7 密文前 len(none) 字节一致（同一 IV、同一前缀）
	if !bytes.Equal(none, pkcs7[:len(none)]) {
		t.Error("CBC ciphertext prefix should match regardless of padding")
	}

	// none 在未对齐时报错
	if _, err := Encrypt("AES-128-CBC", key, iv, plain[:len(plain)-1], &Options{Padding: PaddingNone}); err == nil {
		t.Error("none with unaligned input: want error, got nil")
	}
}

// TestAESZeroPadding 验证零填充会补足到分组整数倍，且解密不剥离。
//
// TestAESZeroPadding verifies zero padding extends to a block boundary
// and that decryption does not strip it.
func TestAESZeroPadding(t *testing.T) {
	key := bytes.Repeat([]byte{0x0d}, AES128KeySize)
	plain := []byte("unaligned") // 9 字节
	ct, err := Encrypt("AES-128-ECB", key, nil, plain, &Options{Padding: PaddingZero})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(ct) != BlockSize {
		t.Errorf("ciphertext length = %d, want %d", len(ct), BlockSize)
	}
	pt, err := Decrypt("AES-128-ECB", key, nil, ct, &Options{Padding: PaddingZero})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.HasPrefix(pt, plain) {
		t.Errorf("decrypted = %x, want prefix %x", pt, plain)
	}
	if len(pt) != BlockSize {
		t.Errorf("decrypted length = %d, want %d (zero padding is not stripped)", len(pt), BlockSize)
	}
}

// TestSM4ZeroEntryMatchesByOption 验证 SM4 的 *Zero 类型化入口与
// Options.Padding="zero" 走同一实现。
//
// TestSM4ZeroEntryMatchesByOption verifies the typed SM4 *Zero entries
// share the implementation used by Options.Padding="zero".
func TestSM4ZeroEntryMatchesByOption(t *testing.T) {
	key := bytes.Repeat([]byte{0x0e}, SM4KeySize)
	iv := bytes.Repeat([]byte{0x0f}, BlockSize)
	plain := []byte("zero padded")

	viaEntry, err := EncryptSM4CBCZero(key, iv, plain)
	if err != nil {
		t.Fatalf("EncryptSM4CBCZero: %v", err)
	}
	viaOption, err := Encrypt("SM4-CBC", key, iv, plain, &Options{Padding: PaddingZero})
	if err != nil {
		t.Fatalf("Encrypt(SM4-CBC, zero): %v", err)
	}
	if !bytes.Equal(viaEntry, viaOption) {
		t.Errorf("typed zero entry != Options.Padding=zero:\n  %x\n  %x", viaEntry, viaOption)
	}
}

// TestAESOFBCFBRoundTrip 验证 AES OFB / CFB 的往返与流式对称性。
//
// TestAESOFBCFBRoundTrip verifies AES OFB / CFB round trips and stream
// symmetry.
func TestAESOFBCFBRoundTrip(t *testing.T) {
	plain := []byte("AES OFB and CFB are stream modes with a 16-byte IV.")
	cases := []struct {
		name string
		key  []byte
		iv   []byte
	}{
		{"AES-128-OFB", bytes.Repeat([]byte{0xa1}, AES128KeySize), bytes.Repeat([]byte{0xb1}, BlockSize)},
		{"AES-128-CFB", bytes.Repeat([]byte{0xa2}, AES128KeySize), bytes.Repeat([]byte{0xb2}, BlockSize)},
		{"AES-192-OFB", bytes.Repeat([]byte{0xa3}, AES192KeySize), bytes.Repeat([]byte{0xb3}, BlockSize)},
		{"AES-192-CFB", bytes.Repeat([]byte{0xa4}, AES192KeySize), bytes.Repeat([]byte{0xb4}, BlockSize)},
		{"AES-256-OFB", bytes.Repeat([]byte{0xa5}, AES256KeySize), bytes.Repeat([]byte{0xb5}, BlockSize)},
		{"AES-256-CFB", bytes.Repeat([]byte{0xa6}, AES256KeySize), bytes.Repeat([]byte{0xb6}, BlockSize)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ct, err := Encrypt(c.name, c.key, c.iv, plain, nil)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if len(ct) != len(plain) {
				t.Errorf("ciphertext length = %d, want %d (stream mode keeps length)", len(ct), len(plain))
			}
			pt, err := Decrypt(c.name, c.key, c.iv, ct, nil)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(pt, plain) {
				t.Errorf("round trip = %q, want %q", pt, plain)
			}
			if !Available(c.name) {
				t.Errorf("Available(%q) = false", c.name)
			}
		})
	}
}

// TestAESOFBDecryptEqualsEncrypt 验证 OFB 的加解密是同一运算。
//
// TestAESOFBDecryptEqualsEncrypt verifies OFB encryption and decryption
// are the same operation.
func TestAESOFBDecryptEqualsEncrypt(t *testing.T) {
	key := bytes.Repeat([]byte{0xc1}, AES128KeySize)
	iv := bytes.Repeat([]byte{0xc2}, BlockSize)
	src := []byte("the same operation")

	enc, err := EncryptAESOFB(key, iv, src)
	if err != nil {
		t.Fatalf("EncryptAESOFB: %v", err)
	}
	dec, err := DecryptAESOFB(key, iv, src)
	if err != nil {
		t.Fatalf("DecryptAESOFB: %v", err)
	}
	if !bytes.Equal(enc, dec) {
		t.Errorf("OFB encrypt != decrypt:\n  %x\n  %x", enc, dec)
	}
}

// TestAESOFBCFBIvErrors 验证 OFB / CFB 的 IV 长度校验。
//
// TestAESOFBCFBIvErrors verifies OFB / CFB IV length validation.
func TestAESOFBCFBIvErrors(t *testing.T) {
	key := bytes.Repeat([]byte{0xd1}, AES128KeySize)
	if _, err := EncryptAESOFB(key, make([]byte, BlockSize-1), []byte("x")); err == nil {
		t.Error("EncryptAESOFB short iv: want error")
	}
	if _, err := DecryptAESCFB(key, make([]byte, BlockSize+1), []byte("x")); err == nil {
		t.Error("DecryptAESCFB long iv: want error")
	}
}
