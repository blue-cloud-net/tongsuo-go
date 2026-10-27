package sym

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"testing"
)

// decodeHex 解码十六进制字符串，失败即终止测试。
//
// decodeHex decodes a hexadecimal string and fails the test on error.
func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}
	return b
}

// TestAES192RoundTrip 验证 AES-192 在 ECB / CBC / CTR 下的加解密往返，
// 并确认 24 字节密钥被接受、其它长度被拒绝。
//
// TestAES192RoundTrip verifies the AES-192 round trip in ECB / CBC / CTR
// modes and confirms that a 24-byte key is accepted while other lengths
// are rejected.
func TestAES192RoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, AES192KeySize)
	iv := bytes.Repeat([]byte{0x11}, BlockSize)
	data := bytes.Repeat([]byte("payload"), 8)

	ct, err := EncryptAESECB(key, data)
	if err != nil {
		t.Fatalf("EncryptAESECB: %v", err)
	}
	pt, err := DecryptAESECB(key, ct)
	if err != nil {
		t.Fatalf("DecryptAESECB: %v", err)
	}
	if !bytes.Equal(pt, data) {
		t.Fatal("AES-192-ECB round trip mismatch")
	}

	ct, err = EncryptAESCBC(key, iv, data)
	if err != nil {
		t.Fatalf("EncryptAESCBC: %v", err)
	}
	pt, err = DecryptAESCBC(key, iv, ct)
	if err != nil {
		t.Fatalf("DecryptAESCBC: %v", err)
	}
	if !bytes.Equal(pt, data) {
		t.Fatal("AES-192-CBC round trip mismatch")
	}

	ct, err = EncryptAESCTR(key, iv, data)
	if err != nil {
		t.Fatalf("EncryptAESCTR: %v", err)
	}
	pt, err = DecryptAESCTR(key, iv, ct)
	if err != nil {
		t.Fatalf("DecryptAESCTR: %v", err)
	}
	if !bytes.Equal(pt, data) {
		t.Fatal("AES-192-CTR round trip mismatch")
	}

	// 非 16/24/32 字节密钥必须被拒绝。
	if _, err := EncryptAESCBC(bytes.Repeat([]byte{0}, 20), iv, data); err == nil {
		t.Error("20-byte AES key accepted")
	}
}

// TestAES192ByName 验证按名入口支持 AES-192 的四种模式。
//
// TestAES192ByName verifies the by-name entry points for the four
// AES-192 modes.
func TestAES192ByName(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, AES192KeySize)
	iv := bytes.Repeat([]byte{0x11}, BlockSize)
	data := []byte("aes-192 by-name payload, longer than one block")

	for _, name := range []string{"AES-192-CBC", "AES-192-CTR", "AES-192-ECB"} {
		t.Run(name, func(t *testing.T) {
			useIV := iv
			if name == "AES-192-ECB" {
				useIV = nil
			}
			ct, err := Encrypt(name, key, useIV, data, nil)
			if err != nil {
				t.Fatalf("Encrypt(%s): %v", name, err)
			}
			pt, err := Decrypt(name, key, useIV, ct, nil)
			if err != nil {
				t.Fatalf("Decrypt(%s): %v", name, err)
			}
			if !bytes.Equal(pt, data) {
				t.Fatalf("%s round trip mismatch", name)
			}
		})
	}

	t.Run("AES-192-GCM", func(t *testing.T) {
		nonce := bytes.Repeat([]byte{0x33}, NonceSize)
		aad := []byte("aad")
		ct, tag, err := EncryptAEAD("AES-192-GCM", key, nonce, data, aad)
		if err != nil {
			t.Fatalf("EncryptAEAD: %v", err)
		}
		pt, err := DecryptAEAD("AES-192-GCM", key, nonce, ct, tag, aad)
		if err != nil {
			t.Fatalf("DecryptAEAD: %v", err)
		}
		if !bytes.Equal(pt, data) {
			t.Fatal("AES-192-GCM round trip mismatch")
		}
	})
}

// TestSM4CCMKnownVector 验证 SM4-CCM 对 RFC 8998 的标准向量。
//
// 向量来源：铜锁 evpciph_sm4.txt 的 "SM4 CCM test vectors from RFC8998"。
//
// TestSM4CCMKnownVector verifies SM4-CCM against the RFC 8998 vector in
// Tongsuo's evpciph_sm4.txt.
func TestSM4CCMKnownVector(t *testing.T) {
	key := decodeHex(t, "0123456789abcdeffedcba9876543210")
	nonce := decodeHex(t, "00001234567800000000abcd")
	aad := decodeHex(t, "feedfacedeadbeeffeedfacedeadbeefabaddad2")
	wantCT := decodeHex(t, "48af93501fa62adbcd414cce6034d895dda1bf8f132f042098661572e7483094"+
		"fd12e518ce062c98acee28d95df4416bed31a2f04476c18bb40c84a74b97dc5b")
	wantTag := decodeHex(t, "16842d4fa186f56ab33256971fa110f4")
	pt := decodeHex(t, "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddddddddddddd"+
		"eeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa")

	ct, tag, err := EncryptSM4CCM(key, nonce, pt, aad)
	if err != nil {
		t.Fatalf("EncryptSM4CCM: %v", err)
	}
	if !bytes.Equal(ct, wantCT) {
		t.Fatalf("SM4-CCM ciphertext = %x, want %x", ct, wantCT)
	}
	if !bytes.Equal(tag, wantTag) {
		t.Fatalf("SM4-CCM tag = %x, want %x", tag, wantTag)
	}
	got, err := DecryptSM4CCM(key, nonce, ct, tag, aad)
	if err != nil {
		t.Fatalf("DecryptSM4CCM: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("SM4-CCM plaintext mismatch")
	}
}

// TestSM4CCMTamperDetected 验证篡改密文 / tag / AAD 都会被检测到。
//
// TestSM4CCMTamperDetected verifies that tampering with the ciphertext,
// the tag or the AAD is detected.
func TestSM4CCMTamperDetected(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, SM4KeySize)
	nonce := bytes.Repeat([]byte{0x02}, SM4CCMNonceSize)
	aad := []byte("aad")
	pt := []byte("sm4-ccm tamper test")

	ct, tag, err := EncryptSM4CCM(key, nonce, pt, aad)
	if err != nil {
		t.Fatalf("EncryptSM4CCM: %v", err)
	}

	badCT := append([]byte(nil), ct...)
	badCT[0] ^= 0xff
	if _, err := DecryptSM4CCM(key, nonce, badCT, tag, aad); err == nil {
		t.Error("tampered ciphertext accepted")
	}

	badTag := append([]byte(nil), tag...)
	badTag[0] ^= 0xff
	if _, err := DecryptSM4CCM(key, nonce, ct, badTag, aad); err == nil {
		t.Error("tampered tag accepted")
	}

	if _, err := DecryptSM4CCM(key, nonce, ct, tag, []byte("bad aad")); err == nil {
		t.Error("tampered AAD accepted")
	}
}

// TestSM4CCMArgumentValidation 验证 nonce / 密钥长度校验。
//
// TestSM4CCMArgumentValidation verifies the nonce and key length checks.
func TestSM4CCMArgumentValidation(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, SM4KeySize)
	if _, _, err := EncryptSM4CCM(key, bytes.Repeat([]byte{2}, 6), []byte("x"), nil); err == nil {
		t.Error("nonce of 6 bytes accepted")
	}
	if _, _, err := EncryptSM4CCM(key, bytes.Repeat([]byte{2}, 14), []byte("x"), nil); err == nil {
		t.Error("nonce of 14 bytes accepted")
	}
	if _, _, err := EncryptSM4CCM(bytes.Repeat([]byte{1}, 15), bytes.Repeat([]byte{2}, 12), []byte("x"), nil); err == nil {
		t.Error("15-byte key accepted")
	}
}

// TestSM4XTSKnownVectors 验证 SM4-XTS 对 GB/T 17964-2021 的标准向量。
//
// 向量来源：铜锁 evpciph_sm4.txt 的 "SM4 XTS test vectors from
// GB/T 17964-2021"。铜锁对 SM4-XTS 默认采用 GB 口径（tweak 大端）。
//
// TestSM4XTSKnownVectors verifies SM4-XTS against the GB/T 17964-2021
// vectors in Tongsuo's evpciph_sm4.txt. Tongsuo defaults to the GB tweak
// convention (big-endian data-unit number) for SM4-XTS.
func TestSM4XTSKnownVectors(t *testing.T) {
	if !Available("SM4-XTS") {
		t.Skip("this build has no SM4-XTS (it is fetched via EVP_CIPHER_fetch; Tongsuo 8.4.0 lacks it)")
	}
	tests := []struct {
		name  string
		key   string
		tweak string
		pt    string
		ct    string
	}{
		{
			name:  "GB/T 17964-2021 第 1 条",
			key:   "2B7E151628AED2A6ABF7158809CF4F3C000102030405060708090A0B0C0D0E0F",
			tweak: "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
			pt: "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51" +
				"30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17",
			ct: "E9538251C71D7B80BBE4483FEF497BD12C5C581BD6242FC51E08964FB4F60FDB" +
				"0BA42F63499279213D318D2C11F6886E903BE7F93A1B3479",
		},
		{
			name:  "GB/T 17964-2021 单块",
			key:   "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0",
			tweak: "9A785634120000000000000000000000",
			pt:    "000102030405060708090A0B0C0D0E0F10",
			ct:    "9E52443A35410CA0BA5637B94C0766F469",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := decodeHex(t, tt.key)
			tweak := decodeHex(t, tt.tweak)
			pt := decodeHex(t, tt.pt)
			want := decodeHex(t, tt.ct)

			ct, err := EncryptSM4XTS(key, tweak, pt)
			if err != nil {
				t.Fatalf("EncryptSM4XTS: %v", err)
			}
			if !bytes.Equal(ct, want) {
				t.Fatalf("SM4-XTS = %X, want %X", ct, want)
			}
			got, err := DecryptSM4XTS(key, tweak, ct)
			if err != nil {
				t.Fatalf("DecryptSM4XTS: %v", err)
			}
			if !bytes.Equal(got, pt) {
				t.Fatal("SM4-XTS round trip mismatch")
			}
		})
	}
}

// TestSM4XTSArgumentValidation 验证密钥 / tweak / 数据长度校验。
//
// TestSM4XTSArgumentValidation verifies the key, tweak and data length
// checks.
func TestSM4XTSArgumentValidation(t *testing.T) {
	key := bytes.Repeat([]byte{1}, SM4XTSKeySize)
	tweak := bytes.Repeat([]byte{2}, BlockSize)
	if _, err := EncryptSM4XTS(bytes.Repeat([]byte{1}, 16), tweak, bytes.Repeat([]byte{3}, 32)); err == nil {
		t.Error("16-byte key accepted")
	}
	if _, err := EncryptSM4XTS(key, bytes.Repeat([]byte{2}, 8), bytes.Repeat([]byte{3}, 32)); err == nil {
		t.Error("8-byte tweak accepted")
	}
	if _, err := EncryptSM4XTS(key, tweak, bytes.Repeat([]byte{3}, 15)); err == nil {
		t.Error("15-byte data accepted")
	}
	if _, err := EncryptSM4XTS(key, tweak, nil); err == nil {
		t.Error("empty data accepted")
	}
	if !Available("SM4-XTS") {
		// 长度校验已在提供该算法的构建上覆盖；本构建的 provider 没有
		// SM4-XTS，17 字节的「接受」断言无从验证。
		// The length checks ran above; this build's providers have no
		// SM4-XTS, so the 17-byte acceptance assertion cannot be made.
		t.Skip("this build has no SM4-XTS; length checks covered, acceptance cannot be asserted")
	}
	// XTS 允许末块不足 16 字节（密文窃取），17 字节应当被接受。
	if _, err := EncryptSM4XTS(key, tweak, bytes.Repeat([]byte{3}, 17)); err != nil {
		t.Errorf("EncryptSM4XTS(17 bytes) = %v, want success (ciphertext stealing)", err)
	}
}

// TestChaCha20KnownVector 验证 ChaCha20 对 RFC 7539 §A.1 测试向量 2。
//
// 向量来源：铜锁 evpciph_chacha.txt（RFC 7539 §A.1）。
//
// TestChaCha20KnownVector verifies ChaCha20 against RFC 7539 section A.1
// test vector 2 (Tongsuo's evpciph_chacha.txt).
func TestChaCha20KnownVector(t *testing.T) {
	key := make([]byte, ChaCha20KeySize)
	iv := decodeHex(t, "01000000000000000000000000000000")
	pt := make([]byte, 64)
	want := decodeHex(t, "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"+
		"29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f")

	ct, err := EncryptChaCha20(key, iv, pt)
	if err != nil {
		t.Fatalf("EncryptChaCha20: %v", err)
	}
	if !bytes.Equal(ct, want) {
		t.Fatalf("ChaCha20 = %x, want %x", ct, want)
	}
	back, err := DecryptChaCha20(key, iv, ct)
	if err != nil {
		t.Fatalf("DecryptChaCha20: %v", err)
	}
	if !bytes.Equal(back, pt) {
		t.Fatal("ChaCha20 round trip mismatch")
	}
}

// TestChaCha20ArgumentValidation 验证密钥 / IV 长度校验。
//
// TestChaCha20ArgumentValidation verifies the key and IV length checks.
func TestChaCha20ArgumentValidation(t *testing.T) {
	if _, err := EncryptChaCha20(bytes.Repeat([]byte{1}, 16), make([]byte, ChaCha20IVSize), nil); err == nil {
		t.Error("16-byte key accepted")
	}
	if _, err := EncryptChaCha20(make([]byte, ChaCha20KeySize), make([]byte, 8), nil); err == nil {
		t.Error("8-byte IV accepted")
	}
}

// TestChaCha20Poly1305KnownVector 验证 ChaCha20-Poly1305 对 RFC 7539
// §A.5 测试向量。
//
// 向量来源：铜锁 evpciph_chacha.txt。
//
// TestChaCha20Poly1305KnownVector verifies ChaCha20-Poly1305 against RFC
// 7539 section A.5 (Tongsuo's evpciph_chacha.txt).
func TestChaCha20Poly1305KnownVector(t *testing.T) {
	key := decodeHex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := decodeHex(t, "070000004041424344454647")
	aad := decodeHex(t, "50515253c0c1c2c3c4c5c6c7")
	pt := decodeHex(t, "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"+
		"73206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e6520"+
		"74697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069"+
		"742e")
	wantCT := decodeHex(t, "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d"+
		"63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8"+
		"c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64"+
		"b6116")
	wantTag := decodeHex(t, "1ae10b594f09e26a7e902ecbd0600691")

	ct, tag, err := EncryptChaCha20Poly1305(key, nonce, pt, aad)
	if err != nil {
		t.Fatalf("EncryptChaCha20Poly1305: %v", err)
	}
	if !bytes.Equal(ct, wantCT) {
		t.Fatalf("ChaCha20-Poly1305 ciphertext mismatch")
	}
	if !bytes.Equal(tag, wantTag) {
		t.Fatalf("ChaCha20-Poly1305 tag = %x, want %x", tag, wantTag)
	}
	back, err := DecryptChaCha20Poly1305(key, nonce, ct, tag, aad)
	if err != nil {
		t.Fatalf("DecryptChaCha20Poly1305: %v", err)
	}
	if !bytes.Equal(back, pt) {
		t.Fatal("ChaCha20-Poly1305 round trip mismatch")
	}

	// 篡改 tag 必须被检测到。
	badTag := append([]byte(nil), tag...)
	badTag[0] ^= 0x01
	if _, err := DecryptChaCha20Poly1305(key, nonce, ct, badTag, aad); err == nil {
		t.Error("tampered tag accepted")
	}
}

// TestAEADConstructors 验证三个 AEAD 构造器满足 cipher.AEAD 契约并能往返。
//
// TestAEADConstructors verifies that the three AEAD constructors satisfy
// the cipher.AEAD contract and round trip correctly.
func TestAEADConstructors(t *testing.T) {
	tests := []struct {
		name  string
		key   []byte
		nonce []byte
	}{
		{"SM4-CCM", bytes.Repeat([]byte{1}, SM4KeySize), bytes.Repeat([]byte{2}, SM4CCMNonceSize)},
		{"SM4-GCM", bytes.Repeat([]byte{1}, SM4KeySize), bytes.Repeat([]byte{2}, NonceSize)},
		{"AES-192-GCM", bytes.Repeat([]byte{1}, AES192KeySize), bytes.Repeat([]byte{2}, NonceSize)},
		{"ChaCha20-Poly1305", bytes.Repeat([]byte{1}, ChaCha20KeySize), bytes.Repeat([]byte{2}, NonceSize)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aead, err := NewAEAD(tt.name, tt.key)
			if err != nil {
				t.Fatalf("NewAEAD(%s): %v", tt.name, err)
			}
			if got, want := len(tt.nonce), aead.NonceSize(); got != want {
				// SM4-CCM 的 NonceSize 只是推荐值，允许不等。
				if tt.name != "SM4-CCM" {
					t.Fatalf("nonce length %d != NonceSize() %d", got, want)
				}
			}
			pt := []byte("aead " + tt.name)
			aad := []byte("header")
			sealed := aead.Seal(nil, tt.nonce, pt, aad)
			if len(sealed) != len(pt)+aead.Overhead() {
				t.Fatalf("Seal length = %d, want %d", len(sealed), len(pt)+aead.Overhead())
			}
			opened, err := aead.Open(nil, tt.nonce, sealed, aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(opened, pt) {
				t.Fatalf("Open = %q, want %q", opened, pt)
			}
			// 篡改密文必须被检测到。
			bad := append([]byte(nil), sealed...)
			bad[0] ^= 0xff
			if _, err := aead.Open(nil, tt.nonce, bad, aad); err == nil {
				t.Error("tampered ciphertext accepted")
			}
		})
	}
}

// TestNewAEADRejectsNonAEAD 验证非 AEAD 模式返回 ErrUnsupported。
//
// TestNewAEADRejectsNonAEAD verifies that non-AEAD modes return
// ErrUnsupported.
func TestNewAEADRejectsNonAEAD(t *testing.T) {
	key := bytes.Repeat([]byte{1}, SM4KeySize)
	if _, err := NewAEAD("SM4-CBC", key); !errors.Is(err, ErrUnsupported) {
		t.Errorf("NewAEAD(SM4-CBC) err = %v, want ErrUnsupported", err)
	}
	if _, err := NewAEAD("NO-SUCH", key); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Errorf("NewAEAD(unknown) err = %v, want ErrUnknownAlgorithm", err)
	}
}

// TestAEADByNameRejectsNonAEAD 验证 EncryptAEAD 拒绝非 AEAD 模式。
//
// TestAEADByNameRejectsNonAEAD verifies that EncryptAEAD rejects non-AEAD
// modes.
func TestAEADByNameRejectsNonAEAD(t *testing.T) {
	key := bytes.Repeat([]byte{1}, SM4KeySize)
	if _, _, err := EncryptAEAD("SM4-CTR", key, nil, []byte("x"), nil); !errors.Is(err, ErrUnsupported) {
		t.Errorf("EncryptAEAD(SM4-CTR) err = %v, want ErrUnsupported", err)
	}
	if _, err := DecryptAEAD("SM4-CTR", key, nil, []byte("x"), nil, nil); !errors.Is(err, ErrUnsupported) {
		t.Errorf("DecryptAEAD(SM4-CTR) err = %v, want ErrUnsupported", err)
	}
}

// TestEncryptRejectsAEAD 验证 Encrypt/Decrypt 对 AEAD 模式返回 ErrUnsupported，
// 并提示改用 EncryptAEAD（与既有 GCM 行为一致）。
//
// TestEncryptRejectsAEAD verifies that Encrypt / Decrypt reject AEAD modes
// with ErrUnsupported and point at EncryptAEAD, matching the previous GCM
// behaviour.
func TestEncryptRejectsAEAD(t *testing.T) {
	key := bytes.Repeat([]byte{1}, SM4KeySize)
	for _, name := range []string{"SM4-GCM", "SM4-CCM", "ChaCha20-Poly1305"} {
		emptyKey := make([]byte, ChaCha20KeySize)
		if name != "ChaCha20-Poly1305" {
			emptyKey = key
		}
		if _, err := Encrypt(name, emptyKey, nil, []byte("x"), nil); !errors.Is(err, ErrUnsupported) {
			t.Errorf("Encrypt(%s) err = %v, want ErrUnsupported", name, err)
		}
		if _, err := Decrypt(name, emptyKey, nil, []byte("x"), nil); !errors.Is(err, ErrUnsupported) {
			t.Errorf("Decrypt(%s) err = %v, want ErrUnsupported", name, err)
		}
	}
}

// TestNewCipherRejectsAEADAndXTS 验证 NewCipher 拒绝 AEAD / XTS / 流模式。
//
// TestNewCipherRejectsAEADAndXTS verifies that NewCipher rejects the AEAD,
// XTS and stream modes.
func TestNewCipherRejectsAEADAndXTS(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"SM4-CCM", bytes.Repeat([]byte{1}, SM4KeySize)},
		{"SM4-XTS", bytes.Repeat([]byte{1}, SM4XTSKeySize)},
		{"ChaCha20", bytes.Repeat([]byte{1}, ChaCha20KeySize)},
	}
	for _, tt := range tests {
		if _, err := NewCipher(tt.name, tt.key); !errors.Is(err, ErrUnsupported) {
			t.Errorf("NewCipher(%s) err = %v, want ErrUnsupported", tt.name, err)
		}
	}
}

// 编译期断言：三个 AEAD 构造器都满足 cipher.AEAD。
var (
	_ cipher.AEAD = mustAEAD(NewSM4CCM(make([]byte, SM4KeySize)))
	_ cipher.AEAD = mustAEAD(NewChaCha20Poly1305(make([]byte, ChaCha20KeySize)))
)

// mustAEAD 把 (cipher.AEAD, error) 折叠为 cipher.AEAD，仅供编译期断言。
//
// mustAEAD folds (cipher.AEAD, error) into cipher.AEAD for the
// compile-time assertions.
func mustAEAD(a cipher.AEAD, err error) cipher.AEAD {
	if err != nil {
		panic(err)
	}
	return a
}
