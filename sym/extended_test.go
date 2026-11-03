package sym

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

func extHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestExtendedVectors 验证 RFC 3394/5297/7253 与 ZUC 标准向量。
//
// TestExtendedVectors checks RFC 3394/5297/7253 and ZUC standard vectors.
func TestExtendedVectors(t *testing.T) {
	t.Run("RFC3394", func(t *testing.T) {
		key := extHex(t, "000102030405060708090a0b0c0d0e0f")
		pt := extHex(t, "00112233445566778899aabbccddeeff")
		want := extHex(t, "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5")
		got, err := EncryptAESWrap(key, nil, pt)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%x != %x", got, want)
		}
		got, err = DecryptAESWrap(key, nil, want)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("unwrap: %x %v", got, err)
		}
	})
	t.Run("RFC5297_A1", func(t *testing.T) {
		key := extHex(t, "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
		aad := extHex(t, "101112131415161718191a1b1c1d1e1f2021222324252627")
		pt := extHex(t, "112233445566778899aabbccddee")
		ct, tag, err := EncryptAESSIV(key, nil, pt, aad)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ct, extHex(t, "40c02b9690c4dc04daef7f6afe5c")) || !bytes.Equal(tag, extHex(t, "85632d07c6e8f37f950acd320a2ecc93")) {
			t.Fatalf("%x %x", ct, tag)
		}
	})
	t.Run("RFC7253_Empty", func(t *testing.T) {
		key := extHex(t, "000102030405060708090a0b0c0d0e0f")
		nonce := extHex(t, "bbaa99887766554433221100")
		ct, tag, err := EncryptAESOCB(key, nonce, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(ct) != 0 || !bytes.Equal(tag, extHex(t, "785407bfffc8ad9edcc5520ac9111ee6")) {
			t.Fatalf("%x %x", ct, tag)
		}
		tag[0] ^= 1
		if _, err = DecryptAESOCB(key, nonce, ct, tag, nil); err == nil {
			t.Fatal("accepted bad empty-message tag")
		}
	})
	t.Run("ZUC_Zero", func(t *testing.T) {
		got, err := EncryptZUC(make([]byte, 16), make([]byte, 5), make([]byte, 8))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, extHex(t, "27bede74018082da")) {
			t.Fatalf("%x", got)
		}
	})
}

// TestExtendedModes 验证所有新增模式的往返、认证失败与长度边界。
//
// TestExtendedModes checks round trips, authentication failures and length boundaries for all added modes.
func TestExtendedModes(t *testing.T) {
	for _, bits := range []int{128, 192, 256} {
		for _, mode := range []string{"CCM", "OCB", "SIV", "WRAP", "WRAP-PAD", "CBC-CTS", "XTS"} {
			if mode == "XTS" && bits == 192 {
				continue
			}
			name := fmt.Sprintf("AES-%d-%s", bits, mode)
			t.Run(name, func(t *testing.T) {
				size := bits / 8
				if mode == "SIV" || mode == "XTS" {
					size *= 2
				}
				key := make([]byte, size)
				for i := range key {
					key[i] = byte(i)
				}
				if !Available(name) {
					t.Fatalf("8.4 baseline algorithm unavailable: %s", name)
				}
				lengths := []int{16, 31, 64}
				if mode == "WRAP" {
					lengths = []int{16, 24, 64}
				}
				if mode == "WRAP-PAD" {
					lengths = []int{1, 7, 8, 9, 31, 64}
				}
				if mode == "CCM" || mode == "OCB" {
					lengths = []int{0, 1, 16, 31, 64}
				}
				for _, n := range lengths {
					pt := bytes.Repeat([]byte{0x42}, n)
					if mode == "CCM" || mode == "OCB" || mode == "SIV" {
						nonce := make([]byte, 12)
						aad := []byte("associated data")
						ct, tag, err := EncryptAEAD(name, key, nonce, pt, aad)
						if err != nil {
							t.Fatalf("n=%d: %v", n, err)
						}
						got, err := DecryptAEAD(name, key, nonce, ct, tag, aad)
						if err != nil || !bytes.Equal(got, pt) {
							t.Fatalf("n=%d: %x %v", n, got, err)
						}
						for _, change := range []int{0, 1, 2, 3} {
							cc := append([]byte(nil), ct...)
							tt := append([]byte(nil), tag...)
							aa := append([]byte(nil), aad...)
							nn := append([]byte(nil), nonce...)
							switch change {
							case 0:
								tt[0] ^= 1
							case 1:
								aa[0] ^= 1
							case 2:
								if len(cc) == 0 {
									continue
								}
								cc[0] ^= 1
							case 3:
								nn[0] ^= 1
							}
							if _, err = DecryptAEAD(name, key, nn, cc, tt, aa); err == nil {
								t.Fatalf("n=%d: accepted tamper %d", n, change)
							}
						}
					} else {
						iv := make([]byte, 16)
						if mode == "WRAP" || mode == "WRAP-PAD" {
							iv = nil
						}
						ct, err := Encrypt(name, key, iv, pt, nil)
						if err != nil {
							t.Fatalf("n=%d: %v", n, err)
						}
						got, err := Decrypt(name, key, iv, ct, nil)
						if err != nil || !bytes.Equal(got, pt) {
							t.Fatalf("n=%d: %x %v", n, got, err)
						}
						if mode == "WRAP" || mode == "WRAP-PAD" {
							ct[0] ^= 1
							if _, err = Decrypt(name, key, iv, ct, nil); err == nil {
								t.Fatal("accepted corrupted wrapped key")
							}
						}
					}
				}
				if _, err := Encrypt(name, key[:len(key)-1], nil, nil, nil); !errors.Is(err, ErrInvalidKeyLength) && mode != "CCM" && mode != "OCB" && mode != "SIV" {
					t.Fatalf("invalid key: %v", err)
				}
				if ok, err := Supports(name, PaddingPKCS7); err != nil || ok {
					t.Fatalf("padding accepted: %v %v", ok, err)
				}
			})
		}
	}
	for _, name := range []string{"AES-128-CCM", "AES-128-OCB", "AES-128-SIV"} {
		size := 16
		if name == "AES-128-SIV" {
			size = 32
		}
		key := make([]byte, size)
		g, err := NewAEAD(name, key)
		if err != nil {
			t.Fatal(err)
		}
		nonce := make([]byte, g.NonceSize())
		pt := []byte("payload")
		sealed := g.Seal([]byte("prefix"), nonce, pt, nil)
		if !bytes.HasPrefix(sealed, []byte("prefix")) {
			t.Fatalf("Seal failed: %s", name)
		}
		dst, err := g.Open([]byte("prefix"), nonce, sealed[6:], nil)
		if err != nil || string(dst) != "prefixpayload" {
			t.Fatalf("%s: %s %v", name, dst, err)
		}
		if _, err = g.Open(nil, nonce, nil, nil); err == nil {
			t.Fatal("short ciphertext accepted")
		}
	}
	if _, _, err := EncryptAESSIV(make([]byte, 32), nil, nil, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("empty SIV: %v", err)
	}
}

// FuzzAESWrapPadRoundTrip 验证任意非空消息的包装往返。
//
// FuzzAESWrapPadRoundTrip checks wrapping round trips for arbitrary nonempty messages.
func FuzzAESWrapPadRoundTrip(f *testing.F) {
	f.Add([]byte{1})
	f.Add([]byte("arbitrary wrapped key material"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		key := make([]byte, 16)
		ct, err := EncryptAESWrapPad(key, nil, data)
		if len(data) == 0 {
			if err == nil {
				t.Fatal("empty input accepted")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		pt, err := DecryptAESWrapPad(key, nil, ct)
		if err != nil || !bytes.Equal(pt, data) {
			t.Fatalf("round trip: %v", err)
		}
	})
}

// BenchmarkAESOCB 测量 4 KiB OCB 消息的开销。
//
// BenchmarkAESOCB measures OCB overhead for 4 KiB messages.
func BenchmarkAESOCB(b *testing.B) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	data := make([]byte, 4096)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := EncryptAESOCB(key, nonce, data, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// TestExtendedKeyValidation 验证类型化与按名入口不会静默选择其他密钥位宽。
//
// TestExtendedKeyValidation checks that typed and by-name entries cannot silently select a different key size.
func TestExtendedKeyValidation(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := Encrypt("AES-128-CBC", key, iv, nil, nil); !errors.Is(err, ErrInvalidKeyLength) {
		t.Fatalf("CBC mismatch: %v", err)
	}
	if _, _, err := EncryptGCM("AES-128-GCM", key, nonce, nil, nil); !errors.Is(err, ErrInvalidKeyLength) {
		t.Fatalf("GCM mismatch: %v", err)
	}
	if _, err := DecryptGCM("AES-128-GCM", key, nonce, nil, make([]byte, 16), nil); !errors.Is(err, ErrInvalidKeyLength) {
		t.Fatalf("GCM mismatch: %v", err)
	}
	if _, err := NewAESCCM(make([]byte, 15)); !errors.Is(err, ErrInvalidKeyLength) {
		t.Fatalf("CCM key: %v", err)
	}
	if _, _, err := EncryptAESSIV(make([]byte, 31), nil, []byte{1}, nil); !errors.Is(err, ErrInvalidKeyLength) {
		t.Fatalf("SIV key: %v", err)
	}
	if _, err := EncryptAESXTS(make([]byte, 48), iv, make([]byte, 16)); !errors.Is(err, ErrInvalidKeyLength) {
		t.Fatalf("192-XTS key: %v", err)
	}
	if _, err := NewCipher(" aes-128-cbc ", make([]byte, 16)); err != nil {
		t.Fatalf("canonical name: %v", err)
	}
}

// TestNISTXTSVectors 验证 NIST CAVS 11.0 的 AES-128/256-XTS 与密文窃取向量。
//
// TestNISTXTSVectors checks NIST CAVS 11.0 AES-128/256-XTS and ciphertext-stealing vectors.
func TestNISTXTSVectors(t *testing.T) {
	// Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/XTSTestVectors.zip
	cases := []struct{ name, key, iv, pt, ct string }{
		{"AES128/bits128/count1", "a1b90cba3f06ac353b2c343876081762090923026e91771815f29dab01932f2f", "4faef7117cda59c66e4b92013e768ad5", "ebabce95b14d3c8d6fb350390790311c", "778ae8b43cb98d5a825081d5be471c63"},
		{"AES128/bits200/count301", "394c97881abd989d29c703e48a72b397a7acf51b59649eeea9b33274d8541df4", "4b15c684a152d485fe9937d39b168c29", "2f3b9dcfbae729583b1d1ffdd16bb6fe2757329435662a78f0", "f3473802e38a3ffef4d4fb8e6aa266ebde553a64528a06463e"},
		{"AES128/bits256/count101", "b7b93f516aef295eff3a29d837cf1f135347e8a21dae616ff5062b2e8d78ce5e", "873edea653b643bd8bcf51403197ed14", "236f8a5b58dd55f6194ed70c4ac1a17f1fe60ec9a6c454d087ccb77d6b638c47", "22e6a3c6379dcf7599b052b5a749c7f78ad8a11b9f1aa9430cf3aef445682e19"},
		{"AES256/bits256/count1", "1ea661c58d943a0e4801e42f4b0947149e7f9f8e3e68d0c7505210bd311a0e7cd6e13ffdf2418d8d1911c004cda58da3d619b7e2b9141e58318eea392cf41b08", "adf8d92627464ad2f0428e84a9f87564", "2eedea52cd8215e1acc647e810bbc3642e87287f8d2e57e36c0a24fbc12a202e", "cbaad0e2f6cea3f50b37f934d46a9b130b9d54f07e34f36af793e86f73c6d7db"},
		{"AES256/bits384/count101", "266c336b3b01489f3267f52835fd92f674374b88b4e1ebd2d36a5f457581d9d042c3eef7b0b7e5137b086496b4d9e6ac658d7196a23f23f036172fdb8faee527", "06b209a7a22f486ecbfadb0f3137ba42", "ca7d65ef8d3dfad345b61ccddca1ad81de830b9e86c7b426d76cb7db766852d981c6b21409399d78f42cc0b33a7bbb06", "c73256870cc2f4dd57acc74b5456dbd776912a128bc1f77d72cdebbf270044b7a43ceed29025e1e8be211fa3c3ed002d"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, iv, pt, want := extHex(t, tc.key), extHex(t, tc.iv), extHex(t, tc.pt), extHex(t, tc.ct)
			got, err := EncryptAESXTS(key, iv, pt)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("encrypt=%x want=%x err=%v", got, want, err)
			}
			got, err = DecryptAESXTS(key, iv, want)
			if err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("decrypt=%x want=%x err=%v", got, pt, err)
			}
		})
	}
}

// TestAESCCMReferenceVector 验证 OpenSSL 3.0.3 官方的 AES-256-CCM 16 字节 tag 向量。
//
// TestAESCCMReferenceVector checks the official OpenSSL 3.0.3 AES-256-CCM vector with a 16-byte tag.
func TestAESCCMReferenceVector(t *testing.T) {
	// Source: https://github.com/openssl/openssl/blob/openssl-3.0.3/test/recipes/30-test_evp_data/evpciph_aes_common.txt
	key := extHex(t, "1bde3251d41a8b5ea013c195ae128b218b3e0306376357077ef1c1c78548b92e")
	nonce := extHex(t, "5b8e40746f6b98e00f1d13ff41")
	aad := extHex(t, "c17a32514eb6103f3249e076d4c871dc97e04b286699e54491dc18f6d734d4c0")
	pt := extHex(t, "53bd72a97089e312422bf72e242377b3c6ee3e2075389b999c4ef7f28bd2b80a")
	want := extHex(t, "9a5fcccdb4cf04e7293d2775cc76a488f042382d949b43b7d6bb2b9864786726")
	wantTag := extHex(t, "2024931d73bca480c24a24ece6b6c2bf")
	ct, tag, err := EncryptAESCCM(key, nonce, pt, aad)
	if err != nil || !bytes.Equal(ct, want) || !bytes.Equal(tag, wantTag) {
		t.Fatalf("ciphertext=%x tag=%x error=%v", ct, tag, err)
	}
	got, err := DecryptAESCCM(key, nonce, want, wantTag, aad)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("plaintext=%x error=%v", got, err)
	}
}
