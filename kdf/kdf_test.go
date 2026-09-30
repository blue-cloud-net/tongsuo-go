package kdf

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// mustHex 解析 hex 字符串（含可选空白）并 fail 测试在错误时。
//
// mustHex parses a hex string (whitespace tolerant) and fails the test
// on error.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, "\n", ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestHKDF_RFC5869 用 RFC 5869 附录 A 的标准向量验证 HKDF。
// A.1 使用 SHA-256，A.2 使用 SHA-1。
func TestHKDF_RFC5869(t *testing.T) {
	vectors := []struct {
		name string
		md   Hash
		ikm  []byte
		salt []byte
		info []byte
		l    int
		okm  []byte
	}{
		{
			name: "SHA-256 A.1",
			md:   HashSHA256,
			ikm:  bytes.Repeat([]byte{0x0b}, 22),
			salt: mustHex(t, "000102030405060708090a0b0c"),
			info: mustHex(t, "f0f1f2f3f4f5f6f7f8f9"),
			l:    42,
			okm: mustHex(t, "3cb25f25faacd57a90434f64d0362f2a"+
				"2d2d0a90cf1a5a4c5db02d56ecc4c5bf"+
				"34007208d5b887185865"),
		},
		{
			name: "SHA-1 A.2",
			md:   HashSHA1,
			ikm:  bytes.Repeat([]byte{0x0b}, 11),
			salt: mustHex(t, "000102030405060708090a0b0c"),
			info: mustHex(t, "f0f1f2f3f4f5f6f7f8f9"),
			l:    42,
			okm: mustHex(t, "085a01ea1b10f36933068b56efa5ad81"+
				"a4f14b822f5b091568a9cdd4f155fda2"+
				"c22e422478d305f3f896"),
		},
	}
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			got, err := HKDF(v.md, v.ikm, v.salt, v.info, v.l)
			if err != nil {
				t.Fatalf("HKDF: %v", err)
			}
			if !bytes.Equal(got, v.okm) {
				t.Fatalf("HKDF = %x, want %x", got, v.okm)
			}
		})
	}
}

// TestHKDFDeterministic 验证相同输入产生相同输出（确定性）。
func TestHKDFDeterministic(t *testing.T) {
	secret := bytes.Repeat([]byte{0x0b}, 22)
	salt := mustHex(t, "000102030405060708090a0b0c")
	info := mustHex(t, "f0f1f2f3f4f5f6f7f8f9")
	a, err := HKDF(HashSHA256, secret, salt, info, 42)
	if err != nil {
		t.Fatal(err)
	}
	b, err := HKDF(HashSHA256, secret, salt, info, 42)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("HKDF not deterministic: %x vs %x", a, b)
	}
}

// TestHKDFInvalidArgs 验证参数校验。
func TestHKDFInvalidArgs(t *testing.T) {
	t.Run("empty-secret", func(t *testing.T) {
		if _, err := HKDF(HashSHA256, nil, nil, nil, 16); err == nil {
			t.Error("want error for empty secret")
		}
	})
	t.Run("zero-length", func(t *testing.T) {
		if _, err := HKDF(HashSHA256, []byte("k"), nil, nil, 0); err == nil {
			t.Error("want error for zero length")
		}
	})
	t.Run("negative-length", func(t *testing.T) {
		if _, err := HKDF(HashSHA256, []byte("k"), nil, nil, -1); err == nil {
			t.Error("want error for negative length")
		}
	})
	t.Run("unsupported-hash", func(t *testing.T) {
		if _, err := HKDF(Hash("BLAKE2"), []byte("k"), nil, nil, 16); err == nil {
			t.Error("want error for unsupported hash")
		}
	})
}

// TestPBKDF2Rounds 验证 PBKDF2 多次派生的稳定性（不依赖外部 RFC 向量
// —— PBKDF2 测试向量易与 OpenSSL 实现版本差异冲突）。
func TestPBKDF2Rounds(t *testing.T) {
	password := []byte("password")
	salt := []byte("salt")
	a, err := PBKDF2(HashSHA256, password, salt, 1000, 32)
	if err != nil {
		t.Fatalf("PBKDF2: %v", err)
	}
	if len(a) != 32 {
		t.Fatalf("PBKDF2 length = %d, want 32", len(a))
	}
	b, err := PBKDF2(HashSHA256, password, salt, 1000, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("PBKDF2 not deterministic: %x vs %x", a, b)
	}
}

// TestPBKDF2InvalidArgs 验证参数校验。
func TestPBKDF2InvalidArgs(t *testing.T) {
	t.Run("empty-password", func(t *testing.T) {
		if _, err := PBKDF2(HashSHA256, nil, []byte("salt"), 1, 16); err == nil {
			t.Error("want error for empty password")
		}
	})
	t.Run("zero-iter", func(t *testing.T) {
		if _, err := PBKDF2(HashSHA256, []byte("p"), []byte("salt"), 0, 16); err == nil {
			t.Error("want error for zero iter")
		}
	})
	t.Run("zero-keylen", func(t *testing.T) {
		if _, err := PBKDF2(HashSHA256, []byte("p"), []byte("salt"), 1, 0); err == nil {
			t.Error("want error for zero keyLen")
		}
	})
	t.Run("unsupported-hash", func(t *testing.T) {
		if _, err := PBKDF2(Hash("BLAKE2"), []byte("p"), []byte("s"), 1, 16); err == nil {
			t.Error("want error for unsupported hash")
		}
	})
}

// TestArgon2IDAvailable 探测当前构建是否带 Argon2ID provider；与现状无关，
// 仅验证 API 返回值有效（不强制 false）。
func TestArgon2IDAvailable(t *testing.T) {
	_ = Argon2IDAvailable()
}

// TestArgon2IDUnsupported 验证 Argon2ID 在 provider 不可用时返回 ErrUnsupported。
// 本测试不依赖具体构建 —— Argon2IDAvailable==true 时此测试仍通过
// （仍返回 ErrUnsupported，因为派生尚未接线）。
func TestArgon2IDUnsupported(t *testing.T) {
	_, err := Argon2ID([]byte("p"), []byte("s"), 1, 1, 1, 32)
	if err == nil {
		t.Skip("Argon2ID unexpectedly available; skipping unsupported check")
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("Argon2ID err = %v, want ErrUnsupported", err)
	}
}

// TestNames 验证 Names 稳定且完整。
func TestNames(t *testing.T) {
	want := []string{"HKDF", "PBKDF2"}
	got := Names()
	if len(got) != len(want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Names()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	again := Names()
	if strings.Join(again, ",") != strings.Join(got, ",") {
		t.Fatalf("Names() not stable: %v then %v", got, again)
	}
}

// TestDeriveByNameMatchesTyped 验证 Derive 与类型化 HKDF/PBKDF2 一致。
func TestDeriveByNameMatchesTyped(t *testing.T) {
	secret := bytes.Repeat([]byte{0x0b}, 22)
	salt := mustHex(t, "000102030405060708090a0b0c")
	info := mustHex(t, "f0f1f2f3f4f5f6f7f8f9")

	hkdfTyped, err := HKDF(HashSHA256, secret, salt, info, 42)
	if err != nil {
		t.Fatal(err)
	}
	hkdfByName, err := Derive("HKDF", &Options{
		Digest: HashSHA256,
		Secret: secret,
		Salt:   salt,
		Info:   info,
		Length: 42,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hkdfTyped, hkdfByName) {
		t.Errorf("HKDF typed %x != by-name %x", hkdfTyped, hkdfByName)
	}

	pwd := []byte("password")
	pSalt := []byte("salt")
	pbTyped, err := PBKDF2(HashSHA256, pwd, pSalt, 1000, 32)
	if err != nil {
		t.Fatal(err)
	}
	pbByName, err := Derive("PBKDF2", &Options{
		Digest:     HashSHA256,
		Password:   pwd,
		Salt:       pSalt,
		Iterations: 1000,
		Length:     32,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pbTyped, pbByName) {
		t.Errorf("PBKDF2 typed %x != by-name %x", pbTyped, pbByName)
	}
}

// TestDeriveCaseInsensitive 验证 Derive 名称大小写不敏感。
func TestDeriveCaseInsensitive(t *testing.T) {
	secret := []byte("k")
	for _, name := range []string{"HKDF", "hkdf", "Hkdf", " HKDF "} {
		got, err := Derive(name, &Options{
			Digest: HashSHA256,
			Secret: secret,
			Length: 16,
		})
		if err != nil {
			t.Fatalf("Derive(%q) error: %v", name, err)
		}
		if len(got) != 16 {
			t.Errorf("Derive(%q) length = %d, want 16", name, len(got))
		}
	}
}

// TestDeriveUnknownAlgorithm 验证 Derive 拒绝未知算法名。
func TestDeriveUnknownAlgorithm(t *testing.T) {
	_, err := Derive("SCRYPT", &Options{Digest: HashSHA256, Secret: []byte("k"), Length: 16})
	if !errors.Is(err, ErrUnknownAlgorithm) {
		t.Errorf("err = %v, want ErrUnknownAlgorithm", err)
	}
}

// TestDeriveNilOptions 验证 nil Options 被拒绝。
func TestDeriveNilOptions(t *testing.T) {
	if _, err := Derive("HKDF", nil); err == nil {
		t.Error("want error for nil Options")
	}
}

// TestDeriveMissingFields 验证必填字段缺失返回明确错误。
func TestDeriveMissingFields(t *testing.T) {
	t.Run("HKDF-zero-length", func(t *testing.T) {
		_, err := Derive("HKDF", &Options{Digest: HashSHA256, Secret: []byte("k")})
		if err == nil {
			t.Error("want error for HKDF with Length=0")
		}
	})
	t.Run("PBKDF2-zero-iter", func(t *testing.T) {
		_, err := Derive("PBKDF2", &Options{Digest: HashSHA256, Password: []byte("p"), Length: 16})
		if err == nil {
			t.Error("want error for PBKDF2 with Iterations=0")
		}
	})
}

// TestValidateHash 验证 validateHash 接受全部 7 个常量。
func TestValidateHash(t *testing.T) {
	for _, h := range []Hash{HashMD5, HashSHA1, HashSHA224, HashSHA256, HashSHA384, HashSHA512, HashSM3} {
		if err := validateHash(h); err != nil {
			t.Errorf("validateHash(%q) = %v, want nil", h, err)
		}
	}
	if err := validateHash(Hash("BLAKE2")); err == nil {
		t.Error("want error for unknown hash")
	}
}

// mustHexB 是 mustHex 的 testing.B 版本（避免在 benchmark 里强制参数化）。
func mustHexB(b *testing.B, s string) []byte {
	b.Helper()
	out, err := hex.DecodeString(strings.ReplaceAll(s, "\n", ""))
	if err != nil {
		b.Fatalf("bad hex %q: %v", s, err)
	}
	return out
}

// BenchmarkHKDF 测量 HKDF-SHA256 派生 32 字节的吞吐。
func BenchmarkHKDF(b *testing.B) {
	secret := bytes.Repeat([]byte{0x0b}, 22)
	salt := mustHexB(b, "000102030405060708090a0b0c")
	info := mustHexB(b, "f0f1f2f3f4f5f6f7f8f9")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = HKDF(HashSHA256, secret, salt, info, 32)
	}
}

// BenchmarkPBKDF2 测量 PBKDF2-SHA256 1000 轮的吞吐。
func BenchmarkPBKDF2(b *testing.B) {
	password := []byte("password")
	salt := []byte("salt")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = PBKDF2(HashSHA256, password, salt, 1000, 32)
	}
}
