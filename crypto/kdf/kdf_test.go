package kdf_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/crypto/kdf"
)

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
		md   string
		ikm  []byte
		salt []byte
		info []byte
		l    int
		okm  []byte
	}{
		{
			name: "SHA-256 A.1",
			md:   "SHA256",
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
			md:   "SHA1",
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
			out, err := kdf.HKDF(v.md, v.ikm, v.salt, v.info, v.l)
			if err != nil {
				t.Fatalf("HKDF: %v", err)
			}
			if !bytes.Equal(out, v.okm) {
				t.Fatalf("HKDF mismatch:\n got  %x\n want %x", out, v.okm)
			}
		})
	}
}

// TestHKDF_EmptySaltEqualsZeroSalt 验证空 salt 等价于 HashLen 字节的零盐（RFC 5869）。
func TestHKDF_EmptySaltEqualsZeroSalt(t *testing.T) {
	secret := []byte("secret-material")
	info := []byte("application-info")
	zero := make([]byte, 32) // SHA-256 的 HashLen

	a, err := kdf.HKDF("SHA256", secret, nil, info, 32)
	if err != nil {
		t.Fatalf("HKDF empty salt: %v", err)
	}
	b, err := kdf.HKDF("SHA256", secret, zero, info, 32)
	if err != nil {
		t.Fatalf("HKDF zero salt: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("empty salt != zero salt:\n a=%x\n b=%x", a, b)
	}
}

// TestHKDF_DigestNameNormalized 验证摘要名大小写与连字符不敏感。
func TestHKDF_DigestNameNormalized(t *testing.T) {
	secret := []byte("secret-material")
	info := []byte("info")
	a, err := kdf.HKDF("SHA256", secret, nil, info, 32)
	if err != nil {
		t.Fatalf("HKDF SHA256: %v", err)
	}
	b, err := kdf.HKDF("sha-256", secret, nil, info, 32)
	if err != nil {
		t.Fatalf("HKDF sha-256: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("normalized name mismatch")
	}
}

// TestHKDF_InvalidArgs 验证非法入参被拒绝。
func TestHKDF_InvalidArgs(t *testing.T) {
	secret := []byte("secret")
	if _, err := kdf.HKDF("", secret, nil, nil, 32); err == nil {
		t.Fatal("want error for empty digest name")
	}
	if _, err := kdf.HKDF("SHA256", nil, nil, nil, 32); err == nil {
		t.Fatal("want error for empty secret")
	}
	if _, err := kdf.HKDF("SHA256", secret, nil, nil, 0); err == nil {
		t.Fatal("want error for zero length")
	}
}

// TestPBKDF2_RFC6070 用 RFC 6070 的标准向量验证 PBKDF2（SHA-1，c=1）。
func TestPBKDF2_RFC6070(t *testing.T) {
	out, err := kdf.PBKDF2("SHA1", []byte("password"), []byte("salt"), 1, 20)
	if err != nil {
		t.Fatalf("PBKDF2: %v", err)
	}
	want := mustHex(t, "0c60c80f961f0e71f3a9b524af6012062fe037a6")
	if !bytes.Equal(out, want) {
		t.Fatalf("PBKDF2 mismatch:\n got  %x\n want %x", out, want)
	}
}

// TestPBKDF2_InvalidArgs 验证非法入参被拒绝。
func TestPBKDF2_InvalidArgs(t *testing.T) {
	if _, err := kdf.PBKDF2("", []byte("password"), nil, 1, 20); err == nil {
		t.Fatal("want error for empty digest name")
	}
	if _, err := kdf.PBKDF2("SHA1", nil, nil, 1, 20); err == nil {
		t.Fatal("want error for empty password")
	}
	if _, err := kdf.PBKDF2("SHA1", []byte("password"), nil, 0, 20); err == nil {
		t.Fatal("want error for zero iterations")
	}
}
