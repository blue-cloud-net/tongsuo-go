package key_test

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/key"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// RFC 5869 附录 A.1：HKDF-SHA-256，extract-and-expand，L=42。
//
// RFC 5869 Appendix A.1: HKDF-SHA-256, extract-and-expand, L=42.
func TestHKDFRFC5869(t *testing.T) {
	ikm := mustHex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustHex(t, "000102030405060708090a0b0c")
	info := mustHex(t, "f0f1f2f3f4f5f6f7f8f9")
	want := mustHex(t, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

	got, err := key.HKDF(key.HashSHA256, ikm, salt, info, len(want))
	if err != nil {
		t.Fatalf("HKDF: %v", err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Errorf("HKDF mismatch:\n got %x\nwant %x", got, want)
	}

	// 空 salt 路径也须可用（视为全零盐）。
	if _, err := key.HKDF(key.HashSHA256, ikm, nil, nil, 32); err != nil {
		t.Errorf("HKDF with empty salt/info: %v", err)
	}
}

// RFC 6070 附录 A：PBKDF2-HMAC-SHA1 向量（P="password"，S="salt"）。
//
// RFC 6070 Appendix A: PBKDF2-HMAC-SHA1 vectors (P="password", S="salt").
func TestPBKDF2RFC6070(t *testing.T) {
	password := []byte("password")
	salt := []byte("salt")
	cases := []struct {
		iter int
		want string
	}{
		{1, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
		{2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
		{4096, "4b007901b765489abead49d926f721d065a429c1"},
	}
	for _, c := range cases {
		got, err := key.PBKDF2(key.HashSHA1, password, salt, c.iter, 20)
		if err != nil {
			t.Fatalf("PBKDF2(iter=%d): %v", c.iter, err)
		}
		if hex.EncodeToString(got) != c.want {
			t.Errorf("PBKDF2(iter=%d) = %x, want %s", c.iter, got, c.want)
		}
	}
}

func TestKDFSM3(t *testing.T) {
	// SM3 与 SHA-256 输出同长（32 字节），仅验证可执行且长度正确。
	out, err := key.PBKDF2(key.HashSM3, []byte("pass"), []byte("salt"), 2, 32)
	if err != nil {
		t.Fatalf("PBKDF2(SM3): %v", err)
	}
	if len(out) != 32 {
		t.Errorf("PBKDF2(SM3) length = %d, want 32", len(out))
	}
}

func TestKDFValidation(t *testing.T) {
	if _, err := key.HKDF("SHA512X", []byte("secret"), nil, nil, 16); err == nil {
		t.Error("unsupported hash: want error")
	}
	if _, err := key.HKDF(key.HashSHA256, nil, nil, nil, 16); err == nil {
		t.Error("empty secret: want error")
	}
	if _, err := key.HKDF(key.HashSHA256, []byte("s"), nil, nil, 0); err == nil {
		t.Error("zero length: want error")
	}
	if _, err := key.PBKDF2(key.HashSHA256, nil, nil, 1, 16); err == nil {
		t.Error("empty password: want error")
	}
	if _, err := key.PBKDF2(key.HashSHA256, []byte("p"), nil, 0, 16); err == nil {
		t.Error("zero iter: want error")
	}
}

func TestArgon2IDUnavailable(t *testing.T) {
	// 无论 provider 是否存在,当前实现都返回 ErrUnsupported(可用则尚未接线)。
	if _, err := key.Argon2ID([]byte("p"), []byte("s"), 1, 1<<16, 1, 32); !errors.Is(err, key.ErrUnsupported) {
		t.Fatalf("Argon2ID error = %v, want ErrUnsupported", err)
	}
}
