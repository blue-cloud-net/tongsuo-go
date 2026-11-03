package asym

import (
	"bytes"
	"errors"
	"testing"
)

// TestRSASM3PKCS1v15 验证 RSA-PKCS#1 v1.5 + SM3 的签名验签往返与篡改检测。
//
// TestRSASM3PKCS1v15 verifies the RSA-PKCS#1 v1.5 + SM3 sign/verify round
// trip and tamper detection.
func TestRSASM3PKCS1v15(t *testing.T) {
	priv, err := GenerateRSA(2048)
	if err != nil {
		t.Fatalf("GenerateRSA: %v", err)
	}
	pub := priv.Public()
	msg := []byte("rsa with sm3 digest")

	supported, probeErr := SupportsRSASignatureDigest(priv, "sm3")
	if probeErr != nil {
		t.Fatal(probeErr)
	}
	if !supported {
		if _, err := SignPKCS1v15(priv, msg, "sm3"); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unavailable RSA-SM3 must return ErrUnsupported: %v", err)
		}
		return
	}

	sig, err := SignPKCS1v15(priv, msg, "sm3")
	if err != nil {
		t.Fatalf("SignPKCS1v15(sm3): %v", err)
	}
	if err := VerifyPKCS1v15(pub, msg, sig, "sm3"); err != nil {
		t.Fatalf("VerifyPKCS1v15(sm3): %v", err)
	}

	// 篡改消息必须失败
	if err := VerifyPKCS1v15(pub, []byte("rsa with sm3 digesT"), sig, "sm3"); err == nil {
		t.Error("tampered message: want verification failure")
	}
	// 摘要不匹配必须失败（用 SHA-256 验 SM3 签名）
	if err := VerifyPKCS1v15(pub, msg, sig, "sha256"); err == nil {
		t.Error("wrong digest: want verification failure")
	}
}

// TestRSASM3PSS 验证 RSA-PSS + SM3（MGF1 同用 SM3）。
//
// TestRSASM3PSS verifies RSA-PSS with SM3 (MGF1 uses SM3 as well).
func TestRSASM3PSS(t *testing.T) {
	priv, err := GenerateRSA(2048)
	if err != nil {
		t.Fatalf("GenerateRSA: %v", err)
	}
	pub := priv.Public()
	msg := []byte("rsa-pss with sm3")

	supported, probeErr := SupportsRSASignatureDigest(priv, "sm3")
	if probeErr != nil {
		t.Fatal(probeErr)
	}
	if !supported {
		if _, err := SignPSS(priv, msg, PSSSaltLenDigest, "sm3"); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unavailable RSA-SM3 must return ErrUnsupported: %v", err)
		}
		return
	}

	sig, err := SignPSS(priv, msg, PSSSaltLenDigest, "sm3")
	if err != nil {
		t.Fatalf("SignPSS(sm3): %v", err)
	}
	if err := VerifyPSS(pub, msg, sig, PSSSaltLenDigest, "sm3"); err != nil {
		t.Fatalf("VerifyPSS(sm3): %v", err)
	}
	if err := VerifyPSS(pub, []byte("tampered"), sig, PSSSaltLenDigest, "sm3"); err == nil {
		t.Error("tampered message: want verification failure")
	}
}

// TestRSASM3OAEP 验证 RSA-OAEP + SM3 的加解密往返。
//
// TestRSASM3OAEP verifies the RSA-OAEP + SM3 encrypt/decrypt round trip.
func TestRSASM3OAEP(t *testing.T) {
	priv, err := GenerateRSA(2048)
	if err != nil {
		t.Fatalf("GenerateRSA: %v", err)
	}
	pub := priv.Public()
	plain := []byte("oaep with sm3")

	ct, err := EncryptOAEP(pub, plain, "sm3")
	if err != nil {
		t.Fatalf("EncryptOAEP(sm3): %v", err)
	}
	pt, err := DecryptOAEP(priv, ct, "sm3")
	if err != nil {
		t.Fatalf("DecryptOAEP(sm3): %v", err)
	}
	if !bytes.Equal(pt, plain) {
		t.Errorf("round trip = %q, want %q", pt, plain)
	}
	// 摘要不一致时解密必须失败
	if _, err := DecryptOAEP(priv, ct, "sha256"); err == nil {
		t.Error("wrong digest: want decryption failure")
	}
}

// TestRSAUnsupportedHash 验证未知摘要名返回明确错误。
//
// TestRSAUnsupportedHash verifies an unknown digest name returns a clear
// error.
func TestRSAUnsupportedHash(t *testing.T) {
	priv, err := GenerateRSA(2048)
	if err != nil {
		t.Fatalf("GenerateRSA: %v", err)
	}
	if _, err := SignPKCS1v15(priv, []byte("x"), "md4"); err == nil {
		t.Error("SignPKCS1v15(md4): want error")
	}
	if _, err := SignPSS(priv, []byte("x"), PSSSaltLenDigest, "md4"); err == nil {
		t.Error("SignPSS(md4): want error")
	}
}
