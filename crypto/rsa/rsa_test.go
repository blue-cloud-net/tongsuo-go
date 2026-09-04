package rsa

import (
	"bytes"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// TestGenerateKey 验证 RSA 密钥生成与参数提取。
func TestGenerateKey(t *testing.T) {
	priv, err := GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	p := priv.Params()
	if p.Type != "RSA" {
		t.Fatalf("params type = %q, want RSA", p.Type)
	}
	if p.N == nil || p.E == nil || p.D == nil {
		t.Fatalf("RSA params N/E/D should be set: %+v", p)
	}
	if p.N.BitLen() != 2048 {
		t.Fatalf("N bitlen = %d, want 2048", p.N.BitLen())
	}
	if p.E.Int64() != 65537 {
		t.Fatalf("E = %v, want 65537", p.E)
	}
	if p.P == nil || p.Q == nil {
		t.Fatal("RSA params P/Q should be set for private key")
	}
}

// TestPEMRoundtrip 验证 PKCS#8 与 PKCS#1 PEM 往返。
func TestPEMRoundtrip(t *testing.T) {
	priv, _ := GenerateKey(2048)

	pkcs8, err := priv.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pkcs8, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Fatalf("bad PKCS#8 header: %q", pkcs8[:28])
	}
	loaded, err := LoadPrivateKeyPEM(pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Key().Equal(priv.Key()) {
		t.Fatal("PKCS#8 roundtrip key mismatch")
	}

	pkcs1, err := priv.MarshalPKCS1PEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pkcs1, []byte("-----BEGIN RSA PRIVATE KEY-----")) {
		t.Fatalf("bad PKCS#1 header: %q", pkcs1[:30])
	}
	loaded1, err := LoadPrivateKeyPEM(pkcs1) // 自动识别 PKCS#1
	if err != nil {
		t.Fatal(err)
	}
	if !loaded1.Key().Equal(priv.Key()) {
		t.Fatal("PKCS#1 roundtrip key mismatch")
	}

	// 公钥往返
	pubPEM, err := priv.Public().MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Key().PublicEqual(priv.Public().Key()) {
		t.Fatal("public key roundtrip mismatch")
	}
}

// TestSignVerifyPKCS1v15 验证 PKCS#1 v1.5 签名验签与篡改检测。
func TestSignVerifyPKCS1v15(t *testing.T) {
	priv, _ := GenerateKey(2048)
	data := []byte("hello rsa signature")

	sig, err := priv.SignPKCS1v15(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 256 {
		t.Fatalf("signature length = %d, want 256", len(sig))
	}
	if err := priv.Public().VerifyPKCS1v15(data, sig); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if err := priv.Public().VerifyPKCS1v15([]byte("tampered"), sig); err == nil {
		t.Fatal("verify tampered data should fail")
	}
	sig[0] ^= 0xff
	if err := priv.Public().VerifyPKCS1v15(data, sig); err == nil {
		t.Fatal("verify tampered signature should fail")
	}
}

// TestSignVerifyPSS 验证 RSA-PSS 签名验签。
func TestSignVerifyPSS(t *testing.T) {
	priv, _ := GenerateKey(2048)
	data := []byte("hello rsa pss")

	sig, err := priv.SignPSS(data, -1) // 盐长=摘要长
	if err != nil {
		t.Fatal(err)
	}
	if err := priv.Public().VerifyPSS(data, sig, -1); err != nil {
		t.Fatalf("pss verify failed: %v", err)
	}
	if err := priv.Public().VerifyPSS(data, sig, -2); err != nil {
		t.Fatalf("pss verify (auto salt) failed: %v", err)
	}
	if err := priv.Public().VerifyPSS([]byte("tampered"), sig, -1); err == nil {
		t.Fatal("pss verify tampered should fail")
	}
}

// TestEncryptDecrypt 验证 PKCS#1 v1.5 与 OAEP 加解密。
func TestEncryptDecrypt(t *testing.T) {
	priv, _ := GenerateKey(2048)
	pub := priv.Public()
	msg := []byte("secret message")

	ct, err := EncryptPKCS1v15(pub, msg)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := DecryptPKCS1v15(priv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatal("PKCS1v15 decrypt mismatch")
	}

	ct2, err := EncryptOAEP(pub, msg, core.SHA256())
	if err != nil {
		t.Fatal(err)
	}
	pt2, err := DecryptOAEP(priv, ct2, core.SHA256())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt2, msg) {
		t.Fatal("OAEP decrypt mismatch")
	}
}

// TestEncryptedPEM 验证加密 PEM 往返与改密。
func TestEncryptedPEM(t *testing.T) {
	priv, _ := GenerateKey(2048)

	enc, err := priv.MarshalEncryptedPEM("secret123")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(enc, []byte("ENCRYPTED")) {
		t.Fatalf("encrypted PEM should contain ENCRYPTED header: %q", enc[:32])
	}
	loaded, err := LoadEncryptedPEM(enc, "secret123")
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Key().Equal(priv.Key()) {
		t.Fatal("encrypted PEM roundtrip key mismatch")
	}
	// 错误口令失败
	if _, err := LoadEncryptedPEM(enc, "wrong"); err == nil {
		t.Fatal("load with wrong passphrase should fail")
	}

	// 改密
	changed, err := ChangePassword(enc, "secret123", "newpass")
	if err != nil {
		t.Fatal(err)
	}
	loaded2, err := LoadEncryptedPEM(changed, "newpass")
	if err != nil {
		t.Fatal(err)
	}
	if !loaded2.Key().Equal(priv.Key()) {
		t.Fatal("changed password key mismatch")
	}
}

// TestMatch 验证公钥匹配。
func TestMatch(t *testing.T) {
	priv1, _ := GenerateKey(2048)
	priv2, _ := GenerateKey(2048)

	if !priv1.Match(priv1.Public().Key()) {
		t.Fatal("priv1 should match its own public key")
	}
	if priv1.Match(priv2.Public().Key()) {
		t.Fatal("priv1 should NOT match priv2 public key")
	}
}

// TestEncryptEmptyPlaintext 验证 RSA 空明文加解密往返可用（对齐 Go stdlib
// rsa.EncryptPKCS1v15 / EncryptOAEP 允许空明文语义）。
func TestEncryptEmptyPlaintext(t *testing.T) {
	priv, _ := GenerateKey(2048)
	pub := priv.Public()

	ct, err := EncryptPKCS1v15(pub, nil)
	if err != nil {
		t.Fatalf("PKCS1v15 empty plaintext should be allowed: %v", err)
	}
	pt, err := DecryptPKCS1v15(priv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if len(pt) != 0 {
		t.Fatalf("PKCS1v15 empty decrypt returned %q", pt)
	}

	ct2, err := EncryptOAEP(pub, nil, core.SHA256())
	if err != nil {
		t.Fatalf("OAEP empty plaintext should be allowed: %v", err)
	}
	pt2, err := DecryptOAEP(priv, ct2, core.SHA256())
	if err != nil {
		t.Fatal(err)
	}
	if len(pt2) != 0 {
		t.Fatalf("OAEP empty decrypt returned %q", pt2)
	}
}

// TestLoadPrivateKeyTypeMismatch 验证把 SM2 私钥 PKCS#8 PEM 传给 rsa 加载器
// 会返回明确类型错误（而非静默包装成 RSA）。
func TestLoadPrivateKeyTypeMismatch(t *testing.T) {
	sm2priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sm2pem, err := sm2priv.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKeyPEM(sm2pem); err == nil {
		t.Fatal("expected type-mismatch error for SM2 PEM loaded as RSA")
	} else if !bytes.Contains([]byte(err.Error()), []byte("not RSA")) {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestLoadPrivateKeyDoubleFailure 验证既非 PKCS#8 也非 PKCS#1 的输入返回
// 同时说明两条路径的合并错误。
func TestLoadPrivateKeyDoubleFailure(t *testing.T) {
	_, err := LoadPrivateKeyPEM([]byte("garbage"))
	if err == nil {
		t.Fatal("expected error for garbage input")
	}
	msg := err.Error()
	if !bytes.Contains([]byte(msg), []byte("pkcs8")) || !bytes.Contains([]byte(msg), []byte("pkcs1")) {
		t.Fatalf("expected combined pkcs8+pkcs1 error, got: %v", err)
	}
}
