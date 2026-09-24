package asym

import (
	"bytes"
	"errors"
	"testing"
)

// TestGenerateRSA 验证 RSA 密钥生成：bits 太小报错误；正常生成返回非空 + 算法正确。
func TestGenerateRSA(t *testing.T) {
	if _, err := GenerateRSA(512); err == nil {
		t.Fatal("bits<1024 should fail")
	}
	priv, err := GenerateRSA(2048)
	if err != nil {
		t.Fatalf("GenerateRSA(2048): %v", err)
	}
	if priv.Algorithm() != AlgRSA {
		t.Fatalf("alg = %s, want RSA", priv.Algorithm())
	}
	pub := priv.Public()
	if pub.Algorithm() != AlgRSA {
		t.Fatalf("pub alg = %s", pub.Algorithm())
	}
}

// TestRSAPEMRoundtrip 验证 PKCS#8 私钥 / SPKI 公钥 PEM 往返。
func TestRSAPEMRoundtrip(t *testing.T) {
	priv, err := GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(privPEM, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Fatalf("unexpected private PEM header: %q", privPEM[:32])
	}
	loaded, err := LoadPrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	loadedPEM, err := loaded.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loadedPEM, privPEM) {
		t.Fatal("PKCS#8 roundtrip mismatch")
	}

	// PKCS#1 私钥
	pkcs1, err := MarshalRSAPrivateKeyPKCS1PEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pkcs1, []byte("-----BEGIN RSA PRIVATE KEY-----")) {
		t.Fatalf("unexpected PKCS#1 header: %q", pkcs1[:32])
	}
	if _, err := LoadPrivateKeyPEM(pkcs1); err != nil {
		t.Fatalf("PKCS#1 load: %v", err)
	}

	// 公钥
	pubPEM, err := priv.Public().MarshalPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pubPEM, []byte("-----BEGIN PUBLIC KEY-----")) {
		t.Fatalf("unexpected public PEM header: %q", pubPEM[:32])
	}
	loadedPub, err := LoadPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	loadedPubPEM, err := loadedPub.MarshalPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loadedPubPEM, pubPEM) {
		t.Fatal("public PEM roundtrip mismatch")
	}
}

// TestRSASignVerifyPKCS1v15 验证 PKCS#1 v1.5 签名验签往返。
func TestRSASignVerifyPKCS1v15(t *testing.T) {
	priv, err := GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("hello rsa pkcs1v15")
	sig, err := SignPKCS1v15(priv, data, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPKCS1v15(priv.Public(), data, sig, "sha256"); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// 篡改数据
	if err := VerifyPKCS1v15(priv.Public(), []byte("tamper"), sig, "sha256"); err == nil {
		t.Fatal("verify tampered should fail")
	}
}

// TestRSASignPKCS1v15Hash 验证 hash 名称分发。
func TestRSASignPKCS1v15Hash(t *testing.T) {
	priv, _ := GenerateRSA(2048)
	data := []byte("hash dispatch")
	for _, h := range []string{"sha1", "sha224", "sha256", "sha384", "sha512", ""} {
		sig, err := SignPKCS1v15(priv, data, h)
		if err != nil {
			t.Fatalf("sign %q: %v", h, err)
		}
		if err := VerifyPKCS1v15(priv.Public(), data, sig, h); err != nil {
			t.Fatalf("verify %q: %v", h, err)
		}
	}
	if _, err := SignPKCS1v15(priv, []byte("x"), "md5"); err == nil {
		t.Fatal("unsupported hash should fail")
	}
}

// TestRSASignVerifyPSS 验证 PSS 签名验签往返。
func TestRSASignVerifyPSS(t *testing.T) {
	priv, err := GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("hello rsa pss")
	sig, err := SignPSS(priv, data, PSSSaltLenDigest, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPSS(priv.Public(), data, sig, PSSSaltLenDigest, "sha256"); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// saltLen 不一致 → 验签失败
	if err := VerifyPSS(priv.Public(), data, sig, PSSSaltLenMax, "sha256"); err == nil {
		t.Fatal("saltLen mismatch should fail")
	}
}

// TestRSASignPSSHash 验证 PSS hash 分发。
func TestRSASignPSSHash(t *testing.T) {
	priv, _ := GenerateRSA(2048)
	data := []byte("pss hash")
	for _, h := range []string{"sha1", "sha224", "sha256", "sha384", "sha512"} {
		sig, err := SignPSS(priv, data, 0, h)
		if err != nil {
			t.Fatalf("sign %q: %v", h, err)
		}
		if err := VerifyPSS(priv.Public(), data, sig, 0, h); err != nil {
			t.Fatalf("verify %q: %v", h, err)
		}
	}
}

// TestRSAEncryptDecryptPKCS1v15 验证 PKCS#1 v1.5 加解密。
func TestRSAEncryptDecryptPKCS1v15(t *testing.T) {
	priv, err := GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{
		[]byte("a"),
		bytes.Repeat([]byte("rsa"), 32),
	} {
		ct, err := EncryptPKCS1v15(priv.Public(), data)
		if err != nil {
			t.Fatalf("encrypt len %d: %v", len(data), err)
		}
		pt, err := DecryptPKCS1v15(priv, ct)
		if err != nil {
			t.Fatalf("decrypt len %d: %v", len(data), err)
		}
		if !bytes.Equal(pt, data) {
			t.Fatalf("decrypt mismatch for len %d", len(data))
		}
	}
}

// TestRSAEncryptDecryptOAEP 验证 OAEP 加解密（多种 digest）。
func TestRSAEncryptDecryptOAEP(t *testing.T) {
	priv, err := GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, digest := range []string{"sha1", "sha256", "sha384", "sha512", ""} {
		t.Run(digest, func(t *testing.T) {
			data := []byte("oaep payload")
			ct, err := EncryptOAEP(priv.Public(), data, digest)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			pt, err := DecryptOAEP(priv, ct, digest)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(pt, data) {
				t.Errorf("decrypt mismatch")
			}
		})
	}
}

// TestRSAEncryptedPEM 验证加密 PEM 加解密与 ChangePassword。
func TestRSAEncryptedPEM(t *testing.T) {
	priv, err := GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := MarshalRSAPrivateKeyEncryptedPEM(priv, "password")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(enc, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
		t.Fatalf("unexpected header: %q", enc[:32])
	}
	// 加载 + 验签可行
	loaded, err := LoadEncryptedPrivateKeyPEM(enc, "password")
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := SignPKCS1v15(priv, []byte("hello"), "sha256")
	if err := VerifyPKCS1v15(loaded.Public(), []byte("hello"), sig, "sha256"); err != nil {
		t.Fatalf("verify with reloaded key: %v", err)
	}

	// 错误口令
	if _, err := LoadEncryptedPrivateKeyPEM(enc, "wrong"); err == nil {
		t.Fatal("wrong password should fail")
	}

	// 改密
	re, err := ChangePassword(enc, "password", "newpass")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEncryptedPrivateKeyPEM(re, "newpass"); err != nil {
		t.Fatalf("reload after change: %v", err)
	}
}

// TestRSAParams 验证 RSA 参数提取。
func TestRSAParams(t *testing.T) {
	priv, err := GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	p, err := RSAParams(priv)
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("Params is nil")
	}
	if p.N == nil || p.E == nil {
		t.Error("N or E missing")
	}
	if p.D == nil || p.P == nil || p.Q == nil {
		t.Error("D/P/Q missing for private key")
	}
	pub := priv.Public()
	pp, err := RSAPublicParams(pub)
	if err != nil {
		t.Fatal(err)
	}
	if pp.N == nil || pp.E == nil {
		t.Error("public N/E missing")
	}
}

// TestRSAMatch 验证私钥与另一私钥公钥分量相等性判断。
func TestRSAMatch(t *testing.T) {
	a, _ := GenerateRSA(2048)
	b, _ := GenerateRSA(2048)
	match, err := RSAMatch(a, b.corePKey())
	if err != nil {
		t.Fatal(err)
	}
	if match {
		t.Fatal("different keys should not match")
	}
	match, err = RSAMatch(a, a.Public().corePKey())
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Fatal("self match should be true")
	}
}

// TestRSALoadTypeMismatch 验证非 RSA PEM 拒绝。
func TestRSALoadTypeMismatch(t *testing.T) {
	// SM2 私钥 PEM 喂给 RSA Load
	sm2Priv, err := GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	pem, err := sm2Priv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKeyPEM(pem); err == nil {
		t.Fatal("LoadPrivateKeyPEM should reject non-RSA PEM")
	}
}

// TestRSALoadInvalidPEM 验证非法 PEM 返回错误。
func TestRSALoadInvalidPEM(t *testing.T) {
	if _, err := LoadPrivateKeyPEM([]byte("not a pem")); err == nil {
		t.Fatal("expected error for invalid private PEM")
	}
	if _, err := LoadPublicKeyPEM([]byte("not a pem")); err == nil {
		t.Fatal("expected error for invalid public PEM")
	}
}

// TestRSATypeGuards 验证非 RSA 接收时返回明确错误。
func TestRSATypeGuards(t *testing.T) {
	sm2, _ := GenerateSM2()
	if _, err := SignPKCS1v15(sm2, []byte("x"), "sha256"); err == nil {
		t.Fatal("SignPKCS1v15 with SM2 should fail")
	}
	if _, err := EncryptPKCS1v15(sm2.Public(), []byte("x")); err == nil {
		t.Fatal("EncryptPKCS1v15 with SM2 should fail")
	}
	if errors.Is(nil, ErrUnknownAlgorithm) {
		t.Fatal("sentinel leak")
	}
}
