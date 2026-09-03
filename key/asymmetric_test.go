package key_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/key"
)

// 编译期断言:key 自有类型满足相应接口。
//
// Compile-time assertions that the package's own types satisfy the
// relevant interfaces.
var (
	_ key.Key                  = (*key.PrivateKey)(nil)
	_ key.Key                  = (*key.PublicKey)(nil)
	_ key.AsymmetricKey        = (*key.PrivateKey)(nil)
	_ key.AsymmetricPrivateKey = (*key.PrivateKey)(nil)
	_ key.AsymmetricPublicKey  = (*key.PublicKey)(nil)
	_ key.CoreKey              = (*key.PrivateKey)(nil)
	_ key.CoreKey              = (*key.PublicKey)(nil)
)

func TestGenerateRSAKeyRoundTrip(t *testing.T) {
	priv, err := key.GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}
	if priv.Algorithm() != key.AlgRSA {
		t.Fatalf("Algorithm() = %s, want RSA", priv.Algorithm())
	}
	// PKCS#8 往返
	pem8, err := priv.Marshal()
	if err != nil {
		t.Fatalf("Marshal(PKCS#8): %v", err)
	}
	parsed, err := key.LoadPrivateKeyPEM(pem8)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM(PKCS#8): %v", err)
	}
	if !parsed.Equal(priv) {
		t.Error("PKCS#8 round-trip key not Equal")
	}
	// PKCS#1 往返(自动回退解析)
	pem1, err := priv.MarshalPKCS1()
	if err != nil {
		t.Fatalf("MarshalPKCS1: %v", err)
	}
	parsed1, err := key.LoadPrivateKeyPEM(pem1)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM(PKCS#1): %v", err)
	}
	if !parsed1.Equal(priv) {
		t.Error("PKCS#1 round-trip key not Equal")
	}
}

func TestGenerateSM2KeyRoundTrip(t *testing.T) {
	priv, err := key.GenerateSM2Key()
	if err != nil {
		t.Fatalf("GenerateSM2Key: %v", err)
	}
	if priv.Algorithm() != key.AlgSM2 {
		t.Fatalf("Algorithm() = %s, want SM2", priv.Algorithm())
	}
	pem8, err := priv.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := key.LoadPrivateKeyPEM(pem8)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM: %v", err)
	}
	if !parsed.Equal(priv) {
		t.Error("SM2 round-trip key not Equal")
	}
	if _, err := priv.MarshalPKCS1(); !errors.Is(err, key.ErrUnsupported) {
		t.Fatalf("MarshalPKCS1 on SM2: err = %v, want ErrUnsupported", err)
	}
}

func TestGenerateECKeyRoundTrip(t *testing.T) {
	for _, curve := range []string{"prime256v1", "secp384r1"} {
		priv, err := key.GenerateECKey(curve)
		if err != nil {
			t.Fatalf("GenerateECKey(%s): %v", curve, err)
		}
		if priv.Algorithm() != key.AlgECDSA {
			t.Errorf("GenerateECKey(%s) Algorithm() = %s, want ECDSA", curve, priv.Algorithm())
		}
		pem8, err := priv.Marshal()
		if err != nil {
			t.Fatalf("Marshal(%s): %v", curve, err)
		}
		parsed, err := key.LoadPrivateKeyPEM(pem8)
		if err != nil {
			t.Fatalf("LoadPrivateKeyPEM(%s): %v", curve, err)
		}
		if !parsed.Equal(priv) {
			t.Errorf("%s round-trip key not Equal", curve)
		}
		if _, err := priv.MarshalPKCS1(); !errors.Is(err, key.ErrUnsupported) {
			t.Errorf("MarshalPKCS1 on %s: err = %v, want ErrUnsupported", curve, err)
		}
	}
}

func TestGenerateECKeySM2Curve(t *testing.T) {
	// EC 生成在 sm2 曲线上仍是 EC 类型(ECDSA over SM2 curve),不报告 SM2。
	priv, err := key.GenerateECKey("sm2")
	if err != nil {
		t.Fatalf("GenerateECKey(sm2): %v", err)
	}
	if priv.Algorithm() != key.AlgECDSA {
		t.Fatalf("GenerateECKey(sm2) Algorithm() = %s, want ECDSA", priv.Algorithm())
	}
}

func TestGenerateRSAKeySmallBits(t *testing.T) {
	if _, err := key.GenerateRSAKey(512); err == nil {
		t.Fatal("512-bit RSA: want error")
	}
}

func TestPublicKeyRoundTrip(t *testing.T) {
	priv, err := key.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()
	if pub.Algorithm() != key.AlgRSA {
		t.Fatalf("public Algorithm() = %s, want RSA", pub.Algorithm())
	}
	spki, err := pub.Marshal()
	if err != nil {
		t.Fatalf("public Marshal: %v", err)
	}
	if !strings.Contains(string(spki), "PUBLIC KEY") {
		t.Error("public Marshal output lacks PUBLIC KEY block")
	}
	parsedPub, err := key.LoadPublicKeyPEM(spki)
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM: %v", err)
	}
	if !parsedPub.Equal(pub) {
		t.Error("public round-trip key not Equal")
	}
}

func TestEncryptedRoundTrip(t *testing.T) {
	priv, err := key.GenerateSM2Key()
	if err != nil {
		t.Fatal(err)
	}
	const pass = "hunter2"
	enc, err := priv.MarshalEncrypted(pass)
	if err != nil {
		t.Fatalf("MarshalEncrypted: %v", err)
	}
	parsed, err := key.LoadPrivateKeyPEMEncrypted(enc, pass)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEMEncrypted: %v", err)
	}
	if !parsed.Equal(priv) {
		t.Error("encrypted round-trip key not Equal")
	}
	if _, err := key.LoadPrivateKeyPEMEncrypted(enc, "wrong"); err == nil {
		t.Error("wrong passphrase: want error")
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := key.LoadPrivateKeyPEM([]byte("garbage")); err == nil {
		t.Error("LoadPrivateKeyPEM(garbage): want error")
	}
	if _, err := key.LoadPublicKeyPEM([]byte("garbage")); err == nil {
		t.Error("LoadPublicKeyPEM(garbage): want error")
	}
	if _, err := key.ParsePEM([]byte("not a pem")); err == nil {
		t.Error("ParsePEM(garbage): want error")
	}
}

func TestCloseThenMarshalError(t *testing.T) {
	priv, err := key.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Close(priv); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// 幂等关闭
	if err := key.Close(priv); err != nil {
		t.Fatalf("second Close: %v, want nil", err)
	}
	if _, err := priv.Marshal(); err == nil {
		t.Error("Marshal after Close: want error")
	}
}
