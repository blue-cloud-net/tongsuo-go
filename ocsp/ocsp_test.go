package ocsp

import (
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/rsa"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// buildCerts 构建 CA 签发叶证书（RSA）。
func buildCerts(t *testing.T) (leaf *x509.Certificate, caCert *x509.Certificate) {
	t.Helper()
	now := time.Now()
	caPriv, err := rsa.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	caSubject := x509.NewName().Add("CN", "OCSP Test CA")
	caCert = x509.NewCertificate()
	if err := caCert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetSerial(1); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetIssuer(caSubject); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetSubject(caSubject); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetValidity(now.Add(-time.Hour), now.Add(2*365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := caCert.SetPublicKey(caPriv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := caCert.AddBasicConstraints(true); err != nil {
		t.Fatal(err)
	}
	if err := caCert.Sign(caPriv); err != nil {
		t.Fatal(err)
	}

	leafPriv, err := rsa.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.CreateCertificate(x509.NewName().Add("CN", "leaf.ocsp.dev"),
		caSubject, 2, now.Add(-time.Hour), now.Add(365*24*time.Hour), leafPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, caCert
}

// TestCreateRequest 验证 OCSP 请求生成（DER 结构 + 非法参数）。
func TestCreateRequest(t *testing.T) {
	leaf, caCert := buildCerts(t)
	for _, hash := range []string{"sha1", "sha256", "sm3"} {
		der, err := CreateRequest(leaf, caCert, hash)
		if err != nil {
			t.Fatalf("CreateRequest(%s): %v", hash, err)
		}
		if len(der) == 0 || der[0] != 0x30 { // 顶层应为 SEQUENCE
			t.Fatalf("request DER invalid: %x", der[:min(4, len(der))])
		}
	}
	if _, err := CreateRequest(nil, caCert, "sha1"); err == nil {
		t.Fatal("nil cert should error")
	}
	if _, err := CreateRequest(leaf, nil, "sha1"); err == nil {
		t.Fatal("nil issuer should error")
	}
	if _, err := CreateRequest(leaf, caCert, "md5"); err == nil {
		t.Fatal("unsupported hash should error")
	}
}

// TestParseResponseInvalid 验证非法响应解析报错。
func TestParseResponseInvalid(t *testing.T) {
	leaf, caCert := buildCerts(t)
	if _, err := ParseResponse([]byte("garbage"), leaf, caCert); err == nil {
		t.Fatal("garbage response should error")
	}
	if _, err := ParseResponse(nil, leaf, caCert); err == nil {
		t.Fatal("nil response should error")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
