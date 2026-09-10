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

// TestParseResponseNilCertOrIssuer 验证 ParseResponse 对 nil 参数报错。
func TestParseResponseNilCertOrIssuer(t *testing.T) {
	if _, err := ParseResponse([]byte{0x30, 0x00}, nil, nil); err == nil {
		t.Fatal("nil cert/issuer should error")
	}
}

// TestCreateRequestEmptyHash 验证空 hash 等价 sha1。
func TestCreateRequestEmptyHash(t *testing.T) {
	leaf, caCert := buildCerts(t)
	der1, _ := CreateRequest(leaf, caCert, "")
	der2, _ := CreateRequest(leaf, caCert, "sha1")
	// 空 hash 与 sha1 应产生等价请求（X509_NAME_hash 一样）
	if len(der1) != len(der2) {
		t.Fatalf("empty vs sha1 differ in length: %d vs %d", len(der1), len(der2))
	}
}

// TestResponseCloseIdempotent 验证 Response.Close 幂等。
func TestResponseCloseIdempotent(t *testing.T) {
	// 构造一个 Response（绕开真实响应生成；这里只测 Close 路径）
	var r *Response
	if err := r.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}

	// 有 resp 但已 Close
	r2 := &Response{}
	if err := r2.Close(); err != nil {
		t.Fatalf("empty Close: %v", err)
	}
	// 二次也安全
	if err := r2.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestVerifyNilResponse 验证 Verify 对 nil Response 返回错误。
func TestVerifyNilResponse(t *testing.T) {
	var r *Response
	if err := r.Verify(nil, nil); err == nil {
		t.Fatal("nil Verify should error")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
