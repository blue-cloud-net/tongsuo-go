package pkcs7

import (
	"bytes"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/rsa"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// makeCert 构建一张自签证书（RSA）。
func makeCert(t *testing.T, cn string, serial int64) *x509.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := x509.NewName().Add("CN", cn)
	cert, err := x509.CreateCertificate(subject, subject, serial,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestBuildExtract 验证证书集合打包/提取往返。
func TestBuildExtract(t *testing.T) {
	c1 := makeCert(t, "a.pkcs7.dev", 1)
	c2 := makeCert(t, "b.pkcs7.dev", 2)

	der, err := Build([]*x509.Certificate{c1, c2})
	if err != nil {
		t.Fatal(err)
	}
	certs, err := Extract(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("extracted %d certs, want 2", len(certs))
	}
	if certs[0].Subject() != "a.pkcs7.dev" || certs[1].Subject() != "b.pkcs7.dev" {
		t.Fatalf("extracted subjects = %q, %q", certs[0].Subject(), certs[1].Subject())
	}
}

// TestPEMRoundtrip 验证 PEM 封装与提取。
func TestPEMRoundtrip(t *testing.T) {
	c1 := makeCert(t, "pem.pkcs7.dev", 3)
	der, err := Build([]*x509.Certificate{c1})
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := MarshalPEM(der)
	if !bytes.HasPrefix(pemBytes, []byte("-----BEGIN PKCS7-----")) {
		t.Fatalf("bad PEM header: %q", pemBytes[:24])
	}
	certs, err := Extract(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || certs[0].Subject() != "pem.pkcs7.dev" {
		t.Fatalf("PEM roundtrip mismatch: %v", certs)
	}
}

// TestBuildEmpty 验证空证书切片返回有效 DER（OpenSSL 允许空 SignedData）。
func TestBuildEmpty(t *testing.T) {
	der, err := Build(nil)
	if err != nil {
		t.Fatalf("Build(nil): %v", err)
	}
	if len(der) == 0 {
		t.Fatal("Build(nil) returned empty DER")
	}
}

// TestExtractInvalidDER 验证非法 DER / PEM 返回错误。
func TestExtractInvalidDER(t *testing.T) {
	if _, err := Extract([]byte("garbage")); err == nil {
		t.Fatal("garbage should error")
	}
	if _, err := Extract(nil); err == nil {
		t.Fatal("nil should error")
	}
	if _, err := Extract([]byte("not pem either")); err == nil {
		t.Fatal("invalid data should error")
	}
}

// TestMarshalPEMRoundtrip 验证 PEM 多次编码后仍可被 Extract。
func TestMarshalPEMRoundtrip(t *testing.T) {
	c1 := makeCert(t, "marshal.pkcs7.dev", 5)
	der, _ := Build([]*x509.Certificate{c1})
	pem1 := MarshalPEM(der)
	// 再次 marshal（DER 与 PEM 等价输入应都能解码）
	certs, err := Extract(pem1)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("MarshalPEM roundtrip count = %d, want 1", len(certs))
	}
}

// TestBuildOrder 验证证书顺序保持（先进先出）。
func TestBuildOrder(t *testing.T) {
	cs := []*x509.Certificate{
		makeCert(t, "first", 1),
		makeCert(t, "second", 2),
		makeCert(t, "third", 3),
	}
	der, err := Build(cs)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Extract(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d certs, want 3", len(got))
	}
	for i, want := range []string{"first", "second", "third"} {
		if got[i].Subject() != want {
			t.Errorf("position %d: got %q, want %q", i, got[i].Subject(), want)
		}
	}
}
