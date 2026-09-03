package key_test

import (
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/jwk"
	"github.com/blue-cloud-net/tongsuo-go/key"
	"github.com/blue-cloud-net/tongsuo-go/pkcs/pkcs12"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// TestUnifiedKeyThroughConsumers 验证统合密钥可直接贯穿消费方,无需改动其 API:
// x509.CreateCertificate(窄接口 Key() *core.PKey)、pkcs12.Pack(key.CoreKey 别名)、
// jwk.MarshalKey(key.CoreKey) 均接受 key.PrivateKey / key.PublicKey。
//
// TestUnifiedKeyThroughConsumers verifies that unified keys flow directly
// through the consumers without any change to their APIs:
// x509.CreateCertificate (narrow interface Key() *core.PKey),
// pkcs12.Pack (alias of key.CoreKey) and jwk.MarshalKey (key.CoreKey) all
// accept key.PrivateKey / key.PublicKey.
func TestUnifiedKeyThroughConsumers(t *testing.T) {
	priv, err := key.GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}
	now := time.Now()
	subject := x509.NewName().Add("CN", "unified.example")
	cert, err := x509.CreateCertificate(subject, subject, 7,
		now.Add(-time.Hour), now.Add(24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	// pkcs12:打包时直接接受统合 key.PrivateKey。
	p12, err := pkcs12.Pack(cert, priv, nil, "password", "unified")
	if err != nil {
		t.Fatalf("pkcs12.Pack: %v", err)
	}
	bundle, err := pkcs12.Parse(p12, "password")
	if err != nil {
		t.Fatalf("pkcs12.Parse: %v", err)
	}
	if bundle.Certificate == nil {
		t.Fatal("expected a leaf certificate")
	}
	// 解析出的底层核心句柄与统合私钥底层句柄相等。
	if bundle.PrivateKey == nil || !bundle.PrivateKey.Equal(priv.Key()) {
		t.Fatal("pkcs12 private key mismatch")
	}
	if err := bundle.PrivateKey.Close(); err != nil {
		t.Fatalf("close bundle private key: %v", err)
	}

	// jwk:MarshalKey 接受统合 key.PrivateKey。
	jw, err := jwk.MarshalKey(priv)
	if err != nil {
		t.Fatalf("jwk.MarshalKey: %v", err)
	}
	if !jw.IsPrivate() || jw.Kty != "RSA" {
		t.Fatalf("unexpected JWK: kty=%s private=%v", jw.Kty, jw.IsPrivate())
	}
	// JWK → PEM → key 解析回,底层密钥相等。
	pemBytes, err := jw.ToPEM()
	if err != nil {
		t.Fatalf("jwk.ToPEM: %v", err)
	}
	back, err := key.LoadPrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("key.LoadPrivateKeyPEM: %v", err)
	}
	if !back.Equal(priv) {
		t.Fatal("jwk round-trip key mismatch")
	}
	if err := key.Close(back); err != nil {
		t.Fatal(err)
	}
	if err := key.Close(priv); err != nil {
		t.Fatal(err)
	}
}
