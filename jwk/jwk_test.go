package jwk

import (
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/crypto/ecdsa"
	"github.com/blue-cloud-net/tongsuo-go/crypto/rsa"
)

// TestRSA 验证 RSA JWK ↔ PEM 往返。
func TestRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	k, err := Marshal(priv.Key())
	if err != nil {
		t.Fatal(err)
	}
	if k.Kty != "RSA" || k.N == "" || k.E == "" || k.D == "" {
		t.Fatalf("jwk fields: %+v", k)
	}
	if !k.IsPrivate() {
		t.Fatal("RSA private JWK should have private material")
	}

	// 私钥 PEM 往返
	pemBytes, err := k.ToPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := rsa.LoadPrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Key().Equal(priv.Key()) {
		t.Fatal("RSA private PEM roundtrip mismatch")
	}

	// 公钥 PEM 往返
	pubPEM, err := k.ToPublicPEM()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := rsa.LoadPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Key().PublicEqual(priv.Public().Key()) {
		t.Fatal("RSA public PEM roundtrip mismatch")
	}
}

// TestEC 验证 EC JWK ↔ PEM 往返。
func TestEC(t *testing.T) {
	priv, err := ecdsa.GenerateKey("prime256v1")
	if err != nil {
		t.Fatal(err)
	}
	k, err := Marshal(priv.Key())
	if err != nil {
		t.Fatal(err)
	}
	if k.Kty != "EC" || k.Crv != "P-256" || k.X == "" || k.Y == "" || k.D == "" {
		t.Fatalf("jwk fields: %+v", k)
	}
	pemBytes, err := k.ToPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := ecdsa.LoadPrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Key().Equal(priv.Key()) {
		t.Fatal("EC private PEM roundtrip mismatch")
	}
}

// TestParseAndFromPEM 验证 JSON 解析与 FromPEM。
func TestParseAndFromPEM(t *testing.T) {
	priv, _ := rsa.GenerateKey(2048)
	k, _ := Marshal(priv.Key())
	data, err := k.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if k2.Kty != "RSA" || k2.N != k.N {
		t.Fatal("parse mismatch")
	}

	privPEM, _ := priv.MarshalPEM()
	k3, err := FromPEM(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	if k3.N != k.N {
		t.Fatal("FromPEM mismatch")
	}
}
