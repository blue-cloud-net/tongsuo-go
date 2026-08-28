package ecdsa
package ecdsa

import (
	"bytes"
	"testing"
)

// TestGenerateKey 验证 EC 密钥生成与参数提取。
func TestGenerateKey(t *testing.T) {
	priv, err := GenerateKey("prime256v1")
	if err != nil {
		t.Fatal(err)
	}
	p := priv.Params()
	if p.Type != "EC" {
		t.Fatalf("params type = %q, want EC", p.Type)
	}
	if p.Curve != "prime256v1" {
		t.Fatalf("curve = %q, want prime256v1", p.Curve)
	}
	if p.X == nil || p.Y == nil {
		t.Fatal("EC params X/Y should be set")
	}
	if p.D == nil {
		t.Fatal("EC params D should be set for private key")
	}
	// P-256 坐标应为 32 字节
	if p.X.BitLen() > 256 || p.Y.BitLen() > 256 {
		t.Fatalf("point coords too large: X=%d bits Y=%d bits", p.X.BitLen(), p.Y.BitLen())
	}
}

// TestPEMRoundtrip 验证 PEM 往返。
func TestPEMRoundtrip(t *testing.T) {
	priv, _ := GenerateKey("prime256v1")

	pem, err := priv.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPrivateKeyPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Key().Equal(priv.Key()) {
		t.Fatal("private PEM roundtrip mismatch")
	}

	pubPEM, err := priv.Public().MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Key().PublicEqual(priv.Public().Key()) {
		t.Fatal("public PEM roundtrip mismatch")
	}
}

// TestSignVerify 验证 ECDSA-SHA256 签名验签与篡改检测。
func TestSignVerify(t *testing.T) {
	priv, _ := GenerateKey("prime256v1")
	data := []byte("hello ecdsa")

	sig, err := Sign(priv, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
	if err := Verify(priv.Public(), data, sig); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if err := Verify(priv.Public(), []byte("tampered"), sig); err == nil {
		t.Fatal("verify tampered data should fail")
	}
}

// TestOtherCurves 验证多曲线。
func TestOtherCurves(t *testing.T) {
	for _, curve := range []string{"secp384r1", "secp521r1"} {
		priv, err := GenerateKey(curve)
		if err != nil {
			t.Fatalf("GenerateKey(%s): %v", curve, err)
		}
		if priv.Params().Curve != curve {
			t.Fatalf("curve = %q, want %s", priv.Params().Curve, curve)
		}
		data := []byte("msg-" + curve)
		sig, err := Sign(priv, data)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(priv.Public(), data, sig); err != nil {
			t.Fatalf("%s verify failed: %v", curve, err)
		}
	}
}

// TestMatch 验证公钥匹配。
func TestMatch(t *testing.T) {
	priv1, _ := GenerateKey("prime256v1")
	priv2, _ := GenerateKey("prime256v1")
	if !priv1.Match(priv1.Public().Key()) {
		t.Fatal("priv1 should match its own public key")
	}
	if priv1.Match(priv2.Public().Key()) {
		t.Fatal("priv1 should NOT match priv2 public key")
	}
}

// TestSignDeterministicData 空数据/大文件边界。
func TestSignDeterministicData(t *testing.T) {
	priv, _ := GenerateKey("prime256v1")
	sig1, err := Sign(priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := Sign(priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(priv.Public(), nil, sig1); err != nil {
		t.Fatal("verify empty data failed")
	}
	// ECDSA 随机化签名（不同随机数），但各自都能验签
	if bytes.Equal(sig1, sig2) {
		t.Log("note: two empty-data signatures happened to be equal")
	}
}
