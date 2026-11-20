package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	stdx509 "crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// sameKeyParams 比较两把密钥的参数指纹（含私钥分量），供整键往返断言。
//
// 原先用 `Key().Equal(...)` / `PublicEqual(...)`（核心句柄比较），随 roadmap §5 E1
// 收敛已删除，现改经 asym.Params 比较算法无关的参数快照。
//
// sameKeyParams compares the parameter fingerprints of two keys (private
// components included) for whole-key round-trip assertions. It replaces the
// retired core-handle comparisons Key().Equal / PublicEqual by comparing the
// algorithm-agnostic snapshot from asym.Params.
func sameKeyParams(t *testing.T, a, b asym.Key) bool {
	t.Helper()
	pa, err := asym.Params(a)
	if err != nil {
		t.Fatalf("asym.Params(a): %v", err)
	}
	pb, err := asym.Params(b)
	if err != nil {
		t.Fatalf("asym.Params(b): %v", err)
	}
	bi := func(x *big.Int) string {
		if x == nil {
			return "-"
		}
		return x.Text(16)
	}
	return pa.Type == pb.Type && pa.Curve == pb.Curve &&
		bi(pa.N) == bi(pb.N) && bi(pa.E) == bi(pb.E) && bi(pa.D) == bi(pb.D) &&
		bi(pa.P) == bi(pb.P) && bi(pa.Q) == bi(pb.Q) &&
		bi(pa.Dmp1) == bi(pb.Dmp1) && bi(pa.Dmq1) == bi(pb.Dmq1) &&
		bi(pa.Iqmp) == bi(pb.Iqmp) && bi(pa.X) == bi(pb.X) && bi(pa.Y) == bi(pb.Y)
}

// TestMarshalKey 验证 MarshalKey 接受 asym 密钥（roadmap §5 E1-1：参数由
// key.CoreKey 改为 asym.Key；key 包将被删除）。
//
// TestMarshalKey verifies MarshalKey accepts asym keys (roadmap §5, E1-1: the
// parameter changed from key.CoreKey to asym.Key as the key package goes away).
func TestMarshalKey(t *testing.T) {
	// 私钥
	rsaPriv, err := asym.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = asym.Close(rsaPriv) }()
	k1, err := MarshalKey(rsaPriv)
	if err != nil {
		t.Fatalf("MarshalKey(asym.PrivateKey): %v", err)
	}
	if k1.Kty != "RSA" || !k1.IsPrivate() {
		t.Fatalf("unexpected RSA jwk: %+v", k1)
	}

	k2, err := MarshalKey(rsaPriv.Public())
	if err != nil {
		t.Fatalf("MarshalKey(asym.PublicKey): %v", err)
	}
	if k2.Kty != "RSA" {
		t.Fatalf("unexpected RSA public jwk: %+v", k2)
	}
	if k2.IsPrivate() || k2.P != "" || k2.Q != "" || k2.DP != "" || k2.DQ != "" || k2.QI != "" {
		t.Fatal("RSA public JWK contains private parameters")
	}

	// EC
	ecPriv, err := asym.GenerateEC(asym.CurveP256)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = asym.Close(ecPriv) }()
	k3, err := MarshalKey(ecPriv)
	if err != nil {
		t.Fatalf("MarshalKey(EC): %v", err)
	}
	if k3.Kty != "EC" || k3.Crv != "P-256" {
		t.Fatalf("unexpected EC jwk: %+v", k3)
	}

	if _, err := MarshalKey(nil); err == nil {
		t.Error("MarshalKey(nil): want error")
	}
}

// TestRSA 验证 RSA JWK ↔ PEM 往返。
func TestRSA(t *testing.T) {
	priv, err := asym.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = asym.Close(priv) }()
	k, err := MarshalKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if k.Kty != "RSA" || k.N == "" || k.E == "" || k.D == "" {
		t.Fatalf("jwk fields: %+v", k)
	}
	if !k.IsPrivate() {
		t.Fatal("RSA private JWK should have private material")
	}
	// 私钥 JWK 现在应包含 RFC 7518 §6.3.2 的 CRT 字段 dp/dq/qi。
	// （公钥 Marshal 时这些字段保持为空，已由其它用例覆盖。）
	if k.DP == "" || k.DQ == "" || k.QI == "" {
		t.Fatalf("RSA private JWK should carry dp/dq/qi: %+v", k)
	}
	// 私钥 ↔ 私钥比较：dp/dq/qi 与 asym.Params 的 CRT 系数应一致。
	p, err := asym.Params(priv)
	if err != nil {
		t.Fatalf("asym.Params: %v", err)
	}
	if p == nil || p.Dmp1 == nil || p.Dmq1 == nil || p.Iqmp == nil {
		t.Fatal("underlying CRT params should be populated")
	}
	if want := b64(p.Dmp1); k.DP != want {
		t.Fatalf("JWK dp mismatch: got %q want %q", k.DP, want)
	}
	if want := b64(p.Dmq1); k.DQ != want {
		t.Fatalf("JWK dq mismatch: got %q want %q", k.DQ, want)
	}
	if want := b64(p.Iqmp); k.QI != want {
		t.Fatalf("JWK qi mismatch: got %q want %q", k.QI, want)
	}

	// 私钥 PEM 往返
	pemBytes, err := k.ToPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := asym.LoadPrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = asym.Close(loaded) }()
	if !sameKeyParams(t, loaded, priv) {
		t.Fatal("RSA private PEM roundtrip mismatch")
	}

	// 公钥 PEM 往返
	pubPEM, err := k.ToPublicPEM()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := asym.LoadPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = asym.Close(pub) }()
	matched, err := asym.Match(priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("RSA public PEM roundtrip mismatch")
	}
}

// TestEC 验证 EC JWK ↔ PEM 往返。
func TestEC(t *testing.T) {
	priv, err := asym.GenerateEC(asym.CurveP256)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = asym.Close(priv) }()
	k, err := MarshalKey(priv)
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
	loaded, err := asym.LoadPrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = asym.Close(loaded) }()
	if !sameKeyParams(t, loaded, priv) {
		t.Fatal("EC private PEM roundtrip mismatch")
	}
}

// TestParseAndFromPEM 验证 JSON 解析与 FromPEM。
func TestParseAndFromPEM(t *testing.T) {
	priv, err := asym.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = asym.Close(priv) }()
	k, err := MarshalKey(priv)
	if err != nil {
		t.Fatal(err)
	}
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

	privPEM, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	k3, err := FromPEM(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	if k3.N != k.N {
		t.Fatal("FromPEM mismatch")
	}
}

func TestPublicKeyExportOmitsPrivateParameters(t *testing.T) {
	for _, tc := range []struct {
		name     string
		generate func() (asym.PrivateKey, error)
	}{
		{"RSA", func() (asym.PrivateKey, error) { return asym.GenerateRSA(2048) }},
		{"ECDSA", func() (asym.PrivateKey, error) { return asym.GenerateEC(asym.CurveP256) }},
		{"SM2", asym.GenerateSM2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := tc.generate()
			if err != nil {
				t.Fatal(err)
			}
			defer asym.Close(priv)
			private, err := asym.Params(priv)
			if err != nil || private == nil || private.D == nil {
				t.Fatalf("private parameters unavailable: %v", err)
			}
			pub := priv.Public()
			pem, err := pub.MarshalPublicKeyPEM()
			if err != nil {
				t.Fatal(err)
			}
			independent, err := asym.LoadPublicKeyPEM(pem)
			if err != nil {
				t.Fatal(err)
			}
			defer asym.Close(independent)
			for _, key := range []asym.PublicKey{pub, independent} {
				p, err := asym.Params(key)
				if err != nil || p == nil {
					t.Fatalf("public parameters unavailable: %v", err)
				}
				if p.D != nil || p.P != nil || p.Q != nil || p.Dmp1 != nil || p.Dmq1 != nil || p.Iqmp != nil {
					t.Fatal("public key snapshot contains private parameters")
				}
				j, err := MarshalKey(key)
				if err != nil {
					t.Fatal(err)
				}
				if j.IsPrivate() || j.P != "" || j.Q != "" || j.DP != "" || j.DQ != "" || j.QI != "" {
					t.Fatal("public JWK contains private parameters")
				}
			}
		})
	}
}

// TestECJWKFixedWidth 验证 P-521 导出保留前导零。
//
// TestECJWKFixedWidth verifies that P-521 export retains leading zero bytes.
func TestECJWKFixedWidth(t *testing.T) {
	curve := elliptic.P521()
	x, y := curve.ScalarBaseMult([]byte{1})
	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: big.NewInt(1)}
	der, err := stdx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	j, err := FromPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{j.X, j.Y, j.D} {
		raw, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(raw) != 66 {
			t.Fatalf("encoded value width = %d, error = %v", len(raw), err)
		}
	}
	if _, err := j.ToPEM(); err != nil {
		t.Fatal(err)
	}
}
