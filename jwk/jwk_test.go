package jwk

import (
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/crypto/ecdsa"
	"github.com/blue-cloud-net/tongsuo-go/crypto/rsa"
)

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

	// 公钥（同一把密钥的 Public()，共享句柄）
	//
	// ⚠️ 已知问题 docs/issues/2026-09-24/P1008：`asym.PrivateKey.Public()` 返回的
	// 对象与私钥**共享同一个底层 EVP_PKEY**（不 Dup、也不剥离私钥分量），因此
	// MarshalKey(priv.Public()) 依然会导出**私钥** JWK（含 d/p/q/dp/dq/qi）。
	// 这是既有行为（旧 crypto/rsa 与 key 的 Public() 同样共享句柄），不是本次重构
	// 引入的；但它属于安全相关缺陷，故在此把当前行为**显式钉住**：一旦 P1008 修好，
	// 下面的断言会失败并提示翻转。
	// 需要真正的公钥 JWK 时，应先把公钥 PEM 走一遍 Load 再 MarshalKey。
	k2, err := MarshalKey(rsaPriv.Public())
	if err != nil {
		t.Fatalf("MarshalKey(asym.PublicKey): %v", err)
	}
	if k2.Kty != "RSA" {
		t.Fatalf("unexpected RSA public jwk: %+v", k2)
	}
	if !k2.IsPrivate() {
		t.Error("asym.PrivateKey.Public() 已不再携带私钥材料 —— 请翻转本断言并关闭 docs/issues/2026-09-24/P1008")
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
	priv, err := rsa.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	k, err := marshalCore(priv.Key())
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
	// 私钥 ↔ 私钥比较：dp/dq/qi 与底层 core.KeyParams 的 CRT 系数应一致。
	p := priv.Key().Params()
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
	k, err := marshalCore(priv.Key())
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
	k, _ := marshalCore(priv.Key())
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
