package jwk

import (
	"strings"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/sym"
)

// TestMarshalOKPRoundTrip 验证四种 OKP 曲线的 JWK 往返（公钥与私钥）。
//
// TestMarshalOKPRoundTrip verifies the JWK round trip for all four OKP
// curves, for both public and private keys.
func TestMarshalOKPRoundTrip(t *testing.T) {
	cases := []struct {
		alg asym.Algorithm
		crv string
	}{
		{asym.AlgEd25519, CrvEd25519},
		{asym.AlgEd448, CrvEd448},
		{asym.AlgX25519, CrvX25519},
		{asym.AlgX448, CrvX448},
	}
	for _, c := range cases {
		t.Run(c.crv, func(t *testing.T) {
			priv, err := genOKP(c.alg)
			if err != nil {
				t.Fatalf("GenerateKey(%s): %v", c.alg, err)
			}
			defer asym.Close(priv)

			k, err := MarshalKey(priv)
			if err != nil {
				t.Fatalf("MarshalKey: %v", err)
			}
			if k.Kty != "OKP" || k.Crv != c.crv {
				t.Fatalf("kty/crv = %s/%s, want OKP/%s", k.Kty, k.Crv, c.crv)
			}
			if k.X == "" || k.D == "" {
				t.Fatalf("missing x or d: %+v", k)
			}

			back, err := k.ToOKPKey()
			if err != nil {
				t.Fatalf("ToOKPKey: %v", err)
			}
			defer asym.Close(back)
			backPriv, ok := back.(asym.PrivateKey)
			if !ok {
				t.Fatalf("ToOKPKey returned %T, want PrivateKey", back)
			}
			seedWant, _ := asym.RawPrivateKey(priv)
			seedGot, _ := asym.RawPrivateKey(backPriv)
			if string(seedWant) != string(seedGot) {
				t.Error("private seed changed across the JWK round trip")
			}

			// 公钥 JWK 不含私钥材料
			pubJWK, err := MarshalKey(priv.Public())
			if err != nil {
				t.Fatalf("MarshalKey(public): %v", err)
			}
			if pubJWK.IsPrivate() {
				t.Error("public JWK must not carry d")
			}
			pubBack, err := pubJWK.ToOKPKey()
			if err != nil {
				t.Fatalf("ToOKPKey(public): %v", err)
			}
			defer asym.Close(pubBack)
			if _, ok := pubBack.(asym.PublicKey); !ok {
				t.Errorf("ToOKPKey returned %T, want PublicKey", pubBack)
			}
		})
	}
}

// TestOKPPEMMarshal 验证 OKP JWK 能导出为 PEM（覆盖标准库不支持的 Ed448/X448）。
//
// TestOKPPEMMarshal verifies OKP JWKs export to PEM (covering Ed448/X448,
// which the standard library does not support).
func TestOKPPEMMarshal(t *testing.T) {
	for _, alg := range []asym.Algorithm{asym.AlgEd25519, asym.AlgEd448, asym.AlgX25519, asym.AlgX448} {
		t.Run(string(alg), func(t *testing.T) {
			priv, err := genOKP(alg)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			defer asym.Close(priv)
			k, err := MarshalKey(priv)
			if err != nil {
				t.Fatalf("MarshalKey: %v", err)
			}
			privPEM, err := k.ToPEM()
			if err != nil {
				t.Fatalf("ToPEM: %v", err)
			}
			if !strings.Contains(string(privPEM), "BEGIN PRIVATE KEY") {
				t.Errorf("unexpected private PEM header: %s", privPEM)
			}
			pubPEM, err := k.ToPublicPEM()
			if err != nil {
				t.Fatalf("ToPublicPEM: %v", err)
			}
			if !strings.Contains(string(pubPEM), "BEGIN PUBLIC KEY") {
				t.Errorf("unexpected public PEM header: %s", pubPEM)
			}
			// 导出的 PEM 必须能被 asym 重新加载
			loaded, err := asym.LoadPrivateKeyPEM(privPEM)
			if err != nil {
				t.Fatalf("LoadPrivateKeyPEM: %v", err)
			}
			defer asym.Close(loaded)
			if loaded.Algorithm() != alg {
				t.Errorf("loaded algorithm = %s, want %s", loaded.Algorithm(), alg)
			}
		})
	}
}

// TestOKPMismatchedX 验证 "x" 与私钥种子不一致时报错（不静默接受错配 JWK）。
//
// TestOKPMismatchedX verifies a mismatch between "x" and the private seed
// is rejected instead of silently accepted.
func TestOKPMismatchedX(t *testing.T) {
	a, err := genOKP(asym.AlgEd25519)
	if err != nil {
		t.Fatalf("GenerateKey(a): %v", err)
	}
	defer asym.Close(a)
	b, err := genOKP(asym.AlgEd25519)
	if err != nil {
		t.Fatalf("GenerateKey(b): %v", err)
	}
	defer asym.Close(b)

	ka, err := MarshalKey(a)
	if err != nil {
		t.Fatalf("MarshalKey(a): %v", err)
	}
	kb, err := MarshalKey(b)
	if err != nil {
		t.Fatalf("MarshalKey(b): %v", err)
	}
	ka.X = kb.X // 植入不匹配的公钥
	if _, err := ka.ToOKPKey(); err == nil {
		t.Error("mismatched x: want error")
	}
}

// TestSymmetricJWKRoundTrip 验证 oct 往返（AES-128/192/256/SM4）。
//
// TestSymmetricJWKRoundTrip verifies the oct round trip for AES-128/192/256
// and SM4.
func TestSymmetricJWKRoundTrip(t *testing.T) {
	for _, alg := range []sym.Algorithm{sym.AlgAES128, sym.AlgAES192, sym.AlgAES256, sym.AlgSM4} {
		t.Run(string(alg), func(t *testing.T) {
			key, err := sym.GenerateSymmetricKey(alg)
			if err != nil {
				t.Fatalf("GenerateSymmetricKey: %v", err)
			}
			k, err := MarshalSymmetric(key)
			if err != nil {
				t.Fatalf("MarshalSymmetric: %v", err)
			}
			if k.Kty != "oct" || k.K == "" {
				t.Fatalf("kty/k = %q/%q", k.Kty, k.K)
			}
			back, err := k.ToSymmetricKey()
			if err != nil {
				t.Fatalf("ToSymmetricKey: %v", err)
			}
			if back.Algorithm() != key.Algorithm() {
				t.Errorf("algorithm = %s, want %s", back.Algorithm(), key.Algorithm())
			}
			if string(back.Bytes()) != string(key.Bytes()) {
				t.Error("key bytes changed across the JWK round trip")
			}
		})
	}
}

// TestOctInferAlgorithm 验证缺省 alg 时按长度推断，长度无法推断时报错。
//
// TestOctInferAlgorithm verifies length-based inference when alg is absent
// and the error path for an ambiguous length.
func TestOctInferAlgorithm(t *testing.T) {
	key, err := sym.GenerateSymmetricKey(sym.AlgAES256)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey: %v", err)
	}
	k, err := MarshalSymmetric(key)
	if err != nil {
		t.Fatalf("MarshalSymmetric: %v", err)
	}
	k.Alg = "" // 走推断
	back, err := k.ToSymmetricKey()
	if err != nil {
		t.Fatalf("ToSymmetricKey: %v", err)
	}
	if back.Algorithm() != sym.AlgAES256 {
		t.Errorf("inferred algorithm = %s, want AES-256", back.Algorithm())
	}

	k.K = "AAAA" // 3 字节，无法推断
	if _, err := k.ToSymmetricKey(); err == nil {
		t.Error("ambiguous length: want error")
	}
}

// TestParseOKPAndOct 验证 Parse 接受 OKP / oct 的 kty。
//
// TestParseOKPAndOct verifies Parse accepts the OKP and oct kty values.
func TestParseOKPAndOct(t *testing.T) {
	for _, body := range []string{
		`{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
		`{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}`,
	} {
		if _, err := Parse([]byte(body)); err != nil {
			t.Errorf("Parse(%s): %v", body, err)
		}
	}
	if _, err := Parse([]byte(`{"kty":"weird"}`)); err == nil {
		t.Error("unknown kty: want error")
	}
}

// genOKP 按算法生成 OKP 密钥（asym 目前按曲线各提供一个生成函数）。
//
// genOKP generates an OKP key per algorithm (asym currently exposes one
// generator per curve).
func genOKP(alg asym.Algorithm) (asym.PrivateKey, error) {
	switch alg {
	case asym.AlgEd25519:
		return asym.GenerateEd25519()
	case asym.AlgEd448:
		return asym.GenerateEd448()
	case asym.AlgX25519:
		return asym.GenerateX25519()
	case asym.AlgX448:
		return asym.GenerateX448()
	}
	return nil, nil
}
