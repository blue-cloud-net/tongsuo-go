package ecdh_test

import (
	"bytes"
	stdEcdh "crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdx509 "crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/crypto/ecdh"
	"github.com/blue-cloud-net/tongsuo-go/crypto/x25519"
	"github.com/blue-cloud-net/tongsuo-go/crypto/x448"
)

type curveCase struct {
	name string
	ts   *ecdh.Curve
	ec   elliptic.Curve
	ecdh stdEcdh.Curve
	size int
}

var curveCases = []curveCase{
	{"P-256", ecdh.P256(), elliptic.P256(), stdEcdh.P256(), 32},
	{"P-384", ecdh.P384(), elliptic.P384(), stdEcdh.P384(), 48},
	{"P-521", ecdh.P521(), elliptic.P521(), stdEcdh.P521(), 66},
}

// genStdECDSA 生成一对标准库 ECDSA 密钥（仅用于造钥与交叉验证）。
func genStdECDSA(t *testing.T, ec elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(ec, rand.Reader)
	if err != nil {
		t.Fatalf("stdlib ecdsa generate: %v", err)
	}
	return priv
}

// marshalPrivPKCS8 把标准库 EC 私钥序列化为 PKCS#8 PEM。
func marshalPrivPKCS8(t *testing.T, priv *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := stdx509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// marshalPrivSEC1 把标准库 EC 私钥序列化为 SEC1（"EC PRIVATE KEY"）PEM。
func marshalPrivSEC1(t *testing.T, priv *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := stdx509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal sec1: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// marshalPubSPKI 把标准库 EC 公钥序列化为 SPKI PEM。
func marshalPubSPKI(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := stdx509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal spki: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// stdSharedSecret 用标准库 crypto/ecdh 计算 priv 与 peer 的共享密钥（参考实现）。
func stdSharedSecret(t *testing.T, c curveCase, priv *ecdsa.PrivateKey, peer *ecdsa.PublicKey) []byte {
	t.Helper()
	privBytes := priv.D.FillBytes(make([]byte, c.size))
	k, err := c.ecdh.NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("stdlib ecdh NewPrivateKey: %v", err)
	}
	point := elliptic.Marshal(peer.Curve, peer.X, peer.Y)
	pub, err := c.ecdh.NewPublicKey(point)
	if err != nil {
		t.Fatalf("stdlib ecdh NewPublicKey: %v", err)
	}
	s, err := k.ECDH(pub)
	if err != nil {
		t.Fatalf("stdlib ecdh ECDH: %v", err)
	}
	return s
}

// TestECDHMatchesStdlib 验证 tongsuo ECDH 输出与 Go 标准库 crypto/ecdh 完全一致，
// 覆盖三条 NIST 曲线（双向均验证）。
func TestECDHMatchesStdlib(t *testing.T) {
	for _, c := range curveCases {
		t.Run(c.name, func(t *testing.T) {
			alice := genStdECDSA(t, c.ec)
			bob := genStdECDSA(t, c.ec)
			expected := stdSharedSecret(t, c, alice, &bob.PublicKey)

			ta, err := ecdh.LoadPrivateKeyPEM(c.ts, marshalPrivPKCS8(t, alice))
			if err != nil {
				t.Fatalf("load alice priv: %v", err)
			}
			tbpub, err := ecdh.LoadPublicKeyPEM(c.ts, marshalPubSPKI(t, &bob.PublicKey))
			if err != nil {
				t.Fatalf("load bob pub: %v", err)
			}
			got, err := ta.ECDH(tbpub)
			if err != nil {
				t.Fatalf("tongsuo ECDH: %v", err)
			}
			if len(got) != c.size {
				t.Fatalf("shared length = %d, want %d", len(got), c.size)
			}
			if !bytes.Equal(got, expected) {
				t.Fatalf("shared secret mismatch with stdlib:\n got  %x\n want %x", got, expected)
			}

			// 反向：bob 私钥 + alice 公钥 应得到同一共享密钥。
			tb, err := ecdh.LoadPrivateKeyPEM(c.ts, marshalPrivPKCS8(t, bob))
			if err != nil {
				t.Fatalf("load bob priv: %v", err)
			}
			tapub, err := ecdh.LoadPublicKeyPEM(c.ts, marshalPubSPKI(t, &alice.PublicKey))
			if err != nil {
				t.Fatalf("load alice pub: %v", err)
			}
			got2, err := tb.ECDH(tapub)
			if err != nil {
				t.Fatalf("tongsuo reverse ECDH: %v", err)
			}
			if !bytes.Equal(got2, expected) {
				t.Fatalf("reverse shared secret mismatch: got %x want %x", got2, expected)
			}
		})
	}
}

// TestLoadPrivateKeyPEM_SEC1 验证 SEC1（"EC PRIVATE KEY"）PEM 私钥可加载并派生正确。
func TestLoadPrivateKeyPEM_SEC1(t *testing.T) {
	c := curveCases[0]
	alice := genStdECDSA(t, c.ec)
	bob := genStdECDSA(t, c.ec)
	expected := stdSharedSecret(t, c, alice, &bob.PublicKey)

	ta, err := ecdh.LoadPrivateKeyPEM(c.ts, marshalPrivSEC1(t, alice))
	if err != nil {
		t.Fatalf("load SEC1 private key: %v", err)
	}
	tbpub, err := ecdh.LoadPublicKeyPEM(c.ts, marshalPubSPKI(t, &bob.PublicKey))
	if err != nil {
		t.Fatalf("load bob pub: %v", err)
	}
	got, err := ta.ECDH(tbpub)
	if err != nil {
		t.Fatalf("ECDH with SEC1 key: %v", err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatalf("SEC1 shared secret mismatch: got %x want %x", got, expected)
	}
}

// TestGeneratedPairs 验证 tongsuo 自生成密钥对的双向一致与 PEM 往返。
func TestGeneratedPairs(t *testing.T) {
	for _, c := range curveCases {
		t.Run(c.name, func(t *testing.T) {
			alice, err := c.ts.GenerateKey()
			if err != nil {
				t.Fatalf("alice generate: %v", err)
			}
			bob, err := c.ts.GenerateKey()
			if err != nil {
				t.Fatalf("bob generate: %v", err)
			}
			sa, err := alice.ECDH(bob.Public())
			if err != nil {
				t.Fatalf("alice ECDH: %v", err)
			}
			sb, err := bob.ECDH(alice.Public())
			if err != nil {
				t.Fatalf("bob ECDH: %v", err)
			}
			if len(sa) != c.size || !bytes.Equal(sa, sb) {
				t.Fatalf("shared mismatch: len=%d equal=%v", len(sa), bytes.Equal(sa, sb))
			}

			// PEM 往返：私钥导出后可重新加载并得到一致结果。
			privPEM, err := alice.MarshalPEM()
			if err != nil {
				t.Fatalf("marshal priv: %v", err)
			}
			reloaded, err := ecdh.LoadPrivateKeyPEM(c.ts, privPEM)
			if err != nil {
				t.Fatalf("reload priv: %v", err)
			}
			sr, err := reloaded.ECDH(bob.Public())
			if err != nil {
				t.Fatalf("reloaded ECDH: %v", err)
			}
			if !bytes.Equal(sr, sa) {
				t.Fatalf("reload shared mismatch")
			}
		})
	}
}

// TestLoadCurveMismatch 验证用错误曲线加载密钥会被拒绝。
func TestLoadCurveMismatch(t *testing.T) {
	p384 := curveCases[1]
	priv384 := genStdECDSA(t, p384.ec)
	_, err := ecdh.LoadPrivateKeyPEM(ecdh.P256(), marshalPrivPKCS8(t, priv384))
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("want curve-mismatch error, got %v", err)
	}
	_, err = ecdh.LoadPublicKeyPEM(ecdh.P256(), marshalPubSPKI(t, &priv384.PublicKey))
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("want public curve-mismatch error, got %v", err)
	}
}

// TestLoadRejectsNonEC 验证非 EC 密钥（X25519 公钥）会被拒绝。
func TestLoadRejectsNonEC(t *testing.T) {
	xk, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("x25519 generate: %v", err)
	}
	xpub, _ := xk.Public()
	pemBytes, err := xpub.MarshalPEM()
	if err != nil {
		t.Fatalf("x25519 marshal: %v", err)
	}
	_, err = ecdh.LoadPublicKeyPEM(ecdh.P256(), pemBytes)
	if err == nil || !strings.Contains(err.Error(), "not an EC key") {
		t.Fatalf("want non-EC rejection, got %v", err)
	}
}

// TestX25519Roundtrip 验证 ecdh.X25519() 生成的密钥对能正确 derive，
// 且与 Go 标准库 crypto/ecdh X25519 完全一致。
func TestX25519Roundtrip(t *testing.T) {
	curve := ecdh.X25519()
	if curve == nil || curve.Name() != "X25519" {
		t.Fatalf("X25519() curve = %v, want X25519", curve)
	}

	priv, err := curve.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	privPEM, err := priv.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}
	pubPEM, err := priv.Public().MarshalPEM()
	if err != nil {
		t.Fatalf("Public MarshalPEM: %v", err)
	}

	// 重新加载（验证 Load{Public,Private}KeyPEM 路径对 X25519 也走得通）。
	priv2, err := ecdh.LoadPrivateKeyPEM(curve, privPEM)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM: %v", err)
	}
	pub2, err := ecdh.LoadPublicKeyPEM(curve, pubPEM)
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM: %v", err)
	}

	// derive 路径：同侧对端协商。
	sharedA, err := priv2.ECDH(pub2)
	if err != nil {
		t.Fatalf("ECDH(priv2, pub2): %v", err)
	}
	if len(sharedA) != 32 {
		t.Fatalf("X25519 shared length = %d, want 32", len(sharedA))
	}

	// 与标准库 crypto/ecdh X25519 比对：通过 x25519.{Private,Public}KeyFromBytes
	// 加载 PEM → raw 32 字节 → 喂给 stdlib。
	xPriv, err := x25519.LoadPrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("x25519 LoadPrivateKeyPEM: %v", err)
	}
	xPub, err := x25519.LoadPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("x25519 LoadPublicKeyPEM: %v", err)
	}
	xPrivBytes, err := xPriv.Bytes()
	if err != nil {
		t.Fatalf("x25519 Bytes: %v", err)
	}
	xPubBytes, err := xPub.Bytes()
	if err != nil {
		t.Fatalf("x25519 pub Bytes: %v", err)
	}
	stdPriv, err := stdEcdh.X25519().NewPrivateKey(xPrivBytes)
	if err != nil {
		t.Fatalf("stdlib NewPrivateKey: %v", err)
	}
	stdPub, err := stdEcdh.X25519().NewPublicKey(xPubBytes)
	if err != nil {
		t.Fatalf("stdlib NewPublicKey: %v", err)
	}
	stdShared, err := stdPriv.ECDH(stdPub)
	if err != nil {
		t.Fatalf("stdlib ECDH: %v", err)
	}
	if !bytes.Equal(sharedA, stdShared) {
		t.Fatalf("X25519 mismatch:\n  ours  = %x\n  std   = %x", sharedA, stdShared)
	}

	// 第二对密钥：ours privC + ours pub2 与 stdlib privC + stdlib pub2 应一致（同一组密钥，
	// 配对 privC ↔ pub2 + privC ↔ pub2，两端结果应相等）。
	privC, err := curve.GenerateKey()
	if err != nil {
		t.Fatalf("second GenerateKey: %v", err)
	}
	pubC := privC.Public()
	privCPEM, err := privC.MarshalPEM()
	if err != nil {
		t.Fatalf("privC MarshalPEM: %v", err)
	}
	xPrivC, err := x25519.LoadPrivateKeyPEM(privCPEM)
	if err != nil {
		t.Fatalf("x25519 LoadPrivateKeyPEM C: %v", err)
	}
	xPub2, err := x25519.LoadPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("x25519 LoadPublicKeyPEM pub2: %v", err)
	}
	xPrivCBytes, _ := xPrivC.Bytes()
	xPub2Bytes, _ := xPub2.Bytes()
	stdPrivC, err := stdEcdh.X25519().NewPrivateKey(xPrivCBytes)
	if err != nil {
		t.Fatalf("stdlib NewPrivateKey C: %v", err)
	}
	stdPub2, err := stdEcdh.X25519().NewPublicKey(xPub2Bytes)
	if err != nil {
		t.Fatalf("stdlib NewPublicKey 2: %v", err)
	}
	sharedC, err := privC.ECDH(pub2)
	if err != nil {
		t.Fatalf("ECDH(privC, pub2): %v", err)
	}
	stdSharedC, err := stdPrivC.ECDH(stdPub2)
	if err != nil {
		t.Fatalf("stdlib ECDH C: %v", err)
	}
	if !bytes.Equal(sharedC, stdSharedC) {
		t.Fatalf("X25519 second pair mismatch:\n  ours = %x\n  std  = %x", sharedC, stdSharedC)
	}

	// 加密导出 + 回环也走通。
	enc, err := priv.MarshalEncryptedPEM("test-pass-1234")
	if err != nil {
		t.Fatalf("MarshalEncryptedPEM: %v", err)
	}
	privLoaded, err := ecdh.LoadEncryptedPEM(curve, enc, "test-pass-1234")
	if err != nil {
		t.Fatalf("LoadEncryptedPEM: %v", err)
	}
	loadedShared, err := privLoaded.ECDH(pubC)
	if err != nil {
		t.Fatalf("loaded ECDH: %v", err)
	}
	if !bytes.Equal(loadedShared, sharedC) {
		t.Fatalf("loaded ECDH diverges from fresh key: %x vs %x", loadedShared, sharedC)
	}
}

// TestOKPRejectsECKeys 验证用 OKP 曲线（X25519 / X448）加载 EC 密钥会被拒绝。
//
// TestOKPRejectsECKeys verifies that EC keys are rejected when loaded
// through an OKP curve (X25519 / X448).
func TestOKPRejectsECKeys(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	privPEM, err := priv.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}
	pubPEM, err := priv.Public().MarshalPEM()
	if err != nil {
		t.Fatalf("Public MarshalPEM: %v", err)
	}
	for _, curve := range []*ecdh.Curve{ecdh.X25519(), ecdh.X448()} {
		want := "not " + curve.Name()
		if _, err := ecdh.LoadPrivateKeyPEM(curve, privPEM); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: load EC private key err = %v, want substring %q", curve.Name(), err, want)
		}
		if _, err := ecdh.LoadPublicKeyPEM(curve, pubPEM); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: load EC public key err = %v, want substring %q", curve.Name(), err, want)
		}
	}
}

// TestOKPMismatch 验证 EC 与 OKP 密钥混用会被拒绝（双向）。
//
// TestOKPMismatch verifies that mixing an EC key with an OKP key is
// rejected in both directions.
func TestOKPMismatch(t *testing.T) {
	x, err := ecdh.X25519().GenerateKey()
	if err != nil {
		t.Fatalf("X25519 GenerateKey: %v", err)
	}
	ec, err := ecdh.P256().GenerateKey()
	if err != nil {
		t.Fatalf("P256 GenerateKey: %v", err)
	}
	if _, err := x.ECDH(ec.Public()); err == nil || !strings.Contains(err.Error(), "curve mismatch") {
		t.Fatalf("X25519 vs EC: err = %v, want curve mismatch", err)
	}
	if _, err := ec.ECDH(x.Public()); err == nil || !strings.Contains(err.Error(), "curve mismatch") {
		t.Fatalf("EC vs X25519: err = %v, want curve mismatch", err)
	}
}

// TestOKPLowOrderPoint 验证低阶点（全零公钥，RFC 7748 §6.1）不会静默产出全零共享密钥。
//
// TestOKPLowOrderPoint verifies that a low-order point (all-zero public key,
// RFC 7748 §6.1) never silently yields an all-zero shared secret, on both OKP
// curves.
func TestOKPLowOrderPoint(t *testing.T) {
	tests := []struct {
		name     string
		curve    *ecdh.Curve
		optional bool
		lowOrder func() ([]byte, error) // 全零公钥的 SPKI PEM
	}{
		{
			name:  "X25519",
			curve: ecdh.X25519(),
			lowOrder: func() ([]byte, error) {
				k, err := x25519.PublicKeyFromBytes(make([]byte, 32))
				if err != nil {
					return nil, err
				}
				return k.MarshalPEM()
			},
		},
		{
			name:     "X448",
			curve:    ecdh.X448(),
			optional: true,
			lowOrder: func() ([]byte, error) {
				k, err := x448.PublicKeyFromBytes(make([]byte, 56))
				if err != nil {
					return nil, err
				}
				return k.MarshalPEM()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv, err := tt.curve.GenerateKey()
			if err != nil {
				if tt.optional {
					t.Skipf("%s unavailable in this Tongsuo build: %v", tt.name, err)
				}
				t.Fatalf("GenerateKey: %v", err)
			}
			pemBytes, err := tt.lowOrder()
			if err != nil {
				t.Skipf("provider rejects an all-zero %s public key up front: %v", tt.name, err)
			}
			pub, err := ecdh.LoadPublicKeyPEM(tt.curve, pemBytes)
			if err != nil {
				t.Fatalf("LoadPublicKeyPEM: %v", err)
			}
			if shared, err := priv.ECDH(pub); err == nil {
				t.Fatalf("low-order point accepted, shared = %x", shared)
			}
		})
	}
}

// TestX448Roundtrip 验证 ecdh.X448() 的生成、PEM 往返、加密 PEM 回环与 56 字节派生，
// 并与 crypto/x448 包就同一份 PEM 的密钥对象达成一致。
//
// TestX448Roundtrip covers ecdh.X448() keygen, PEM / encrypted-PEM
// roundtrips and the 56-byte shared secret, and cross-checks that the
// crypto/x448 package sees the same keys for the same PEM input.
func TestX448Roundtrip(t *testing.T) {
	curve := ecdh.X448()
	if curve == nil || curve.Name() != "X448" {
		t.Fatalf("X448() curve = %v, want X448", curve)
	}
	priv, err := curve.GenerateKey()
	if err != nil {
		t.Skipf("X448 unavailable in this Tongsuo build: %v", err)
	}
	privPEM, err := priv.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}
	pubPEM, err := priv.Public().MarshalPEM()
	if err != nil {
		t.Fatalf("Public MarshalPEM: %v", err)
	}
	priv2, err := ecdh.LoadPrivateKeyPEM(curve, privPEM)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM: %v", err)
	}
	pub2, err := ecdh.LoadPublicKeyPEM(curve, pubPEM)
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM: %v", err)
	}
	shared, err := priv2.ECDH(pub2)
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}
	if len(shared) != 56 {
		t.Fatalf("X448 shared length = %d, want 56", len(shared))
	}

	// crypto/x448 包就同一份 PEM 应得到同一对密钥。
	xPriv, err := x448.LoadPrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("x448 LoadPrivateKeyPEM: %v", err)
	}
	xPub, err := x448.LoadPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("x448 LoadPublicKeyPEM: %v", err)
	}
	if !priv2.Key().Equal(xPriv.Key()) {
		t.Fatal("ecdh and crypto/x448 disagree on the private key")
	}
	if !pub2.Key().PublicEqual(xPub.Key()) {
		t.Fatal("ecdh and crypto/x448 disagree on the public key")
	}

	// 加密 PEM 回环：重新加载后派生结果应不变。
	enc, err := priv.MarshalEncryptedPEM("test-pass-1234")
	if err != nil {
		t.Fatalf("MarshalEncryptedPEM: %v", err)
	}
	loaded, err := ecdh.LoadEncryptedPEM(curve, enc, "test-pass-1234")
	if err != nil {
		t.Fatalf("LoadEncryptedPEM: %v", err)
	}
	loadedShared, err := loaded.ECDH(pub2)
	if err != nil {
		t.Fatalf("loaded ECDH: %v", err)
	}
	if !bytes.Equal(loadedShared, shared) {
		t.Fatalf("encrypted PEM roundtrip diverges: %x vs %x", loadedShared, shared)
	}
}

// TestSecp256k1Roundtrip 验证 secp256k1 曲线的生成、派生与 PEM 往返；
// 运行时 provider 不支持该曲线时跳过。
//
// TestSecp256k1Roundtrip covers keygen, derivation and PEM roundtrip on
// secp256k1; it skips when the runtime provider does not support the curve.
func TestSecp256k1Roundtrip(t *testing.T) {
	curve := ecdh.Secp256k1()
	if curve == nil || curve.Name() != "secp256k1" {
		t.Fatalf("Secp256k1() curve = %v, want secp256k1", curve)
	}
	alice, err := curve.GenerateKey()
	if err != nil {
		t.Skipf("secp256k1 unsupported by this Tongsuo build: %v", err)
	}
	bob, err := curve.GenerateKey()
	if err != nil {
		t.Fatalf("second GenerateKey: %v", err)
	}
	sa, err := alice.ECDH(bob.Public())
	if err != nil {
		t.Fatalf("alice ECDH: %v", err)
	}
	sb, err := bob.ECDH(alice.Public())
	if err != nil {
		t.Fatalf("bob ECDH: %v", err)
	}
	if len(sa) != 32 || !bytes.Equal(sa, sb) {
		t.Fatalf("secp256k1 shared mismatch (len=%d):\n  %x\n  %x", len(sa), sa, sb)
	}
	privPEM, err := alice.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}
	if _, err := ecdh.LoadPrivateKeyPEM(curve, privPEM); err != nil {
		t.Fatalf("LoadPrivateKeyPEM: %v", err)
	}
}
