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
