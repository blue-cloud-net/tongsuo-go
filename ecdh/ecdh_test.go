package ecdh_test

import (
	"bytes"
	stdEcdh "crypto/ecdh"
	"crypto/rand"
	stdx509 "crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/ecdh"
)

// mustHex 解码十六进制字符串，失败即终止。
//
// mustHex decodes a hex string and fails the test on error.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}
	return b
}

// genOnCurve 在指定曲线上生成密钥对。
// 生成统一走 asym（本包不提供生成入口），再用 LoadPrivateKey / LoadPublicKey
// 转成 ecdh 对象。
//
// genOnCurve generates a key pair on the named curve. Generation goes
// through asym (this package has no generation entry point) and the result
// is wrapped with LoadPrivateKey / LoadPublicKey.
func genOnCurve(t *testing.T, name string) (*ecdh.PrivateKey, *ecdh.PublicKey) {
	t.Helper()
	var (
		ak  asym.PrivateKey
		err error
	)
	switch name {
	case "P-256":
		ak, err = asym.GenerateEC(asym.CurveP256)
	case "P-384":
		ak, err = asym.GenerateEC(asym.CurveP384)
	case "P-521":
		ak, err = asym.GenerateEC(asym.CurveP521)
	case "secp256k1":
		ak, err = asym.GenerateEC(asym.CurveSecp256k1)
	case "X25519":
		ak, err = asym.GenerateX25519()
	case "X448":
		ak, err = asym.GenerateX448()
	default:
		t.Fatalf("unknown curve %q", name)
	}
	if err != nil {
		t.Fatalf("generate on %s: %v", name, err)
	}
	priv, err := ecdh.LoadPrivateKey(ak)
	if err != nil {
		t.Fatalf("LoadPrivateKey on %s: %v", name, err)
	}
	pub, err := ecdh.LoadPublicKey(ak.Public())
	if err != nil {
		t.Fatalf("LoadPublicKey on %s: %v", name, err)
	}
	return priv, pub
}

// TestCurves 验证 Curves() 返回稳定且完整的曲线名集合。
func TestCurves(t *testing.T) {
	want := []string{"P-256", "P-384", "P-521", "secp256k1", "X25519", "X448"}
	got := ecdh.Curves()
	if len(got) != len(want) {
		t.Fatalf("len(Curves()) = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Curves()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestCurveByName 验证按名构造（含大小写不敏感与别名）；未知名返回 ErrUnknownCurve。
func TestCurveByName(t *testing.T) {
	cases := map[string]string{
		"P-256":      "P-256",
		"p-256":      "P-256",
		"prime256v1": "P-256",
		"secp256r1":  "P-256",
		"P-384":      "P-384",
		"secp384r1":  "P-384",
		"P-521":      "P-521",
		"secp521r1":  "P-521",
		"secp256k1":  "secp256k1",
		"X25519":     "X25519",
		"x448":       "X448",
		"  X448  ":   "X448",
	}
	for in, want := range cases {
		c, err := ecdh.CurveByName(in)
		if err != nil {
			t.Errorf("CurveByName(%q): %v", in, err)
			continue
		}
		if c.Name() != want {
			t.Errorf("CurveByName(%q).Name() = %q, want %q", in, c.Name(), want)
		}
	}
	for _, bad := range []string{"", "NOPE", "ed25519", "sm2"} {
		if _, err := ecdh.CurveByName(bad); !errors.Is(err, ecdh.ErrUnknownCurve) {
			t.Errorf("CurveByName(%q) err = %v, want ErrUnknownCurve", bad, err)
		}
	}
}

// TestCurveNameNilSafe 验证 (*Curve).Name() 对 nil 接收者安全。
func TestCurveNameNilSafe(t *testing.T) {
	var c *ecdh.Curve
	if got := c.Name(); got != "" {
		t.Errorf("nil curve Name() = %q, want \"\"", got)
	}
}

// TestLoadKeyAllCurves 验证 6 条曲线的 LoadPrivateKey / LoadPublicKey 与 Curve() 回读。
func TestLoadKeyAllCurves(t *testing.T) {
	for _, name := range ecdh.Curves() {
		t.Run(name, func(t *testing.T) {
			priv, pub := genOnCurve(t, name)
			if got := priv.Curve(); got == nil || got.Name() != name {
				t.Errorf("priv.Curve() = %v, want %s", got, name)
			}
			if got := pub.Curve(); got == nil || got.Name() != name {
				t.Errorf("pub.Curve() = %v, want %s", got, name)
			}
			// 私钥派生的公钥应与独立加载的公钥曲线一致
			if got := priv.Public().Curve().Name(); got != name {
				t.Errorf("priv.Public().Curve() = %s, want %s", got, name)
			}
			// 公钥 PEM 与私钥派生结果应一致
			derivedPEM, err := priv.Public().MarshalPEM()
			if err != nil {
				t.Fatal(err)
			}
			loadedPEM, err := pub.MarshalPEM()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(derivedPEM, loadedPEM) {
				t.Error("priv.Public() 与 LoadPublicKey 结果不一致")
			}
		})
	}
}

// TestLoadKeyUnsupported 验证不可协商的密钥（RSA / Ed25519 / Ed448 / SM2）被拒绝。
func TestLoadKeyUnsupported(t *testing.T) {
	rsaKey, err := asym.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	ed25519Key, err := asym.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	ed448Key, err := asym.GenerateEd448()
	if err != nil {
		t.Fatal(err)
	}
	sm2Key, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		priv asym.PrivateKey
	}{
		{"RSA", rsaKey},
		{"Ed25519", ed25519Key},
		{"Ed448", ed448Key},
		{"SM2", sm2Key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ecdh.LoadPrivateKey(tc.priv); !errors.Is(err, ecdh.ErrUnsupportedKey) {
				t.Errorf("LoadPrivateKey err = %v, want ErrUnsupportedKey", err)
			}
			if _, err := ecdh.LoadPublicKey(tc.priv.Public()); !errors.Is(err, ecdh.ErrUnsupportedKey) {
				t.Errorf("LoadPublicKey err = %v, want ErrUnsupportedKey", err)
			}
		})
	}

	// nil 守卫
	if _, err := ecdh.LoadPrivateKey(nil); err == nil {
		t.Error("LoadPrivateKey(nil) 应报错")
	}
	if _, err := ecdh.LoadPublicKey(nil); err == nil {
		t.Error("LoadPublicKey(nil) 应报错")
	}
}

// TestSharedSecretRFC7748X25519 用 RFC 7748 §6.1 标准向量验证 X25519 协商结果。
func TestSharedSecretRFC7748X25519(t *testing.T) {
	alicePrivRaw := mustHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	bobPrivRaw := mustHex(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	wantShared := mustHex(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	// 双方私钥经 asym 的种子入口构造，再转成 ecdh 对象
	aliceAsym, err := asym.GenerateKeyFromSeed(asym.AlgX25519, alicePrivRaw)
	if err != nil {
		t.Fatal(err)
	}
	bobAsym, err := asym.GenerateKeyFromSeed(asym.AlgX25519, bobPrivRaw)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := ecdh.LoadPrivateKey(aliceAsym)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := ecdh.LoadPrivateKey(bobAsym)
	if err != nil {
		t.Fatal(err)
	}
	alicePub, err := ecdh.LoadPublicKey(aliceAsym.Public())
	if err != nil {
		t.Fatal(err)
	}
	bobPub, err := ecdh.LoadPublicKey(bobAsym.Public())
	if err != nil {
		t.Fatal(err)
	}

	shared, err := ecdh.SharedSecret(alice, bobPub)
	if err != nil {
		t.Fatalf("SharedSecret: %v", err)
	}
	if !bytes.Equal(shared, wantShared) {
		t.Errorf("X25519 shared 不匹配\n got %x\nwant %x", shared, wantShared)
	}
	// 对称性
	back, err := ecdh.SharedSecret(bob, alicePub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, shared) {
		t.Error("X25519 协商不满足对称性")
	}
}

// TestSharedSecretRFC7748X448 用 RFC 7748 §6.2 标准向量验证 X448 协商结果。
func TestSharedSecretRFC7748X448(t *testing.T) {
	alicePrivRaw := mustHex(t, "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"+
		"d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b")
	bobPrivRaw := mustHex(t, "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d"+
		"6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d")
	wantShared := mustHex(t, "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"+
		"b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d")

	aliceAsym, err := asym.GenerateKeyFromSeed(asym.AlgX448, alicePrivRaw)
	if err != nil {
		t.Fatal(err)
	}
	bobAsym, err := asym.GenerateKeyFromSeed(asym.AlgX448, bobPrivRaw)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := ecdh.LoadPrivateKey(aliceAsym)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := ecdh.LoadPrivateKey(bobAsym)
	if err != nil {
		t.Fatal(err)
	}
	alicePub, err := ecdh.LoadPublicKey(aliceAsym.Public())
	if err != nil {
		t.Fatal(err)
	}
	bobPub, err := ecdh.LoadPublicKey(bobAsym.Public())
	if err != nil {
		t.Fatal(err)
	}

	shared, err := ecdh.SharedSecret(alice, bobPub)
	if err != nil {
		t.Fatalf("SharedSecret: %v", err)
	}
	if !bytes.Equal(shared, wantShared) {
		t.Errorf("X448 shared 不匹配\n got %x\nwant %x", shared, wantShared)
	}
	back, err := ecdh.SharedSecret(bob, alicePub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, shared) {
		t.Error("X448 协商不满足对称性")
	}
}

// TestSharedSecretSymmetry 验证全部曲线上的协商对称性与长度。
func TestSharedSecretSymmetry(t *testing.T) {
	wantLen := map[string]int{
		"P-256":     32,
		"P-384":     48,
		"P-521":     66, // P-521 的 X 坐标按 66 字节定长编码
		"secp256k1": 32,
		"X25519":    32,
		"X448":      56,
	}
	for _, name := range ecdh.Curves() {
		t.Run(name, func(t *testing.T) {
			alice, alicePub := genOnCurve(t, name)
			bob, bobPub := genOnCurve(t, name)

			ab, err := ecdh.SharedSecret(alice, bobPub)
			if err != nil {
				t.Fatalf("alice→bob: %v", err)
			}
			ba, err := ecdh.SharedSecret(bob, alicePub)
			if err != nil {
				t.Fatalf("bob→alice: %v", err)
			}
			if !bytes.Equal(ab, ba) {
				t.Errorf("%s 协商不满足对称性", name)
			}
			if len(ab) != wantLen[name] {
				t.Errorf("%s 共享密钥长度 = %d, want %d", name, len(ab), wantLen[name])
			}
			// 两次独立协商结果应不同（密钥随机）
			carol, _ := genOnCurve(t, name)
			ac, err := ecdh.SharedSecret(alice, carol.Public())
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(ab, ac) {
				t.Errorf("%s 不同对端的共享密钥不应相同", name)
			}
		})
	}
}

// TestECDHMethodMatchesSharedSecret 验证方法形式与包级形式等价。
func TestECDHMethodMatchesSharedSecret(t *testing.T) {
	for _, name := range ecdh.Curves() {
		t.Run(name, func(t *testing.T) {
			alice, _ := genOnCurve(t, name)
			_, bobPub := genOnCurve(t, name)

			viaMethod, err := alice.ECDH(bobPub)
			if err != nil {
				t.Fatal(err)
			}
			viaFunc, err := ecdh.SharedSecret(alice, bobPub)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(viaMethod, viaFunc) {
				t.Errorf("ECDH 与 SharedSecret 结果不一致")
			}
		})
	}
}

// TestSharedSecretMismatch 验证跨曲线 / 跨算法协商被拒绝。
func TestSharedSecretMismatch(t *testing.T) {
	p256, _ := genOnCurve(t, "P-256")
	p384, _ := genOnCurve(t, "P-384")
	x25519, _ := genOnCurve(t, "X25519")
	x448, _ := genOnCurve(t, "X448")

	if _, err := ecdh.SharedSecret(p256, p384.Public()); err == nil {
		t.Error("P-256 私钥 + P-384 公钥 应报错")
	}
	if _, err := ecdh.SharedSecret(x25519, x448.Public()); err == nil {
		t.Error("X25519 私钥 + X448 公钥 应报错")
	}
	if _, err := ecdh.SharedSecret(p256, x25519.Public()); err == nil {
		t.Error("EC 私钥 + OKP 公钥 应报错")
	}
	// nil 守卫
	if _, err := ecdh.SharedSecret(nil, x25519.Public()); err == nil {
		t.Error("SharedSecret(nil, pub) 应报错")
	}
	if _, err := ecdh.SharedSecret(x25519, nil); err == nil {
		t.Error("SharedSecret(priv, nil) 应报错")
	}
}

// TestSharedSecretNISTMatchesStdlib 验证 NIST 曲线协商结果与 Go 标准库 crypto/ecdh 一致。
// 做法：用标准库生成密钥 → PKCS#8 / SPKI PEM → 本库加载 → 比对派生结果。
func TestSharedSecretNISTMatchesStdlib(t *testing.T) {
	cases := []struct {
		name  string
		curve *ecdh.Curve
		std   stdEcdh.Curve
	}{
		{"P-256", ecdh.P256(), stdEcdh.P256()},
		{"P-384", ecdh.P384(), stdEcdh.P384()},
		{"P-521", ecdh.P521(), stdEcdh.P521()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdPriv, err := tc.std.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			stdPeer, err := tc.std.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			wantShared, err := stdPriv.ECDH(stdPeer.PublicKey())
			if err != nil {
				t.Fatal(err)
			}

			// 标准库私钥 → PKCS#8 PEM → 本库加载
			der, err := stdx509.MarshalPKCS8PrivateKey(stdPriv)
			if err != nil {
				t.Fatal(err)
			}
			privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
			priv, err := ecdh.LoadPrivateKeyPEM(tc.curve, privPEM)
			if err != nil {
				t.Fatalf("LoadPrivateKeyPEM: %v", err)
			}

			// 标准库对端公钥 → SPKI PEM → 本库加载
			pubDER, err := stdx509.MarshalPKIXPublicKey(stdPeer.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
			peer, err := ecdh.LoadPublicKeyPEM(tc.curve, pubPEM)
			if err != nil {
				t.Fatalf("LoadPublicKeyPEM: %v", err)
			}

			got, err := ecdh.SharedSecret(priv, peer)
			if err != nil {
				t.Fatalf("SharedSecret: %v", err)
			}
			if !bytes.Equal(got, wantShared) {
				t.Errorf("%s 与标准库不一致\n got %x\nwant %x", tc.name, got, wantShared)
			}
		})
	}
}

// TestOKPLowOrderPointRejected 验证 OKP 低阶点输入被拒绝（共享密钥为全零）。
func TestOKPLowOrderPointRejected(t *testing.T) {
	// u = 0 是 X25519 的低阶点，标量乘结果恒为全零
	lowOrderPEM := x25519LowOrderPEM(t)
	priv, _ := genOnCurve(t, "X25519")

	peer, err := ecdh.LoadPublicKeyPEM(ecdh.X25519(), lowOrderPEM)
	if err != nil {
		t.Skipf("provider rejected the low-order point at load time: %v", err)
	}
	shared, err := ecdh.SharedSecret(priv, peer)
	if err == nil {
		// 若 provider 未在 derive 阶段拒绝，则本库必须拒绝全零结果
		allZero := true
		for _, b := range shared {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Fatal("低阶点导致的全零共享密钥必须返回错误")
		}
	}
}

// x25519LowOrderPEM 构造一个携带 u=0 的 X25519 公钥 PEM。
// 若底层拒绝该编码则测试自行跳过（见调用方）。
//
// x25519LowOrderPEM builds an X25519 public key PEM carrying u = 0.
func x25519LowOrderPEM(t *testing.T) []byte {
	t.Helper()
	// SPKI: SEQUENCE { AlgorithmIdentifier { id-X25519 }, BIT STRING { 32 字节全零 } }
	// 直接取本库生成的真公钥再加长度校验过于脆弱，这里用固定 DER 前缀拼接。
	prefix := mustHex(t, "302a300506032b656e032100")
	body := make([]byte, 32)
	der := append(prefix, body...)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// TestPEMRoundtrip 验证各曲线的私钥 / 公钥 PEM 往返与加密 PEM。
func TestPEMRoundtrip(t *testing.T) {
	for _, name := range ecdh.Curves() {
		t.Run(name, func(t *testing.T) {
			curve, err := ecdh.CurveByName(name)
			if err != nil {
				t.Fatal(err)
			}
			priv, pub := genOnCurve(t, name)

			privPEM, err := priv.MarshalPEM()
			if err != nil {
				t.Fatal(err)
			}
			loadedPriv, err := ecdh.LoadPrivateKeyPEM(curve, privPEM)
			if err != nil {
				t.Fatalf("LoadPrivateKeyPEM: %v", err)
			}
			if loadedPriv.Curve().Name() != name {
				t.Errorf("重载后曲线 = %s, want %s", loadedPriv.Curve().Name(), name)
			}
			rePrivPEM, err := loadedPriv.MarshalPEM()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(rePrivPEM, privPEM) {
				t.Error("私钥 PEM 往返不一致")
			}

			pubPEM, err := pub.MarshalPEM()
			if err != nil {
				t.Fatal(err)
			}
			loadedPub, err := ecdh.LoadPublicKeyPEM(curve, pubPEM)
			if err != nil {
				t.Fatalf("LoadPublicKeyPEM: %v", err)
			}
			if loadedPub.Curve().Name() != name {
				t.Errorf("重载后曲线 = %s, want %s", loadedPub.Curve().Name(), name)
			}
			// 重载后的公私钥仍可协商
			if _, err := ecdh.SharedSecret(loadedPriv, loadedPub); err != nil {
				t.Errorf("重载后协商失败：%v", err)
			}
		})
	}
}

// TestPEMCurveMismatch 验证把 A 曲线的 PEM 当作 B 曲线加载会被拒绝。
func TestPEMCurveMismatch(t *testing.T) {
	priv, _ := genOnCurve(t, "P-256")
	privPEM, err := priv.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ecdh.LoadPrivateKeyPEM(ecdh.P384(), privPEM); err == nil {
		t.Error("P-256 私钥当作 P-384 加载应报错")
	}
	if _, err := ecdh.LoadPrivateKeyPEM(ecdh.X25519(), privPEM); err == nil {
		t.Error("P-256 私钥当作 X25519 加载应报错")
	}

	// 非 EC 密钥（RSA）被拒绝
	rsaKey, err := asym.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM, err := rsaKey.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ecdh.LoadPrivateKeyPEM(ecdh.P256(), rsaPEM); err == nil {
		t.Error("RSA 私钥当作 P-256 加载应报错")
	}
}

// TestEncryptedPEMAndChangePassword 验证加密 PEM 导出 / 加载与改密。
func TestEncryptedPEMAndChangePassword(t *testing.T) {
	for _, name := range ecdh.Curves() {
		t.Run(name, func(t *testing.T) {
			curve, err := ecdh.CurveByName(name)
			if err != nil {
				t.Fatal(err)
			}
			priv, _ := genOnCurve(t, name)

			enc, err := priv.MarshalEncryptedPEM("secret")
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := ecdh.LoadEncryptedPEM(curve, enc, "secret")
			if err != nil {
				t.Fatalf("LoadEncryptedPEM: %v", err)
			}
			if loaded.Curve().Name() != name {
				t.Errorf("曲线 = %s, want %s", loaded.Curve().Name(), name)
			}
			if _, err := ecdh.LoadEncryptedPEM(curve, enc, "wrong"); err == nil {
				t.Error("错误口令应报错")
			}

			re, err := ecdh.ChangePassword(enc, "secret", "newpw")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ecdh.LoadEncryptedPEM(curve, re, "newpw"); err != nil {
				t.Fatalf("改密后加载失败：%v", err)
			}
			if _, err := ecdh.LoadEncryptedPEM(curve, re, "secret"); err == nil {
				t.Error("旧口令应已失效")
			}
		})
	}
}

// TestLoadInvalidPEM 验证非法 PEM 返回错误。
func TestLoadInvalidPEM(t *testing.T) {
	bogus := []byte("not a pem")
	if _, err := ecdh.LoadPrivateKeyPEM(ecdh.P256(), bogus); err == nil {
		t.Error("非法私钥 PEM 应报错")
	}
	if _, err := ecdh.LoadPublicKeyPEM(ecdh.P256(), bogus); err == nil {
		t.Error("非法公钥 PEM 应报错")
	}
	if _, err := ecdh.LoadEncryptedPEM(ecdh.P256(), bogus, "pw"); err == nil {
		t.Error("非法加密 PEM 应报错")
	}
}
