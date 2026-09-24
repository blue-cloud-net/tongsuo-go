package asym

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

// TestGenerateEd25519 验证密钥生成：非空、算法标识正确、两次生成不同。
func TestGenerateEd25519(t *testing.T) {
	a, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	if a.Algorithm() != AlgEd25519 {
		t.Errorf("alg = %s, want ED25519", a.Algorithm())
	}
	if a.Public().Algorithm() != AlgEd25519 {
		t.Errorf("pub alg = %s", a.Public().Algorithm())
	}
	b, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	ap, _ := a.MarshalPrivateKeyPEM()
	bp, _ := b.MarshalPrivateKeyPEM()
	if bytes.Equal(ap, bp) {
		t.Fatal("两次生成的密钥相同")
	}
}

// TestEd25519RFC8032Vectors 用 RFC 8032 §7.1 标准向量验证公钥派生与签名。
func TestEd25519RFC8032Vectors(t *testing.T) {
	cases := []struct {
		name string
		seed string
		pub  string
		msg  string
		sig  string
	}{
		{
			name: "TEST1-empty-message",
			seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			pub:  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
			msg:  "",
			sig: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
				"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
		},
		{
			name: "TEST2-one-byte-message",
			seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
			pub:  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
			msg:  "72",
			sig: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
				"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			seed := mustHex(t, c.seed)
			wantPub := mustHex(t, c.pub)
			msg := mustHex(t, c.msg)
			wantSig := mustHex(t, c.sig)

			priv, err := GenerateKeyFromSeed(AlgEd25519, seed)
			if err != nil {
				t.Fatal(err)
			}
			gotPub, err := RawPublicKey(priv.Public())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotPub, wantPub) {
				t.Errorf("公钥不匹配\n got %x\nwant %x", gotPub, wantPub)
			}

			sig, err := SignEd25519(priv, msg)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(sig, wantSig) {
				t.Errorf("签名不匹配\n got %x\nwant %x", sig, wantSig)
			}
			if err := VerifyEd25519(priv.Public(), msg, sig); err != nil {
				t.Errorf("验签失败：%v", err)
			}
		})
	}
}

// TestEd25519SeedRoundtrip 验证种子导入 / 导出往返。
func TestEd25519SeedRoundtrip(t *testing.T) {
	priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := RawPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != 32 {
		t.Fatalf("seed 长度 = %d，应为 32", len(seed))
	}
	again, err := GenerateKeyFromSeed(AlgEd25519, seed)
	if err != nil {
		t.Fatal(err)
	}
	// 同一 seed 派生的公钥必须一致
	p1, err := RawPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	p2, err := RawPublicKey(again.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p1, p2) {
		t.Fatal("同一 seed 派生的公钥不一致")
	}
}

// TestEd25519SeedLengthGuard 验证种子 / 公钥长度校验。
func TestEd25519SeedLengthGuard(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := GenerateKeyFromSeed(AlgEd25519, make([]byte, n)); !errors.Is(err, ErrInvalidSeedLength) {
			t.Errorf("seed 长度 %d：err = %v，应为 ErrInvalidSeedLength", n, err)
		}
		if _, err := PublicKeyFromBytes(AlgEd25519, make([]byte, n)); !errors.Is(err, ErrInvalidPublicKeyLength) {
			t.Errorf("公钥长度 %d：err = %v，应为 ErrInvalidPublicKeyLength", n, err)
		}
	}
	// 尚未接入的算法返回 ErrUnsupported（Ed448 / X25519 已接入，见各自测试文件）
	if _, err := GenerateKeyFromSeed(AlgX448, make([]byte, 56)); !errors.Is(err, ErrUnsupported) {
		t.Error("AlgX448 应返回 ErrUnsupported")
	}
	if _, err := PublicKeyFromBytes(AlgX448, make([]byte, 56)); !errors.Is(err, ErrUnsupported) {
		t.Error("AlgX448 应返回 ErrUnsupported")
	}
	// Ed25519 的 32 字节长度不得被 Ed448 接受
	if _, err := GenerateKeyFromSeed(AlgEd448, make([]byte, ed25519SeedSize)); !errors.Is(err, ErrInvalidSeedLength) {
		t.Error("Ed448 不应接受 32 字节种子")
	}
}

// TestEd25519PEMRoundtrip 验证 PKCS#8 私钥 / SPKI 公钥 PEM 往返。
func TestEd25519PEMRoundtrip(t *testing.T) {
	priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(privPEM, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Fatalf("私钥 PEM 头异常：%q", privPEM[:32])
	}
	loaded, err := LoadPrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	loadedPEM, err := loaded.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loadedPEM, privPEM) {
		t.Fatal("私钥 PEM 往返不一致")
	}

	pubPEM, err := priv.Public().MarshalPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pubPEM, []byte("-----BEGIN PUBLIC KEY-----")) {
		t.Fatalf("公钥 PEM 头异常：%q", pubPEM[:32])
	}
	loadedPub, err := LoadPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	lp, err := RawPublicKey(loadedPub)
	if err != nil {
		t.Fatal(err)
	}
	op, err := RawPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(lp, op) {
		t.Fatal("公钥 PEM 往返后字节不一致")
	}
}

// TestEd25519EncryptedPEM 验证加密 PEM 导出 / 加载与错误口令。
func TestEd25519EncryptedPEM(t *testing.T) {
	priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := MarshalEncryptedPrivateKeyPEM(priv, "password")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(enc, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
		t.Fatalf("加密 PEM 头异常：%q", enc[:32])
	}
	loaded, err := LoadEncryptedPrivateKeyPEM(enc, "password")
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("ed25519 encrypted pem")
	sig, err := SignEd25519(loaded, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEd25519(priv.Public(), msg, sig); err != nil {
		t.Fatalf("用原公钥验签失败：%v", err)
	}
	if _, err := LoadEncryptedPrivateKeyPEM(enc, "wrong"); err == nil {
		t.Error("错误口令应报错")
	}

	enc2, err := MarshalEncryptedPrivateKeyPEMWithCipher(priv, "aes-128-cbc", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEncryptedPrivateKeyPEM(enc2, "pw"); err != nil {
		t.Fatalf("aes-128-cbc 加密 PEM 加载失败：%v", err)
	}
}

// TestEd25519SignVerify 验证签名长度、确定性（同输入同签名）与验签。
func TestEd25519SignVerify(t *testing.T) {
	priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello ed25519")
	sig1, err := SignEd25519(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig1) != 64 {
		t.Fatalf("签名长度 = %d，应为 64", len(sig1))
	}
	sig2, err := SignEd25519(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Error("Ed25519 为确定性签名，两次结果应相同")
	}
	if err := VerifyEd25519(priv.Public(), msg, sig1); err != nil {
		t.Fatalf("验签失败：%v", err)
	}
	// 空消息也应可签可验
	emptySig, err := SignEd25519(priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEd25519(priv.Public(), nil, emptySig); err != nil {
		t.Fatalf("空消息验签失败：%v", err)
	}
}

// TestEd25519VerifyTampered 验证篡改数据 / 签名 / 密钥均验签失败。
func TestEd25519VerifyTampered(t *testing.T) {
	priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("tamper test")
	sig, err := SignEd25519(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEd25519(priv.Public(), []byte("tamper test!"), sig); err == nil {
		t.Error("篡改数据应验签失败")
	}
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0x01
	if err := VerifyEd25519(priv.Public(), msg, bad); err == nil {
		t.Error("篡改签名应验签失败")
	}
	// 长度错误的签名
	if err := VerifyEd25519(priv.Public(), msg, sig[:63]); err == nil {
		t.Error("签名长度错误应报错")
	}
	other, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEd25519(other.Public(), msg, sig); err == nil {
		t.Error("换密钥应验签失败")
	}
}

// TestEd25519PublicKeyFromBytes 验证从原始字节构造公钥并验签。
func TestEd25519PublicKeyFromBytes(t *testing.T) {
	priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := RawPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKeyFromBytes(AlgEd25519, raw)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("from raw bytes")
	sig, err := SignEd25519(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEd25519(pub, msg, sig); err != nil {
		t.Fatalf("由原始字节构造的公钥验签失败：%v", err)
	}
}

// TestEd25519Match 验证公钥分量匹配判断。
func TestEd25519Match(t *testing.T) {
	a, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	match, err := Match(a, b.Public())
	if err != nil {
		t.Fatal(err)
	}
	if match {
		t.Error("不同密钥不应匹配")
	}
	match, err = Match(a, a.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Error("自身公钥应匹配")
	}
}

// TestEd25519LoadInvalidPEM 验证非法 PEM 返回错误。
func TestEd25519LoadInvalidPEM(t *testing.T) {
	if _, err := LoadPrivateKeyPEM([]byte("not a pem")); err == nil {
		t.Error("非法私钥 PEM 应报错")
	}
	if _, err := LoadPublicKeyPEM([]byte("not a pem")); err == nil {
		t.Error("非法公钥 PEM 应报错")
	}
	if _, err := LoadEncryptedPrivateKeyPEM([]byte("not a pem"), "pw"); err == nil {
		t.Error("非法加密 PEM 应报错")
	}
}

// TestEd25519TypeGuards 验证非 Ed25519 密钥传入 Ed25519 函数时报错，以及 nil 守卫。
func TestEd25519TypeGuards(t *testing.T) {
	ecPriv, err := GenerateEC(CurveP256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignEd25519(ecPriv, []byte("x")); err == nil {
		t.Error("EC 密钥调用 SignEd25519 应报错")
	}
	if err := VerifyEd25519(ecPriv.Public(), []byte("x"), []byte{1}); err == nil {
		t.Error("EC 公钥调用 VerifyEd25519 应报错")
	}

	if _, err := SignEd25519(nil, nil); err == nil {
		t.Error("SignEd25519(nil) 应报错")
	}
	if err := VerifyEd25519(nil, nil, nil); err == nil {
		t.Error("VerifyEd25519(nil) 应报错")
	}
	if _, err := RawPrivateKey(nil); err == nil {
		t.Error("RawPrivateKey(nil) 应报错")
	}
	if _, err := RawPublicKey(nil); err == nil {
		t.Error("RawPublicKey(nil) 应报错")
	}
}
