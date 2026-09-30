package asym

import (
	"bytes"
	"errors"
	"testing"
)

// TestGenerateEd448 验证密钥生成：算法标识正确、两次生成不同。
func TestGenerateEd448(t *testing.T) {
	a, err := GenerateEd448()
	if err != nil {
		t.Fatal(err)
	}
	if a.Algorithm() != AlgEd448 {
		t.Errorf("alg = %s, want ED448", a.Algorithm())
	}
	if a.Public().Algorithm() != AlgEd448 {
		t.Errorf("pub alg = %s", a.Public().Algorithm())
	}
	b, err := GenerateEd448()
	if err != nil {
		t.Fatal(err)
	}
	ap, _ := a.MarshalPrivateKeyPEM()
	bp, _ := b.MarshalPrivateKeyPEM()
	if bytes.Equal(ap, bp) {
		t.Fatal("两次生成的密钥相同")
	}
}

// TestEd448RFC8032Vector 用 RFC 8032 §7.4「Blank」标准向量验证公钥派生与签名。
// 该向量为纯 Ed448（空消息、无 context、无预哈希），与本库 SignMessage 路径一致。
func TestEd448RFC8032Vector(t *testing.T) {
	seed := mustHex(t, "6c82a562cb808d10d632be89c8513ebf"+
		"6c929f34ddfa8c9f63c9960ef6e348a3"+
		"528c8a3fcc2f044e39a3fc5b94492f8f"+
		"032e7549a20098f95b")
	wantPub := mustHex(t, "5fd7449b59b461fd2ce787ec616ad46a"+
		"1da1342485a70e1f8a0ea75d80e96778"+
		"edf124769b46c7061bd6783df1e50f6c"+
		"d1fa1abeafe8256180")
	wantSig := mustHex(t, "533a37f6bbe457251f023c0d88f976ae"+
		"2dfb504a843e34d2074fd823d41a591f"+
		"2b233f034f628281f2fd7a22ddd47d78"+
		"28c59bd0a21bfd3980ff0d2028d4b18a"+
		"9df63e006c5d1c2d345b925d8dc00b41"+
		"04852db99ac5c7cdda8530a113a0f4db"+
		"b61149f05a7363268c71d95808ff2e65"+
		"2600")

	if len(seed) != 57 {
		t.Fatalf("seed 长度 = %d，应为 57", len(seed))
	}
	if len(wantSig) != 114 {
		t.Fatalf("签名长度 = %d，应为 114", len(wantSig))
	}

	priv, err := GenerateKeyFromSeed(AlgEd448, seed)
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

	sig, err := SignEd448(priv, nil) // 空消息
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, wantSig) {
		t.Errorf("签名不匹配\n got %x\nwant %x", sig, wantSig)
	}
	if err := VerifyEd448(priv.Public(), nil, sig); err != nil {
		t.Errorf("验签失败：%v", err)
	}
}

// TestEd448SeedRoundtrip 验证种子导入 / 导出往返。
func TestEd448SeedRoundtrip(t *testing.T) {
	priv, err := GenerateEd448()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := RawPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != 57 {
		t.Fatalf("seed 长度 = %d，应为 57", len(seed))
	}
	again, err := GenerateKeyFromSeed(AlgEd448, seed)
	if err != nil {
		t.Fatal(err)
	}
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

// TestEd448LengthGuard 验证种子 / 公钥长度校验（57 字节）。
func TestEd448LengthGuard(t *testing.T) {
	for _, n := range []int{0, 32, 56, 58, 114} {
		if _, err := GenerateKeyFromSeed(AlgEd448, make([]byte, n)); !errors.Is(err, ErrInvalidSeedLength) {
			t.Errorf("seed 长度 %d：err = %v，应为 ErrInvalidSeedLength", n, err)
		}
		if _, err := PublicKeyFromBytes(AlgEd448, make([]byte, n)); !errors.Is(err, ErrInvalidPublicKeyLength) {
			t.Errorf("公钥长度 %d：err = %v，应为 ErrInvalidPublicKeyLength", n, err)
		}
	}
	// Ed25519 的 32 字节长度不得被 Ed448 接受
	if _, err := GenerateKeyFromSeed(AlgEd448, make([]byte, ed25519SeedSize)); !errors.Is(err, ErrInvalidSeedLength) {
		t.Error("Ed448 不应接受 Ed25519 的 32 字节种子")
	}
}

// TestEd448PEMRoundtrip 验证 PKCS#8 私钥 / SPKI 公钥 PEM 往返。
func TestEd448PEMRoundtrip(t *testing.T) {
	priv, err := GenerateEd448()
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
	if loaded.Algorithm() != AlgEd448 {
		t.Errorf("加载后 alg = %s, want ED448", loaded.Algorithm())
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

// TestEd448EncryptedPEM 验证加密 PEM 导出 / 加载与错误口令。
func TestEd448EncryptedPEM(t *testing.T) {
	priv, err := GenerateEd448()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := MarshalEncryptedPrivateKeyPEM(priv, "password")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadEncryptedPrivateKeyPEM(enc, "password")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Algorithm() != AlgEd448 {
		t.Errorf("alg = %s, want ED448", loaded.Algorithm())
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

// TestEd448SignVerify 验证签名长度（114 字节）、确定性与验签。
func TestEd448SignVerify(t *testing.T) {
	priv, err := GenerateEd448()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello ed448")
	sig1, err := SignEd448(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig1) != 114 {
		t.Fatalf("签名长度 = %d，应为 114", len(sig1))
	}
	sig2, err := SignEd448(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Error("Ed448 为确定性签名，两次结果应相同")
	}
	if err := VerifyEd448(priv.Public(), msg, sig1); err != nil {
		t.Fatalf("验签失败：%v", err)
	}
}

// TestEd448VerifyTampered 验证篡改数据 / 签名 / 密钥均验签失败。
func TestEd448VerifyTampered(t *testing.T) {
	priv, err := GenerateEd448()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("tamper test")
	sig, err := SignEd448(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEd448(priv.Public(), []byte("tamper test!"), sig); err == nil {
		t.Error("篡改数据应验签失败")
	}
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0x01
	if err := VerifyEd448(priv.Public(), msg, bad); err == nil {
		t.Error("篡改签名应验签失败")
	}
	if err := VerifyEd448(priv.Public(), msg, sig[:113]); err == nil {
		t.Error("签名长度错误应报错")
	}
	other, err := GenerateEd448()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEd448(other.Public(), msg, sig); err == nil {
		t.Error("换密钥应验签失败")
	}
}

// TestEd448PublicKeyFromBytes 验证从原始字节构造公钥并验签。
func TestEd448PublicKeyFromBytes(t *testing.T) {
	priv, err := GenerateEd448()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := RawPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKeyFromBytes(AlgEd448, raw)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("from raw bytes")
	sig, err := SignEd448(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEd448(pub, msg, sig); err != nil {
		t.Fatalf("由原始字节构造的公钥验签失败：%v", err)
	}
}

// TestEd448Match 验证公钥分量匹配判断。
func TestEd448Match(t *testing.T) {
	a, err := GenerateEd448()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateEd448()
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

// TestEd448AlgorithmDispatch 验证算法无关入口识别 Ed448。
func TestEd448AlgorithmDispatch(t *testing.T) {
	priv, err := GenerateEd448()
	if err != nil {
		t.Fatal(err)
	}
	pem, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPrivateKeyPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.(*ed448PrivateKey); !ok {
		t.Errorf("未分发到 *ed448PrivateKey，得到 %T", loaded)
	}
	if _, ok := loaded.Public().(*ed448PublicKey); !ok {
		t.Errorf("公钥未分发到 *ed448PublicKey，得到 %T", loaded.Public())
	}
	params, err := Params(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if params.Type != string(AlgEd448) {
		t.Errorf("params.Type = %q, want ED448", params.Type)
	}
	if !bytes.Equal(mustMarshalEd448(t, loaded), pem) {
		t.Error("PEM 往返不一致")
	}
}

func mustMarshalEd448(t *testing.T, k PrivateKey) []byte {
	t.Helper()
	pem, err := k.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	return pem
}

// TestEd448TypeGuards 验证非 Ed448 密钥传入 Ed448 函数时报错，以及 nil 守卫。
func TestEd448TypeGuards(t *testing.T) {
	ed25519Priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignEd448(ed25519Priv, []byte("x")); err == nil {
		t.Error("Ed25519 密钥调用 SignEd448 应报错")
	}
	if err := VerifyEd448(ed25519Priv.Public(), []byte("x"), []byte{1}); err == nil {
		t.Error("Ed25519 公钥调用 VerifyEd448 应报错")
	}
	if _, err := SignEd448(nil, nil); err == nil {
		t.Error("SignEd448(nil) 应报错")
	}
	if err := VerifyEd448(nil, nil, nil); err == nil {
		t.Error("VerifyEd448(nil) 应报错")
	}
}
