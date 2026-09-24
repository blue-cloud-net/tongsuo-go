package asym

import (
	"bytes"
	"errors"
	"testing"
)

// TestGenerateX25519 验证密钥生成：算法标识正确、两次生成不同。
func TestGenerateX25519(t *testing.T) {
	a, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	if a.Algorithm() != AlgX25519 {
		t.Errorf("alg = %s, want X25519", a.Algorithm())
	}
	if a.Public().Algorithm() != AlgX25519 {
		t.Errorf("pub alg = %s", a.Public().Algorithm())
	}
	b, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	ap, _ := a.MarshalPrivateKeyPEM()
	bp, _ := b.MarshalPrivateKeyPEM()
	if bytes.Equal(ap, bp) {
		t.Fatal("两次生成的密钥相同")
	}
}

// TestX25519RFC7748Vectors 用 RFC 7748 §6.1 标准向量验证「私钥标量 → 公钥」派生。
// 该派生即标量与基点（u=9）的 X25519 运算，钳位（clamping）由铜锁 provider 完成，
// 与 RFC 给出的期望公钥一致。
func TestX25519RFC7748Vectors(t *testing.T) {
	cases := []struct {
		name string
		priv string
		pub  string
	}{
		{
			name: "Alice",
			priv: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
			pub:  "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
		},
		{
			name: "Bob",
			priv: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
			pub:  "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			seed := mustHex(t, c.priv)
			wantPub := mustHex(t, c.pub)
			if len(seed) != 32 {
				t.Fatalf("seed 长度 = %d，应为 32", len(seed))
			}

			priv, err := GenerateKeyFromSeed(AlgX25519, seed)
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
		})
	}
}

// TestX25519SeedRoundtrip 验证种子导入 / 导出往返与确定性。
func TestX25519SeedRoundtrip(t *testing.T) {
	priv, err := GenerateX25519()
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
	again, err := GenerateKeyFromSeed(AlgX25519, seed)
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

// TestX25519LengthGuard 验证种子 / 公钥长度校验（32 字节）。
func TestX25519LengthGuard(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 57} {
		if _, err := GenerateKeyFromSeed(AlgX25519, make([]byte, n)); !errors.Is(err, ErrInvalidSeedLength) {
			t.Errorf("seed 长度 %d：err = %v，应为 ErrInvalidSeedLength", n, err)
		}
		if _, err := PublicKeyFromBytes(AlgX25519, make([]byte, n)); !errors.Is(err, ErrInvalidPublicKeyLength) {
			t.Errorf("公钥长度 %d：err = %v，应为 ErrInvalidPublicKeyLength", n, err)
		}
	}
}

// TestX25519PEMRoundtrip 验证 PKCS#8 私钥 / SPKI 公钥 PEM 往返。
func TestX25519PEMRoundtrip(t *testing.T) {
	priv, err := GenerateX25519()
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
	if loaded.Algorithm() != AlgX25519 {
		t.Errorf("加载后 alg = %s, want X25519", loaded.Algorithm())
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

// TestX25519EncryptedPEM 验证加密 PEM 导出 / 加载与错误口令。
func TestX25519EncryptedPEM(t *testing.T) {
	priv, err := GenerateX25519()
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
	if loaded.Algorithm() != AlgX25519 {
		t.Errorf("alg = %s, want X25519", loaded.Algorithm())
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

// TestX25519Dispatch 验证算法无关入口识别 X25519。
func TestX25519Dispatch(t *testing.T) {
	priv, err := GenerateX25519()
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
	if _, ok := loaded.(*x25519PrivateKey); !ok {
		t.Errorf("未分发到 *x25519PrivateKey，得到 %T", loaded)
	}
	if _, ok := loaded.Public().(*x25519PublicKey); !ok {
		t.Errorf("公钥未分发到 *x25519PublicKey，得到 %T", loaded.Public())
	}
	params, err := Params(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if params.Type != string(AlgX25519) {
		t.Errorf("params.Type = %q, want X25519", params.Type)
	}
	// Match：同一密钥对的公钥应配对
	match, err := Match(loaded, priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Error("同一密钥对的公私钥应配对")
	}
	// 经 RawPublicKey 构造的公钥同样应配对
	raw, err := RawPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKeyFromBytes(AlgX25519, raw)
	if err != nil {
		t.Fatal(err)
	}
	match, err = Match(loaded, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Error("由原始字节构造的公钥应配对")
	}
}

// TestX25519TypeGuards 验证 X25519 不具备签名能力，且签名入口会明确拒绝它。
func TestX25519TypeGuards(t *testing.T) {
	priv, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	// X25519 只能协商，不能签名：各签名入口必须报错
	if _, err := SignEd25519(priv, []byte("x")); err == nil {
		t.Error("X25519 密钥调用 SignEd25519 应报错")
	}
	if _, err := SignEd448(priv, []byte("x")); err == nil {
		t.Error("X25519 密钥调用 SignEd448 应报错")
	}
	if _, err := SignECDSA(priv, []byte("x")); err == nil {
		t.Error("X25519 密钥调用 SignECDSA 应报错")
	}
	if _, err := SignPKCS1v15(priv, []byte("x"), "sha256"); err == nil {
		t.Error("X25519 密钥调用 SignPKCS1v15 应报错")
	}
	if _, err := Sign(priv, []byte("x")); err == nil {
		t.Error("X25519 密钥调用 SM2 Sign 应报错")
	}
	if err := VerifyEd25519(priv.Public(), []byte("x"), []byte{1}); err == nil {
		t.Error("X25519 公钥调用 VerifyEd25519 应报错")
	}

	// nil 守卫
	if _, err := RawPrivateKey(nil); err == nil {
		t.Error("RawPrivateKey(nil) 应报错")
	}
	if _, err := RawPublicKey(nil); err == nil {
		t.Error("RawPublicKey(nil) 应报错")
	}
}
