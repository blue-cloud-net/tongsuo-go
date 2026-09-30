package asym

import (
	"bytes"
	"errors"
	"testing"
)

// TestGenerateX448 验证密钥生成：算法标识正确、两次生成不同。
func TestGenerateX448(t *testing.T) {
	a, err := GenerateX448()
	if err != nil {
		t.Fatal(err)
	}
	if a.Algorithm() != AlgX448 {
		t.Errorf("alg = %s, want X448", a.Algorithm())
	}
	if a.Public().Algorithm() != AlgX448 {
		t.Errorf("pub alg = %s", a.Public().Algorithm())
	}
	b, err := GenerateX448()
	if err != nil {
		t.Fatal(err)
	}
	ap, _ := a.MarshalPrivateKeyPEM()
	bp, _ := b.MarshalPrivateKeyPEM()
	if bytes.Equal(ap, bp) {
		t.Fatal("两次生成的密钥相同")
	}
}

// TestX448RFC7748Vectors 用 RFC 7748 §6.2 标准向量验证「私钥标量 → 公钥」派生。
// 该派生即标量与基点（u=5）的 X448 运算，钳位（clamping）由铜锁 provider 完成，
// 与 RFC 给出的期望公钥一致。
func TestX448RFC7748Vectors(t *testing.T) {
	cases := []struct {
		name string
		priv string
		pub  string
	}{
		{
			name: "Alice",
			priv: "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d" +
				"d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
			pub: "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c" +
				"22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
		},
		{
			name: "Bob",
			priv: "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d" +
				"6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
			pub: "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430" +
				"27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			seed := mustHex(t, c.priv)
			wantPub := mustHex(t, c.pub)
			if len(seed) != 56 {
				t.Fatalf("seed 长度 = %d，应为 56", len(seed))
			}
			if len(wantPub) != 56 {
				t.Fatalf("公钥长度 = %d，应为 56", len(wantPub))
			}

			priv, err := GenerateKeyFromSeed(AlgX448, seed)
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

// TestX448SeedRoundtrip 验证种子导入 / 导出往返与确定性。
func TestX448SeedRoundtrip(t *testing.T) {
	priv, err := GenerateX448()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := RawPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != 56 {
		t.Fatalf("seed 长度 = %d，应为 56", len(seed))
	}
	again, err := GenerateKeyFromSeed(AlgX448, seed)
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

// TestX448LengthGuard 验证种子 / 公钥长度校验（56 字节）。
func TestX448LengthGuard(t *testing.T) {
	for _, n := range []int{0, 32, 55, 57, 114} {
		if _, err := GenerateKeyFromSeed(AlgX448, make([]byte, n)); !errors.Is(err, ErrInvalidSeedLength) {
			t.Errorf("seed 长度 %d：err = %v，应为 ErrInvalidSeedLength", n, err)
		}
		if _, err := PublicKeyFromBytes(AlgX448, make([]byte, n)); !errors.Is(err, ErrInvalidPublicKeyLength) {
			t.Errorf("公钥长度 %d：err = %v，应为 ErrInvalidPublicKeyLength", n, err)
		}
	}
	// X25519 的 32 字节长度不得被 X448 接受
	if _, err := GenerateKeyFromSeed(AlgX448, make([]byte, x25519KeySize)); !errors.Is(err, ErrInvalidSeedLength) {
		t.Error("X448 不应接受 X25519 的 32 字节种子")
	}
}

// TestX448PEMRoundtrip 验证 PKCS#8 私钥 / SPKI 公钥 PEM 往返。
func TestX448PEMRoundtrip(t *testing.T) {
	priv, err := GenerateX448()
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
	if loaded.Algorithm() != AlgX448 {
		t.Errorf("加载后 alg = %s, want X448", loaded.Algorithm())
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

// TestX448EncryptedPEM 验证加密 PEM 导出 / 加载与错误口令。
func TestX448EncryptedPEM(t *testing.T) {
	priv, err := GenerateX448()
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
	if loaded.Algorithm() != AlgX448 {
		t.Errorf("alg = %s, want X448", loaded.Algorithm())
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

// TestX448Dispatch 验证算法无关入口识别 X448。
func TestX448Dispatch(t *testing.T) {
	priv, err := GenerateX448()
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
	if _, ok := loaded.(*x448PrivateKey); !ok {
		t.Errorf("未分发到 *x448PrivateKey，得到 %T", loaded)
	}
	if _, ok := loaded.Public().(*x448PublicKey); !ok {
		t.Errorf("公钥未分发到 *x448PublicKey，得到 %T", loaded.Public())
	}
	params, err := Params(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if params.Type != string(AlgX448) {
		t.Errorf("params.Type = %q, want X448", params.Type)
	}
	match, err := Match(loaded, priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Error("同一密钥对的公私钥应配对")
	}
	raw, err := RawPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKeyFromBytes(AlgX448, raw)
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

// TestX448NoSignCapability 验证 X448 不具备签名能力，签名入口会明确拒绝它。
func TestX448NoSignCapability(t *testing.T) {
	priv, err := GenerateX448()
	if err != nil {
		t.Fatal(err)
	}
	signers := []struct {
		name string
		fn   func(PrivateKey) error
	}{
		{"SignEd25519", func(k PrivateKey) error { _, err := SignEd25519(k, []byte("x")); return err }},
		{"SignEd448", func(k PrivateKey) error { _, err := SignEd448(k, []byte("x")); return err }},
		{"SignECDSA", func(k PrivateKey) error { _, err := SignECDSA(k, []byte("x")); return err }},
		{"SignPKCS1v15", func(k PrivateKey) error { _, err := SignPKCS1v15(k, []byte("x"), "sha256"); return err }},
		{"SignPSS", func(k PrivateKey) error { _, err := SignPSS(k, []byte("x"), PSSSaltLenDigest, "sha256"); return err }},
		{"Sign(SM2)", func(k PrivateKey) error { _, err := Sign(k, []byte("x")); return err }},
	}
	for _, s := range signers {
		if err := s.fn(priv); err == nil {
			t.Errorf("X448 密钥调用 %s 应报错", s.name)
		}
	}
	if err := VerifyEd448(priv.Public(), []byte("x"), []byte{1}); err == nil {
		t.Error("X448 公钥调用 VerifyEd448 应报错")
	}

	// nil 守卫
	if _, err := RawPrivateKey(nil); err == nil {
		t.Error("RawPrivateKey(nil) 应报错")
	}
	if _, err := RawPublicKey(nil); err == nil {
		t.Error("RawPublicKey(nil) 应报错")
	}
}

// TestAllAlgorithmsRegistered 验证 Alg* 常量全部有对应生成入口与分发，
// 即 asym 的 7 种算法均已接入（无遗漏）。
func TestAllAlgorithmsRegistered(t *testing.T) {
	gens := map[Algorithm]func() (PrivateKey, error){
		AlgSM2:     GenerateSM2,
		AlgRSA:     func() (PrivateKey, error) { return GenerateRSA(2048) },
		AlgEC:      func() (PrivateKey, error) { return GenerateEC(CurveP256) },
		AlgEd25519: GenerateEd25519,
		AlgEd448:   GenerateEd448,
		AlgX25519:  GenerateX25519,
		AlgX448:    GenerateX448,
	}
	for alg, gen := range gens {
		t.Run(string(alg), func(t *testing.T) {
			priv, err := gen()
			if err != nil {
				t.Fatalf("生成失败：%v", err)
			}
			if priv.Algorithm() != alg {
				t.Errorf("alg = %s, want %s", priv.Algorithm(), alg)
			}
			// 算法无关加载必须分发回同一算法
			pem, err := priv.MarshalPrivateKeyPEM()
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadPrivateKeyPEM(pem)
			if err != nil {
				t.Fatalf("LoadPrivateKeyPEM: %v", err)
			}
			if loaded.Algorithm() != alg {
				t.Errorf("加载后 alg = %s, want %s", loaded.Algorithm(), alg)
			}
			// 公钥同样可分发
			pubPEM, err := priv.Public().MarshalPublicKeyPEM()
			if err != nil {
				t.Fatal(err)
			}
			loadedPub, err := LoadPublicKeyPEM(pubPEM)
			if err != nil {
				t.Fatalf("LoadPublicKeyPEM: %v", err)
			}
			if loadedPub.Algorithm() != alg {
				t.Errorf("公钥加载后 alg = %s, want %s", loadedPub.Algorithm(), alg)
			}
			// Params 的 Type 必须与算法名一致
			params, err := Params(loaded)
			if err != nil {
				t.Fatal(err)
			}
			if params.Type != string(alg) {
				t.Errorf("params.Type = %q, want %q", params.Type, alg)
			}
			// 自身配对
			match, err := Match(loaded, priv.Public())
			if err != nil {
				t.Fatal(err)
			}
			if !match {
				t.Error("自身公钥应配对")
			}
		})
	}

	// 未注册的算法名不得被接受
	if _, err := GenerateKeyFromSeed(Algorithm("BOGUS"), make([]byte, 32)); !errors.Is(err, ErrUnsupported) {
		t.Error("未知算法应返回 ErrUnsupported")
	}
}
