package asym

import (
	"bytes"
	"testing"
)

// TestGenerateEC 验证 NIST 曲线密钥生成与参数回读。
func TestGenerateEC(t *testing.T) {
	for _, curve := range []string{CurveP256, CurveP384, CurveP521, CurveSecp256k1} {
		t.Run(curve, func(t *testing.T) {
			priv, err := GenerateEC(curve)
			if err != nil {
				t.Fatalf("GenerateEC(%s): %v", curve, err)
			}
			if priv.Algorithm() != AlgEC {
				t.Errorf("alg = %s, want EC", priv.Algorithm())
			}
			params, err := ECParams(priv)
			if err != nil {
				t.Fatal(err)
			}
			if params.Curve != curve {
				t.Errorf("curve = %q, want %q", params.Curve, curve)
			}
			if params.D == nil || params.X == nil || params.Y == nil {
				t.Error("D / X / Y 应非 nil")
			}
		})
	}
}

// TestGenerateECRandomness 验证两次生成得到不同密钥。
func TestGenerateECRandomness(t *testing.T) {
	a, err := GenerateEC(CurveP256)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateEC(CurveP256)
	if err != nil {
		t.Fatal(err)
	}
	ap, _ := a.MarshalPrivateKeyPEM()
	bp, _ := b.MarshalPrivateKeyPEM()
	if bytes.Equal(ap, bp) {
		t.Fatal("两次生成的密钥相同")
	}
}

// TestGenerateECErrors 验证空曲线与 SM2 曲线被拒绝。
func TestGenerateECErrors(t *testing.T) {
	if _, err := GenerateEC(""); err == nil {
		t.Error("空曲线名应报错")
	}
	for _, c := range []string{"sm2", "sm2p256v1"} {
		if _, err := GenerateEC(c); err == nil {
			t.Errorf("GenerateEC(%q) 应报错并指向 GenerateSM2", c)
		}
	}
	if _, err := GenerateEC("no-such-curve"); err == nil {
		t.Error("未知曲线名应报错")
	}
}

// TestECPEMRoundtrip 验证 PKCS#8 私钥 / SPKI 公钥 PEM 往返。
func TestECPEMRoundtrip(t *testing.T) {
	priv, err := GenerateEC(CurveP256)
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
	loaded, err := LoadECPrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	// 重新加载的密钥可与原公钥配对
	loadedPEM, err := loaded.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loadedPEM, privPEM) {
		t.Fatal("私钥 PEM 往返不一致")
	}

	pub := priv.Public()
	if pub.Algorithm() != AlgEC {
		t.Errorf("公钥 alg = %s", pub.Algorithm())
	}
	pubPEM, err := pub.MarshalPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pubPEM, []byte("-----BEGIN PUBLIC KEY-----")) {
		t.Fatalf("公钥 PEM 头异常：%q", pubPEM[:32])
	}
	loadedPub, err := LoadECPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	loadedPubPEM, err := loadedPub.MarshalPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loadedPubPEM, pubPEM) {
		t.Fatal("公钥 PEM 往返不一致")
	}
}

// TestECEncryptedPEM 验证加密 PEM 导出 / 加载与错误口令。
func TestECEncryptedPEM(t *testing.T) {
	priv, err := GenerateEC(CurveP256)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := MarshalECPrivateKeyEncryptedPEM(priv, "password")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(enc, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
		t.Fatalf("加密 PEM 头异常：%q", enc[:32])
	}
	loaded, err := LoadECPrivateKeyPEMEncrypted(enc, "password")
	if err != nil {
		t.Fatal(err)
	}
	// 重新加载的私钥可签名，且原公钥可验签
	data := []byte("ec encrypted pem")
	sig, err := SignECDSA(loaded, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyECDSA(priv.Public(), data, sig); err != nil {
		t.Fatalf("用原公钥验签失败：%v", err)
	}

	if _, err := LoadECPrivateKeyPEMEncrypted(enc, "wrong"); err == nil {
		t.Error("错误口令应报错")
	}

	// 指定 cipher 导出
	enc2, err := MarshalECPrivateKeyEncryptedPEMWithCipher(priv, "aes-128-cbc", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadECPrivateKeyPEMEncrypted(enc2, "pw"); err != nil {
		t.Fatalf("aes-128-cbc 加密 PEM 加载失败：%v", err)
	}
}

// TestECSignVerify 验证 ECDSA-SHA256 签名验签往返。
func TestECSignVerify(t *testing.T) {
	for _, curve := range []string{CurveP256, CurveP384, CurveP521, CurveSecp256k1} {
		t.Run(curve, func(t *testing.T) {
			priv, err := GenerateEC(curve)
			if err != nil {
				t.Fatal(err)
			}
			data := []byte("msg-" + curve)
			sig, err := SignECDSA(priv, data)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyECDSA(priv.Public(), data, sig); err != nil {
				t.Fatalf("验签失败：%v", err)
			}
		})
	}
}

// TestECVerifyTampered 验证篡改数据 / 签名 / 密钥均验签失败。
func TestECVerifyTampered(t *testing.T) {
	priv, err := GenerateEC(CurveP256)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("tamper test")
	sig, err := SignECDSA(priv, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyECDSA(priv.Public(), []byte("tamper test!"), sig); err == nil {
		t.Error("篡改数据应验签失败")
	}
	bad := append([]byte(nil), sig...)
	bad[len(bad)-1] ^= 0x01
	if err := VerifyECDSA(priv.Public(), data, bad); err == nil {
		t.Error("篡改签名应验签失败")
	}
	other, err := GenerateEC(CurveP256)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyECDSA(other.Public(), data, sig); err == nil {
		t.Error("换密钥应验签失败")
	}
}

// TestECSignRandomized 验证 ECDSA 签名随机化（同一输入两次签名不同）。
func TestECSignRandomized(t *testing.T) {
	priv, err := GenerateEC(CurveP256)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("same input")
	a, err := SignECDSA(priv, data)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SignECDSA(priv, data)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("ECDSA 签名应为随机化（两次结果不应相同）")
	}
}

// TestECPublicParams 验证公钥参数。
// 注意 priv.Public() 与私钥共享底层句柄，其 Params() 会带回 D；
// 只有从 SPKI PEM 独立加载的公钥才无 D。
func TestECPublicParams(t *testing.T) {
	priv, err := GenerateEC(CurveP384)
	if err != nil {
		t.Fatal(err)
	}
	// 共享句柄视图：X / Y / Curve 可用（D 是否为空不在此断言）
	shared, err := ECPublicParams(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if shared.Curve != CurveP384 {
		t.Errorf("共享视图 curve = %q", shared.Curve)
	}
	if shared.X == nil || shared.Y == nil {
		t.Error("共享视图 X / Y 应非 nil")
	}

	// 独立加载的公钥：无 D
	pubPEM, err := priv.Public().MarshalPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadECPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	params, err := ECPublicParams(pub)
	if err != nil {
		t.Fatal(err)
	}
	if params.Curve != CurveP384 {
		t.Errorf("curve = %q", params.Curve)
	}
	if params.X == nil || params.Y == nil {
		t.Error("公钥 X / Y 应非 nil")
	}
	if params.D != nil {
		t.Error("独立加载的公钥不应有 D")
	}
}

// TestECMatch 验证公钥分量匹配判断。
func TestECMatch(t *testing.T) {
	a, err := GenerateEC(CurveP256)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateEC(CurveP256)
	if err != nil {
		t.Fatal(err)
	}
	match, err := ECMatch(a, b.corePKey())
	if err != nil {
		t.Fatal(err)
	}
	if match {
		t.Error("不同密钥不应匹配")
	}
	match, err = ECMatch(a, a.Public().corePKey())
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Error("自身公钥应匹配")
	}
}

// TestECLoadTypeMismatch 验证非 EC PEM 被拒绝。
func TestECLoadTypeMismatch(t *testing.T) {
	// SM2 PEM
	sm2Priv, err := GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	sm2PEM, err := sm2Priv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadECPrivateKeyPEM(sm2PEM); err == nil {
		t.Error("SM2 私钥 PEM 应被 EC 加载器拒绝")
	}
	if _, err := LoadECPublicKeyPEM(sm2PEM); err == nil {
		t.Error("SM2 私钥 PEM 应被 EC 公钥加载器拒绝")
	}

	// RSA PEM
	rsaPriv, err := GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM, err := rsaPriv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadECPrivateKeyPEM(rsaPEM); err == nil {
		t.Error("RSA 私钥 PEM 应被 EC 加载器拒绝")
	}
}

// TestECLoadInvalidPEM 验证非法 PEM 返回错误。
func TestECLoadInvalidPEM(t *testing.T) {
	if _, err := LoadECPrivateKeyPEM([]byte("not a pem")); err == nil {
		t.Error("非法私钥 PEM 应报错")
	}
	if _, err := LoadECPublicKeyPEM([]byte("not a pem")); err == nil {
		t.Error("非法公钥 PEM 应报错")
	}
	if _, err := LoadECPrivateKeyPEMEncrypted([]byte("not a pem"), "pw"); err == nil {
		t.Error("非法加密 PEM 应报错")
	}
}

// TestECTypeGuards 验证非 EC 密钥传入 EC 函数时报错。
func TestECTypeGuards(t *testing.T) {
	sm2Priv, err := GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignECDSA(sm2Priv, []byte("x")); err == nil {
		t.Error("SM2 密钥调用 SignECDSA 应报错")
	}
	if err := VerifyECDSA(sm2Priv.Public(), []byte("x"), []byte{1}); err == nil {
		t.Error("SM2 公钥调用 VerifyECDSA 应报错")
	}
	if _, err := ECParams(sm2Priv); err == nil {
		t.Error("SM2 密钥调用 ECParams 应报错")
	}
	if _, err := ECPublicParams(sm2Priv.Public()); err == nil {
		t.Error("SM2 公钥调用 ECPublicParams 应报错")
	}
	if _, err := ECMatch(sm2Priv, nil); err == nil {
		t.Error("SM2 密钥调用 ECMatch 应报错")
	}

	rsaPriv, err := GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MarshalECPrivateKeyEncryptedPEM(rsaPriv, "pw"); err == nil {
		t.Error("RSA 密钥调用 EC 加密导出应报错")
	}
	if _, err := MarshalECPrivateKeyEncryptedPEMWithCipher(rsaPriv, "aes-128-cbc", "pw"); err == nil {
		t.Error("RSA 密钥调用 EC 加密导出（指定 cipher）应报错")
	}

	// nil 守卫
	if _, err := SignECDSA(nil, nil); err == nil {
		t.Error("SignECDSA(nil) 应报错")
	}
	if err := VerifyECDSA(nil, nil, nil); err == nil {
		t.Error("VerifyECDSA(nil) 应报错")
	}
	if _, err := ECParams(nil); err == nil {
		t.Error("ECParams(nil) 应报错")
	}
	if _, err := ECPublicParams(nil); err == nil {
		t.Error("ECPublicParams(nil) 应报错")
	}
	if _, err := ECMatch(nil, nil); err == nil {
		t.Error("ECMatch(nil) 应报错")
	}
	if _, err := MarshalECPrivateKeyEncryptedPEM(nil, "pw"); err == nil {
		t.Error("MarshalECPrivateKeyEncryptedPEM(nil) 应报错")
	}
	if _, err := MarshalECPrivateKeyEncryptedPEMWithCipher(nil, "aes-128-cbc", "pw"); err == nil {
		t.Error("MarshalECPrivateKeyEncryptedPEMWithCipher(nil) 应报错")
	}
}
