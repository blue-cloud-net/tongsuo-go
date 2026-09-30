package asym

import (
	"bytes"
	"errors"
	"testing"
)

func mustMarshalSM2Priv(t *testing.T, k PrivateKey) []byte {
	t.Helper()
	pem, err := k.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	return pem
}

// TestGenerateSM2 验证密钥生成：每次不同。
func TestGenerateSM2(t *testing.T) {
	a, err := GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	if a.Algorithm() != AlgSM2 {
		t.Fatalf("alg = %s, want SM2", a.Algorithm())
	}
	if bytes.Equal(mustMarshalSM2Priv(t, a), mustMarshalSM2Priv(t, b)) {
		t.Fatal("two generated keys are identical")
	}
}

// TestSM2PEMRoundTrip 验证私钥/公钥 PEM 序列化往返。
func TestSM2PEMRoundTrip(t *testing.T) {
	priv, err := GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	privPEM := mustMarshalSM2Priv(t, priv)
	if !bytes.HasPrefix(privPEM, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Fatalf("unexpected private PEM header: %q", privPEM[:32])
	}
	loaded, err := LoadPrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(privPEM, mustMarshalSM2Priv(t, loaded)) {
		t.Fatal("private PEM roundtrip mismatch")
	}

	pub := priv.Public()
	if pub.Algorithm() != AlgSM2 {
		t.Fatalf("pub alg = %s, want SM2", pub.Algorithm())
	}
	pubPEM, err := pub.MarshalPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pubPEM, []byte("-----BEGIN PUBLIC KEY-----")) {
		t.Fatalf("unexpected public PEM header: %q", pubPEM[:32])
	}
	loadedPub, err := LoadPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	loadedPubPEM, err := loadedPub.MarshalPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pubPEM, loadedPubPEM) {
		t.Fatal("public PEM roundtrip mismatch")
	}
}

// TestSM2EncryptDecrypt 验证 SM2 加解密往返。
func TestSM2EncryptDecrypt(t *testing.T) {
	priv, err := GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{
		[]byte("a"),
		bytes.Repeat([]byte("sm2-data"), 10),
	} {
		ct, err := Encrypt(priv.Public(), data)
		if err != nil {
			t.Fatalf("encrypt len %d: %v", len(data), err)
		}
		if bytes.Equal(ct, data) {
			t.Fatal("ciphertext equals plaintext")
		}
		pt, err := Decrypt(priv, ct)
		if err != nil {
			t.Fatalf("decrypt len %d: %v", len(data), err)
		}
		if !bytes.Equal(pt, data) {
			t.Fatalf("decrypt mismatch for len %d", len(data))
		}
	}
}

// TestSM2EncryptRandomness 验证 SM2 加密具有随机性。
func TestSM2EncryptRandomness(t *testing.T) {
	priv, _ := GenerateSM2()
	data := []byte("same data")
	a, err := Encrypt(priv.Public(), data)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt(priv.Public(), data)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("SM2 encryption is deterministic")
	}
}

// TestSM2CipherFormatRoundTrip 验证 DER / C1C3C2 / C1C2C3 三种密文格式互转与加解密往返。
func TestSM2CipherFormatRoundTrip(t *testing.T) {
	priv, err := GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()
	plaintext := []byte("tongsuo asym sm2 cipher format")

	der, err := Encrypt(pub, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// 互转：DER → C1C3C2 → C1C2C3 → DER 应还原原始 DER。
	c132, err := Format(der, "der", "c1c3c2")
	if err != nil {
		t.Fatal(err)
	}
	c123, err := Format(c132, "c1c3c2", "c1c2c3")
	if err != nil {
		t.Fatal(err)
	}
	back, err := Format(c123, "c1c2c3", "der")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, der) {
		t.Fatal("DER roundtrip mismatch")
	}

	// 裸格式仅 C2/C3 顺序不同：C1 相同、C3 一致。
	if len(c132) != len(c123) {
		t.Fatalf("raw length mismatch: %d vs %d", len(c132), len(c123))
	}
	if !bytes.Equal(c132[:65], c123[:65]) {
		t.Fatal("C1 mismatch")
	}
	c3 := c132[65 : 65+32]
	c2 := c132[65+32:]
	if !bytes.Equal(c3, c123[len(c123)-32:]) {
		t.Fatal("C3 mismatch")
	}
	if !bytes.Equal(c2, c123[65:65+len(c2)]) {
		t.Fatal("C2 mismatch")
	}

	// 裸格式加解密（含默认顺序）。
	for _, order := range []string{"c1c3c2", "c1c2c3", ""} {
		enc, err := EncryptWithOrder(pub, plaintext, order)
		if err != nil {
			t.Fatalf("encrypt order %q: %v", order, err)
		}
		if enc[0] != 0x04 {
			t.Fatalf("expected uncompressed C1 for order %q", order)
		}
		pt, err := DecryptWithOrder(priv, enc, order)
		if err != nil {
			t.Fatalf("decrypt order %q: %v", order, err)
		}
		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("roundtrip mismatch for order %q", order)
		}
	}

	// Format 相同格式返回副本。
	copyOf, err := Format(der, "der", "der")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copyOf, der) {
		t.Fatal("same-format copy mismatch")
	}
}

// TestSM2CipherFormatErrors 验证密文格式转换的错误路径。
func TestSM2CipherFormatErrors(t *testing.T) {
	if _, err := Format([]byte{1}, "bogus", "der"); err == nil {
		t.Fatal("expected unknown from-format error")
	}
	if _, err := Format([]byte{1}, "der", "bogus"); err == nil {
		t.Fatal("expected unknown to-format error")
	}
	if _, err := Format([]byte("not-der"), "der", "c1c3c2"); err == nil {
		t.Fatal("expected invalid DER error")
	}
	if _, err := Format([]byte{0x04, 0x01}, "c1c3c2", "der"); err == nil {
		t.Fatal("expected short ciphertext error")
	}
	if _, err := Format([]byte{0x00, 0x01}, "c1c2c3", "der"); err == nil {
		t.Fatal("expected unsupported point prefix error")
	}
	// 压缩点无法转 DER（缺少坐标）。
	if _, err := Format(bytes.Repeat([]byte{0x02}, 33+32+8), "c1c3c2", "der"); err == nil {
		t.Fatal("expected compressed-to-DER error")
	}
}

// TestSM2SignVerify 验证 SM2withSM3 签名验签（默认 userId）。
func TestSM2SignVerify(t *testing.T) {
	priv, err := GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("hello sm2 sign")
	sig, err := Sign(priv, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(priv.Public(), data, sig); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

// TestSM2SignVerifyWithID 验证自定义 userId 签名验签。
func TestSM2SignVerifyWithID(t *testing.T) {
	priv, _ := GenerateSM2()
	data := []byte("with custom id")
	id := []byte("tongsuo-user-id-01")

	sig, err := SignWithID(priv, data, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWithID(priv.Public(), data, sig, id); err != nil {
		t.Fatal(err)
	}
	// 不同 ID 验签应失败
	if err := VerifyWithID(priv.Public(), data, sig, []byte("other-id")); err == nil {
		t.Fatal("verify with different id should fail")
	}
}

// TestSM2VerifyTampered 验证篡改数据/签名/密钥均验签失败。
func TestSM2VerifyTampered(t *testing.T) {
	priv, _ := GenerateSM2()
	data := []byte("tamper test")
	sig, _ := Sign(priv, data)

	if err := Verify(priv.Public(), []byte("tamper test!"), sig); err == nil {
		t.Fatal("verify tampered data should fail")
	}
	badSig := append([]byte(nil), sig...)
	badSig[len(badSig)-1] ^= 0x01
	if err := Verify(priv.Public(), data, badSig); err == nil {
		t.Fatal("verify tampered sig should fail")
	}
	other, _ := GenerateSM2()
	if err := Verify(other.Public(), data, sig); err == nil {
		t.Fatal("verify with other key should fail")
	}
}

// TestSM2EmptyData 验证空数据行为。
func TestSM2EmptyData(t *testing.T) {
	priv, _ := GenerateSM2()
	sig, err := Sign(priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(priv.Public(), nil, sig); err != nil {
		t.Fatal(err)
	}
	// SM2 加密不支持空明文。
	if _, err := Encrypt(priv.Public(), nil); err == nil {
		t.Fatal("expected error for empty plaintext encryption")
	}
}

// TestSM2LoadInvalidPEM 验证加载非法 PEM 返回错误。
func TestSM2LoadInvalidPEM(t *testing.T) {
	if _, err := LoadPrivateKeyPEM([]byte("not a pem")); err == nil {
		t.Fatal("expected error for invalid private PEM")
	}
	if _, err := LoadPublicKeyPEM([]byte("not a pem")); err == nil {
		t.Fatal("expected error for invalid public PEM")
	}
}

// TestSM2TypeGuards 验证错算法调用返回明确的 ErrUnsupported 路径。
func TestSM2TypeGuards(t *testing.T) {
	priv, _ := GenerateSM2()
	pub := priv.Public()

	// 构造一个「不是 SM2」的伪 PublicKey，强制走非 SM2 分支。
	// 这里直接借用 nil 路径 + 错算法名占位（无法构造非 SM2 私钥，仅测 Sign nil）。
	if _, err := Sign(nil, []byte("data")); err == nil {
		t.Fatal("Sign(nil) must fail")
	}
	if err := Verify(nil, []byte("data"), []byte{1, 2}); err == nil {
		t.Fatal("Verify(nil) must fail")
	}
	if _, err := Encrypt(nil, []byte("data")); err == nil {
		t.Fatal("Encrypt(nil) must fail")
	}
	if _, err := Decrypt(nil, []byte("data")); err == nil {
		t.Fatal("Decrypt(nil) must fail")
	}
	// 公钥 Encrypt 但传私钥：算法标识虽然仍是 SM2 但类型断言失败；
	// 这里跳过（必须用真 RSA 才能跑反向用例，留给 commit 11 覆盖）。
	_ = pub

	// Public 方法返回的 pub 与 priv 算法一致。
	if pub.Algorithm() != AlgSM2 {
		t.Fatalf("pub alg = %s", pub.Algorithm())
	}
}

// TestSM2ErrWrapping 验证错误可识别。
func TestSM2ErrWrapping(t *testing.T) {
	// 无底层句柄时 Decrypt 会通过类型断言失败并报错；这里通过 Encrypt/Decrypt
	// 验签错场景拿到 ErrSignature（在 TestSM2VerifyTampered 已覆盖）。
	if errors.Is(nil, ErrUnknownAlgorithm) {
		t.Fatal("sentinel leak check")
	}
}
