package sm2

import (
	"bytes"
	"testing"
)

func mustMarshalPriv(t *testing.T, k *PrivateKey) []byte {
	t.Helper()
	pem, err := k.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	return pem
}

// TestGenerateKey 验证密钥生成：每次不同。
func TestGenerateKey(t *testing.T) {
	a, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(mustMarshalPriv(t, a), mustMarshalPriv(t, b)) {
		t.Fatal("two generated keys are identical")
	}
}

// TestPEMRoundTrip 验证私钥/公钥 PEM 序列化往返。
func TestPEMRoundTrip(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privPEM := mustMarshalPriv(t, priv)
	if !bytes.HasPrefix(privPEM, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Fatalf("unexpected private PEM header: %q", privPEM[:32])
	}
	loaded, err := LoadPrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(privPEM, mustMarshalPriv(t, loaded)) {
		t.Fatal("private PEM roundtrip mismatch")
	}

	pubPEM, err := priv.Public().MarshalPEM()
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
	loadedPubPEM, err := loadedPub.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pubPEM, loadedPubPEM) {
		t.Fatal("public PEM roundtrip mismatch")
	}
}

// TestEncryptDecrypt 验证 SM2 加解密往返。
func TestEncryptDecrypt(t *testing.T) {
	priv, err := GenerateKey()
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

// TestEncryptDifferentCiphertext 验证 SM2 加密具有随机性（相同输入密文不同）。
func TestEncryptDifferentCiphertext(t *testing.T) {
	priv, _ := GenerateKey()
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

// TestCipherFormatRoundTrip 验证 DER / C1C3C2 / C1C2C3 三种密文格式互转与加解密往返。
func TestCipherFormatRoundTrip(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()
	plaintext := []byte("tongsuo sm2 cipher format")

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

// TestCipherFormatErrors 验证密文格式转换的错误路径。
func TestCipherFormatErrors(t *testing.T) {
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

// TestSignVerify 验证 SM2withSM3 签名验签（默认 userId）。
func TestSignVerify(t *testing.T) {
	priv, err := GenerateKey()
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

// TestSignVerifyWithID 验证自定义 userId 签名验签。
func TestSignVerifyWithID(t *testing.T) {
	priv, _ := GenerateKey()
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

// TestVerifyTampered 验证篡改数据/签名/密钥均验签失败。
func TestVerifyTampered(t *testing.T) {
	priv, _ := GenerateKey()
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
	other, _ := GenerateKey()
	if err := Verify(other.Public(), data, sig); err == nil {
		t.Fatal("verify with other key should fail")
	}
}

// TestEmptyData 验证空数据行为：签名/验签支持空数据，加密不支持（SM2 限制）。
func TestEmptyData(t *testing.T) {
	priv, _ := GenerateKey()
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

// TestLoadInvalidPEM 验证加载非法 PEM 返回错误。
func TestLoadInvalidPEM(t *testing.T) {
	if _, err := LoadPrivateKeyPEM([]byte("not a pem")); err == nil {
		t.Fatal("expected error for invalid private PEM")
	}
	if _, err := LoadPublicKeyPEM([]byte("not a pem")); err == nil {
		t.Fatal("expected error for invalid public PEM")
	}
}
