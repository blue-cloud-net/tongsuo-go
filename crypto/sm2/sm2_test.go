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
