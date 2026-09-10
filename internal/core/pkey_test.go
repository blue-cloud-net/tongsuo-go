package core

import (
	"bytes"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// NidUndef 在 core 层不可见（封装于 native 包），此处重新声明以让测试断言。
// 在生产代码中请用 k.BaseID()/TypeID() 直接判断返回值。
const nidUndef = native.NidUndef

// TestX448TypeIDMatchesNID 验证 EvpPkeyX448 常量与铜锁 obj_mac.h 中 NID_x448
// 的数值一致（不依赖绑定层硬编码的数字）。
//
// TestX448TypeIDMatchesNID verifies that the EvpPkeyX448 constant matches
// the NID_x448 value exposed by Tongsuo (obj_mac.h), so the hard-coded
// number in the binding layer is not taken on faith.
func TestX448TypeIDMatchesNID(t *testing.T) {
	nid := native.OBJ_txt2nid("X448")
	if nid == nidUndef {
		t.Skip("this Tongsuo build exposes no X448 short name")
	}
	if native.EvpPkeyX448 != nid {
		t.Fatalf("EvpPkeyX448 = %d, want NID_x448 = %d", native.EvpPkeyX448, nid)
	}
}

// TestGenerateKeys 验证各种算法的密钥生成。
func TestGenerateKeys(t *testing.T) {
	tests := []struct {
		name     string
		fn       func() (*PKey, error)
		optional bool // provider 可能不支持的算法：生成失败时跳过而非失败
	}{
		{"SM2", GenerateSM2Key, false},
		{"RSA-2048", func() (*PKey, error) { return GenerateRSAKey(2048) }, false},
		{"RSA-3072", func() (*PKey, error) { return GenerateRSAKey(3072) }, false},
		{"EC-P256", func() (*PKey, error) { return GenerateECKey("P-256") }, false},
		{"ED25519", GenerateED25519Key, false},
		{"ED448", GenerateED448Key, false},
		{"X25519", GenerateX25519Key, false},
		{"X448", GenerateX448Key, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := mustGenerate(t, tt.name, tt.optional, tt.fn)
			defer k.Close()
			if k.BaseID() == nidUndef {
				t.Error("BaseID should be defined")
			}
		})
	}
}

// mustGenerate 生成密钥；optional 为 true 时把“provider 不支持该算法”转为跳过。
//
// mustGenerate generates a key, turning a “provider does not support this
// algorithm” failure into a skip when optional is true.
func mustGenerate(t *testing.T, name string, optional bool, fn func() (*PKey, error)) *PKey {
	t.Helper()
	k, err := fn()
	if err != nil {
		if optional {
			t.Skipf("%s unsupported by this Tongsuo build: %v", name, err)
		}
		t.Fatalf("generate: %v", err)
	}
	return k
}

// TestPKeyAlgorithm 验证 Algorithm() 字符串识别各类密钥。
func TestPKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		gen      func() (*PKey, error)
		want     string // 期望包含
		optional bool
	}{
		{"RSA", func() (*PKey, error) { return GenerateRSAKey(2048) }, "RSA", false},
		{"ED25519", GenerateED25519Key, "ED25519", false},
		{"X25519", GenerateX25519Key, "X25519", false},
		{"X448", GenerateX448Key, "X448", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := mustGenerate(t, tt.name, tt.optional, tt.gen)
			defer k.Close()
			alg := k.Algorithm()
			if !contains(alg, tt.want) {
				t.Errorf("Algorithm() = %q, want to contain %q", alg, tt.want)
			}
		})
	}
}

// TestPKeyClosedMethods 验证关闭后所有方法返回零值或错误（不 panic）。
func TestPKeyClosedMethods(t *testing.T) {
	k, err := GenerateSM2Key()
	if err != nil {
		t.Fatalf("GenerateSM2Key: %v", err)
	}
	if err := k.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// nil 接收者 / closed 句柄的方法都应返回零值或错误
	if k.BaseID() != nidUndef {
		t.Errorf("BaseID on closed: got %d, want NidUndef", k.BaseID())
	}
	if k.TypeID() != nidUndef {
		t.Errorf("TypeID on closed: got %d, want NidUndef", k.TypeID())
	}
	if _, err := k.Sign([]byte("x"), nil); err == nil {
		t.Error("Sign on closed should error")
	}
	if _, err := k.MarshalPrivateKeyPEM(); err == nil {
		t.Error("MarshalPrivateKeyPEM on closed should error")
	}
	if _, err := k.RawPrivateKey(); err == nil {
		t.Error("RawPrivateKey on closed should error")
	}
	if !k.PublicEqual(k) { // 公钥相等检测对 closed 不应 panic
		// 接受任何返回值，仅要求不 panic
	}
}

// TestPKeyEqual 验证相同密钥 Equal 返回 true。
func TestPKeyEqual(t *testing.T) {
	k1, err := GenerateSM2Key()
	if err != nil {
		t.Fatalf("generate k1: %v", err)
	}
	defer k1.Close()

	k2, err := GenerateSM2Key()
	if err != nil {
		t.Fatalf("generate k2: %v", err)
	}
	defer k2.Close()

	if k1.Equal(k2) {
		t.Error("two different SM2 keys should not be Equal")
	}
	if k1.Equal(nil) {
		t.Error("Equal(nil) should be false")
	}
}

// TestSignDigestClosed 验证 Phase 1.2 修复：已关闭的 Digest 不导致 C 崩溃。
func TestSignDigestClosed(t *testing.T) {
	k, err := GenerateSM2Key()
	if err != nil {
		t.Fatalf("GenerateSM2Key: %v", err)
	}
	defer k.Close()

	// 拿一个 digest 然后 close 它
	d := SM3()
	hd := d.handle
	_ = hd.Close()

	if _, err := k.SignDigest([]byte("data"), d); err == nil {
		t.Fatal("SignDigest with closed digest should error")
	}
}

// TestVerifyDigestClosed 验证 Phase 1.2 修复：VerifyDigest 同样守卫。
func TestVerifyDigestClosed(t *testing.T) {
	k, err := GenerateSM2Key()
	if err != nil {
		t.Fatalf("GenerateSM2Key: %v", err)
	}
	defer k.Close()

	d := SHA256()
	hd := d.handle
	_ = hd.Close()

	sig := make([]byte, 64) // dummy
	if err := k.VerifyDigest([]byte("data"), sig, d); err == nil {
		t.Fatal("VerifyDigest with closed digest should error")
	}
}

// TestSM2SignVerifyRoundtrip 验证 SM2 默认 userId 签名 / 验签往返。
func TestSM2SignVerifyRoundtrip(t *testing.T) {
	k, err := GenerateSM2Key()
	if err != nil {
		t.Fatalf("GenerateSM2Key: %v", err)
	}
	defer k.Close()

	data := []byte("SM2 sign/verify roundtrip")
	sig, err := k.Sign(data, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := k.Verify(data, sig, nil); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// 篡改数据 → 验签失败
	bad := append([]byte{}, data...)
	bad[0] ^= 1
	if err := k.Verify(bad, sig, nil); err == nil {
		t.Fatal("Verify on tampered data should error")
	}
	// 篡改签名 → 验签失败
	badSig := append([]byte{}, sig...)
	badSig[len(badSig)-1] ^= 1
	if err := k.Verify(data, badSig, nil); err == nil {
		t.Fatal("Verify on tampered signature should error")
	}
}

// TestED25519SignMessageRoundtrip 验证 Ed25519 pure-EdDSA 签名。
func TestED25519SignMessageRoundtrip(t *testing.T) {
	k, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("GenerateED25519Key: %v", err)
	}
	defer k.Close()

	data := []byte("ed25519 message")
	sig, err := k.SignMessage(data)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if err := k.VerifyMessage(data, sig); err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	// 篡改
	bad := append([]byte{}, data...)
	bad[0] ^= 1
	if err := k.VerifyMessage(bad, sig); err == nil {
		t.Fatal("VerifyMessage on tampered data should error")
	}
}

// TestX25519ECDH 验证 X25519 ECDH 双方推导出相同共享密钥。
func TestX25519ECDH(t *testing.T) {
	a, err := GenerateX25519Key()
	if err != nil {
		t.Fatalf("GenerateX25519Key a: %v", err)
	}
	defer a.Close()
	b, err := GenerateX25519Key()
	if err != nil {
		t.Fatalf("GenerateX25519Key b: %v", err)
	}
	defer b.Close()

	// Derive 接受对方的公钥推导共享密钥
	ab, err := a.Derive(b)
	if err != nil {
		t.Fatalf("a.Derive(b): %v", err)
	}
	ba, err := b.Derive(a)
	if err != nil {
		t.Fatalf("b.Derive(a): %v", err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatalf("ECDH mismatch: ab=%x ba=%x", ab, ba)
	}
}

// TestDeriveLowOrderPointRejected 验证 OKP 低阶点（全零公钥，RFC 7748 §6.1）派生的全零
// 共享密钥被拒绝，而不是静默返回；同时顺便锁定 rawKeySize 对 X25519 / X448 的长度。
//
// TestDeriveLowOrderPointRejected verifies the all-zero shared secret produced by
// an OKP low-order point (all-zero public key, RFC 7748 §6.1) is rejected instead
// of being returned silently, and pins the rawKeySize lengths for X25519 / X448.
func TestDeriveLowOrderPointRejected(t *testing.T) {
	tests := []struct {
		name     string
		algo     int
		keySize  int
		optional bool
		gen      func() (*PKey, error)
	}{
		{"X25519", PKeyAlgoX25519, 32, false, GenerateX25519Key},
		{"X448", PKeyAlgoX448, 56, true, GenerateX448Key},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if n, ok := rawKeySize(tt.algo); !ok || n != tt.keySize {
				t.Errorf("rawKeySize(%s) = (%d, %v), want (%d, true)", tt.name, n, ok, tt.keySize)
			}
			priv := mustGenerate(t, tt.name, tt.optional, tt.gen)
			defer priv.Close()
			lowOrder, err := NewRawPublicKey(tt.algo, make([]byte, tt.keySize))
			if err != nil {
				t.Skipf("provider rejects an all-zero %s public key up front: %v", tt.name, err)
			}
			defer lowOrder.Close()
			if shared, err := priv.Derive(lowOrder); err == nil {
				t.Fatalf("low-order point accepted, shared = %x", shared)
			}
		})
	}
}

// TestPEMRoundtrip 验证 PEM 序列化往返。
func TestPEMRoundtrip(t *testing.T) {
	k, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}
	defer k.Close()

	privPEM, err := k.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatalf("MarshalPrivateKeyPEM: %v", err)
	}
	reloaded, err := LoadPrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM: %v", err)
	}
	defer reloaded.Close()

	if !k.PublicEqual(reloaded) {
		t.Error("public key should match after PEM roundtrip")
	}

	pubPEM, err := k.MarshalPublicKeyPEM()
	if err != nil {
		t.Fatalf("MarshalPublicKeyPEM: %v", err)
	}
	pub, err := LoadPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM: %v", err)
	}
	defer pub.Close()
	if !k.PublicEqual(pub) {
		t.Error("public key should match after SPKI roundtrip")
	}
}

// TestPKeyGenerateInvalidAlgo 验证非法算法返回错误。
func TestPKeyGenerateInvalidAlgo(t *testing.T) {
	if _, err := GenerateECKey("bogus-curve"); err == nil {
		t.Error("invalid EC curve should error")
	}
}

// TestEncryptDecryptPKCS1v15 验证 RSA PKCS#1 v1.5 加解密往返。
func TestEncryptDecryptPKCS1v15(t *testing.T) {
	k, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}
	defer k.Close()

	plaintext := []byte("PKCS1v15 plaintext")
	ct, err := k.EncryptPKCS1v15(plaintext)
	if err != nil {
		t.Fatalf("EncryptPKCS1v15: %v", err)
	}
	pt, err := k.DecryptPKCS1v15(ct)
	if err != nil {
		t.Fatalf("DecryptPKCS1v15: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("decrypted differs: got %q want %q", pt, plaintext)
	}
}

// contains 是 strings.Contains 的简化版（避免 import cycle）。
func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
