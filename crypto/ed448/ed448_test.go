// Package ed448 的同包单元测试（生成、PEM、Sign/Verify、确定性签名）。
// Unit tests for ed448 (keygen, PEM roundtrip, sign/verify, deterministic signatures).
package ed448

import (
	"bytes"
	"testing"
)

// TestGenerateKey 验证 GenerateKey 返回非空、Algorithm="ED448"、两次生成不同。
//
// TestGenerateKey verifies GenerateKey returns a non-nil key with
// Algorithm() == "ED448" and two calls produce different keys.
func TestGenerateKey(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if k == nil || k.key == nil {
		t.Fatal("nil key")
	}
	if got := k.Key().Algorithm(); got != "ED448" {
		t.Fatalf("Algorithm() = %q, want ED448", got)
	}
	k3, err := GenerateKey()
	if err != nil {
		t.Fatalf("second GenerateKey: %v", err)
	}
	if k.Key().PublicEqual(k3.Key()) {
		t.Fatal("two fresh keys should differ")
	}
}

// TestSignVerify 验证基础签名/验签循环，并确认篡改数据/签名导致 Verify 返回 error。
//
// TestSignVerify verifies the basic sign/verify round trip and confirms
// that tampered data or signature cause Verify to return an error.
func TestSignVerify(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	msg := []byte("hello ed448")
	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 114 {
		t.Fatalf("sig len = %d, want 114", len(sig))
	}
	if err := Verify(pub, msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := Verify(pub, []byte("tampered"), sig); err == nil {
		t.Fatal("Verify tampered data should fail")
	}
	if err := Verify(pub, msg, sig[:100]); err == nil {
		t.Fatal("Verify short sig should fail")
	}
}

// TestSeedRoundtrip 验证 Seed() 导出与 PrivateKeyFromSeed 重建后公钥一致。
//
// TestSeedRoundtrip checks that Seed() / PrivateKeyFromSeed produce the
// same public key as the original.
func TestSeedRoundtrip(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	seed, err := priv.Seed()
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if len(seed) != 57 {
		t.Fatalf("seed len = %d, want 57", len(seed))
	}
	priv2, err := PrivateKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("PrivateKeyFromSeed: %v", err)
	}
	pub1, _ := priv.Public()
	pub2, _ := priv2.Public()
	pb1, _ := pub1.Bytes()
	pb2, _ := pub2.Bytes()
	if !bytes.Equal(pb1, pb2) {
		t.Fatal("seed roundtrip pub bytes differ")
	}
}

// TestSeedLengthGuard 验证传入非 57 字节种子的 ErrInvalidSeedLength 哨兵。
//
// TestSeedLengthGuard checks that a non-57-byte seed returns the
// ErrInvalidSeedLength sentinel.
func TestSeedLengthGuard(t *testing.T) {
	if _, err := PrivateKeyFromSeed(make([]byte, 56)); err != ErrInvalidSeedLength {
		t.Fatalf("got %v, want ErrInvalidSeedLength", err)
	}
	if _, err := PrivateKeyFromSeed(make([]byte, 58)); err != ErrInvalidSeedLength {
		t.Fatalf("got %v, want ErrInvalidSeedLength", err)
	}
	if _, err := PublicKeyFromBytes(make([]byte, 56)); err != ErrInvalidPublicKeyLength {
		t.Fatalf("got %v, want ErrInvalidPublicKeyLength", err)
	}
}

// TestPEMRoundtrip 验证 PKCS#8 / SPKI / 加密 PEM 往返一致性。
//
// TestPEMRoundtrip checks that PKCS#8 / SPKI / encrypted PEM round-trips
// preserve the public key.
func TestPEMRoundtrip(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}

	p8, err := priv.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}
	if !bytes.HasPrefix(p8, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Fatal("not PKCS#8 PEM")
	}
	priv2, err := LoadPrivateKeyPEM(p8)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM: %v", err)
	}
	if !priv2.Key().PublicEqual(pub.Key()) {
		t.Fatal("PKCS#8 roundtrip pub differ")
	}

	spki, err := pub.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM pub: %v", err)
	}
	if !bytes.HasPrefix(spki, []byte("-----BEGIN PUBLIC KEY-----")) {
		t.Fatal("not SPKI PEM")
	}
	pub2, err := LoadPublicKeyPEM(spki)
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM: %v", err)
	}
	if !pub2.Key().PublicEqual(pub.Key()) {
		t.Fatal("SPKI roundtrip pub differ")
	}

	enc, err := priv.MarshalEncryptedPEM("test-pass")
	if err != nil {
		t.Fatalf("MarshalEncryptedPEM: %v", err)
	}
	dec, err := LoadEncryptedPEM(enc, "test-pass")
	if err != nil {
		t.Fatalf("LoadEncryptedPEM: %v", err)
	}
	if _, err := LoadEncryptedPEM(enc, "wrong"); err == nil {
		t.Fatal("LoadEncryptedPEM with wrong pass should fail")
	}
	if !dec.Key().PublicEqual(pub.Key()) {
		t.Fatal("enc PEM roundtrip pub differ")
	}
}

// TestRFC8032StableSignatures 验证 Ed448 在固定种子+固定消息下产生确定签名（与铜锁 EdDSA
// provider 行为一致）。
//
// TestRFC8032StableSignatures checks Ed448 produces deterministic
// signatures from a fixed seed and message, matching the local Tongsuo
// EdDSA provider.
func TestRFC8032StableSignatures(t *testing.T) {
	// 任意 57 字节 seed（确定性签名只要求同一 seed+msg 出同一 sig）。
	seed := make([]byte, 57)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv, err := PrivateKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("PrivateKeyFromSeed: %v", err)
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}

	sig1, err := Sign(priv, []byte("ed448 fixed message"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig2, err := Sign(priv, []byte("ed448 fixed message"))
	if err != nil {
		t.Fatalf("Sign 2: %v", err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Fatal("Ed448 deterministic: two sigs differ")
	}
	if err := Verify(pub, []byte("ed448 fixed message"), sig1); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}