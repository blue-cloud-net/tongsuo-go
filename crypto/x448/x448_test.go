// Package x448 的同包单元测试（生成、PEM、SharedSecret、原始字节互操作）。
// Unit tests for x448 (keygen, PEM roundtrip, SharedSecret, raw byte interop).
package x448

import (
	"bytes"
	"errors"
	"testing"
)

// TestGenerateKey 验证 GenerateKey 返回非空、Algorithm()="X448"、两次生成不同，
// 且原始私钥 / 公钥均为 56 字节。
//
// TestGenerateKey verifies GenerateKey returns a non-nil key with
// Algorithm() == "X448", that two calls produce different keys, and that
// both raw keys are 56 bytes long.
func TestGenerateKey(t *testing.T) {
	a, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if a == nil || a.key == nil {
		t.Fatal("nil key")
	}
	if got := a.Key().Algorithm(); got != "X448" {
		t.Fatalf("Algorithm() = %q, want X448", got)
	}
	privBytes, err := a.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if len(privBytes) != keySize {
		t.Fatalf("private key length = %d, want %d", len(privBytes), keySize)
	}
	pub, err := a.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	pubBytes, err := pub.Bytes()
	if err != nil {
		t.Fatalf("public Bytes: %v", err)
	}
	if len(pubBytes) != keySize {
		t.Fatalf("public key length = %d, want %d", len(pubBytes), keySize)
	}
	b, err := GenerateKey()
	if err != nil {
		t.Fatalf("second GenerateKey: %v", err)
	}
	if a.Key().PublicEqual(b.Key()) {
		t.Fatal("two fresh keys should differ")
	}
}

// TestSharedSecretSymmetry 验证 Alice、Bob 共享密钥双向一致且为 56 字节。
//
// TestSharedSecretSymmetry verifies the X448 derived shared secret is
// symmetric and 56 bytes long:
// SharedSecret(alice, bob_pub) == SharedSecret(bob, alice_pub).
func TestSharedSecretSymmetry(t *testing.T) {
	alice, err := GenerateKey()
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	bob, err := GenerateKey()
	if err != nil {
		t.Fatalf("bob: %v", err)
	}
	alicePub, err := alice.Public()
	if err != nil {
		t.Fatalf("alice pub: %v", err)
	}
	bobPub, err := bob.Public()
	if err != nil {
		t.Fatalf("bob pub: %v", err)
	}
	sa, err := SharedSecret(alice, bobPub)
	if err != nil {
		t.Fatalf("alice derive: %v", err)
	}
	sb, err := SharedSecret(bob, alicePub)
	if err != nil {
		t.Fatalf("bob derive: %v", err)
	}
	if len(sa) != keySize || len(sb) != keySize {
		t.Fatalf("shared len: alice=%d bob=%d, want %d", len(sa), len(sb), keySize)
	}
	if !bytes.Equal(sa, sb) {
		t.Fatalf("shared not symmetric:\n  %x\n  %x", sa, sb)
	}
}

// TestRawBytesRoundtrip 验证 PrivateKeyFromBytes / PublicKeyFromBytes / Bytes()
// 互转一致，且长度不符时返回 ErrInvalidKeyLength。
//
// TestRawBytesRoundtrip checks the raw 56-byte private/public constructors
// interoperate with Bytes(), and that a wrong length yields
// ErrInvalidKeyLength.
func TestRawBytesRoundtrip(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	privBytes, err := priv.Bytes()
	if err != nil {
		t.Fatalf("private Bytes: %v", err)
	}
	pubBytes, err := pub.Bytes()
	if err != nil {
		t.Fatalf("public Bytes: %v", err)
	}
	priv2, err := PrivateKeyFromBytes(privBytes)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes: %v", err)
	}
	if !priv.Key().Equal(priv2.Key()) {
		t.Fatal("private key roundtrip mismatch")
	}
	pub2, err := PublicKeyFromBytes(pubBytes)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes: %v", err)
	}
	if !pub.Key().PublicEqual(pub2.Key()) {
		t.Fatal("public key roundtrip mismatch")
	}
	// 派生结果应与重新导入的密钥一致。
	peer, err := GenerateKey()
	if err != nil {
		t.Fatalf("peer: %v", err)
	}
	peerPub, err := peer.Public()
	if err != nil {
		t.Fatalf("peer pub: %v", err)
	}
	want, err := SharedSecret(priv, peerPub)
	if err != nil {
		t.Fatalf("SharedSecret: %v", err)
	}
	got, err := SharedSecret(priv2, peerPub)
	if err != nil {
		t.Fatalf("SharedSecret (reimported): %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("reimported key derives a different secret:\n  %x\n  %x", want, got)
	}
	if _, err := PrivateKeyFromBytes(make([]byte, keySize-1)); !errors.Is(err, ErrInvalidKeyLength) {
		t.Fatalf("short private key: err = %v, want ErrInvalidKeyLength", err)
	}
	if _, err := PublicKeyFromBytes(make([]byte, keySize+1)); !errors.Is(err, ErrInvalidKeyLength) {
		t.Fatalf("long public key: err = %v, want ErrInvalidKeyLength", err)
	}
}

// TestLowOrderPointRejected 验证低阶点（全零公钥，RFC 7748 §6.1）导致的全零共享
// 密钥会被拒绝，语义与 Go 标准库 crypto/ecdh 对齐。
//
// TestLowOrderPointRejected verifies that the all-zero shared secret produced
// by a low-order point (all-zero public key, RFC 7748 §6.1) is rejected, in
// line with Go's crypto/ecdh semantics.
func TestLowOrderPointRejected(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	lowOrder, err := PublicKeyFromBytes(make([]byte, keySize))
	if err != nil {
		t.Fatalf("PublicKeyFromBytes(all-zero): %v", err)
	}
	shared, err := SharedSecret(priv, lowOrder)
	if err == nil {
		t.Fatalf("low-order point accepted, shared = %x", shared)
	}
}

// TestPEMRoundtrip 验证 PKCS#8 / SPKI PEM 往返、加密 PEM 回环与口令轮换。
//
// TestPEMRoundtrip covers PKCS#8 / SPKI PEM roundtrips, the encrypted PEM
// roundtrip and passphrase rotation.
func TestPEMRoundtrip(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	privPEM, err := priv.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}
	pubPEM, err := pub.MarshalPEM()
	if err != nil {
		t.Fatalf("public MarshalPEM: %v", err)
	}
	priv2, err := LoadPrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM: %v", err)
	}
	if !priv.Key().Equal(priv2.Key()) {
		t.Fatal("private PEM roundtrip mismatch")
	}
	pub2, err := LoadPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM: %v", err)
	}
	if !pub.Key().PublicEqual(pub2.Key()) {
		t.Fatal("public PEM roundtrip mismatch")
	}

	enc, err := priv.MarshalEncryptedPEM("test-pass-1234")
	if err != nil {
		t.Fatalf("MarshalEncryptedPEM: %v", err)
	}
	loaded, err := LoadEncryptedPEM(enc, "test-pass-1234")
	if err != nil {
		t.Fatalf("LoadEncryptedPEM: %v", err)
	}
	if !priv.Key().Equal(loaded.Key()) {
		t.Fatal("encrypted PEM roundtrip mismatch")
	}
	if _, err := LoadEncryptedPEM(enc, "wrong-pass"); err == nil {
		t.Fatal("wrong passphrase should fail")
	}
	rotated, err := ChangePassword(enc, "test-pass-1234", "new-pass-5678")
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if _, err := LoadEncryptedPEM(rotated, "new-pass-5678"); err != nil {
		t.Fatalf("load rotated PEM: %v", err)
	}
}

// TestMatch 验证 Match 仅比较公钥分量：自身及其公钥视图为 true，另一密钥为 false，
// nil 接收者 / nil 参数也为 false。
//
// TestMatch verifies Match compares only the public component: true for the key
// itself and its public view, false for another key, and false for nil receivers
// or nil arguments.
func TestMatch(t *testing.T) {
	a, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	b, err := GenerateKey()
	if err != nil {
		t.Fatalf("second GenerateKey: %v", err)
	}
	pub, err := a.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	if !a.Match(a.Key()) {
		t.Error("Match(self) = false, want true")
	}
	if !a.Match(pub.Key()) {
		t.Error("Match(public view) = false, want true")
	}
	if a.Match(b.Key()) {
		t.Error("Match(other key) = true, want false")
	}
	var nilPriv *PrivateKey
	if nilPriv.Match(nil) {
		t.Error("Match on a nil receiver = true, want false")
	}
}
