package asym_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// TestLoadPrivateKeySource 验证从 source 读取的 PEM 私钥与直接解析等价。
//
// TestLoadPrivateKeySource verifies that a PEM key read from a source
// matches the one parsed directly.
func TestLoadPrivateKeySource(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatalf("GenerateSM2: %v", err)
	}
	pemBytes, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatalf("MarshalPrivateKeyPEM: %v", err)
	}

	loaded, err := asym.LoadPrivateKeySource(meta.NewBytesSource(pemBytes), nil)
	if err != nil {
		t.Fatalf("LoadPrivateKeySource: %v", err)
	}
	if got, want := loaded.Algorithm(), priv.Algorithm(); got != want {
		t.Errorf("Algorithm = %q, want %q", got, want)
	}
	if !samePublicPEM(t, loaded.Public(), priv.Public()) {
		t.Error("public key bytes differ after source round-trip")
	}
}

// TestPrivateKeySourceEncrypted 验证带口令时按加密 PEM 解析。
//
// TestPrivateKeySourceEncrypted verifies that a passphrase triggers
// encrypted-PEM parsing.
func TestPrivateKeySourceEncrypted(t *testing.T) {
	priv, err := asym.GenerateRSA(2048)
	if err != nil {
		t.Fatalf("GenerateRSA: %v", err)
	}
	enc, err := asym.MarshalEncryptedPrivateKeyPEM(priv, "s3cret")
	if err != nil {
		t.Fatalf("MarshalEncryptedPrivateKeyPEM: %v", err)
	}

	pass, err := meta.NewPassphrase("pass:s3cret")
	if err != nil {
		t.Fatalf("NewPassphrase: %v", err)
	}
	loaded, err := asym.LoadPrivateKeySource(meta.NewBytesSource(enc), pass)
	if err != nil {
		t.Fatalf("LoadPrivateKeySource(encrypted): %v", err)
	}
	if !samePublicPEM(t, loaded.Public(), priv.Public()) {
		t.Error("public key bytes differ after encrypted round-trip")
	}

	// 不带口令时必须失败，而不是返回空私钥。
	if _, err := asym.LoadPrivateKeySource(meta.NewBytesSource(enc), nil); err == nil {
		t.Fatal("loading encrypted key without passphrase: want error, got nil")
	}
}

// TestMarshalPrivateKeyTo 验证加密与未加密两条写出路径都能被读回。
//
// TestMarshalPrivateKeyTo verifies that both the encrypted and the plain
// write paths can be read back.
func TestMarshalPrivateKeyTo(t *testing.T) {
	priv, err := asym.GenerateEd25519()
	if err != nil {
		t.Fatalf("GenerateEd25519: %v", err)
	}

	// 未加密。
	sink := meta.NewBytesSink()
	if err := asym.MarshalPrivateKeyTo(priv, sink, nil); err != nil {
		t.Fatalf("MarshalPrivateKeyTo(plain): %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("sink.Close: %v", err)
	}
	if !strings.Contains(string(sink.Bytes()), "BEGIN PRIVATE KEY") {
		t.Errorf("plain output lacks PKCS#8 header: %q", sink.Bytes())
	}
	if _, err := asym.LoadPrivateKeyPEM(sink.Bytes()); err != nil {
		t.Errorf("LoadPrivateKeyPEM on plain output: %v", err)
	}

	// 加密。
	pass, err := meta.NewPassphrase("pass:hunter2")
	if err != nil {
		t.Fatalf("NewPassphrase: %v", err)
	}
	encSink := meta.NewBytesSink()
	if err := asym.MarshalPrivateKeyTo(priv, encSink, pass); err != nil {
		t.Fatalf("MarshalPrivateKeyTo(encrypted): %v", err)
	}
	if err := encSink.Close(); err != nil {
		t.Fatalf("sink.Close: %v", err)
	}
	if _, err := asym.LoadEncryptedPrivateKeyPEM(encSink.Bytes(), "hunter2"); err != nil {
		t.Errorf("LoadEncryptedPrivateKeyPEM on encrypted output: %v", err)
	}
}

// TestMarshalPublicKeyTo 验证公钥写出后可被 LoadPublicKeySource 读回。
//
// TestMarshalPublicKeyTo verifies that a written public key can be read
// back with LoadPublicKeySource.
func TestMarshalPublicKeyTo(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatalf("GenerateSM2: %v", err)
	}
	sink := meta.NewBytesSink()
	if err := asym.MarshalPublicKeyTo(priv.Public(), sink); err != nil {
		t.Fatalf("MarshalPublicKeyTo: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("sink.Close: %v", err)
	}

	pub, err := asym.LoadPublicKeySource(meta.NewBytesSource(sink.Bytes()))
	if err != nil {
		t.Fatalf("LoadPublicKeySource: %v", err)
	}
	if !samePublicPEM(t, pub, priv.Public()) {
		t.Error("public key bytes differ after write/read cycle")
	}
}

// TestMarshalPrivateKeyToNilKey 验证 nil 私钥返回明确错误而非 panic。
//
// TestMarshalPrivateKeyToNilKey verifies that a nil key yields an error
// rather than a panic.
func TestMarshalPrivateKeyToNilKey(t *testing.T) {
	if err := asym.MarshalPrivateKeyTo(nil, meta.NewBytesSink(), nil); err == nil {
		t.Fatal("MarshalPrivateKeyTo(nil): want error, got nil")
	}
	if err := asym.MarshalPublicKeyTo(nil, meta.NewBytesSink()); err == nil {
		t.Fatal("MarshalPublicKeyTo(nil): want error, got nil")
	}
}

// samePublicPEM 比较两个公钥的 SPKI PEM 序列化是否一致。
//
// samePublicPEM reports whether two public keys serialise to the same
// SPKI PEM block.
func samePublicPEM(t *testing.T, a, b asym.PublicKey) bool {
	t.Helper()
	pa, err := a.MarshalPublicKeyPEM()
	if err != nil {
		t.Fatalf("MarshalPublicKeyPEM(a): %v", err)
	}
	pb, err := b.MarshalPublicKeyPEM()
	if err != nil {
		t.Fatalf("MarshalPublicKeyPEM(b): %v", err)
	}
	return bytes.Equal(pa, pb)
}
