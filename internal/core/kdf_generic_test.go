package core

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestDeriveFamilies 验证泛化 KDF 派生的各算法族可派生出结果。
//
// TestDeriveFamilies verifies that every supported KDF family produces a
// derivation result.
func TestDeriveFamilies(t *testing.T) {
	tests := []struct {
		name string
		alg  string
		p    *KDFParams
	}{
		{"HKDF", "HKDF", &KDFParams{Digest: "SHA256", Key: []byte("ikm"), Salt: []byte("salt"), Info: []byte("info")}},
		{"PBKDF2", "PBKDF2", &KDFParams{Digest: "SHA256", Pass: []byte("pw"), Salt: []byte("salt"), Iter: 1}},
		{"SCRYPT", "SCRYPT", &KDFParams{Pass: []byte("pw"), Salt: []byte("salt"), N: 1024, R: 8, P: 1, MaxMem: 32 * 1024 * 1024}},
		{"SSKDF", "SSKDF", &KDFParams{Digest: "SHA256", Secret: []byte("z"), Info: []byte("info")}},
		{"TLS1-PRF", "TLS1-PRF", &KDFParams{Digest: "SHA256", Secret: []byte("secret"), Seed: []byte("seed")}},
		{"TLS13-KDF", "TLS13-KDF", &KDFParams{Digest: "SHA256", Mode: "EXTRACT_ONLY", Key: []byte("ikm")}},
		{"KBKDF", "KBKDF", &KDFParams{Digest: "SHA256", MAC: "HMAC", Mode: "counter", Key: []byte("ki"), Salt: []byte("label"), Info: []byte("context"), R: 8}},
		{"X942KDF-ASN1", "X942KDF-ASN1", &KDFParams{Digest: "SHA256", Secret: []byte("z"), Key: []byte("kek"), CEKAlg: "AES-128-WRAP"}},
		{"X963KDF", "X963KDF", &KDFParams{Digest: "SHA256", Secret: []byte("z"), Info: []byte("info")}},
		{"HMAC-DRBG-KDF", "HMAC-DRBG-KDF", &KDFParams{Digest: "SHA256", Entropy: []byte("entropy"), Nonce: []byte("nonce")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := make([]byte, 32)
			if err := Derive(tt.alg, tt.p, out); err != nil {
				t.Fatalf("Derive(%s): %v", tt.alg, err)
			}
			if bytes.Equal(out, make([]byte, 32)) {
				t.Fatalf("Derive(%s): all-zero output", tt.alg)
			}
			// 同样的输入必须得到同样的输出。
			again := make([]byte, 32)
			if err := Derive(tt.alg, tt.p, again); err != nil {
				t.Fatalf("Derive(%s) second: %v", tt.alg, err)
			}
			if !bytes.Equal(out, again) {
				t.Fatalf("Derive(%s) not deterministic", tt.alg)
			}
		})
	}
}

// TestDeriveScryptKnownVector 验证 SCRYPT 对 RFC 7914 §11 的标准向量。
//
// TestDeriveScryptKnownVector verifies SCRYPT against the RFC 7914
// section 11 test vector.
func TestDeriveScryptKnownVector(t *testing.T) {
	out := make([]byte, 64)
	p := &KDFParams{
		Pass:   []byte("password"),
		Salt:   []byte("NaCl"),
		N:      1024,
		R:      8,
		P:      16,
		MaxMem: 32 * 1024 * 1024,
	}
	if err := Derive("SCRYPT", p, out); err != nil {
		t.Fatalf("Derive(SCRYPT): %v", err)
	}
	want, err := hex.DecodeString(
		"fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162" +
			"2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640")
	if err != nil {
		t.Fatalf("decode want: %v", err)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("SCRYPT = %x, want %x", out, want)
	}
}

// TestDeriveRejectsBadInput 验证空算法名与零长度输出被拒绝。
//
// TestDeriveRejectsBadInput verifies that an empty algorithm name and a
// zero-length output are rejected.
func TestDeriveRejectsBadInput(t *testing.T) {
	if err := Derive("", nil, make([]byte, 16)); err == nil {
		t.Error("Derive: expected error for empty algorithm name")
	}
	if err := Derive("HKDF", nil, nil); err == nil {
		t.Error("Derive: expected error for zero-length output")
	}
}
