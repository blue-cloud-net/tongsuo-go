package core

import (
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// TestAlgNamesFamilies 验证七个算法族的枚举都能返回非空列表，
// 且必含的规范名在其中。
//
// TestAlgNamesFamilies verifies that the enumeration of all seven
// algorithm families returns a non-empty list containing the expected
// canonical names.
func TestAlgNamesFamilies(t *testing.T) {
	tests := []struct {
		name  string
		kind  int
		musts []string
	}{
		{"digest", native.AlgKindMD, []string{"SM3", "SHA2-256"}},
		{"cipher", native.AlgKindCipher, []string{"SM4-CBC", "SM4-GCM", "AES-128-CBC", "ChaCha20"}},
		{"mac", native.AlgKindMAC, []string{"CMAC", "GMAC", "HMAC", "KMAC-128", "POLY1305"}},
		{"kdf", native.AlgKindKDF, []string{"HKDF", "PBKDF2", "SCRYPT", "SSKDF", "TLS13-KDF", "TLS1-PRF", "KBKDF", "X942KDF-ASN1", "X963KDF", "HMAC-DRBG-KDF"}},
		{"signature", native.AlgKindSignature, []string{"RSA", "ECDSA"}},
		{"keyexch", native.AlgKindKeyExch, []string{"ECDH"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			names := AlgNames(tt.kind)
			if len(names) == 0 {
				t.Fatalf("AlgNames(%s) returned no names", tt.name)
			}
			for _, must := range tt.musts {
				found := false
				for _, n := range names {
					if n == must {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("AlgNames(%s) missing %q (got %v)", tt.name, must, names)
				}
			}
		})
	}
}

// TestProviders 验证 provider 列表至少包含 default provider 且状态为 active。
//
// TestProviders verifies that the provider list contains at least the
// default provider and that its status is active.
func TestProviders(t *testing.T) {
	ps := Providers()
	if len(ps) == 0 {
		t.Fatal("Providers: no provider reported")
	}
	found := false
	for _, p := range ps {
		if p.Name == "default" {
			found = true
			if p.Status != "active" {
				t.Errorf("default provider status = %q, want active", p.Status)
			}
		}
	}
	if !found {
		t.Errorf("Providers: default provider not found (got %v)", ps)
	}
}

// TestTLSGroups 验证 TLS 组枚举返回非空列表且含 x25519。
//
// TestTLSGroups verifies that the TLS group enumeration returns a
// non-empty list containing x25519.
func TestTLSGroups(t *testing.T) {
	groups := TLSGroups()
	if len(groups) == 0 {
		t.Fatal("TLSGroups: no group reported")
	}
	found := false
	for _, g := range groups {
		if g == "x25519" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("TLSGroups: x25519 not found (got %v)", groups)
	}
}

// TestSeedingSource 验证种子来源查询返回非空描述。
//
// TestSeedingSource verifies that the seeding source query returns a
// non-empty description.
func TestSeedingSource(t *testing.T) {
	if s := SeedingSource(); s == "" {
		t.Error("SeedingSource: empty description")
	}
}
