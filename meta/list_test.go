package meta

import (
	"strings"
	"testing"
)

// TestAlgorithmEnumerations 验证七族算法枚举返回非空、去重、排序的列表，
// 且必含的规范名在其中。
//
// TestAlgorithmEnumerations verifies that the seven algorithm-family
// enumerations return non-empty, de-duplicated and sorted lists that
// contain the expected canonical names.
func TestAlgorithmEnumerations(t *testing.T) {
	tests := []struct {
		name  string
		got   []string
		musts []string
	}{
		{"Digests", Digests(), []string{"SM3", "SHA2-256", "SHA2-512"}},
		{"Ciphers", Ciphers(), []string{"SM4-CBC", "SM4-GCM", "SM4-CCM", "SM4-XTS", "AES-128-CBC", "AES-192-CBC", "AES-256-GCM", "ChaCha20", "ChaCha20-Poly1305"}},
		{"MACs", MACs(), []string{"CMAC", "GMAC", "HMAC", "KMAC-128", "KMAC-256", "SIPHASH", "POLY1305", "EIA3"}},
		{"KDFs", KDFs(), []string{"HKDF", "PBKDF2", "SCRYPT", "SSKDF", "TLS1-PRF", "TLS13-KDF", "KBKDF", "X942KDF-ASN1", "X963KDF", "HMAC-DRBG-KDF"}},
		{"Signatures", Signatures(), []string{"RSA", "ECDSA", "ED25519"}},
		{"KeyExchanges", KeyExchanges(), []string{"ECDH", "X25519"}},
		{"KEMs", KEMs(), nil},
		{"TLSGroups", TLSGroups(), []string{"x25519", "secp256r1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.got) == 0 {
				t.Fatalf("%s: empty enumeration", tt.name)
			}
			seen := make(map[string]struct{}, len(tt.got))
			for i, n := range tt.got {
				if n == "" {
					t.Errorf("%s: empty name at index %d", tt.name, i)
				}
				if _, dup := seen[n]; dup {
					t.Errorf("%s: duplicate name %q", tt.name, n)
				}
				seen[n] = struct{}{}
				if i > 0 && tt.got[i-1] > n {
					t.Errorf("%s: not sorted at index %d (%q > %q)", tt.name, i, tt.got[i-1], n)
				}
			}
			for _, must := range tt.musts {
				if _, ok := seen[must]; !ok {
					t.Errorf("%s: missing %q", tt.name, must)
				}
			}
		})
	}
}

// TestProviders 验证 provider 列表含 default provider 且状态为 active。
//
// TestProviders verifies that the provider list contains the default
// provider and that its status is active.
func TestProviders(t *testing.T) {
	ps := Providers()
	if len(ps) == 0 {
		t.Fatal("Providers: empty list")
	}
	found := false
	for _, p := range ps {
		if p.Name == "default" {
			found = true
			if p.Status != "active" {
				t.Errorf("default provider status = %q, want active", p.Status)
			}
			if p.Version == "" {
				t.Error("default provider version is empty")
			}
		}
	}
	if !found {
		t.Errorf("Providers: default provider missing (%v)", ps)
	}
}

// TestSeedingSource 验证种子来源返回非空描述。
//
// TestSeedingSource verifies that the seeding source returns a non-empty
// description.
func TestSeedingSource(t *testing.T) {
	s := SeedingSource()
	if s == "" {
		t.Fatal("SeedingSource: empty description")
	}
	if strings.TrimSpace(s) == "" {
		t.Fatal("SeedingSource: blank description")
	}
}
