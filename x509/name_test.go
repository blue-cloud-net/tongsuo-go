package x509

import (
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// TestNameHelpers 验证 Name.Nid / Name.Len / SubjectText / IssuerEntries / SubjectEntries。
func TestNameHelpers(t *testing.T) {
	n := NewName().Add("CN", "name.example.com").Add("O", "Name Org").Add("C", "CN")
	if n.Len() != 3 {
		t.Fatalf("Name.Len = %d, want 3", n.Len())
	}
	if n.Nid("CN") == 0 {
		t.Fatal("Name.Nid(\"CN\") = 0, want nonzero")
	}
	if n.Nid("") != 0 {
		t.Fatalf("Name.Nid(\"\") = %d, want 0", n.Nid(""))
	}
	if n.Nid("unknown-field-xyz") != 0 {
		t.Fatal("Name.Nid(unknown) should return 0")
	}
	if n.String() == "" {
		t.Fatal("Name.String() should not be empty")
	}

	// CSR SubjectEntries / SubjectText
	priv, _ := asym.GenerateSM2()
	req, _ := NewCertificateRequest(n, priv.Public(), priv)
	entries := req.SubjectEntries()
	if len(entries) != 3 {
		t.Fatalf("CSR SubjectEntries = %d, want 3", len(entries))
	}
	if req.SubjectText() == "" {
		t.Fatal("CSR SubjectText should not be empty")
	}
}
