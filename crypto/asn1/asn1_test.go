package asn1

import (
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/rsa"
	"github.com/blue-cloud-net/tongsuo-go/crypto/x509"
)

// TestParseSimple 验证简单 DER 结构。
func TestParseSimple(t *testing.T) {
	// SEQUENCE { INTEGER 42 }
	der := []byte{0x30, 0x03, 0x02, 0x01, 0x2a}
	root, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	if root.Number != TagSequence || !root.Constructed {
		t.Fatalf("root = %+v", root)
	}
	if len(root.Children) != 1 {
		t.Fatalf("children = %d, want 1", len(root.Children))
	}
	intNode := root.Children[0]
	if intNode.Number != TagInteger || len(intNode.Value) != 1 || intNode.Value[0] != 0x2a {
		t.Fatalf("int node = %+v", intNode)
	}
}

// TestParseCert 验证证书 DER 结构。
func TestParseCert(t *testing.T) {
	priv, err := rsa.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := x509.NewName().Add("CN", "asn1.example.com")
	cert, err := x509.CreateCertificate(subject, subject, 1,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	der, err := cert.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	root, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	// 证书顶层为 SEQUENCE，至少含 tbsCertificate / signatureAlgorithm / signatureValue
	if root.Number != TagSequence {
		t.Fatalf("root tag = %d, want SEQUENCE", root.Number)
	}
	if len(root.Children) < 3 {
		t.Fatalf("cert children = %d, want >= 3", len(root.Children))
	}
	dump := Dump(root)
	for _, want := range []string{"SEQUENCE", "INTEGER", "BIT STRING", "OBJECT IDENTIFIER"} {
		if !strings.Contains(dump, want) {
			t.Fatalf("dump missing %q:\n%s", want, dump)
		}
	}
}

// TestParseErrors 验证非法输入。
func TestParseErrors(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Fatal("empty should error")
	}
	if _, err := Parse([]byte{0x30, 0x05, 0x02}); err == nil { // 截断
		t.Fatal("truncated should error")
	}
	if _, err := Parse([]byte{0x30, 0x80, 0x00}); err == nil { // 不定长 DER 不允许
		t.Fatal("indefinite length should error")
	}
}
