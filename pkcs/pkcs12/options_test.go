package pkcs12

import (
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

func closeBundle(b *Bundle) {
	if b == nil {
		return
	}
	asym.Close(b.PrivateKey)
	if b.Certificate != nil {
		b.Certificate.Close()
	}
	for _, c := range b.CACerts {
		c.Close()
	}
}

// TestPackOptions 验证 PBE、迭代参数与独立读写口令。
//
// TestPackOptions checks PBE, iteration settings and separate input/output passwords.
func TestPackOptions(t *testing.T) {
	cert, key, ca := buildTestCert(t)
	defer cert.Close()
	defer asym.Close(key)
	defer ca.Close()
	for _, pbe := range []string{"AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "PBE-SHA1-3DES"} {
		o := &Options{PBE: pbe, Iterations: 1234, FriendlyName: "custom", WritePass: "old"}
		data, err := PackWithOptions(cert, key, nil, o)
		if err != nil {
			t.Fatal(err)
		}
		b, err := ParseWithOptions(data, &Options{ReadPass: "old"})
		if err != nil {
			t.Fatal(err)
		}
		closeBundle(b)
		changed, err := ChangePasswordWithOptions(data, &Options{ReadPass: "old", WritePass: "new", PBE: pbe, Iterations: 2345})
		if err != nil {
			t.Fatal(err)
		}
		b, err = Parse(changed, "new")
		if err != nil {
			t.Fatal(err)
		}
		closeBundle(b)
		if b, err = Parse(changed, "old"); err == nil {
			closeBundle(b)
			t.Fatal("old password accepted")
		}
	}
	for _, o := range []*Options{{PBE: "RC2-CBC"}, {Iterations: -1}, {Iterations: 1 << 32}, {WritePass: "a\x00b"}} {
		if _, err := PackWithOptions(cert, key, nil, o); err == nil {
			t.Fatal("invalid options accepted")
		}
	}
}
