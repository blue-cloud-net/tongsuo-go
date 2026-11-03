package x509_test

import (
	"bytes"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// TestCompleteSerialRevocation 验证相关操作的正确性、边界与错误处理。
//
// TestCompleteSerialRevocation checks operation correctness, boundaries and error handling.
func TestCompleteSerialRevocation(t *testing.T) {
	now := time.Now()
	ca := newCA(t, "serial CA", func() (asym.PrivateKey, error) { return asym.GenerateSM2() }, now.Add(-time.Hour), now.Add(time.Hour))
	defer ca.cert.Close()
	defer asym.Close(ca.priv)
	serial := new(big.Int).Lsh(big.NewInt(1), 120)
	serial.Add(serial, big.NewInt(42))
	issue := func(n *big.Int) *x509.Certificate {
		t.Helper()
		c := x509.NewCertificate()
		t.Cleanup(func() { c.Close() })
		for _, err := range []error{c.SetVersion(2), c.SetSerialBigInt(n), c.SetSubject(x509.NewName().Add("CN", "leaf")), c.SetIssuer(ca.cert.SubjectName()), c.SetValidity(now.Add(-time.Minute), now.Add(time.Hour)), c.SetPublicKey(ca.priv.Public()), c.Sign(ca.priv)} {
			if err != nil {
				t.Fatal(err)
			}
		}
		return c
	}
	first := issue(serial)
	second := issue(new(big.Int).Add(new(big.Int).Set(serial), new(big.Int).Lsh(big.NewInt(1), 80)))
	got, err := first.SerialBigInt()
	if err != nil || got.Cmp(serial) != 0 {
		t.Fatal(got, err)
	}
	got.SetInt64(9)
	got, err = first.SerialBigInt()
	if err != nil || got.Cmp(serial) != 0 {
		t.Fatal("read aliases certificate")
	}
	der, err := first.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := x509.LoadCertificateDER(der)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	builder, err := x509.NewCRLBuilder(ca.cert)
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close()
	if err := builder.SetThisUpdate(now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := builder.SetNextUpdate(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := builder.Revoke(first, now, x509.ReasonKeyCompromise); err != nil {
		t.Fatal(err)
	}
	hexSerial := new(big.Int).Add(serial, big.NewInt(1))
	if err := builder.RevokeSerialHex("000"+hexSerial.Text(16), now, x509.ReasonUnspecified); err != nil {
		t.Fatal(err)
	}
	if err := builder.RevokeSerial(serial, now, x509.RevocationReason(99)); err == nil {
		t.Fatal("bad reason accepted")
	}
	crl, err := builder.Sign(ca.priv)
	if err != nil {
		t.Fatal(err)
	}
	defer crl.Close()
	if !crl.IsRevoked(loaded) || crl.IsRevoked(second) {
		t.Fatal("full serial matching failed")
	}
	if err := x509.RevocationCheck(second, []*x509.CRL{crl}); err != nil {
		t.Fatal("serial collision", err)
	}
	if err := x509.RevocationCheck(loaded, []*x509.CRL{crl}); err == nil {
		t.Fatal("revocation missed")
	}
	pem, err := crl.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	copyCRL, err := x509.LoadCRLPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	defer copyCRL.Close()
	if !copyCRL.IsRevoked(first) || len(copyCRL.RevokedEntries()) != 2 {
		t.Fatal("CRL round trip failed")
	}
	for _, entry := range copyCRL.RevokedEntries() {
		n, err := entry.SerialBigInt()
		if err != nil || n.BitLen() < 100 {
			t.Fatal(n, err)
		}
	}
	c := x509.NewCertificate()
	defer c.Close()
	for _, n := range []*big.Int{nil, big.NewInt(0), big.NewInt(-1), new(big.Int).Lsh(big.NewInt(1), 159)} {
		if err := c.SetSerialBigInt(n); err == nil {
			t.Fatal("invalid serial accepted", n)
		}
	}
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 159), big.NewInt(1))
	if err := c.SetSerialBigInt(max); err != nil {
		t.Fatal(err)
	}
	max.SetInt64(4)
	n, err := c.SerialBigInt()
	if err != nil || n.BitLen() != 159 {
		t.Fatal("input aliases certificate", n, err)
	}
	if c.SetSerial(0) == nil || c.SetSerial(-1) == nil {
		t.Fatal("legacy serial validation lost")
	}
	if first.SetSerialBigInt(big.NewInt(1)) == nil {
		t.Fatal("signed certificate mutable")
	}
	if _, err := (x509.RevokedEntry{Serial: 3}).SerialBigInt(); err == nil {
		t.Fatal("fallback to truncated serial")
	}
}

// TestCSRCloseAndBigSerial 验证相关操作的正确性、边界与错误处理。
//
// TestCSRCloseAndBigSerial checks operation correctness, boundaries and error handling.
func TestCSRCloseAndBigSerial(t *testing.T) {
	now := time.Now()
	ca := newCA(t, "CSR CA", func() (asym.PrivateKey, error) { return asym.GenerateSM2() }, now.Add(-time.Hour), now.Add(time.Hour))
	defer ca.cert.Close()
	defer asym.Close(ca.priv)
	req, err := x509.NewCertificateRequest(x509.NewName().Add("CN", "CSR leaf"), ca.priv.Public(), ca.priv)
	if err != nil {
		t.Fatal(err)
	}
	defer req.Close()
	serial := new(big.Int).Lsh(big.NewInt(1), 100)
	opts := &x509.IssueOptions{SerialBigInt: serial, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute)}
	c, err := x509.IssueCertificateFromRequest(req, ca.cert, ca.priv, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	n, err := c.SerialBigInt()
	if err != nil || n.Cmp(serial) != 0 {
		t.Fatal(n, err)
	}
	opts.Serial = 1
	if c, err := x509.IssueCertificateFromRequest(req, ca.cert, ca.priv, opts); err == nil {
		c.Close()
		t.Fatal("conflicting serials accepted")
	}
	if err := req.Close(); err != nil {
		t.Fatal(err)
	}
	if err := req.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := req.MarshalDER(); err == nil {
		t.Fatal("closed CSR serialized")
	}
	if req.Verify() == nil {
		t.Fatal("closed CSR verified")
	}
	var nilReq *x509.CertificateRequest
	for _, r := range []*x509.CertificateRequest{nilReq, {}} {
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := r.MarshalPEM(); err == nil {
			t.Fatal("zero CSR accepted")
		}
	}
}

// TestRawExtensionAndTrustLocations 验证相关操作的正确性、边界与错误处理。
//
// TestRawExtensionAndTrustLocations checks operation correctness, boundaries and error handling.
func TestRawExtensionAndTrustLocations(t *testing.T) {
	key, err := asym.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	defer asym.Close(key)
	c := x509.NewCertificate()
	defer c.Close()
	name := x509.NewName().Add("CN", "raw extensions")
	now := time.Now()
	for _, err := range []error{c.SetVersion(2), c.SetSerial(5), c.SetSubject(name), c.SetIssuer(name), c.SetPublicKey(key.Public()), c.SetValidity(now.Add(-time.Hour), now.Add(time.Hour)), c.AddExtensionDER("2.5.29.19", true, []byte{0x30, 3, 1, 1, 0xff}), c.AddExtensionDER("1.2.3.4.55", false, []byte{4, 3, 1, 2, 3})} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if c.AddExtensionDER("not an OID", false, []byte{5, 0}) == nil || c.AddExtensionDER("1.2.3", false, []byte{4, 2, 1}) == nil {
		t.Fatal("invalid extension accepted")
	}
	if err := c.Sign(key); err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(key.Public()); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ext := range c.Extensions() {
		if ext.OID == "1.2.3.4.55" {
			found = true
			if ext.Critical || !bytes.Equal(ext.Data, []byte{4, 3, 1, 2, 3}) {
				t.Fatalf("extension changed %+v", ext)
			}
		}
	}
	if !found {
		t.Fatal("raw extension absent")
	}
	if c.AddExtensionDER("1.2.3.5", false, []byte{5, 0}) == nil {
		t.Fatal("signed extension changed")
	}
	store := x509.NewStore()
	defer store.Close()
	if chain, err := x509.ChainVerify(c, store, []*x509.Certificate{c}); err == nil {
		for _, c := range chain {
			c.Close()
		}
		t.Fatal("input root trusted")
	}
	pem, err := c.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem, 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadLocations(path, ""); err != nil {
		t.Fatal(err)
	}
	chain, err := x509.ChainVerify(c, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range chain {
		c.Close()
	}
	defaults := x509.NewStore()
	defer defaults.Close()
	t.Setenv("SSL_CERT_FILE", path)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	if err := defaults.SetDefaultPaths(); err != nil {
		t.Fatal(err)
	}
	chain, err = x509.ChainVerify(c, defaults, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range chain {
		c.Close()
	}
	if err := defaults.Close(); err != nil {
		t.Fatal(err)
	}
	if defaults.SetDefaultPaths() == nil || store.LoadLocations("", "") == nil || store.LoadLocations("a\x00b", "") == nil {
		t.Fatal("invalid store call accepted")
	}
}
