//go:build tongsuocli

package x509_test

import (
	"bytes"
	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/x509"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCLILongSerialAndTrustDirectory 验证相关操作的正确性、边界与错误处理。
//
// TestCLILongSerialAndTrustDirectory checks operation correctness, boundaries and error handling.
func TestCLILongSerialAndTrustDirectory(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)
	now := time.Now()
	ca := newCA(t, "long serial CLI", func() (asym.PrivateKey, error) { return asym.GenerateRSA(2048) }, now.Add(-time.Hour), now.Add(time.Hour))
	defer ca.cert.Close()
	defer asym.Close(ca.priv)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "key.pem")
	pem, err := ca.cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ca.priv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	for p, d := range map[string][]byte{certPath: pem, keyPath: key} {
		if err := os.WriteFile(p, d, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, hex := range []string{"7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "1234567890ABCDEF0123456789ABCDEF01", "-1234567890ABCDEF0123456789"} {
		encoded, err := testutil.RunOpenSSL([]string{"x509", "-in", certPath, "-signkey", keyPath, "-set_serial", "0x" + hex, "-outform", "DER"}, nil)
		if strings.HasPrefix(hex, "-") {
			encoded, err = testutil.RunOpenSSL([]string{"x509", "-in", certPath, "-signkey", keyPath, "-set_serial", "-0x" + hex[1:], "-outform", "DER"}, nil)
		}
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.LoadCertificateDER(encoded)
		if err != nil {
			t.Fatal(err)
		}
		n, err := c.SerialBigInt()
		c.Close()
		want, ok := new(big.Int).SetString(hex, 16)
		if !ok || err != nil || n.Cmp(want) != 0 {
			t.Fatal("CLI serial read", n, err)
		}
	}
	hash, err := testutil.RunOpenSSL([]string{"x509", "-in", certPath, "-hash", "-noout"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, strings.TrimSpace(string(hash))+".0"), pem, 0600); err != nil {
		t.Fatal(err)
	}
	store := x509.NewStore()
	defer store.Close()
	if err := store.LoadLocations("", dir); err != nil {
		t.Fatal(err)
	}
	chain, err := x509.ChainVerify(ca.cert, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range chain {
		c.Close()
	}
	serial := new(big.Int).Lsh(big.NewInt(1), 120)
	serial.Add(serial, big.NewInt(33))
	b, err := x509.NewCRLBuilder(ca.cert)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, err := range []error{b.SetThisUpdate(now.Add(-time.Minute)), b.SetNextUpdate(now.Add(time.Hour)), b.RevokeSerial(serial, now, x509.ReasonKeyCompromise)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	crl, err := b.Sign(ca.priv)
	if err != nil {
		t.Fatal(err)
	}
	defer crl.Close()
	der, err := crl.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	text, err := testutil.RunOpenSSL([]string{"crl", "-inform", "DER", "-text", "-noout"}, der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(bytes.ToUpper(text), []byte(strings.ToUpper(serial.Text(16)))) {
		t.Fatalf("CLI CRL serial missing: %s", text)
	}
}
