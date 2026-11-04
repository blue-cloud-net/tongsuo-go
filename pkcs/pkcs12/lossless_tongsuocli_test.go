//go:build tongsuocli

package pkcs12

import (
	"bytes"
	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"os"
	"path/filepath"
	"testing"
)

// TestCLIExternalLosslessPasswords 验证相关操作的正确性、边界与错误处理。
//
// TestCLIExternalLosslessPasswords checks operation correctness, boundaries and error handling.
func TestCLIExternalLosslessPasswords(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)
	cert, key, ca := buildTestCert(t)
	defer cert.Close()
	defer asym.Close(key)
	defer ca.Close()
	dir := t.TempDir()
	c := filepath.Join(dir, "cert.pem")
	k := filepath.Join(dir, "key.pem")
	a := filepath.Join(dir, "ca.pem")
	input := filepath.Join(dir, "input.p12")
	output := filepath.Join(dir, "output.p12")
	cp, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	kp, err := key.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	ap, err := ca.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	for p, d := range map[string][]byte{c: cp, k: kp, a: ap} {
		if err := os.WriteFile(p, d, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, pbe := range []string{"AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "PBE-SHA1-3DES"} {
		args := []string{"pkcs12", "-export", "-in", c, "-inkey", k, "-certfile", a, "-out", input, "-passout", "pass:old", "-name", "original-friendly", "-keypbe", pbe, "-certpbe", pbe, "-iter", "2345"}
		if out, err := testutil.RunOpenSSLCombined(args, nil); err != nil {
			t.Fatalf("CLI export %s: %v %s", pbe, err, out)
		}
		before, err := testutil.RunOpenSSLCombined([]string{"pkcs12", "-in", input, "-passin", "pass:old", "-info", "-noout"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(input)
		if err != nil {
			t.Fatal(err)
		}
		changed, err := ChangePassword(data, "old", "new")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(output, changed, 0600); err != nil {
			t.Fatal(err)
		}
		after, err := testutil.RunOpenSSLCombined([]string{"pkcs12", "-in", output, "-passin", "pass:new", "-info", "-noout"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatalf("encryption/MAC parameters changed\nbefore %s\nafter %s", before, after)
		}
		exported, err := testutil.RunOpenSSL([]string{"pkcs12", "-in", output, "-passin", "pass:new", "-nodes"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Count(exported, []byte("BEGIN CERTIFICATE")) != 2 || !bytes.Contains(exported, []byte("friendlyName: original-friendly")) {
			t.Fatal("cert chain or name lost")
		}
	}
	if out, err := testutil.RunOpenSSLCombined([]string{"pkcs12", "-export", "-in", c, "-inkey", k, "-out", input, "-passout", "pass:old", "-nomac"}, nil); err != nil {
		t.Fatalf("no-MAC fixture: %v %s", err, out)
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := ChangePassword(data, "old", "new"); err == nil || out != nil {
		t.Fatal("no-MAC input accepted")
	}
}
