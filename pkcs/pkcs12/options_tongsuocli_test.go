//go:build tongsuocli

package pkcs12

import (
	"bytes"
	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"testing"
)

// TestCLIPKCS12Options 验证 PBE、迭代与友好名称确实写入容器。
//
// TestCLIPKCS12Options verifies PBE, iterations and the friendly name are encoded in the container.
func TestCLIPKCS12Options(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)
	cert, key, ca := buildTestCert(t)
	defer cert.Close()
	defer asym.Close(key)
	defer ca.Close()
	for _, pbe := range []string{"AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "PBE-SHA1-3DES"} {
		data, err := PackWithOptions(cert, key, nil, &Options{PBE: pbe, Iterations: 1234, FriendlyName: "v060 test", WritePass: "secret"})
		if err != nil {
			t.Fatal(err)
		}
		out, err := testutil.RunOpenSSLCombined([]string{"pkcs12", "-passin", "pass:secret", "-info", "-nodes"}, data)
		if err != nil {
			t.Fatalf("%s: %s %v", pbe, out, err)
		}
		if !bytes.Contains(out, []byte("Iteration 1234")) || !bytes.Contains(out, []byte("friendlyName: v060 test")) {
			t.Fatalf("missing settings: %s", out)
		}
		if pbe != "PBE-SHA1-3DES" && !bytes.Contains(bytes.ToUpper(out), []byte(pbe)) {
			t.Fatalf("PBE ignored: %s", out)
		}
	}
}
