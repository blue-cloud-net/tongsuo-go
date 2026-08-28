//go:build tongsuocli

package asn1

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

func runOpenSSL(t *testing.T, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(testutil.OpenSSLBin(), args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %v: %v\n%s", args, err, out)
	}
	return out
}

// TestCLIDerParse 解析 openssl 生成的证书 DER，验证结构。
func TestCLIDerParse(t *testing.T) {
	dir := t.TempDir()
	pemFile := filepath.Join(dir, "cert.pem")
	derFile := filepath.Join(dir, "cert.der")
	runOpenSSL(t, "req", "-new", "-x509", "-nodes", "-keyout", filepath.Join(dir, "key.pem"),
		"-out", pemFile, "-subj", "/CN=asn1-cli.dev", "-days", "365")
	runOpenSSL(t, "x509", "-in", pemFile, "-outform", "DER", "-out", derFile)
	der, err := os.ReadFile(derFile)
	if err != nil {
		t.Fatal(err)
	}
	root, err := Parse(der)
	if err != nil {
		t.Fatalf("parse openssl DER failed: %v", err)
	}
	if root.Number != TagSequence {
		t.Fatalf("root tag = %d, want SEQUENCE", root.Number)
	}
	// 证书顶层至少 3 个字段
	if len(root.Children) < 3 {
		t.Fatalf("children = %d, want >= 3", len(root.Children))
	}
	// 与 openssl asn1parse 直接子节点数对比（根为 d=0，子节点为 d=1）
	out := runOpenSSL(t, "asn1parse", "-in", derFile, "-inform", "DER")
	lines := strings.Split(string(out), "\n")
	childCount := 0
	for _, l := range lines {
		if strings.Contains(l, "d=1 ") {
			childCount++
		}
	}
	if childCount != len(root.Children) {
		t.Fatalf("openssl asn1parse d=1 fields = %d, our children = %d", childCount, len(root.Children))
	}
}
