//go:build tongsuocli

package x509_test

import (
	"bytes"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCLIOCSPHTTPNonce 验证 HTTP OCSP、nonce 匹配/缺失/篡改与响应签名。
//
// TestCLIOCSPHTTPNonce checks HTTP OCSP, matching/missing/tampered nonces and response signatures.
func TestCLIOCSPHTTPNonce(t *testing.T) {
	dir := setupOCSPEnv(t)
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, err := os.ReadFile(filepath.Join(dir, "leaf.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.LoadCertificatePEM(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Close()
	leaf, err := x509.LoadCertificatePEM(leafPEM)
	if err != nil {
		t.Fatal(err)
	}
	defer leaf.Close()
	req, err := x509.CreateOCSPRequestWithNonce(leaf, ca, "sha256", bytes.Repeat([]byte{1}, 16))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "nonce.der"), req, 0600); err != nil {
		t.Fatal(err)
	}
	reply := func(reqName, respName string) []byte {
		testutil.MustRunOpenSSLInDir(t, dir, "ocsp", "-index", "demoCA/index.txt", "-rsigner", "ca.pem", "-rkey", "ca.key", "-CA", "ca.pem", "-reqin", reqName, "-respout", respName, "-noverify")
		data, e := os.ReadFile(filepath.Join(dir, respName))
		if e != nil {
			t.Fatal(e)
		}
		return data
	}
	response := reply("nonce.der", "nonce-response.der")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, e := io.ReadAll(r.Body)
		if e != nil || !bytes.Equal(got, req) {
			t.Error("HTTP changed request")
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(response)
	}))
	defer server.Close()
	result, err := x509.FetchOCSP(server.URL, req, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if result.CertStatus != x509.OCSPGood || result.ThisUpdate.IsZero() {
		t.Fatal("missing certificate status")
	}
	roots := x509.NewStore()
	defer roots.Close()
	if err = roots.AddCert(ca); err != nil {
		t.Fatal(err)
	}
	if err = result.Verify(roots, nil); err != nil {
		t.Fatal(err)
	}
	changed, err := x509.CreateOCSPRequestWithNonce(leaf, ca, "sha256", bytes.Repeat([]byte{2}, 16))
	if err != nil {
		t.Fatal(err)
	}
	if err = result.CheckNonce(changed); err == nil {
		t.Fatal("mismatched nonce accepted")
	}
	plain, err := x509.CreateOCSPRequest(leaf, ca, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "plain.der"), plain, 0600); err != nil {
		t.Fatal(err)
	}
	response = reply("plain.der", "plain-response.der")
	if r, err := x509.FetchOCSP(server.URL, req, time.Second); err == nil {
		r.Close()
		t.Fatal("missing nonce accepted")
	}
}

// TestCLITrustAttributes 验证 trusted PEM 与铜锁 CLI 逐字节一致。
//
// TestCLITrustAttributes verifies trusted PEM matches the Tongsuo CLI byte for byte.
func TestCLITrustAttributes(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)
	leaf, ca := buildCerts(t)
	defer leaf.Close()
	defer ca.Close()
	plain, err := ca.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	want, err := testutil.RunOpenSSL([]string{"x509", "-addtrust", "serverAuth", "-addreject", "clientAuth", "-trustout"}, plain)
	if err != nil {
		t.Fatal(err)
	}
	if err = ca.AddTrust("serverAuth"); err != nil {
		t.Fatal(err)
	}
	if err = ca.AddReject("clientAuth"); err != nil {
		t.Fatal(err)
	}
	got, err := ca.MarshalTrustedPEM()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("trust differs: %v", err)
	}
}
