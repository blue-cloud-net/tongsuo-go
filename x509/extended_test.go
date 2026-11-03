package x509_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// TestTrustedCertificate 验证本地信任属性往返且证书签名内容不变。
//
// TestTrustedCertificate checks local trust round trips without changing signed certificate content.
func TestTrustedCertificate(t *testing.T) {
	leaf, ca := buildCerts(t)
	defer leaf.Close()
	defer ca.Close()
	before, err := ca.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	if err = ca.AddTrust("serverAuth"); err != nil {
		t.Fatal(err)
	}
	if err = ca.AddReject("clientAuth"); err != nil {
		t.Fatal(err)
	}
	data, err := ca.MarshalTrustedPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("TRUSTED CERTIFICATE")) {
		t.Fatal("missing trusted header")
	}
	got, err := x509.LoadTrustedCertificatePEM(data)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	round, err := got.MarshalTrustedPEM()
	if err != nil || !bytes.Equal(round, data) {
		t.Fatalf("trust attributes changed: %v", err)
	}
	after, err := got.MarshalDER()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("signed DER changed")
	}
	if err = got.SetSerial(77); err == nil {
		t.Fatal("loaded trusted certificate is mutable")
	}
	if err = got.ClearTrust(); err != nil {
		t.Fatal(err)
	}
	if err = got.ClearReject(); err != nil {
		t.Fatal(err)
	}
	cleared, err := got.MarshalTrustedPEM()
	if err != nil || bytes.Equal(cleared, data) {
		t.Fatal("attributes not cleared")
	}
	if err = got.AddTrust("not-a-purpose"); err == nil {
		t.Fatal("invalid purpose accepted")
	}
	got.Close()
	if err = got.AddTrust("serverAuth"); err == nil {
		t.Fatal("closed cert accepted")
	}
}

// TestUnifiedCertificateLoading 验证混合 PEM、DER 与文件加载。
//
// TestUnifiedCertificateLoading checks mixed PEM, DER and file loading.
func TestUnifiedCertificateLoading(t *testing.T) {
	leaf, ca := buildCerts(t)
	defer leaf.Close()
	defer ca.Close()
	a, err := leaf.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	b, err := ca.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	data := append(append([]byte(nil), a...), b...)
	certs, crls, err := x509.LoadFromReader(bytes.NewReader(data))
	if err != nil || len(certs) != 2 || len(crls) != 0 {
		t.Fatalf("%d %d %v", len(certs), len(crls), err)
	}
	for _, c := range certs {
		c.Close()
	}
	der, err := leaf.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	certs, _, err = x509.LoadFromReader(bytes.NewReader(der))
	if err != nil || len(certs) != 1 {
		t.Fatal(err)
	}
	certs[0].Close()
	path := filepath.Join(t.TempDir(), "chain.pem")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	certs, _, err = x509.LoadFromURI("file://" + path)
	if err != nil || len(certs) != 2 {
		t.Fatal(err)
	}
	for _, c := range certs {
		c.Close()
	}
	for _, blob := range [][]byte{nil, []byte("invalid"), append(append([]byte(nil), a...), []byte("truncated")...)} {
		c, r, e := x509.LoadFromReader(bytes.NewReader(blob))
		if e == nil || c != nil || r != nil {
			t.Fatal("invalid input or partial result accepted")
		}
	}
	if _, _, err = x509.LoadFromURI("https://example.invalid/chain"); err == nil {
		t.Fatal("remote URI accepted")
	}
}

// TestFetchOCSPErrors 验证 HTTP 参数、协议错误、限长与超时。
//
// TestFetchOCSPErrors checks HTTP arguments, protocol errors, size limits and timeouts.
func TestFetchOCSPErrors(t *testing.T) {
	leaf, ca := buildCerts(t)
	defer leaf.Close()
	defer ca.Close()
	req, err := x509.CreateOCSPRequestWithNonce(leaf, ca, "sha256", bytes.Repeat([]byte{7}, 16))
	if err != nil {
		t.Fatal(err)
	}
	random1, err := x509.CreateOCSPRequestWithNonce(leaf, ca, "sha256", nil)
	if err != nil {
		t.Fatal(err)
	}
	random2, err := x509.CreateOCSPRequestWithNonce(leaf, ca, "sha256", nil)
	if err != nil || bytes.Equal(random1, random2) {
		t.Fatal("nonce not random")
	}
	for _, nonce := range [][]byte{{}, make([]byte, 33)} {
		if _, err := x509.CreateOCSPRequestWithNonce(leaf, ca, "sha1", nonce); err == nil {
			t.Fatal("invalid nonce accepted")
		}
	}
	for _, tc := range []struct {
		name   string
		status int
		ctype  string
		body   []byte
		delay  time.Duration
		ok     bool
	}{
		{"tryLater", 200, "application/ocsp-response", []byte{0x30, 3, 0x0a, 1, 3}, 0, true},
		{"badStatus", 503, "application/ocsp-response", nil, 0, false},
		{"redirect", 302, "application/ocsp-response", nil, 0, false},
		{"wrongType", 200, "text/plain", nil, 0, false},
		{"invalidDER", 200, "application/ocsp-response", []byte("invalid"), 0, false},
		{"tooLarge", 200, "application/ocsp-response", make([]byte, (4<<20)+1), 0, false},
		{"timeout", 200, "application/ocsp-response", nil, 100 * time.Millisecond, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.Header.Get("Content-Type") != "application/ocsp-request" || r.Header.Get("Accept") != "application/ocsp-response" {
					t.Error("invalid OCSP HTTP headers")
				}
				got, e := io.ReadAll(r.Body)
				if e != nil || !bytes.Equal(got, req) {
					t.Error("request DER changed")
				}
				time.Sleep(tc.delay)
				w.Header().Set("Content-Type", tc.ctype)
				w.WriteHeader(tc.status)
				w.Write(tc.body)
			}))
			defer server.Close()
			timeout := time.Second
			if tc.delay > 0 {
				timeout = 10 * time.Millisecond
			}
			resp, e := x509.FetchOCSP(server.URL, req, timeout)
			if tc.ok {
				if e != nil {
					t.Fatal(e)
				}
				defer resp.Close()
				if resp.Status != 3 {
					t.Fatalf("status=%d", resp.Status)
				}
			} else if e == nil {
				resp.Close()
				t.Fatal("expected error")
			}
		})
	}
	if _, err = x509.FetchOCSP("http://unused", req, -1); err == nil {
		t.Fatal("negative timeout accepted")
	}
	if _, err = x509.FetchOCSP("http://unused", []byte("invalid"), 0); err == nil {
		t.Fatal("invalid request accepted")
	}
}
