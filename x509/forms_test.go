package x509_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/meta"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// selfSigned 生成一张 SM2 自签证书用于本文件的测试。
//
// selfSigned builds a self-signed SM2 certificate for the tests in this
// file.
func selfSigned(t *testing.T) (*x509.Certificate, asym.PrivateKey) {
	t.Helper()
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatalf("GenerateSM2: %v", err)
	}
	subject := x509.NewName().Add("CN", "forms.example.com")
	now := time.Now()
	cert, err := x509.CreateSelfSigned(subject, 42,
		now.Add(-time.Hour), now.Add(24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatalf("CreateSelfSigned: %v", err)
	}
	return cert, priv
}

// TestMarshalFormat 验证 MarshalFormat 的 PEM / DER 输出与既有入口一致。
//
// TestMarshalFormat verifies that MarshalFormat's PEM and DER output
// matches the existing entries.
func TestMarshalFormat(t *testing.T) {
	cert, _ := selfSigned(t)

	pemWant, err := cert.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}
	gotPEM, err := x509.MarshalFormat(cert, meta.FormatPEM)
	if err != nil {
		t.Fatalf("MarshalFormat(PEM): %v", err)
	}
	if !bytes.Equal(gotPEM, pemWant) {
		t.Error("MarshalFormat(PEM) differs from MarshalPEM")
	}

	derWant, err := cert.MarshalDER()
	if err != nil {
		t.Fatalf("MarshalDER: %v", err)
	}
	gotDER, err := x509.MarshalFormat(cert, meta.FormatDER)
	if err != nil {
		t.Fatalf("MarshalFormat(DER): %v", err)
	}
	if !bytes.Equal(gotDER, derWant) {
		t.Error("MarshalFormat(DER) differs from MarshalDER")
	}

	if _, err := x509.MarshalFormat(cert, meta.Format("bogus")); err == nil {
		t.Error("MarshalFormat(bogus): want error, got nil")
	}
	if _, err := x509.MarshalFormat(nil, meta.FormatPEM); err == nil {
		t.Error("MarshalFormat(nil): want error, got nil")
	}
}

// TestLoadCertificateSource 验证 PEM 与 DER 两种输入都能被自动识别读回。
//
// TestLoadCertificateSource verifies that both PEM and DER inputs are
// auto-detected and read back.
func TestLoadCertificateSource(t *testing.T) {
	cert, _ := selfSigned(t)
	wantSerial := cert.Serial()

	pemBytes, err := cert.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}
	derBytes, err := cert.MarshalDER()
	if err != nil {
		t.Fatalf("MarshalDER: %v", err)
	}

	cases := []struct {
		name string
		src  *meta.Source
	}{
		{"pem", meta.NewBytesSource(pemBytes)},
		{"der", meta.NewBytesSource(derBytes)},
		// 前置空白不应影响识别。
		{"pem-with-leading-blank", meta.NewBytesSource(append([]byte("\n  "), pemBytes...))},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			loaded, err := x509.LoadCertificateSource(tc.src)
			if err != nil {
				t.Fatalf("LoadCertificateSource: %v", err)
			}
			if got := loaded.Serial(); got != wantSerial {
				t.Errorf("Serial = %d, want %d", got, wantSerial)
			}
			if got, want := loaded.Subject(), cert.Subject(); got != want {
				t.Errorf("Subject = %q, want %q", got, want)
			}
		})
	}

	if _, err := x509.LoadCertificateSource(meta.NewBytesSource(nil)); err == nil {
		t.Error("LoadCertificateSource(empty): want error, got nil")
	}
}

// TestMarshalCertificateTo 验证写入 sink 的 PEM 可被再次读回，
// 并支持 hex 编码。
//
// TestMarshalCertificateTo verifies that the PEM written to a sink can
// be read back and that hex encoding works.
func TestMarshalCertificateTo(t *testing.T) {
	cert, _ := selfSigned(t)

	sink := meta.NewBytesSink()
	if err := x509.MarshalCertificateTo(cert, sink, meta.FormatPEM); err != nil {
		t.Fatalf("MarshalCertificateTo: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("sink.Close: %v", err)
	}
	if !strings.Contains(string(sink.Bytes()), "BEGIN CERTIFICATE") {
		t.Fatalf("output lacks CERTIFICATE header: %q", sink.Bytes())
	}
	if _, err := x509.LoadCertificateSource(meta.NewBytesSource(sink.Bytes())); err != nil {
		t.Errorf("read back: %v", err)
	}

	hexSink := meta.NewBytesSink()
	if err := hexSink.SetEncoding(meta.EncodingHex); err != nil {
		t.Fatalf("SetEncoding: %v", err)
	}
	if err := x509.MarshalCertificateTo(cert, hexSink, meta.FormatDER); err != nil {
		t.Fatalf("MarshalCertificateTo(hex): %v", err)
	}
	if err := hexSink.Close(); err != nil {
		t.Fatalf("hex sink close: %v", err)
	}
	der, err := cert.MarshalDER()
	if err != nil {
		t.Fatalf("MarshalDER: %v", err)
	}
	hexWant, err := meta.Encode(der, meta.EncodingHex)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(hexSink.Bytes(), hexWant) {
		t.Error("hex-encoded DER output mismatch")
	}
}

// TestMarshalCSRTo 验证 CSR 的 PEM / DER 写出与读回。
//
// TestMarshalCSRTo verifies the PEM and DER write paths for a CSR.
func TestMarshalCSRTo(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatalf("GenerateSM2: %v", err)
	}
	req, err := x509.NewCertificateRequest(
		x509.NewName().Add("CN", "csr.forms.example.com"), priv.Public(), priv)
	if err != nil {
		t.Fatalf("NewCertificateRequest: %v", err)
	}

	pemSink := meta.NewBytesSink()
	if err := x509.MarshalCSRTo(req, pemSink, meta.FormatPEM); err != nil {
		t.Fatalf("MarshalCSRTo(PEM): %v", err)
	}
	if err := pemSink.Close(); err != nil {
		t.Fatalf("pem sink close: %v", err)
	}
	if !strings.Contains(string(pemSink.Bytes()), "BEGIN CERTIFICATE REQUEST") {
		t.Fatalf("output lacks CSR header: %q", pemSink.Bytes())
	}

	derSink := meta.NewBytesSink()
	if err := x509.MarshalCSRTo(req, derSink, meta.FormatDER); err != nil {
		t.Fatalf("MarshalCSRTo(DER): %v", err)
	}
	if err := derSink.Close(); err != nil {
		t.Fatalf("der sink close: %v", err)
	}
	derWant, err := req.MarshalDER()
	if err != nil {
		t.Fatalf("MarshalDER: %v", err)
	}
	if !bytes.Equal(derSink.Bytes(), derWant) {
		t.Error("MarshalCSRTo(DER) differs from MarshalDER")
	}

	if err := x509.MarshalCSRTo(nil, meta.NewBytesSink(), meta.FormatPEM); err == nil {
		t.Error("MarshalCSRTo(nil): want error, got nil")
	}
}
